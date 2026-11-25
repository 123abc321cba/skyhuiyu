"""持久化层 —— SQLite（WAL）。

表设计目标：
  · 徽章数据要"记住"，重启不丢、可去重、可回溯；
  · 每条手机消息都有回执，同一个 rid 重发不会二次入库（幂等）；
  · 官方接口的每次调用单独留一条 injection 记录，失败可人工对账。

每次操作独立开连接（WAL 下开销可忽略），避免长连接跨线程问题。
"""

from __future__ import annotations

import json
import sqlite3
import time
import uuid
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterator

# 回执的中间态：占位已写、提交还没结束。
# 任何从这个状态重启的进程都必须把它当成"官方侧状态未知"，绝不自动重发。
INFLIGHT = "inflight"

SCHEMA = """
PRAGMA journal_mode=WAL;

CREATE TABLE IF NOT EXISTS meta (
    k TEXT PRIMARY KEY,
    v TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS devices (
    id            TEXT PRIMARY KEY,
    fingerprint   TEXT NOT NULL,
    name          TEXT NOT NULL DEFAULT '',
    pubkey_b64    TEXT NOT NULL DEFAULT '',
    first_seen    REAL NOT NULL,
    last_seen     REAL NOT NULL,
    paired_count  INTEGER NOT NULL DEFAULT 0
);
CREATE UNIQUE INDEX IF NOT EXISTS devices_fp ON devices(fingerprint);

CREATE TABLE IF NOT EXISTS badges (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    uid          TEXT NOT NULL,
    counter      INTEGER NOT NULL,
    token        TEXT NOT NULL,
    url          TEXT NOT NULL,
    device_id    TEXT,
    received_at  REAL NOT NULL,
    backend      TEXT NOT NULL DEFAULT 'local',
    status       TEXT NOT NULL DEFAULT 'stored',
    note         TEXT NOT NULL DEFAULT '',
    UNIQUE(uid, counter, token)
);
CREATE INDEX IF NOT EXISTS badges_time ON badges(received_at DESC);

CREATE TABLE IF NOT EXISTS receipts (
    rid         TEXT NOT NULL,
    device_id   TEXT NOT NULL DEFAULT '',
    uid         TEXT NOT NULL DEFAULT '',
    counter     INTEGER NOT NULL DEFAULT 0,
    ok          INTEGER NOT NULL,
    action      TEXT NOT NULL DEFAULT '',
    detail      TEXT NOT NULL DEFAULT '',
    payload     TEXT NOT NULL DEFAULT '',
    created_at  REAL NOT NULL,
    badge_id    INTEGER,
    PRIMARY KEY (device_id, rid)
);

CREATE TABLE IF NOT EXISTS injections (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    badge_id     INTEGER,
    backend      TEXT NOT NULL,
    request_id   TEXT NOT NULL,
    url          TEXT NOT NULL DEFAULT '',
    http_status  INTEGER NOT NULL DEFAULT 0,
    result       TEXT NOT NULL DEFAULT '',
    detail       TEXT NOT NULL DEFAULT '',
    response     TEXT NOT NULL DEFAULT '',
    created_at   REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS injections_badge ON injections(badge_id);

CREATE TABLE IF NOT EXISTS sessions (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    account          TEXT NOT NULL DEFAULT 'default',
    user_id          TEXT NOT NULL DEFAULT '',
    session_token    TEXT NOT NULL DEFAULT '',
    level_id         TEXT NOT NULL DEFAULT '',
    build_access_key TEXT NOT NULL DEFAULT '',
    user_agent       TEXT NOT NULL DEFAULT '',
    game_version     TEXT NOT NULL DEFAULT '',
    extra            TEXT NOT NULL DEFAULT '{}',
    captured_at      REAL NOT NULL,
    last_ok          REAL NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS sessions_acct ON sessions(account, captured_at DESC);
"""


def _now() -> float:
    return time.time()


@dataclass
class BadgeRow:
    id: int
    uid: str
    counter: int
    token: str
    url: str
    device_id: str | None
    received_at: float
    backend: str
    status: str
    note: str = ""
    # 徽章库识别结果（由官方定义表算出，见 catalog.py）
    sku: str = ""
    def_name: str = ""
    label: str = ""
    img: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "uid": self.uid,
            "counter": self.counter,
            "token": self.token,
            "url": self.url,
            "device_id": self.device_id,
            "received_at": self.received_at,
            "received_at_iso": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(self.received_at)),
            "backend": self.backend,
            "sku": self.sku,
            "def_name": self.def_name,
            "label": self.label,
            "img": self.img,
            "status": self.status,
            "note": self.note,
        }


@dataclass
class DeviceRow:
    id: str
    fingerprint: str
    name: str
    pubkey_b64: str
    first_seen: float
    last_seen: float
    paired_count: int

    def as_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "fingerprint": self.fingerprint,
            "name": self.name,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "paired_count": self.paired_count,
        }


class Store:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as db:
            db.executescript(SCHEMA)
            self._migrate(db)

    @staticmethod
    def _migrate(db: sqlite3.Connection) -> None:
        """老库平滑升级。只加列/加表，不动既有数据。"""
        cols = {r[1] for r in db.execute("PRAGMA table_info(badges)")}
        for name, decl in (
            ("sku", "TEXT NOT NULL DEFAULT ''"),
            ("def_name", "TEXT NOT NULL DEFAULT ''"),
            ("label", "TEXT NOT NULL DEFAULT ''"),
            ("img", "TEXT NOT NULL DEFAULT ''"),
        ):
            if name not in cols:
                db.execute(f"ALTER TABLE badges ADD COLUMN {name} {decl}")
        db.executescript(
            """
            CREATE TABLE IF NOT EXISTS consumable_defs (
                def_name   TEXT PRIMARY KEY,
                item_id    INTEGER NOT NULL DEFAULT 0,
                name       TEXT NOT NULL DEFAULT '',
                icon       TEXT NOT NULL DEFAULT '',
                category   TEXT NOT NULL DEFAULT '',
                cooldown   REAL NOT NULL DEFAULT 0,
                updated_at REAL NOT NULL
            );
            CREATE TABLE IF NOT EXISTS star_tag_defs (
                sku             TEXT PRIMARY KEY,
                consumable_name TEXT NOT NULL DEFAULT '',
                name            TEXT NOT NULL DEFAULT '',
                updated_at      REAL NOT NULL
            );
            -- 徽章库：SKU → 中文名/图标/冷却/效果说明（随程序内置，启动时导入）
            CREATE TABLE IF NOT EXISTS badge_catalog (
                sk          TEXT PRIMARY KEY,
                idx         INTEGER NOT NULL DEFAULT 0,
                img         TEXT NOT NULL DEFAULT '',
                cooldown_ms INTEGER NOT NULL DEFAULT 0,
                disabled    INTEGER NOT NULL DEFAULT 0,
                name        TEXT NOT NULL DEFAULT '',
                name_hant   TEXT NOT NULL DEFAULT '',
                name_en     TEXT NOT NULL DEFAULT '',
                descr       TEXT NOT NULL DEFAULT '',
                effect      TEXT NOT NULL DEFAULT ''
            );
            """
        )

    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        db = sqlite3.connect(self.path, timeout=10.0)
        db.row_factory = sqlite3.Row
        # synchronous / foreign_keys / busy_timeout 都是**连接级**的，
        # 只在 SCHEMA 里设一次等于没设（每条新连接都是默认值）。
        db.execute("PRAGMA journal_mode=WAL")
        db.execute("PRAGMA synchronous=NORMAL")
        db.execute("PRAGMA foreign_keys=ON")
        db.execute("PRAGMA busy_timeout=10000")
        try:
            yield db
            db.commit()
        except Exception:
            db.rollback()
            raise
        finally:
            db.close()

    # ------------------------------------------------------------------ meta
    def meta_get(self, key: str, default: str | None = None) -> str | None:
        with self.connect() as db:
            row = db.execute("SELECT v FROM meta WHERE k=?", (key,)).fetchone()
        return row["v"] if row else default

    def meta_set(self, key: str, value: str) -> None:
        with self.connect() as db:
            db.execute(
                "INSERT INTO meta(k, v) VALUES(?, ?) "
                "ON CONFLICT(k) DO UPDATE SET v=excluded.v",
                (key, value),
            )

    # --------------------------------------------------------------- devices
    def upsert_device(self, fingerprint: str, pubkey_b64: str, name: str = "") -> DeviceRow:
        now = _now()
        with self.connect() as db:
            # 单条 UPSERT + RETURNING：原来"先 SELECT 再 INSERT"在并发下会撞
            # devices_fp 唯一索引（IntegrityError），这里一次搞定。
            row = db.execute(
                "INSERT INTO devices(id, fingerprint, name, pubkey_b64, first_seen, last_seen, paired_count)"
                " VALUES(?,?,?,?,?,?,0)"
                " ON CONFLICT(fingerprint) DO UPDATE SET"
                "   last_seen=excluded.last_seen,"
                "   pubkey_b64=excluded.pubkey_b64,"
                "   name=COALESCE(NULLIF(excluded.name,''), devices.name)"
                " RETURNING id",
                (uuid.uuid4().hex[:16], fingerprint, name, pubkey_b64, now, now),
            ).fetchone()
        return self.get_device(row["id"])  # type: ignore[return-value]

    def get_device(self, device_id: str) -> DeviceRow | None:
        with self.connect() as db:
            row = db.execute("SELECT * FROM devices WHERE id=?", (device_id,)).fetchone()
        return DeviceRow(**dict(row)) if row else None

    def bump_pair_count(self, device_id: str) -> None:
        with self.connect() as db:
            db.execute("UPDATE devices SET paired_count=paired_count+1, last_seen=? WHERE id=?",
                       (_now(), device_id))

    def list_devices(self) -> list[DeviceRow]:
        with self.connect() as db:
            rows = db.execute("SELECT * FROM devices ORDER BY last_seen DESC").fetchall()
        return [DeviceRow(**dict(r)) for r in rows]

    # ---------------------------------------------------------------- badges
    def add_badge(self, *, uid: str, counter: int, token: str, url: str,
                  device_id: str | None, backend: str, note: str = "",
                  status: str = "stored") -> tuple[BadgeRow, bool]:
        """返回 (行, 是否新建)。重复 (uid,counter,token) 返回旧行，created=False。"""
        now = _now()
        with self.connect() as db:
            cur = db.execute(
                "INSERT OR IGNORE INTO badges(uid, counter, token, url, device_id, received_at, backend, status, note)"
                " VALUES(?,?,?,?,?,?,?,?,?)",
                (uid, counter, token, url, device_id, now, backend, status, note),
            )
            created = cur.rowcount == 1
            row = db.execute(
                "SELECT * FROM badges WHERE uid=? AND counter=? AND token=?",
                (uid, counter, token),
            ).fetchone()
        if row is None:  # pragma: no cover - 只可能在并发删除时发生
            raise RuntimeError("badge 写入后读不到")
        return BadgeRow(**dict(row)), created

    def get_badge(self, badge_id: int) -> BadgeRow | None:
        with self.connect() as db:
            row = db.execute("SELECT * FROM badges WHERE id=?", (badge_id,)).fetchone()
        return BadgeRow(**dict(row)) if row else None

    def find_badge(self, uid: str, token: str) -> BadgeRow | None:
        with self.connect() as db:
            row = db.execute(
                "SELECT * FROM badges WHERE uid=? AND token=? ORDER BY counter DESC LIMIT 1",
                (uid, token),
            ).fetchone()
        return BadgeRow(**dict(row)) if row else None

    def last_counter(self, uid: str, token: str) -> int | None:
        with self.connect() as db:
            row = db.execute(
                "SELECT MAX(counter) AS c FROM badges WHERE uid=? AND token=?", (uid, token)
            ).fetchone()
        return row["c"] if row and row["c"] is not None else None

    def set_badge_status(self, badge_id: int, status: str, note: str = "") -> None:
        with self.connect() as db:
            db.execute("UPDATE badges SET status=?, note=? WHERE id=?", (status, note, badge_id))

    def list_badges(self, limit: int = 200, *, dedupe: bool = True) -> list[BadgeRow]:
        """徽章列表。

        `dedupe=True`（默认）时**按 uid 只留最新一条**：同一枚章反复贴（计数器不同）
        只算一枚，符合「徽章库」的语义。
        完整历史仍然在 badges 表里，`dedupe=False` 可取原始流水。
        """
        with self.connect() as db:
            if dedupe:
                rows = db.execute(
                    "SELECT * FROM badges WHERE id IN ("
                    "  SELECT MAX(id) FROM badges GROUP BY uid"
                    ") ORDER BY received_at DESC LIMIT ?",
                    (limit,),
                ).fetchall()
            else:
                rows = db.execute(
                    "SELECT * FROM badges ORDER BY received_at DESC LIMIT ?", (limit,)
                ).fetchall()
        return [BadgeRow(**dict(r)) for r in rows]

    # --------------------------------------------------------- 徽章库（catalog）
    def upsert_consumable_defs(self, items: list[dict[str, Any]]) -> int:
        """官方道具定义入库。返回写入条数。"""
        now = _now()
        rows = []
        for it in items or []:
            if not isinstance(it, dict):
                continue
            name = str(it.get("name") or "")
            if not name:
                continue
            rows.append((
                name,
                int(it.get("id") or 0),
                str(it.get("display_name") or it.get("title") or ""),
                str(it.get("icon") or ""),
                str(it.get("category") or ""),
                float(it.get("cooldown") or 0),
                now,
            ))
        if not rows:
            return 0
        with self.connect() as db:
            db.executemany(
                "INSERT INTO consumable_defs(def_name, item_id, name, icon, category, cooldown, updated_at)"
                " VALUES(?,?,?,?,?,?,?)"
                " ON CONFLICT(def_name) DO UPDATE SET item_id=excluded.item_id,"
                " name=excluded.name, icon=excluded.icon, category=excluded.category,"
                " cooldown=excluded.cooldown, updated_at=excluded.updated_at",
                rows,
            )
        return len(rows)

    def upsert_star_tags(self, items: list[dict[str, Any]]) -> int:
        """官方星章定义（SKU → 道具名）入库。"""
        now = _now()
        rows = []
        for it in items or []:
            if not isinstance(it, dict):
                continue
            sku = str(it.get("sku") or "")
            if not sku:
                continue
            rows.append((
                sku,
                str(it.get("consumable_name") or ""),
                str(it.get("name") or ""),
                now,
            ))
        if not rows:
            return 0
        with self.connect() as db:
            db.executemany(
                "INSERT INTO star_tag_defs(sku, consumable_name, name, updated_at)"
                " VALUES(?,?,?,?)"
                " ON CONFLICT(sku) DO UPDATE SET consumable_name=excluded.consumable_name,"
                " name=excluded.name, updated_at=excluded.updated_at",
                rows,
            )
        return len(rows)

    # ------------------------------------------------- 徽章库（内置 catalog）
    def import_badge_catalog(self, items: list[dict[str, Any]]) -> int:
        """把内置的徽章库写进库（幂等，重复导入无副作用）。"""
        rows = []
        for it in items or []:
            sk = str(it.get("sk") or "")
            if not sk:
                continue
            rows.append((
                sk,
                int(it.get("idx") or 0),
                str(it.get("img") or ""),
                int(it.get("cd") or 0),
                1 if it.get("disabled") else 0,
                str(it.get("name") or ""),
                str(it.get("name_hant") or ""),
                str(it.get("name_en") or ""),
                str(it.get("desc") or ""),
                str(it.get("effect") or ""),
            ))
        if not rows:
            return 0
        with self.connect() as db:
            db.executemany(
                "INSERT INTO badge_catalog(sk, idx, img, cooldown_ms, disabled, name,"
                " name_hant, name_en, descr, effect) VALUES(?,?,?,?,?,?,?,?,?,?)"
                " ON CONFLICT(sk) DO UPDATE SET idx=excluded.idx, img=excluded.img,"
                " cooldown_ms=excluded.cooldown_ms, disabled=excluded.disabled,"
                " name=excluded.name, name_hant=excluded.name_hant,"
                " name_en=excluded.name_en, descr=excluded.descr, effect=excluded.effect",
                rows,
            )
        return len(rows)

    def badge_catalog_entry(self, sku: str) -> dict[str, Any] | None:
        if not sku:
            return None
        with self.connect() as db:
            row = db.execute("SELECT * FROM badge_catalog WHERE sk=?", (sku,)).fetchone()
        return dict(row) if row else None

    def badge_catalog_all(self) -> list[dict[str, Any]]:
        with self.connect() as db:
            return [dict(r) for r in db.execute(
                "SELECT * FROM badge_catalog ORDER BY idx ASC")]

    def consumable_for_sku(self, sku: str) -> str:
        if not sku:
            return ""
        with self.connect() as db:
            row = db.execute(
                "SELECT consumable_name FROM star_tag_defs WHERE sku=?", (sku,)
            ).fetchone()
        return str(row["consumable_name"]) if row else ""

    def consumable_def(self, def_name: str) -> dict[str, Any] | None:
        if not def_name:
            return None
        with self.connect() as db:
            row = db.execute(
                "SELECT * FROM consumable_defs WHERE def_name=?", (def_name,)
            ).fetchone()
        return dict(row) if row else None

    def set_badge_catalog(self, badge_id: int, *, sku: str, def_name: str,
                          label: str, img: str = "") -> None:
        with self.connect() as db:
            db.execute(
                "UPDATE badges SET sku=?, def_name=?, label=?, img=? WHERE id=?",
                (sku, def_name, label, img, badge_id),
            )

    def stats(self) -> dict[str, Any]:
        with self.connect() as db:
            total = db.execute("SELECT COUNT(*) c FROM badges").fetchone()["c"]
            today = db.execute(
                "SELECT COUNT(*) c FROM badges WHERE received_at >= ?",
                (time.time() - 86400,),
            ).fetchone()["c"]
            devs = db.execute("SELECT COUNT(*) c FROM devices").fetchone()["c"]
            # 按**徽章**去重计数：同一枚章验证两次不该算两个
            ok = db.execute(
                "SELECT COUNT(DISTINCT badge_id) c FROM injections WHERE badge_id IS NOT NULL"
                " AND result IN ('verified','verified_no_inventory','bound_to_user')"
            ).fetchone()["c"]
        return {"badges": total, "last24h": today, "devices": devs, "verified": ok}

    # -------------------------------------------------------------- receipts
    def claim_receipt(self, *, device_id: str, rid: str, uid: str, counter: int,
                      badge_id: int | None) -> bool:
        """原子占位：同一 (device_id, rid) 只有一个调用者能拿到 True。

        用 INSERT OR IGNORE 撞主键来实现，跨连接/跨协程都成立，不需要额外锁。
        """
        with self.connect() as db:
            cur = db.execute(
                "INSERT OR IGNORE INTO receipts(rid, device_id, uid, counter, ok, action,"
                " detail, payload, created_at, badge_id) VALUES(?,?,?,?,0,?,?,?,?,?)",
                (rid, device_id, uid, counter, INFLIGHT, "提交中", "", _now(), badge_id),
            )
            return cur.rowcount == 1

    def finish_receipt(self, *, device_id: str, rid: str, ok: bool, action: str,
                       detail: str, payload: dict[str, Any]) -> None:
        with self.connect() as db:
            db.execute(
                "UPDATE receipts SET ok=?, action=?, detail=?, payload=?"
                " WHERE device_id=? AND rid=?",
                (1 if ok else 0, action, detail,
                 json.dumps(payload, ensure_ascii=False), device_id, rid),
            )
    def get_receipt(self, device_id: str, rid: str) -> dict[str, Any] | None:
        with self.connect() as db:
            row = db.execute(
                "SELECT * FROM receipts WHERE device_id=? AND rid=?", (device_id, rid)
            ).fetchone()
        if not row:
            return None
        d = dict(row)
        try:
            d["payload_obj"] = json.loads(d.get("payload") or "{}")
        except Exception:  # noqa: BLE001
            d["payload_obj"] = {}
        return d

    def put_receipt(self, *, device_id: str, rid: str, uid: str, counter: int, ok: bool,
                    action: str, detail: str, payload: dict[str, Any], badge_id: int | None) -> None:
        with self.connect() as db:
            db.execute(
                "INSERT INTO receipts(rid, device_id, uid, counter, ok, action, detail, payload, created_at, badge_id)"
                " VALUES(?,?,?,?,?,?,?,?,?,?)"
                " ON CONFLICT(device_id, rid) DO UPDATE SET ok=excluded.ok, action=excluded.action,"
                " detail=excluded.detail, payload=excluded.payload",
                (rid, device_id, uid, counter, 1 if ok else 0, action, detail,
                 json.dumps(payload, ensure_ascii=False), _now(), badge_id),
            )

    # ------------------------------------------------------------ injections
    def add_injection(self, *, badge_id: int | None, backend: str, request_id: str, url: str,
                      http_status: int, result: str, detail: str, response: dict[str, Any]) -> int:
        with self.connect() as db:
            cur = db.execute(
                "INSERT INTO injections(badge_id, backend, request_id, url, http_status, result,"
                " detail, response, created_at) VALUES(?,?,?,?,?,?,?,?,?)",
                (badge_id, backend, request_id, url, http_status, result, detail,
                 json.dumps(response, ensure_ascii=False)[:20000], _now()),
            )
            return int(cur.lastrowid or 0)

    def list_injections(self, badge_id: int | None = None, limit: int = 100) -> list[dict[str, Any]]:
        q = "SELECT * FROM injections"
        args: tuple[Any, ...] = ()
        if badge_id is not None:
            q += " WHERE badge_id=?"
            args = (badge_id,)
        q += " ORDER BY id DESC LIMIT ?"
        args = args + (limit,)
        with self.connect() as db:
            rows = db.execute(q, args).fetchall()
        return [dict(r) for r in rows]

    # -------------------------------------------------------------- sessions
    def save_session(self, *, account: str, user_id: str, session_token: str,
                     level_id: str = "", build_access_key: str = "", user_agent: str = "",
                     game_version: str = "", extra: dict[str, Any] | None = None) -> int:
        with self.connect() as db:
            cur = db.execute(
                "INSERT INTO sessions(account, user_id, session_token, level_id, build_access_key,"
                " user_agent, game_version, extra, captured_at, last_ok)"
                " VALUES(?,?,?,?,?,?,?,?,?,0)",
                (account, user_id, session_token, level_id, build_access_key, user_agent,
                 game_version, json.dumps(extra or {}, ensure_ascii=False), _now()),
            )
            return int(cur.lastrowid or 0)

    def latest_session(self, account: str = "default") -> dict[str, Any] | None:
        with self.connect() as db:
            row = db.execute(
                "SELECT * FROM sessions WHERE account=? ORDER BY captured_at DESC LIMIT 1", (account,)
            ).fetchone()
        if not row:
            return None
        d = dict(row)
        try:
            d["extra_obj"] = json.loads(d.get("extra") or "{}")
        except Exception:  # noqa: BLE001
            d["extra_obj"] = {}
        return d

    def mark_session_ok(self, session_id: int) -> None:
        with self.connect() as db:
            db.execute("UPDATE sessions SET last_ok=? WHERE id=?", (_now(), session_id))
