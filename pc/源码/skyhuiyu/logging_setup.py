"""日志：同时写控制台和文件。

为什么要落文件：出问题的时候用户只会说"不行"，而窗口关掉就什么都没有了。
日志留在 `数据目录/logs/skyhuiyu-YYYYMMDD.log`，让用户能直接把文件发出来。
"""

from __future__ import annotations

import logging
import sys
from datetime import datetime
from pathlib import Path

_FORMAT = "%(asctime)s %(levelname)-7s %(name)-22s %(message)s"
_configured = False


def setup(data_dir: Path, level: str = "INFO") -> Path:
    """配置根 logger，返回日志文件路径。重复调用是幂等的。"""
    global _configured
    log_dir = Path(data_dir) / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    logfile = log_dir / f"skyhuiyu-{datetime.now():%Y%m%d}.log"

    if _configured:
        return logfile

    root = logging.getLogger()
    root.setLevel(getattr(logging, str(level).upper(), logging.INFO))

    fmt = logging.Formatter(_FORMAT)

    try:
        fh = logging.FileHandler(logfile, encoding="utf-8")
        fh.setFormatter(fmt)
        root.addHandler(fh)
    except OSError:
        # 目录不可写时至少保留控制台，不能因为日志把主流程搞挂
        pass

    sh = logging.StreamHandler(stream=sys.stdout)
    sh.setFormatter(fmt)
    root.addHandler(sh)

    logging.getLogger("asyncio").setLevel(logging.WARNING)
    _configured = True
    logging.getLogger("skyhuiyu").info("日志文件 %s", logfile)
    return logfile
