package com.skyhuiyu.app

import org.json.JSONObject
import java.util.UUID

/**
 * 一枚徽章。
 *
 * 徽章里存的是 NDEF URI 记录，URL 形如：
 *     https://sky.thatg.co/?s=TOKEN&c=UIDxCOUNTER
 *
 *   s = 签名（官方校验用）
 *   c = UID x 计数器（十六进制），用于防重放
 */
data class BadgeRecord(
    val id: String = UUID.randomUUID().toString(),
    val uid: String,
    val counter: Int,
    val token: String,
    val rawUrl: String,
    val timestamp: Long = System.currentTimeMillis(),
    var status: Status = Status.READ,
    var detail: String = "",
) {
    enum class Status { READ, SENDING, SENT, FAILED }

    fun toJson(): JSONObject = JSONObject().apply {
        put("id", id)
        put("uid", uid)
        put("counter", counter)
        put("token", token)
        put("url", rawUrl)
        put("ts", timestamp)
        put("status", status.name)
        put("detail", detail)
    }

    companion object {
        fun fromJson(o: JSONObject) = BadgeRecord(
            id = o.optString("id", UUID.randomUUID().toString()),
            uid = o.optString("uid"),
            counter = o.optInt("counter"),
            token = o.optString("token"),
            rawUrl = o.optString("url"),
            timestamp = o.optLong("ts"),
            status = runCatching { Status.valueOf(o.optString("status", "READ")) }
                .getOrDefault(Status.READ),
            detail = o.optString("detail"),
        )

        /** 把 NDEF 里的字符串还原成徽章；解不出关键字段就返回 null。 */
        fun parse(rawInput: String): BadgeRecord? {
            var cleaned = rawInput.trim().trim('"', '\'')
            if (cleaned.isEmpty()) return null
            cleaned = cleaned.replace("\u0000", "")
            if (cleaned.startsWith("sky.", ignoreCase = true)) cleaned = "https://$cleaned"

            val params = parseQuery(cleaned)
            val token = params["s"] ?: ""
            val (uid, counter) = splitCounter(params["c"] ?: "")
            if (token.isEmpty() || uid.isEmpty()) return null
            return BadgeRecord(uid = uid, counter = counter, token = token, rawUrl = cleaned)
        }

        private fun parseQuery(url: String): Map<String, String> {
            val q = url.substringAfter('?', "")
            if (q.isEmpty()) return emptyMap()
            val out = HashMap<String, String>()
            for (pair in q.split('&')) {
                if (pair.isEmpty()) continue
                val idx = pair.indexOf('=')
                if (idx <= 0) continue
                out[pair.substring(0, idx).lowercase()] = pair.substring(idx + 1)
            }
            return out
        }

        /**
         * "A1B2C3D4x1A" → ("A1B2C3D4", 26)
         * 从最后一个 x/X 切开（UID 是十六进制，本身不含 x）；没有 x 就整串当 UID。
         */
        fun splitCounter(raw: String): Pair<String, Int> {
            val s = raw.trim()
            if (s.isEmpty()) return Pair("", 0)
            val idx = s.indexOfLast { it == 'x' || it == 'X' }
            if (idx < 0) return Pair(s.uppercase(), 0)
            val uid = s.substring(0, idx).uppercase()
            val cnt = s.substring(idx + 1)
            val value = cnt.toIntOrNull(16) ?: cnt.toIntOrNull() ?: 0
            return Pair(uid, value)
        }
    }
}

/** 配对信息：扫码得到，持久化。 */
data class PairingInfo(
    val host: String,
    val port: Int,
    val pubkey: String,
    val fingerprint: String,
) {
    val wsUrl: String get() = "ws://$host:$port/badge"
    val display: String get() = "$host:$port"
}
