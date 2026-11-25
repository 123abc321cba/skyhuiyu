package com.skyhuiyu.app

import android.content.Context
import android.util.Base64

/**
 * 本地持久化：配对信息、身份密钥、rid 计数器、历史记录。
 *
 * 为什么用 SharedPreferences 而不是 DataStore：这里只有几 KB 数据，
 * 而且写操作都是同步的小对象，上 DataStore 只会引入协程复杂度。
 */
class PairStore(ctx: Context) {

    private val sp = ctx.getSharedPreferences("skyhuiyu", Context.MODE_PRIVATE)

    // ---- 配对信息 ----

    var host: String
        get() = sp.getString("host", "") ?: ""
        set(v) = sp.edit().putString("host", v).apply()

    var port: Int
        get() = sp.getInt("port", 8765)
        set(v) = sp.edit().putInt("port", v).apply()

    /** PC 的 65 字节公钥（标准 base64） */
    var pcPubkey: String
        get() = sp.getString("pc_pubkey", "") ?: ""
        set(v) = sp.edit().putString("pc_pubkey", v).apply()

    var pcFingerprint: String
        get() = sp.getString("pc_fingerprint", "") ?: ""
        set(v) = sp.edit().putString("pc_fingerprint", v).apply()

    val isPaired: Boolean get() = host.isNotEmpty() && pcPubkey.isNotEmpty()

    fun clearPairing() {
        sp.edit().remove("host").remove("port").remove("pc_pubkey").remove("pc_fingerprint").apply()
    }

    // ---- 身份密钥 ----

    fun loadIdentity(): Pair<ByteArray?, ByteArray?> {
        val priv = sp.getString("id_priv", null)?.let { Base64.decode(it, Base64.NO_WRAP) }
        val pub = sp.getString("id_pub", null)?.let { Base64.decode(it, Base64.NO_WRAP) }
        return Pair(priv, pub)
    }

    fun saveIdentity(priv: ByteArray, pub: ByteArray) {
        sp.edit()
            .putString("id_priv", Base64.encodeToString(priv, Base64.NO_WRAP))
            .putString("id_pub", Base64.encodeToString(pub, Base64.NO_WRAP))
            .apply()
    }

    // ---- rid：PC 的幂等键是 (device_id, rid)，必须跨启动递增 ----

    fun nextRid(): Long {
        val v = sp.getLong("rid", 0L) + 1
        sp.edit().putLong("rid", v).apply()
        return v
    }

    // ---- 历史（只留最近 200 条）----

    fun loadRecords(): MutableList<BadgeRecord> {
        val raw = sp.getString("records", null) ?: return mutableListOf()
        return runCatching {
            val arr = org.json.JSONArray(raw)
            val out = mutableListOf<BadgeRecord>()
            for (i in 0 until arr.length()) {
                out.add(BadgeRecord.fromJson(arr.getJSONObject(i)))
            }
            out
        }.getOrDefault(mutableListOf())
    }

    fun saveRecords(list: List<BadgeRecord>) {
        val arr = org.json.JSONArray()
        list.take(200).forEach { arr.put(it.toJson()) }
        sp.edit().putString("records", arr.toString()).apply()
    }
}
