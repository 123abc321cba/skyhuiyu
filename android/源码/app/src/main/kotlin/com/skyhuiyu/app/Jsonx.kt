package com.skyhuiyu.app

import org.json.JSONArray
import org.json.JSONObject

/**
 * 极薄的 JSON 助手。
 *
 * 用 org.json（Android 内置）而不是引第三方库：
 * 协议里的对象都很小，且要保证「数字就是数字、字符串就是字符串」，
 * 任何会改类型的序列化都会让 PC 端解析失败。
 */
object Jsonx {

    fun encode(obj: Map<String, Any?>): String = JSONObject(obj as Map<*, *>).toString()

    fun decodeObject(s: String): Map<String, Any?>? {
        return runCatching { toMap(JSONObject(s)) }.getOrNull()
    }

    fun toMap(o: JSONObject): Map<String, Any?> {
        val out = LinkedHashMap<String, Any?>()
        for (k in o.keys()) {
            out[k] = unwrap(o.get(k))
        }
        return out
    }

    private fun unwrap(v: Any?): Any? = when (v) {
        null, JSONObject.NULL -> null
        is JSONObject -> toMap(v)
        is JSONArray -> (0 until v.length()).map { unwrap(v.get(it)) }
        else -> v
    }
}
