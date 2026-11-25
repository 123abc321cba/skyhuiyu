package com.skyhuiyu.app

import android.app.Activity
import android.nfc.NdefMessage
import android.nfc.NdefRecord
import android.nfc.NfcAdapter
import android.nfc.Tag
import android.os.Bundle
import android.os.Parcelable

/**
 * NFC 徽章读取。
 *
 * 用 `enableReaderMode` 而不是旧的 foreground dispatch：
 * reader mode 关掉系统的提示音/界面，读得稳，而且不要求 Activity 在前台时才派发。
 *
 * 徽章里是 NDEF **URI 记录**，payload 首字节是 NFC Forum URI 标识码
 * （0x04 = "https://"）。Android 的 `NdefRecord.toUri()` 自带这张表，
 * 这里优先用它；不行再退回「整段当字符串」的兜底。
 */
class NfcBadgeReader(private val activity: Activity) {

    companion object {
        const val FLAGS = NfcAdapter.FLAG_READER_NFC_A or
            NfcAdapter.FLAG_READER_NFC_B or
            NfcAdapter.FLAG_READER_NFC_F or
            NfcAdapter.FLAG_READER_NFC_V or
            NfcAdapter.FLAG_READER_NO_PLATFORM_SOUNDS
    }

    private val adapter: NfcAdapter? = NfcAdapter.getDefaultAdapter(activity)
    var onBadge: ((BadgeRecord) -> Unit)? = null
    var onError: ((String) -> Unit)? = null
    private var armed = false

    val available: Boolean get() = adapter != null
    val enabled: Boolean get() = adapter?.isEnabled == true

    fun start() {
        val ad = adapter
        if (ad == null) {
            onError?.invoke("这台设备不支持 NFC")
            return
        }
        if (!ad.isEnabled) {
            onError?.invoke("NFC 没打开：去 设置 → 连接 → NFC 打开")
            return
        }
        armed = true
        ad.enableReaderMode(activity, { tag -> handleTag(tag) }, FLAGS, Bundle())
    }

    fun stop() {
        armed = false
        adapter?.disableReaderMode(activity)
    }

    private fun handleTag(tag: Tag) {
        if (!armed) return
        val raw = tag.let { NdefMessageHelper.readAll(it) }
        val url = raw.firstNotNullOfOrNull { toUrlString(it) }
        if (url == null) {
            onError?.invoke("这个标签里没有可识别的链接")
            return
        }
        val badge = BadgeRecord.parse(url)
        if (badge == null) {
            onError?.invoke("不是有效的星章链接：$url")
            return
        }
        armed = false
        activity.runOnUiThread { onBadge?.invoke(badge) }
    }

    /** NDEF URI 记录 → 完整 URL，兼容三种写法 */
    private fun toUrlString(rec: NdefRecord): String? {
        // 1) 标准 URI 记录：Android 自带前缀表（toUri() 返回 android.net.Uri，要转成 String）
        val asUri = runCatching { rec.toUri()?.toString() }.getOrNull()
        if (!asUri.isNullOrEmpty() && asUri.startsWith("http", ignoreCase = true)) return asUri
        // 2) 整段当字符串
        val text = runCatching { String(rec.payload, Charsets.UTF_8) }.getOrNull() ?: return null
        val trimmed = text.trim()
        if (trimmed.startsWith("http", ignoreCase = true) || trimmed.startsWith("sky.", ignoreCase = true)) {
            return trimmed
        }
        // 3) 去掉开头不可打印字节再试（厂商自定义标识码）
        val cleaned = trimmed.trimStart { !it.isLetterOrDigit() }
        if (cleaned.startsWith("http", ignoreCase = true) || cleaned.startsWith("sky.", ignoreCase = true)) {
            return cleaned
        }
        return null
    }
}

/** 从 Tag 里取出所有 NDEF 记录；没有 NDEF 就返回空列表。 */
object NdefMessageHelper {
    fun readAll(tag: Tag): List<NdefRecord> {
        val ndef = android.nfc.tech.Ndef.get(tag) ?: return emptyList()
        return try {
            ndef.connect()
            ndef.ndefMessage?.records?.toList() ?: emptyList()
        } catch (e: Exception) {
            emptyList()
        } finally {
            runCatching { ndef.close() }
        }
    }
}
