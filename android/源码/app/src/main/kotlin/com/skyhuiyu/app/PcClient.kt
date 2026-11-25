package com.skyhuiyu.app

import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.Response
import okhttp3.WebSocket
import okhttp3.WebSocketListener
import org.json.JSONObject
import java.util.concurrent.CountDownLatch
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit

/**
 * 与 PC 的 WebSocket 会话。
 *
 * 协议（SkyHuiyu PC v1，和 iOS 端 `PCConnection.swift` 完全一致）：
 *   1. 连 ws://host:port/badge
 *   2. 收 server_hello {pubkey(base64), pubkey_hex, fingerprint, protocol, host, port}
 *   3. 发 pairing      {phone_pubkey(base64), data(base64(AESGCM(...)))}
 *   4. 发 badge        {phone_pubkey(base64), data(base64(AESGCM(...)))}
 *   5. 每发一条收一条应答 {status, message, inject, record}
 *
 * 注意：PC 端是**严格顺序**的，发一条必须收一条，否则会永久错位。
 */
class PcClient(private val crypto: CryptoBox, private val store: PairStore) {

    private val http = OkHttpClient.Builder()
        .connectTimeout(8, TimeUnit.SECONDS)
        .readTimeout(30, TimeUnit.SECONDS)
        .pingInterval(20, TimeUnit.SECONDS)
        .build()

    private var ws: WebSocket? = null
    private val inbox = LinkedBlockingQueue<Map<String, Any?>>()

    var connected: Boolean = false
        private set
    var serverFingerprint: String = ""
        private set
    var host: String = ""
        private set
    var port: Int = 8765
        private set
    private var pinnedPubkey: String = ""

    /** 连接 + 握手 + 配对。抛异常表示失败，异常信息可直接展示给用户。 */
    fun connect(info: PairingInfo) {
        host = info.host
        port = info.port
        pinnedPubkey = info.pubkey
        val url = info.wsUrl

        inbox.clear()
        val opened = CountDownLatch(1)
        var openError: String? = null

        val request = Request.Builder().url(url).build()
        ws = http.newWebSocket(request, object : WebSocketListener() {
            override fun onOpen(webSocket: WebSocket, response: Response) {
                opened.countDown()
            }

            override fun onMessage(webSocket: WebSocket, text: String) {
                val obj = runCatching { Jsonx.decodeObject(text) }.getOrNull()
                if (obj != null) inbox.offer(obj)
            }

            override fun onFailure(webSocket: WebSocket, t: Throwable, response: Response?) {
                openError = t.message ?: "连接失败"
                opened.countDown()
            }
        })

        if (!opened.await(10, TimeUnit.SECONDS)) {
            ws?.cancel()
            throw IllegalStateException("连接超时：检查手机和电脑是否在同一 Wi-Fi、端口是否为 ${info.port}")
        }
        openError?.let {
            ws?.cancel()
            throw IllegalStateException("连接失败：$it")
        }

        // 1) server_hello
        val hello = takeMessage(8000) ?: throw IllegalStateException("PC 没有发握手帧")
        val pkRaw = hello["pubkey"] as? String ?: throw IllegalStateException("握手帧里没有公钥")
        val peerBytes = decodeKeyAny(pkRaw) ?: throw IllegalStateException("PC 公钥解不开")
        if (peerBytes.size != 65) throw IllegalStateException("PC 公钥长度不对（应为 65 字节）")

        // 防中间人：二维码里的公钥是唯一可信来源
        if (pinnedPubkey.isNotEmpty()) {
            val pinned = decodeKeyAny(pinnedPubkey)
            if (pinned != null && !pinned.contentEquals(peerBytes)) {
                ws?.cancel()
                throw IllegalStateException("PC 公钥与二维码不一致，可能有中间人")
            }
        }
        crypto.derive(peerBytes)
        serverFingerprint = (hello["fingerprint"] as? String) ?: ""

        // 2) pairing
        send(
            JSONObject().apply {
                put("phone_pubkey", crypto.publicKeyBase64)
                put(
                    "data", crypto.encryptJson(
                        mapOf(
                            "type" to "pairing",
                            "fingerprint" to crypto.fingerprint,
                            "proto" to 1,
                            "device" to android.os.Build.MODEL,
                        )
                    )
                )
            }
        )
        val ack = takeAck(8000) ?: throw IllegalStateException("配对没有应答")
        if ((ack["status"] as? String) != "ok") {
            throw IllegalStateException("配对被拒绝：${ack["message"] ?: ""}")
        }
        connected = true
    }

    /** 发送一枚徽章，返回 (是否成功, 说明文字, 原始应答)。 */
    fun sendBadge(badge: BadgeRecord): Triple<Boolean, String, Map<String, Any?>?> {
        if (!connected || !crypto.isDerived) return Triple(false, "未连接到 PC", null)

        val rid = store.nextRid() // 幂等键是 (device_id, rid)，必须跨启动递增
        val payload = mapOf(
            "type" to "badge",
            "rid" to rid,
            "uid" to badge.uid,
            "counter" to badge.counter,
            "token" to badge.token,
            "url" to badge.rawUrl,
        )
        send(
            JSONObject().apply {
                put("phone_pubkey", crypto.publicKeyBase64)
                put("data", crypto.encryptJson(payload))
            }
        )

        val ack = takeAck(30000) ?: return Triple(false, "PC 没有应答", null)
        val status = (ack["status"] as? String) ?: "error"
        val message = (ack["message"] as? String) ?: ""
        @Suppress("UNCHECKED_CAST")
        val inject = ack["inject"] as? Map<String, Any?>
        val injectOk = (inject?.get("ok") as? Boolean) ?: (status == "ok")

        if (status == "ok" && injectOk) {
            return Triple(true, message.ifEmpty { "注入成功" }, ack)
        }
        val detail = (inject?.get("detail") as? String)
            ?: (inject?.get("error") as? String)
            ?: message
        return Triple(false, detail.ifEmpty { "PC 处理失败" }, ack)
    }

    fun disconnect() {
        runCatching { ws?.close(1000, "bye") }
        ws = null
        connected = false
        inbox.clear()
    }

    // ---- 底层 ----

    private fun send(obj: JSONObject) {
        val socket = ws ?: throw IllegalStateException("未连接")
        socket.send(obj.toString())
    }

    private fun takeMessage(timeoutMs: Long): Map<String, Any?>? =
        inbox.poll(timeoutMs, TimeUnit.MILLISECONDS)

    /** 只取带 status 字段的应答；最多跳过 3 条别的帧。 */
    private fun takeAck(timeoutMs: Long): Map<String, Any?>? {
        val deadline = System.currentTimeMillis() + timeoutMs
        repeat(3) {
            val left = deadline - System.currentTimeMillis()
            if (left <= 0) return null
            val m = inbox.poll(left, TimeUnit.MILLISECONDS) ?: return null
            if (m.containsKey("status")) return m
        }
        return null
    }
}
