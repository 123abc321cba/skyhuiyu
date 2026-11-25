package com.skyhuiyu.app

import android.content.Intent
import android.os.Bundle
import android.widget.Button
import android.widget.TextView
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * 主界面：配对 → 读卡 → 发送 → 看结果。
 *
 * 刻意做成单页 + 纯 TextView 列表：
 * 这个 App 的全部价值在「读一张卡然后发出去」，多一层导航都是负担。
 */
class MainActivity : AppCompatActivity() {

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main)
    private lateinit var store: PairStore
    private lateinit var crypto: CryptoBox
    private lateinit var nfc: NfcBadgeReader
    private lateinit var client: PcClient

    private lateinit var statusText: TextView
    private lateinit var pairText: TextView
    private lateinit var historyText: TextView
    private lateinit var pairButton: Button
    private lateinit var readButton: Button
    private lateinit var connectButton: Button

    private val records = mutableListOf<BadgeRecord>()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        store = PairStore(this)
        val (priv, pub) = store.loadIdentity()
        val (box, isNew) = CryptoBox.identity(priv, pub)
        crypto = box
        if (isNew) store.saveIdentity(crypto.privateKeyEncoded, crypto.publicKeyEncodedX509)

        client = PcClient(crypto, store)
        nfc = NfcBadgeReader(this)

        statusText = findViewById(R.id.statusText)
        pairText = findViewById(R.id.pairText)
        historyText = findViewById(R.id.historyText)
        pairButton = findViewById(R.id.pairButton)
        readButton = findViewById(R.id.readButton)
        connectButton = findViewById(R.id.connectButton)

        records.addAll(store.loadRecords())
        renderPairing()
        renderHistory()

        pairButton.setOnClickListener { startQrScan() }
        connectButton.setOnClickListener { connectToPc(silent = false) }
        readButton.setOnClickListener { startNfcRead() }

        nfc.onBadge = { badge -> onBadgeRead(badge) }
        nfc.onError = { msg -> toast(msg); status("读卡失败：$msg") }

        // 冷启动且已配对：自动连一次，省一次点击
        if (store.isPaired) connectToPc(silent = true)

        handleLaunchIntent(intent)
    }

    override fun onNewIntent(intent: Intent?) {
        super.onNewIntent(intent)
        intent?.let { handleLaunchIntent(it) }
    }

    /** 从系统「贴卡后打开应用」进来时，intent 里直接带 NDEF */
    private fun handleLaunchIntent(intent: Intent) {
        val msg = intent.getParcelableExtra<android.nfc.NdefMessage>(android.nfc.NfcAdapter.EXTRA_NDEF_MESSAGES)
            ?: return
        val url = msg.records.firstNotNullOfOrNull { rec ->
            runCatching { rec.toUri()?.toString() }.getOrNull()
                ?.takeIf { it.startsWith("http", ignoreCase = true) }
        } ?: return
        BadgeRecord.parse(url)?.let { onBadgeRead(it) }
    }


    // ---- 配对 ----

    private val qrLauncher = registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->
        if (result.resultCode != RESULT_OK) return@registerForActivityResult
        val text = result.data?.getStringExtra("qr_text").orEmpty()
        applyPairingPayload(text)
    }

    private fun startQrScan() {
        qrLauncher.launch(Intent(this, QrScanActivity::class.java))
    }

    /** 二维码内容是 {"pubkey":"…","host":"192.168.x.x","port":8765} */
    private fun applyPairingPayload(text: String) {
        val obj = runCatching { Jsonx.decodeObject(text) }.getOrNull()
        if (obj == null) {
            status("二维码不是 SkyHuiyu 的配对码")
            return
        }
        val host = obj["host"] as? String ?: ""
        val port = (obj["port"] as? Number)?.toInt() ?: 8765
        val pubkey = obj["pubkey"] as? String ?: ""
        if (host.isEmpty() || pubkey.isEmpty()) {
            status("配对码缺字段（host / pubkey）")
            return
        }
        store.host = host
        store.port = port
        store.pcPubkey = pubkey
        store.pcFingerprint = decodeKeyAny(pubkey)
            ?.let { java.security.MessageDigest.getInstance("SHA-256").digest(it).copyOf(8) }
            ?.joinToString("") { "%02x".format(it) } ?: ""
        renderPairing()
        status("已记录配对信息，正在连接…")
        connectToPc(silent = false)
    }

    private fun connectToPc(silent: Boolean) {
        if (!store.isPaired) {
            if (!silent) status("还没配对：先扫电脑面板上的二维码")
            return
        }
        status(if (silent) "连接中…" else "正在连接 ${store.host}:${store.port} …")
        scope.launch {
            val result = withContext(Dispatchers.IO) {
                runCatching {
                    client.connect(
                        PairingInfo(
                            host = store.host,
                            port = store.port,
                            pubkey = store.pcPubkey,
                            fingerprint = store.pcFingerprint,
                        )
                    )
                }
            }
            result.onSuccess {
                store.pcFingerprint = client.serverFingerprint
                status("已配对 ✓  ${store.host}:${store.port}")
                readButton.isEnabled = true
            }.onFailure {
                status(it.message ?: "连接失败")
                readButton.isEnabled = false
            }
        }
    }

    // ---- 读卡与发送 ----

    private fun startNfcRead() {
        if (!store.isPaired) {
            status("先配对再读卡")
            return
        }
        if (!client.connected) {
            status("还没连上 PC，先点「重新连接」")
            return
        }
        status("把徽章贴在手机背面（摄像头附近）…")
        toast("贴卡")
        nfc.start()
    }

    private fun onBadgeRead(badge: BadgeRecord) {
        status("读到 ${badge.uid} #${badge.counter}，发送中…")
        records.add(0, badge)
        renderHistory()

        scope.launch(Dispatchers.IO) {
            val (ok, message, ack) = client.sendBadge(badge)
            badge.status = if (ok) BadgeRecord.Status.SENT else BadgeRecord.Status.FAILED
            badge.detail = message
            withContext(Dispatchers.Main) {
                store.saveRecords(records)
                renderHistory()
                status(if (ok) "成功：$message" else "失败：$message")
                toast(if (ok) "已发送成功" else "发送失败")
            }
        }
    }

    // ---- 渲染 ----

    private fun status(text: String) {
        statusText.text = text
    }

    private fun toast(text: String) {
        Toast.makeText(this, text, Toast.LENGTH_SHORT).show()
    }

    private fun renderPairing() {
        pairText.text = if (store.isPaired) {
            "已配对：${store.host}:${store.port}\n指纹 ${store.pcFingerprint}"
        } else {
            "未配对。打开电脑端面板，扫上面的二维码。"
        }
        readButton.isEnabled = store.isPaired
    }

    private fun renderHistory() {
        if (records.isEmpty()) {
            historyText.text = "还没有记录。读一张卡试试。"
            return
        }
        historyText.text = records.take(50).joinToString("\n\n") { r ->
            val mark = when (r.status) {
                BadgeRecord.Status.SENT -> "✓"
                BadgeRecord.Status.FAILED -> "✗"
                BadgeRecord.Status.SENDING -> "…"
                BadgeRecord.Status.READ -> "·"
            }
            "$mark ${r.uid} #${r.counter}" + if (r.detail.isNotEmpty()) "\n   ${r.detail}" else ""
        }
    }

    override fun onResume() {
        super.onResume()
        if (store.isPaired && !client.connected) connectToPc(silent = true)
    }

    override fun onDestroy() {
        nfc.stop()
        client.disconnect()
        scope.cancel()
        super.onDestroy()
    }
}

