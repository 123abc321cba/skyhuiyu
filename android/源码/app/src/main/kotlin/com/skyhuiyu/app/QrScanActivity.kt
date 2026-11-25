package com.skyhuiyu.app

import android.content.Intent
import android.os.Bundle
import androidx.appcompat.app.AppCompatActivity
import com.journeyapps.barcodescanner.CaptureActivity
import com.journeyapps.barcodescanner.DecoratedBarcodeView
import com.journeyapps.barcodescanner.ScanContract
import com.journeyapps.barcodescanner.ScanOptions

/**
 * 扫电脑面板上的配对二维码。
 *
 * 用 ZXing 嵌入式（不依赖 Google Play 服务），扫到就把原文塞进 Intent 返回给 MainActivity。
 */
class QrScanActivity : AppCompatActivity() {

    private val launcher = registerForActivityResult(ScanContract()) { result ->
        val text = result.contents
        if (text.isNullOrEmpty()) {
            setResult(RESULT_CANCELED)
        } else {
            setResult(RESULT_OK, Intent().putExtra("qr_text", text))
        }
        finish()
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val options = ScanOptions().apply {
            setDesiredBarcodeFormats(ScanOptions.QR_CODE)
            setPrompt("对准电脑面板上的二维码")
            setBeepEnabled(false)
            setOrientationLocked(true)
            setBarcodeImageEnabled(false)
            setCaptureActivity(CaptureActivity::class.java)
        }
        launcher.launch(options)
    }
}
