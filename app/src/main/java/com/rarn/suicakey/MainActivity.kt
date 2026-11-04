package com.rarn.suicakey

import android.Manifest
import android.app.Activity
import android.app.AlertDialog
import android.content.Intent
import android.os.Build
import android.os.Bundle
import android.view.WindowManager
import android.widget.Button
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import com.google.zxing.integration.android.IntentIntegrator
import com.rarn.suicakey.core.IO
import com.rarn.suicakey.core.Msg
import com.rarn.suicakey.core.PhoneSide
import com.rarn.suicakey.core.Proto
import java.net.InetSocketAddress
import java.net.Socket
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.concurrent.thread

/** 設定画面：ペアリング・PIN・緊急PIN・生体認証・手動送信 */
class MainActivity : Activity() {
    private lateinit var state: TextView
    private lateinit var status: TextView
    private lateinit var bioBtn: Button
    private lateinit var guard: Guard

    override fun onCreate(b: Bundle?) {
        super.onCreate(b)
        Sk.init(this)
        window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        guard = Guard(this) { msg -> status.text = msg }
        state = TextView(this).apply { textSize = 14f; setPadding(0, 0, 0, 24) }
        status = TextView(this).apply { textSize = 18f; setPadding(0, 32, 0, 0) }
        fun btn(t: String, f: () -> Unit) = Button(this).apply { text = t; setOnClickListener { f() } }
        bioBtn = btn("") { guard.toggleBio { refresh() } }
        setContentView(ScrollView(this).apply {
            addView(LinearLayout(this@MainActivity).apply {
                orientation = LinearLayout.VERTICAL
                setPadding(48, 48, 48, 48)
                addView(state)
                addView(btn("PCへ送る") { manualSend() })
                addView(btn("PINを登録／変更") { guard.changePin { refresh() } })
                addView(btn("緊急PINを設定") { guard.setDuress { refresh(); askLocation() } })
                addView(bioBtn)
                addView(btn("PCとペアリング（QR読取）") { scan() })
                addView(btn("ペアリング解除") { unpair() })
                addView(status)
            })
        })
        if (Build.VERSION.SDK_INT >= 33) requestPermissions(arrayOf(Manifest.permission.POST_NOTIFICATIONS), 1)
        ChannelService.start(this)
        status.text = when {
            !guard.hasPin() -> "まずPINを登録してください"
            !PhoneStore.paired() -> "PCとペアリングしてください"
            else -> "待機中：PCからの依頼は通知で届きます"
        }
    }

    override fun onResume() {
        super.onResume()
        ChannelService.foreground = true
        ChannelService.onState = { runOnUiThread { refresh() } }
        refresh()
    }

    override fun onPause() {
        super.onPause()
        ChannelService.foreground = false
        ChannelService.onState = null
    }

    private fun refresh() {
        state.text = "ペアリング：${if (PhoneStore.paired()) "済" else "未"}　接続：${if (ChannelService.connected) "暗号化接続中" else "未接続"}\n" +
            "PIN：${if (guard.hasPin()) "登録済" else "未登録"}　緊急PIN：${if (guard.hasDuress()) "設定済" else "なし"}　生体認証：${if (guard.bioOn()) "有効" else "無効"}"
        bioBtn.text = if (guard.bioOn()) "生体認証を無効にする" else "生体認証を有効にする"
    }

    /** 緊急時に位置を送るための権限（使うのは緊急PIN入力時のみ） */
    private fun askLocation() {
        if (checkSelfPermission(Manifest.permission.ACCESS_FINE_LOCATION) == android.content.pm.PackageManager.PERMISSION_GRANTED) return
        AlertDialog.Builder(this).setTitle("位置情報の許可")
            .setMessage("緊急PINが使われたとき、登録した通知先へ現在地を送ります。位置情報は緊急時以外は取得しません。")
            .setPositiveButton("許可する") { _, _ ->
                requestPermissions(arrayOf(Manifest.permission.ACCESS_FINE_LOCATION, Manifest.permission.ACCESS_COARSE_LOCATION), 2)
            }
            .setNegativeButton("許可しない", null).show()
    }

    private fun manualSend() {
        if (!guard.hasPin()) { status.text = "エラーです"; return }
        if (!ChannelService.connected) { status.text = "エラーです"; return }
        ChannelService.manualWait = true
        status.text = "PCに依頼しています…"
        thread { if (!ChannelService.send(Msg(Proto.WANT))) runOnUiThread { status.text = "エラーです" } }
    }

    // ── ペアリング ──
    private fun scan() {
        if (!guard.hasPin()) { status.text = "エラーです"; return }
        IntentIntegrator(this).setDesiredBarcodeFormats(IntentIntegrator.QR_CODE)
            .setPrompt("PCに表示されたQRコードを読み取ってください").setBeepEnabled(false).setOrientationLocked(false).initiateScan()
    }

    @Deprecated("Activity API")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        val r = IntentIntegrator.parseActivityResult(requestCode, resultCode, data)
        if (r == null) { super.onActivityResult(requestCode, resultCode, data); return }
        val text = r.contents ?: return
        pair(text)
    }

    private fun pair(qrText: String) {
        val qr = try { PhoneSide.parseQr(qrText) } catch (e: Exception) { status.text = "エラーです"; return }
        status.text = "PCに接続しています…"
        ChannelService.stop(this)
        thread {
            val msg = try {
                val dsa = Sk.pqc.genMlDsa65()
                val ed = Sk.pqc.genEd448()
                Socket().use { s ->
                    s.connect(InetSocketAddress(qr.host, qr.port), 5_000)
                    s.soTimeout = 180_000
                    val res = PhoneSide.pair(Sk.pqc, IO(s), qr, dsa, ed, Build.MODEL) { code -> confirmCode(code) }
                    PhoneStore.savePair(res, dsa, ed)
                }
                "ペアリング完了"
            } catch (e: Exception) {
                "エラーです"
            }
            runOnUiThread { status.text = msg; refresh(); ChannelService.start(this) }
        }
    }

    /** ワーカースレッドから呼ばれ、ユーザーの判断まで待つ */
    private fun confirmCode(code: Int): Boolean {
        val ok = AtomicBoolean(false)
        val latch = CountDownLatch(1)
        runOnUiThread {
            AlertDialog.Builder(this)
                .setTitle("確認コード")
                .setMessage("%03d %03d\n\nPCの画面に同じ番号が出ていれば「一致」を押してください".format(code / 1000, code % 1000))
                .setPositiveButton("一致") { _, _ -> ok.set(true); latch.countDown() }
                .setNegativeButton("違う") { _, _ -> latch.countDown() }
                .setOnCancelListener { latch.countDown() }
                .show()
        }
        latch.await(170, TimeUnit.SECONDS)
        return ok.get()
    }

    private fun unpair() {
        AlertDialog.Builder(this).setMessage("PCとのペアリングを解除しますか？")
            .setPositiveButton("解除") { _, _ ->
                ChannelService.stop(this)
                PhoneStore.unpair()
                refresh()
                status.text = "解除しました"
            }
            .setNegativeButton("キャンセル", null).show()
    }
}
