package com.rarn.suicakey

import android.app.Activity
import android.Manifest
import android.app.NotificationManager
import android.content.pm.PackageManager
import android.location.Location
import android.location.LocationManager
import android.os.CancellationSignal
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference
import android.nfc.NfcAdapter
import android.nfc.Tag
import android.nfc.tech.NfcF
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.view.WindowManager
import android.widget.LinearLayout
import android.widget.TextView
import com.rarn.suicakey.core.Bytes
import com.rarn.suicakey.core.PhoneSide
import com.rarn.suicakey.core.Proto
import kotlin.concurrent.thread

/** 認証依頼への応答：① Suicaタッチ ② 生体 or PIN → 素材を署名付きで送信 */
class AuthActivity : Activity(), NfcAdapter.ReaderCallback {
    private var nfc: NfcAdapter? = null
    private lateinit var label: TextView
    private lateinit var status: TextView
    private lateinit var guard: Guard
    private val main = Handler(Looper.getMainLooper())
    private var busy = false
    private var req: ChannelService.Req? = null

    override fun onCreate(b: Bundle?) {
        super.onCreate(b)
        Sk.init(this)
        window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        label = TextView(this).apply { textSize = 18f }
        status = TextView(this).apply { textSize = 22f; setPadding(0, 48, 0, 0) }
        setContentView(LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(48, 96, 48, 48)
            addView(label); addView(status)
        })
        guard = Guard(this) { msg -> status.text = msg }
        getSystemService(NotificationManager::class.java).cancel(2)
        nfc = NfcAdapter.getDefaultAdapter(this)
        load()
    }

    override fun onNewIntent(intent: android.content.Intent) {
        super.onNewIntent(intent)
        load()
    }

    private fun load() {
        val r = ChannelService.pending
        if (r == null || Proto.now() > r.exp || ChannelService.session == null) {
            req = null
            label.text = ""
            status.text = "エラーです"
            return
        }
        req = r
        busy = false
        label.text = "依頼：${r.label}"
        status.text = "Suicaを背面にタッチしてください"
    }

    override fun onResume() {
        super.onResume()
        ChannelService.foreground = true
        nfc?.enableReaderMode(this, this, NfcAdapter.FLAG_READER_NFC_F or NfcAdapter.FLAG_READER_SKIP_NDEF_CHECK, null)
    }

    override fun onPause() {
        super.onPause()
        ChannelService.foreground = false
        nfc?.disableReaderMode(this)
    }

    override fun onTagDiscovered(tag: Tag) {
        if (NfcF.get(tag) == null) { main.post { status.text = "エラーです" }; return }
        val idm = tag.id
        main.post {
            val r = req
            if (busy || r == null) { Bytes.wipe(idm); return@post }
            if (Proto.now() > r.exp) { Bytes.wipe(idm); status.text = "エラーです"; return@post }
            busy = true
            status.text = "Suica読取OK → 本人確認"
            guard.unlock(onOk = { pin, duress -> send(r, idm, pin, duress) },
                onCancel = { Bytes.wipe(idm); busy = false })
        }
    }

    /** 通常PINと緊急PINで画面・待ち方を完全に同じにする（緊急時のみ裏で位置を取得） */
    private fun send(r: ChannelService.Req, idm: ByteArray, pin: String, duress: Boolean) {
        status.text = "送信中…"
        val ses = ChannelService.session
        if (ses == null) { Bytes.wipe(idm); status.text = "エラーです"; busy = false; return }
        ChannelService.onDone = { id -> if (Bytes.eq(id, r.id)) main.post { finishOk() } }
        main.postDelayed({ if (req === r) { status.text = "エラーです"; ChannelService.onDone = null; busy = false } }, 15_000)
        thread {
            try {
                val material = Sk.material(idm, pin)
                val loc = if (duress) locate() else ""
                PhoneSide.respond(Sk.pqc, ses, PhoneStore, r.id, r.challenge, material, duress, loc)
                Bytes.wipe(material)
            } catch (_: Exception) {
            } finally {
                Bytes.wipe(idm)
            }
        }
    }

    /** 現在地 "緯度,経度,精度m"（最大3秒。権限がなければ空） */
    private fun locate(): String {
        if (checkSelfPermission(Manifest.permission.ACCESS_FINE_LOCATION) != PackageManager.PERMISSION_GRANTED &&
            checkSelfPermission(Manifest.permission.ACCESS_COARSE_LOCATION) != PackageManager.PERMISSION_GRANTED) return ""
        val lm = getSystemService(LocationManager::class.java) ?: return ""
        val got = AtomicReference<Location?>(null)
        try {
            val provider = when {
                android.os.Build.VERSION.SDK_INT >= 31 && lm.isProviderEnabled(LocationManager.FUSED_PROVIDER) -> LocationManager.FUSED_PROVIDER
                lm.isProviderEnabled(LocationManager.GPS_PROVIDER) -> LocationManager.GPS_PROVIDER
                else -> LocationManager.NETWORK_PROVIDER
            }
            val latch = CountDownLatch(1)
            val cancel = CancellationSignal()
            lm.getCurrentLocation(provider, cancel, mainExecutor) { l -> got.set(l); latch.countDown() }
            if (!latch.await(3, TimeUnit.SECONDS)) cancel.cancel()
        } catch (_: Exception) {
        }
        var l = got.get()
        if (l == null) {
            try {
                l = lm.getProviders(true).mapNotNull { lm.getLastKnownLocation(it) }.maxByOrNull { it.time }
            } catch (_: SecurityException) {
            }
        }
        return l?.let { "%.6f,%.6f,%d".format(java.util.Locale.US, it.latitude, it.longitude, it.accuracy.toInt()) } ?: ""
    }

    private fun finishOk() {
        req = null
        ChannelService.pending = null
        ChannelService.onDone = null
        status.text = "送信完了 ✔"
        main.postDelayed({ finish() }, 1200)
    }
}
