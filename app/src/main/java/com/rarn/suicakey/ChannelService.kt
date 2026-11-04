package com.rarn.suicakey

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.IBinder
import com.rarn.suicakey.core.Bytes
import com.rarn.suicakey.core.IO
import com.rarn.suicakey.core.Msg
import com.rarn.suicakey.core.PhoneSide
import com.rarn.suicakey.core.Proto
import java.net.InetSocketAddress
import java.net.Socket
import kotlin.concurrent.thread

/** PCとの常時接続（前面サービス）。PCからの認証依頼を通知で知らせる */
class ChannelService : Service() {
    class Req(val id: ByteArray, val challenge: ByteArray, val label: String, val exp: Long)

    companion object {
        @Volatile var session: PhoneSide.Session? = null
        @Volatile var pending: Req? = null
        @Volatile var connected = false
        @Volatile var manualWait = false
        @Volatile var foreground = false
        @Volatile var onDone: ((ByteArray) -> Unit)? = null
        @Volatile var onState: (() -> Unit)? = null
        @Volatile private var running = false

        fun start(c: Context) { if (PhoneStore.paired()) c.startForegroundService(Intent(c, ChannelService::class.java)) }
        fun stop(c: Context) { running = false; session?.ch?.close(); c.stopService(Intent(c, ChannelService::class.java)) }

        /** バックグラウンドスレッドから呼ぶこと */
        fun send(m: Msg): Boolean = try { session?.ch?.send(m) != null } catch (e: Exception) { false }
    }

    private val nm by lazy { getSystemService(NotificationManager::class.java) }

    override fun onBind(i: Intent?): IBinder? = null

    override fun onCreate() {
        super.onCreate()
        Sk.init(this)
        nm.createNotificationChannel(NotificationChannel("svc", "接続状態", NotificationManager.IMPORTANCE_MIN))
        nm.createNotificationChannel(NotificationChannel("req", "認証依頼", NotificationManager.IMPORTANCE_HIGH).apply {
            lockscreenVisibility = Notification.VISIBILITY_PRIVATE
        })
        startForeground(1, svcNote("PCを探しています"), ServiceInfo.FOREGROUND_SERVICE_TYPE_CONNECTED_DEVICE)
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (!running) {
            running = true
            thread(name = "sk-channel") { loop() }
        }
        return START_STICKY
    }

    override fun onDestroy() {
        running = false
        session?.ch?.close()
        super.onDestroy()
    }

    private fun svcNote(text: String): Notification =
        Notification.Builder(this, "svc")
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setContentTitle("SuicaKey")
            .setContentText(text)
            .setOngoing(true)
            .setContentIntent(PendingIntent.getActivity(this, 0, Intent(this, MainActivity::class.java), PendingIntent.FLAG_IMMUTABLE))
            .build()

    private fun setState(c: Boolean) {
        connected = c
        nm.notify(1, svcNote(if (c) "PCと接続中（暗号化）" else "PCを探しています"))
        onState?.invoke()
    }

    private fun loop() {
        var backoff = 5_000L
        while (running && PhoneStore.paired()) {
            try {
                Socket().use { s ->
                    s.connect(InetSocketAddress(PhoneStore.host(), PhoneStore.port()), 5_000)
                    s.soTimeout = 150_000
                    s.tcpNoDelay = true
                    val io = IO(s)
                    val ses = PhoneSide.connect(Sk.pqc, io, PhoneStore)
                    session = ses
                    setState(true)
                    backoff = 5_000L
                    val pinger = thread(name = "sk-ping") {
                        try { while (session === ses) { Thread.sleep(60_000); ses.ch.send(Msg(Proto.PING)) } } catch (_: Exception) {}
                    }
                    while (running) {
                        val m = ses.ch.recv()
                        when (m.type) {
                            Proto.REQ -> onReq(m)
                            Proto.DONE -> onDone?.invoke(m.get(0))
                            Proto.PONG -> {}
                            else -> throw SecurityException("unexpected")
                        }
                    }
                    pinger.interrupt()
                }
            } catch (_: Exception) {
            }
            session = null
            if (connected) setState(false)
            if (!running) break
            try { Thread.sleep(backoff) } catch (_: InterruptedException) {}
            backoff = minOf(backoff * 2, 60_000L)
        }
        running = false
        stopSelf()
    }

    private fun onReq(m: Msg) {
        if (m.n() != 4) return
        val r = Req(m.get(0), m.get(1), Bytes.str(m.get(2)), Bytes.u64(m.get(3)))
        pending = r
        val open = Intent(this, AuthActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_SINGLE_TOP)
        if (manualWait && foreground) {
            manualWait = false
            startActivity(open)
            return
        }
        nm.notify(2, Notification.Builder(this, "req")
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setContentTitle("認証の依頼")
            .setContentText("${r.label}：タップしてSuicaをタッチ")
            .setCategory(Notification.CATEGORY_CALL)
            .setAutoCancel(true)
            .setTimeoutAfter(90_000)
            .setContentIntent(PendingIntent.getActivity(this, 2, open, PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT))
            .build())
    }
}

/** 再起動後に常時接続を再開 */
class BootReceiver : BroadcastReceiver() {
    override fun onReceive(c: Context, i: Intent) {
        if (i.action == Intent.ACTION_BOOT_COMPLETED) { Sk.init(c); ChannelService.start(c) }
    }
}
