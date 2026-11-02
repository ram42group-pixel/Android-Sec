package com.rarn.suicakey

import android.app.Activity
import android.app.AlertDialog
import android.content.Context
import android.hardware.biometrics.BiometricManager
import android.hardware.biometrics.BiometricPrompt
import android.nfc.NfcAdapter
import android.nfc.Tag
import android.nfc.tech.NfcF
import android.os.Bundle
import android.os.CancellationSignal
import android.os.Handler
import android.os.Looper
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import android.text.InputType
import android.util.Base64
import android.view.WindowManager
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import android.widget.Toast
import java.net.HttpURLConnection
import java.net.URL
import java.security.KeyStore
import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.Mac
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import kotlin.concurrent.thread

/**
 * 認証フロー（2要素とも必須）
 *   ① Suicaタッチ（IDm取得）  ② 本人確認：生体認証 または PIN
 *   → HMAC-SHA256(PIN, IDm) から派生パスワード → AES-GCMで暗号化してWindowsへ
 *
 * 保存するもの
 *   ver    : Keystore内HMAC鍵によるPIN照合値（端末外では総当たり不可）
 *   bio_ct : 生体認証でしか解けないKeystore AES鍵で暗号化したPIN
 * IDm・平文PINは保存しない。
 */
class MainActivity : Activity(), NfcAdapter.ReaderCallback {
    companion object {
        const val TIMEOUT_MS = 30_000L      // Suicaタッチ後、本人確認までの制限時間
        const val MAX_FAILS = 5             // PIN連続失敗の上限
        const val LOCK_MS = 5 * 60_000L     // 上限超過時のロック時間
        const val MIN_PIN = 6
        const val GCM = "AES/GCM/NoPadding"
    }

    private val prefs by lazy { getSharedPreferences("cfg", Context.MODE_PRIVATE) }
    private val ks by lazy { KeyStore.getInstance("AndroidKeyStore").apply { load(null) } }
    private val main = Handler(Looper.getMainLooper())
    private var nfc: NfcAdapter? = null

    private lateinit var host: EditText
    private lateinit var psk: EditText
    private lateinit var state: TextView
    private lateinit var status: TextView
    private lateinit var bioBtn: Button

    private var pendingIdm: ByteArray? = null
    private val expire = Runnable { clearPending(); status.text = "時間切れ：Suicaをもう一度タッチしてください" }

    // ───────── UI ─────────
    override fun onCreate(b: Bundle?) {
        super.onCreate(b)
        window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        val pwType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD

        host = EditText(this).apply {
            hint = "Windows IP:ポート 例 192.168.1.10:8765"; setText(prefs.getString("host", ""))
        }
        psk = EditText(this).apply {
            hint = "共有キー（Windows側と同じ・8文字以上）"; inputType = pwType; setText(prefs.getString("psk", ""))
        }
        val save = Button(this).apply {
            text = "接続設定を保存"
            setOnClickListener {
                prefs.edit().putString("host", host.text.toString().trim())
                    .putString("psk", psk.text.toString()).apply()
                Toast.makeText(this@MainActivity, "保存しました", Toast.LENGTH_SHORT).show()
            }
        }
        val pinBtn = Button(this).apply { text = "PINを登録／変更"; setOnClickListener { changePin() } }
        bioBtn = Button(this).apply { setOnClickListener { toggleBio() } }
        state = TextView(this).apply { textSize = 14f; setPadding(0, 32, 0, 16) }
        status = TextView(this).apply { textSize = 20f; setPadding(0, 32, 0, 0) }

        setContentView(ScrollView(this).apply {
            addView(LinearLayout(this@MainActivity).apply {
                orientation = LinearLayout.VERTICAL
                setPadding(48, 48, 48, 48)
                listOf(host, psk, save, pinBtn, bioBtn, state, status).forEach { addView(it) }
            })
        })

        nfc = NfcAdapter.getDefaultAdapter(this)
        refresh()
        status.text = when {
            nfc == null -> "この端末はNFC非対応です"
            !hasPin() -> "まずPINを登録してください"
            else -> "Suicaを背面にタッチしてください"
        }
    }

    override fun onResume() {
        super.onResume()
        nfc?.enableReaderMode(this, this,
            NfcAdapter.FLAG_READER_NFC_F or NfcAdapter.FLAG_READER_SKIP_NDEF_CHECK, null)
    }

    override fun onPause() {
        super.onPause()
        nfc?.disableReaderMode(this)
    }

    private fun refresh() {
        state.text = "PIN：${if (hasPin()) "登録済" else "未登録"}　／　生体認証：${if (bioOn()) "有効" else "無効"}"
        bioBtn.text = if (bioOn()) "生体認証を無効にする" else "生体認証を有効にする"
    }

    private fun hasPin() = prefs.contains("ver")
    private fun bioOn() = prefs.contains("bio_ct")

    // ───────── ① Suicaタッチ ─────────
    override fun onTagDiscovered(tag: Tag) {
        if (NfcF.get(tag) == null) return ui("FeliCa（Suica）ではありません")
        val id = tag.id
        main.post {
            when {
                pendingIdm != null -> id.fill(0) // 本人確認中の再タッチは無視
                !hasPin() -> { id.fill(0); status.text = "先にPINを登録してください" }
                host.text.isBlank() || psk.text.length < 8 -> {
                    id.fill(0); status.text = "接続設定（IP・共有キー8文字以上）を保存してください"
                }
                else -> {
                    pendingIdm = id
                    main.postDelayed(expire, TIMEOUT_MS)
                    status.text = "Suica読取OK → 本人確認してください（30秒以内）"
                    if (bioOn()) bioUnlock() else askPin()
                }
            }
        }
    }

    private fun clearPending() {
        main.removeCallbacks(expire)
        pendingIdm?.fill(0)
        pendingIdm = null
    }

    // ───────── ② 本人確認 ─────────
    private fun askPin() {
        if (locked()) { clearPending(); return }
        pinDialog("PINを入力", onCancel = { clearPending(); status.text = "キャンセルしました" }) { p ->
            if (checkPin(p)) complete(p) else clearPending()
        }
    }

    private fun bioUnlock() {
        val c = Cipher.getInstance(GCM)
        try {
            c.init(Cipher.DECRYPT_MODE, ks.getKey("bio", null) as SecretKey,
                GCMParameterSpec(128, b64d(prefs.getString("bio_iv", "")!!)))
        } catch (e: KeyPermanentlyInvalidatedException) {
            disableBio(); status.text = "指紋等が追加・変更されたため生体認証を無効化しました"; askPin(); return
        } catch (e: Exception) {
            disableBio(); askPin(); return
        }
        bioPrompt("本人確認", c, onPin = { askPin() }) { ci ->
            complete(String(ci.doFinal(b64d(prefs.getString("bio_ct", "")!!))))
        }
    }

    /** ①②が揃ったら派生→送信 */
    private fun complete(pin: String) {
        val idm = pendingIdm ?: run { status.text = "Suicaをもう一度タッチしてください"; return }
        val secret = derive(idm, pin)
        clearPending()
        val h = host.text.toString().trim()
        val k = psk.text.toString()
        status.text = "送信中…"
        thread { ui(try { send(h, k, secret); "送信完了 ✔" } catch (e: Exception) { "失敗: ${e.message}" }) }
    }

    // ───────── PIN管理 ─────────
    private fun verKey(): SecretKey = (ks.getKey("ver", null) as? SecretKey)
        ?: KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_HMAC_SHA256, "AndroidKeyStore").run {
            init(KeyGenParameterSpec.Builder("ver", KeyProperties.PURPOSE_SIGN).build())
            generateKey()
        }

    private fun verifier(p: String): ByteArray =
        Mac.getInstance("HmacSHA256").run { init(verKey()); doFinal(p.toByteArray()) }

    private fun locked(): Boolean {
        val left = prefs.getLong("lock", 0) - System.currentTimeMillis()
        if (left > 0) status.text = "PINロック中：あと${left / 1000 + 1}秒"
        return left > 0
    }

    private fun checkPin(p: String): Boolean {
        if (MessageDigest.isEqual(verifier(p), b64d(prefs.getString("ver", "")!!))) {
            prefs.edit().putInt("fails", 0).apply(); return true
        }
        val f = prefs.getInt("fails", 0) + 1
        val e = prefs.edit().putInt("fails", f)
        if (f >= MAX_FAILS) e.putLong("lock", System.currentTimeMillis() + LOCK_MS)
        e.apply()
        status.text = if (f >= MAX_FAILS) "PINを${MAX_FAILS}回以上間違えたため5分間ロックします"
                      else "PINが違います（あと${MAX_FAILS - f}回でロック）"
        return false
    }

    private fun changePin() {
        if (!hasPin()) return newPin(false)
        if (locked()) return
        pinDialog("現在のPIN") { p -> if (checkPin(p)) newPin(true) }
    }

    private fun newPin(changing: Boolean) {
        val t = if (changing) "新しいPIN（変更すると生成パスワードも変わります）" else "新しいPIN（${MIN_PIN}桁以上）"
        pinDialog(t) { a ->
            if (a.length < MIN_PIN) { status.text = "PINは${MIN_PIN}桁以上にしてください"; return@pinDialog }
            pinDialog("確認のためもう一度") { b ->
                if (a != b) { status.text = "PINが一致しません"; return@pinDialog }
                prefs.edit().putString("ver", b64(verifier(a))).putInt("fails", 0).remove("lock").apply()
                disableBio()
                refresh()
                status.text = if (changing) "PINを変更しました（生体認証は再設定してください）" else "PINを登録しました"
            }
        }
    }

    // ───────── 生体認証管理 ─────────
    private fun toggleBio() {
        if (bioOn()) { disableBio(); refresh(); status.text = "生体認証を無効にしました"; return }
        if (!hasPin()) { status.text = "先にPINを登録してください"; return }
        val bm = getSystemService(BiometricManager::class.java)
        if (bm.canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG) != BiometricManager.BIOMETRIC_SUCCESS) {
            status.text = "利用できる生体認証（指紋など）が端末に登録されていません"; return
        }
        if (locked()) return
        pinDialog("現在のPIN（生体認証の登録に必要）") { p ->
            if (!checkPin(p)) return@pinDialog
            val c = Cipher.getInstance(GCM).apply { init(Cipher.ENCRYPT_MODE, newBioKey()) }
            bioPrompt("生体認証を登録", c, onPin = null) { ci ->
                val iv = ci.iv
                val ct = ci.doFinal(p.toByteArray())
                prefs.edit().putString("bio_iv", b64(iv)).putString("bio_ct", b64(ct)).apply()
                refresh(); status.text = "生体認証を有効にしました"
            }
        }
    }

    /** 生体認証（クラス3）でしか使えず、指紋追加で無効化される鍵 */
    private fun newBioKey(): SecretKey {
        ks.deleteEntry("bio")
        return KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore").run {
            init(KeyGenParameterSpec.Builder("bio",
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .setUserAuthenticationRequired(true)
                .setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)
                .setInvalidatedByBiometricEnrollment(true)
                .build())
            generateKey()
        }
    }

    private fun disableBio() {
        prefs.edit().remove("bio_iv").remove("bio_ct").apply()
        try { ks.deleteEntry("bio") } catch (_: Exception) {}
    }

    private fun bioPrompt(title: String, c: Cipher, onPin: (() -> Unit)?, onOk: (Cipher) -> Unit) {
        BiometricPrompt.Builder(this)
            .setTitle(title)
            .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
            .setNegativeButton(if (onPin != null) "PINで入力" else "キャンセル", mainExecutor) { _, _ ->
                if (onPin != null) onPin() else status.text = "キャンセルしました"
            }
            .build()
            .authenticate(BiometricPrompt.CryptoObject(c), CancellationSignal(), mainExecutor,
                object : BiometricPrompt.AuthenticationCallback() {
                    override fun onAuthenticationSucceeded(r: BiometricPrompt.AuthenticationResult) {
                        val ci = r.cryptoObject?.cipher ?: return
                        try { onOk(ci) } catch (e: Exception) { status.text = "生体認証エラー: ${e.message}" }
                    }
                    override fun onAuthenticationError(code: Int, msg: CharSequence) {
                        status.text = msg.toString()
                        // 生体認証がロックされた場合はPINへ切替
                        if (onPin != null && (code == BiometricPrompt.BIOMETRIC_ERROR_LOCKOUT ||
                                    code == BiometricPrompt.BIOMETRIC_ERROR_LOCKOUT_PERMANENT)) onPin()
                    }
                })
    }

    // ───────── 共通 ─────────
    private fun pinDialog(title: String, onCancel: (() -> Unit)? = null, onOk: (String) -> Unit) {
        val e = EditText(this).apply {
            inputType = InputType.TYPE_CLASS_NUMBER or InputType.TYPE_NUMBER_VARIATION_PASSWORD
            hint = "PIN"
        }
        val d = AlertDialog.Builder(this).setTitle(title).setView(e)
            .setPositiveButton("OK") { _, _ -> onOk(e.text.toString()) }
            .setNegativeButton("キャンセル") { _, _ -> onCancel?.invoke() }
            .setOnCancelListener { onCancel?.invoke() }
            .create()
        d.window?.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        d.show()
    }

    /** HMAC-SHA256(key=PIN, IDm || "SuicaKey-v1") → base64url 32文字（v1と互換） */
    private fun derive(idm: ByteArray, pin: String): String {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(pin.toByteArray(), "HmacSHA256"))
        mac.update(idm)
        val out = mac.doFinal("SuicaKey-v1".toByteArray())
        return Base64.encodeToString(out, Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP).take(32)
    }

    /** body = base64( nonce(12) || AES-256-GCM(json) ) */
    private fun send(h: String, pskStr: String, secret: String) {
        val key = MessageDigest.getInstance("SHA-256").digest(pskStr.toByteArray())
        val nonce = ByteArray(12).also { SecureRandom().nextBytes(it) }
        val json = """{"ts":${System.currentTimeMillis() / 1000},"secret":"$secret"}"""
        val c = Cipher.getInstance(GCM)
        c.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, nonce))
        val body = Base64.encodeToString(nonce + c.doFinal(json.toByteArray()), Base64.NO_WRAP).toByteArray()

        val con = URL("http://$h/").openConnection() as HttpURLConnection
        con.requestMethod = "POST"
        con.connectTimeout = 5000
        con.readTimeout = 5000
        con.doOutput = true
        con.setRequestProperty("Content-Type", "text/plain")
        con.outputStream.use { it.write(body) }
        val code = con.responseCode
        con.disconnect()
        if (code != 200) throw Exception(
            when (code) { 400 -> "共有キー不一致"; 409 -> "時刻ずれ/再送"; 403 -> "許可されていないIP"; else -> "HTTP $code" })
    }

    private fun b64(b: ByteArray) = Base64.encodeToString(b, Base64.NO_WRAP)
    private fun b64d(s: String) = Base64.decode(s, Base64.NO_WRAP)
    private fun ui(msg: String) = runOnUiThread { status.text = msg }
}
