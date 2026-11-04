package com.rarn.suicakey

import android.app.Activity
import android.app.AlertDialog
import android.hardware.biometrics.BiometricManager
import android.hardware.biometrics.BiometricPrompt
import android.os.CancellationSignal
import android.os.SystemClock
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import android.text.InputType
import android.view.WindowManager
import android.widget.EditText
import com.rarn.suicakey.core.Bytes
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/** PIN／緊急PIN／生体認証の管理と本人確認 */
class Guard(private val a: Activity, private val status: (String) -> Unit) {
    companion object {
        const val MIN_PIN = 6
        const val GCM = "AES/GCM/NoPadding"
        /** 総当たり対策：PIN入力は5秒に1回まで */
        const val MIN_INTERVAL_MS = 5_000L
        @Volatile private var lastMono = 0L
    }

    /*
     * 重要：スマホには「本物のPINが正しいか」を判定する情報を一切置かない。
     * PINの正否はPCに送って初めて分かる（PC側で5秒に1回＋連続失敗ロック）。
     * スマホをroot化・デバッグされても、PINをスマホ内だけで総当たりできない。
     * 端末内に残すのは「緊急PINかどうか」の照合値だけ（本物のPINの手がかりにはならない）。
     */

    private val p get() = Sk.prefs
    private val ks by lazy { KeyStore.getInstance("AndroidKeyStore").apply { load(null) } }

    /** 前回の入力から5秒未満なら true（単調時計と保存済み時刻の両方で判定） */
    private fun tooSoon(): Boolean {
        val nowW = System.currentTimeMillis()
        val lastW = p.getLong("last_try", 0)
        return (lastMono != 0L && SystemClock.elapsedRealtime() - lastMono < MIN_INTERVAL_MS) ||
            (nowW - lastW in 0 until MIN_INTERVAL_MS)
    }

    private fun markTry() {
        lastMono = SystemClock.elapsedRealtime()
        p.edit().putLong("last_try", System.currentTimeMillis()).commit()
    }

    fun hasPin() = p.getBoolean("pin_set", false)
    fun hasDuress() = p.contains("dver")
    fun bioOn() = p.contains("bio_ct")

    /** 0=通常として送信, 1=緊急PIN, -1=送信しない（5秒以内・桁数不足） */
    fun check(pin: String): Int {
        if (tooSoon()) { status("エラーです"); return -1 }
        markTry()
        if (pin.length < MIN_PIN) { status("エラーです"); return -1 }
        return if (hasDuress() && Bytes.eq(Sk.duressVer(pin), Bytes.unb64(p.getString("dver", "")!!))) 1 else 0
    }

    fun pinDialog(title: String, onCancel: (() -> Unit)? = null, onOk: (String) -> Unit) {
        val e = EditText(a).apply {
            inputType = InputType.TYPE_CLASS_NUMBER or InputType.TYPE_NUMBER_VARIATION_PASSWORD
            hint = "PIN"
        }
        val d = AlertDialog.Builder(a).setTitle(title).setView(e)
            .setPositiveButton("OK") { _, _ -> onOk(e.text.toString()) }
            .setNegativeButton("キャンセル") { _, _ -> onCancel?.invoke() }
            .setOnCancelListener { onCancel?.invoke() }
            .create()
        d.window?.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        d.show()
    }

    /** 同じPINを2回入力させる（照合値を持たないため、打ち間違いはここで防ぐ） */
    private fun pinTwice(title: String, onOk: (String) -> Unit) {
        pinDialog(title) { x ->
            if (x.length < MIN_PIN) { status("エラーです"); return@pinDialog }
            pinDialog("確認のためもう一度") { y ->
                if (x != y) { status("エラーです"); return@pinDialog }
                onOk(x)
            }
        }
    }

    // ── 本人確認：生体 or PIN（緊急PIN含む） ──
    fun unlock(onOk: (pin: String, duress: Boolean) -> Unit, onCancel: () -> Unit) {
        if (bioOn()) bioUnlock(onOk, onCancel) else askPin(onOk, onCancel)
    }

    private fun askPin(onOk: (String, Boolean) -> Unit, onCancel: () -> Unit) {
        pinDialog("PINを入力", onCancel = onCancel) { pin ->
            when (check(pin)) {
                0 -> onOk(pin, false)
                1 -> onOk(pin, true)
                else -> onCancel()
            }
        }
    }

    private fun bioUnlock(onOk: (String, Boolean) -> Unit, onCancel: () -> Unit) {
        val c = Cipher.getInstance(GCM)
        try {
            c.init(Cipher.DECRYPT_MODE, ks.getKey("sk_bio", null) as SecretKey,
                GCMParameterSpec(128, Bytes.unb64(p.getString("bio_iv", "")!!)))
        } catch (e: KeyPermanentlyInvalidatedException) {
            disableBio(); status("エラーです"); askPin(onOk, onCancel); return
        } catch (e: Exception) {
            disableBio(); askPin(onOk, onCancel); return
        }
        bioPrompt("本人確認", c, onPin = { askPin(onOk, onCancel) }) { ci ->
            if (tooSoon()) { status("エラーです"); onCancel(); return@bioPrompt }
            markTry()
            onOk(String(ci.doFinal(Bytes.unb64(p.getString("bio_ct", "")!!))), false)
        }
    }

    // ── PIN管理（照合値は保存しない） ──
    fun changePin(done: () -> Unit) {
        pinTwice("新しいPIN（${MIN_PIN}桁以上）※変更後はPCの管理メニューで「カード/PINを登録」") { x ->
            if (hasDuress() && Bytes.eq(Sk.duressVer(x), Bytes.unb64(p.getString("dver", "")!!))) {
                status("エラーです"); return@pinTwice
            }
            p.edit().putBoolean("pin_set", true).remove("ver").remove("fails").remove("lock").apply()
            disableBio()
            status("PINを設定しました")
            done()
        }
    }

    fun setDuress(done: () -> Unit) {
        if (!hasPin()) { status("エラーです"); return }
        pinDialog("通常のPIN（緊急PINと重複しないかの確認用・保存しません）") { cur ->
            pinTwice("緊急PIN（${MIN_PIN}桁以上・通常PINと別）") { x ->
                if (x == cur) { status("エラーです"); return@pinTwice }
                p.edit().putString("dver", Bytes.b64(Sk.duressVer(x))).apply()
                status("緊急PINを設定しました")
                done()
            }
        }
    }

    // ── 生体認証 ──
    fun toggleBio(done: () -> Unit) {
        if (bioOn()) { disableBio(); status("生体認証を無効にしました"); done(); return }
        if (!hasPin()) { status("エラーです"); return }
        val bm = a.getSystemService(BiometricManager::class.java)
        if (bm.canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG) != BiometricManager.BIOMETRIC_SUCCESS) {
            status("エラーです"); return
        }
        pinTwice("現在のPIN（生体認証の登録に必要）") { pin ->
            if (hasDuress() && Bytes.eq(Sk.duressVer(pin), Bytes.unb64(p.getString("dver", "")!!))) {
                status("エラーです"); return@pinTwice
            }
            val c = Cipher.getInstance(GCM).apply { init(Cipher.ENCRYPT_MODE, newBioKey()) }
            bioPrompt("生体認証を登録", c, onPin = null) { ci ->
                val iv = ci.iv
                val ct = ci.doFinal(pin.toByteArray())
                p.edit().putString("bio_iv", Bytes.b64(iv)).putString("bio_ct", Bytes.b64(ct)).apply()
                status("生体認証を有効にしました")
                done()
            }
        }
    }

    private fun newBioKey(): SecretKey {
        ks.deleteEntry("sk_bio")
        return KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore").run {
            init(KeyGenParameterSpec.Builder("sk_bio", KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
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

    fun disableBio() {
        p.edit().remove("bio_iv").remove("bio_ct").apply()
        try { ks.deleteEntry("sk_bio") } catch (_: Exception) {}
    }

    private fun bioPrompt(title: String, c: Cipher, onPin: (() -> Unit)?, onOk: (Cipher) -> Unit) {
        BiometricPrompt.Builder(a)
            .setTitle(title)
            .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
            .setNegativeButton(if (onPin != null) "PINで入力" else "キャンセル", a.mainExecutor) { _, _ ->
                if (onPin != null) onPin() else status("キャンセルしました")
            }
            .build()
            .authenticate(BiometricPrompt.CryptoObject(c), CancellationSignal(), a.mainExecutor,
                object : BiometricPrompt.AuthenticationCallback() {
                    override fun onAuthenticationSucceeded(r: BiometricPrompt.AuthenticationResult) {
                        val ci = r.cryptoObject?.cipher ?: return
                        try { onOk(ci) } catch (e: Exception) { status("エラーです") }
                    }
                    override fun onAuthenticationError(code: Int, msg: CharSequence) {
                        status("エラーです")
                        if (onPin != null && (code == BiometricPrompt.BIOMETRIC_ERROR_LOCKOUT ||
                                    code == BiometricPrompt.BIOMETRIC_ERROR_LOCKOUT_PERMANENT)) onPin()
                    }
                })
    }
}
