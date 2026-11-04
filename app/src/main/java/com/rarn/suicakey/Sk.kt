package com.rarn.suicakey

import android.content.Context
import android.content.SharedPreferences
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import com.rarn.suicakey.bc.BcPqc
import com.rarn.suicakey.core.Bytes
import com.rarn.suicakey.core.Pqc
import com.rarn.suicakey.core.Proto
import java.security.KeyStore
import java.security.Security
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import org.bouncycastle.jce.provider.BouncyCastleProvider

/**
 * 端末側の鍵・保存領域。
 *  sk_store : AES-256-GCM（Keystore, 取り出し不可）… 秘密情報の保存用
 *  sk_prf   : AES-256-ECB（Keystore, 取り出し不可）… 端末束縛PRF（SHA3-512で前後処理）
 */
object Sk {
    lateinit var app: Context
        private set

    fun init(c: Context) {
        if (::app.isInitialized) return
        app = c.applicationContext
        Security.removeProvider("BC")
        Security.addProvider(BouncyCastleProvider())
    }

    val pqc: Pqc by lazy { BcPqc() }
    val prefs: SharedPreferences get() = app.getSharedPreferences("sk2", Context.MODE_PRIVATE)
    private val ks: KeyStore by lazy { KeyStore.getInstance("AndroidKeyStore").apply { load(null) } }

    private fun gen(alias: String, purposes: Int, cfg: KeyGenParameterSpec.Builder.() -> Unit): SecretKey {
        fun spec(strongBox: Boolean) = KeyGenParameterSpec.Builder(alias, purposes)
            .setKeySize(256).apply(cfg).setIsStrongBoxBacked(strongBox).build()
        return try {
            KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore").run { init(spec(true)); generateKey() }
        } catch (e: Exception) {
            KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore").run { init(spec(false)); generateKey() }
        }
    }

    @Synchronized
    private fun storeKey(): SecretKey = (ks.getKey("sk_store", null) as? SecretKey)
        ?: gen("sk_store", KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT) {
            setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
        }

    @Synchronized
    private fun prfKey(): SecretKey = (ks.getKey("sk_prf", null) as? SecretKey)
        ?: gen("sk_prf", KeyProperties.PURPOSE_ENCRYPT) {
            setBlockModes(KeyProperties.BLOCK_MODE_ECB)
            setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            setRandomizedEncryptionRequired(false)
            setUnlockedDeviceRequired(true)
        }

    fun seal(b: ByteArray): String {
        val c = Cipher.getInstance("AES/GCM/NoPadding")
        c.init(Cipher.ENCRYPT_MODE, storeKey())
        return Bytes.b64(c.iv + c.doFinal(b))
    }

    fun open(s: String): ByteArray {
        val d = Bytes.unb64(s)
        val c = Cipher.getInstance("AES/GCM/NoPadding")
        c.init(Cipher.DECRYPT_MODE, storeKey(), GCMParameterSpec(128, d, 0, 12))
        return c.doFinal(d, 12, d.size - 12)
    }

    /** 端末束縛PRF: SHA3-512 → Keystore AES（2ブロック）→ SHA3-512。鍵は端末外に出ない */
    fun devPrf(label: String, data: ByteArray): ByteArray {
        val h = pqc.sha3(Proto.label("prf $label"), data)
        val c = Cipher.getInstance("AES/ECB/NoPadding")
        c.init(Cipher.ENCRYPT_MODE, prfKey())
        val o = c.doFinal(h, 0, 32)
        val r = pqc.sha3(Proto.label("prfout"), o, h)
        Bytes.wipe(o, h)
        return r
    }

    fun duressVer(pin: String): ByteArray = devPrf("duressver", pin.toByteArray())

    /** 認証素材: HMAC-SHA3-512(端末PRF(IDm‖PIN), IDm‖PIN) 64B */
    fun material(idm: ByteArray, pin: String): ByteArray {
        val p = pin.toByteArray()
        val d = devPrf("pw", idm + p)
        val m = pqc.hmac(d, Proto.label("pw"), idm, p)
        Bytes.wipe(d, p)
        return m
    }
}
