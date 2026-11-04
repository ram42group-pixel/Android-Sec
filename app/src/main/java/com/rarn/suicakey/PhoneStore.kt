package com.rarn.suicakey

import com.rarn.suicakey.core.Bytes
import com.rarn.suicakey.core.PhoneSide
import com.rarn.suicakey.core.PhoneState
import com.rarn.suicakey.core.Pqc
import java.security.KeyPair
import java.security.PrivateKey
import java.security.PublicKey

/** スマホ側の永続状態。秘密情報は Keystore の鍵で暗号化して保存 */
object PhoneStore : PhoneState {
    private fun s(k: String) = Sk.prefs.getString(k, null) ?: throw IllegalStateException("未ペアリング")
    private fun d(k: String) = Bytes.unb64(s(k))

    fun paired() = Sk.prefs.contains("pc_kem")
    fun host(): String = s("host")
    fun port(): Int = Sk.prefs.getInt("port", 8765)

    override fun pcFp(): ByteArray = d("pc_fp")
    override fun pcKem(): PublicKey = Sk.pqc.pub(Pqc.MLKEM, d("pc_kem"))
    override fun pcX(): PublicKey = Sk.pqc.pub(Pqc.X448, d("pc_x"))
    override fun pcDsa(): PublicKey = Sk.pqc.pub(Pqc.MLDSA, d("pc_dsa"))
    override fun pcEd(): PublicKey = Sk.pqc.pub(Pqc.ED448, d("pc_ed"))
    override fun phoneFp(): ByteArray = d("me_fp")
    override fun phoneDsa(): PrivateKey = Sk.pqc.priv(Pqc.MLDSA, Sk.open(s("me_dsa")))
    override fun phoneEd(): PrivateKey = Sk.pqc.priv(Pqc.ED448, Sk.open(s("me_ed")))
    override fun psk(): ByteArray = Sk.open(s("psk"))
    override fun n(): Long = Sk.prefs.getLong("n", 0)

    @Synchronized
    override fun commit(newPsk: ByteArray, newN: Long) {
        Sk.prefs.edit().putString("psk", Sk.seal(newPsk)).putLong("n", newN).commit()
        Bytes.wipe(newPsk)
    }

    fun savePair(r: PhoneSide.PairResult, dsa: KeyPair, ed: KeyPair) {
        Sk.prefs.edit()
            .putString("pc_kem", Bytes.b64(r.pcKem)).putString("pc_x", Bytes.b64(r.pcX))
            .putString("pc_dsa", Bytes.b64(r.pcDsa)).putString("pc_ed", Bytes.b64(r.pcEd))
            .putString("pc_fp", Bytes.b64(r.pcFp)).putString("me_fp", Bytes.b64(r.phoneFp))
            .putString("me_dsa", Sk.seal(dsa.private.encoded)).putString("me_ed", Sk.seal(ed.private.encoded))
            .putString("psk", Sk.seal(r.psk0)).putLong("n", 0)
            .putString("host", r.host).putInt("port", r.port)
            .commit()
        Bytes.wipe(r.psk0)
    }

    fun unpair() {
        Sk.prefs.edit().apply {
            listOf("pc_kem", "pc_x", "pc_dsa", "pc_ed", "pc_fp", "me_fp", "me_dsa", "me_ed", "psk", "n", "host", "port")
                .forEach { remove(it) }
        }.commit()
    }
}
