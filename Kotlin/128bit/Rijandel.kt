import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

fun aesEncrypt(plaintext: String, key: ByteArray): ByteArray {
    val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
    val iv = ByteArray(16)
    SecureRandom().nextBytes(iv)
    val ivSpec = IvParameterSpec(iv)
    val keySpec = SecretKeySpec(key, "AES")

    cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec)

    val ciphertext = cipher.doFinal(plaintext.toByteArray(Charsets.UTF_8))
    return iv + ciphertext
}

fun main() {
    val keyGen = KeyGenerator.getInstance("AES")
    keyGen.init(128) // 128-bit key
    val key = keyGen.generateKey().encoded

    val plaintext = "This is a test message for AES-128 encryption!"
    val ciphertext = aesEncrypt(plaintext, key)

    println("Ciphertext is: ${ciphertext.joinToString("") { "%02x".format(it) }}")
}
