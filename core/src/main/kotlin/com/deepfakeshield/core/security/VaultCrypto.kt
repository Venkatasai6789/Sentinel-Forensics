package com.deepfakeshield.core.security

import android.content.Context
import android.content.ContextWrapper
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import java.security.KeyStore
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.Mac
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import javax.inject.Inject
import javax.inject.Singleton

data class EncryptedPayload(
    val cipherTextBase64: String,
    val ivBase64: String
)

/**
 * Abstraction for authenticated credential & note encryption.
 */
interface VaultCipher {
    fun encryptString(plaintext: String): EncryptedPayload
    fun decryptString(cipherTextBase64: String, ivBase64: String): String
    fun computeReuseDigest(plaintext: String): String
}

/**
 * Android Keystore-backed AES-256-GCM + HMAC-SHA256 implementation.
 * Every encryption operation uses a hardware/TEE-backed key when supported and a fresh random 96-bit IV.
 */
@Singleton
class KeystoreVaultCipher @Inject constructor() : VaultCipher {

    companion object {
        private const val ANDROID_KEYSTORE = "AndroidKeyStore"
        private const val AES_ALIAS = "sentinel_vault_aes_256_gcm_v1"
        private const val HMAC_ALIAS = "sentinel_vault_hmac_sha256_v1"
        private const val GCM_TAG_BITS = 128
    }

    private fun getOrCreateAesKey(): SecretKey {
        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        (keyStore.getKey(AES_ALIAS, null) as? SecretKey)?.let { return it }

        val keyGen = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
        val spec = KeyGenParameterSpec.Builder(
            AES_ALIAS,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .setRandomizedEncryptionRequired(true)
            .build()
        keyGen.init(spec)
        return keyGen.generateKey()
    }

    private fun getOrCreateHmacKey(): SecretKey {
        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        (keyStore.getKey(HMAC_ALIAS, null) as? SecretKey)?.let { return it }

        val keyGen = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_HMAC_SHA256, ANDROID_KEYSTORE)
        val spec = KeyGenParameterSpec.Builder(
            HMAC_ALIAS,
            KeyProperties.PURPOSE_SIGN
        ).build()
        keyGen.init(spec)
        return keyGen.generateKey()
    }

    override fun encryptString(plaintext: String): EncryptedPayload {
        val key = getOrCreateAesKey()
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, key)
        val iv = cipher.iv ?: throw IllegalStateException("Keystore cipher failed to generate IV")
        val encryptedBytes = cipher.doFinal(plaintext.toByteArray(Charsets.UTF_8))
        return EncryptedPayload(
            cipherTextBase64 = Base64.encodeToString(encryptedBytes, Base64.NO_WRAP),
            ivBase64 = Base64.encodeToString(iv, Base64.NO_WRAP)
        )
    }

    override fun decryptString(cipherTextBase64: String, ivBase64: String): String {
        val key = getOrCreateAesKey()
        val iv = Base64.decode(ivBase64, Base64.NO_WRAP)
        val cipherText = Base64.decode(cipherTextBase64, Base64.NO_WRAP)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(GCM_TAG_BITS, iv))
        val plainBytes = cipher.doFinal(cipherText)
        return String(plainBytes, Charsets.UTF_8)
    }

    override fun computeReuseDigest(plaintext: String): String {
        val key = getOrCreateHmacKey()
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(key)
        val digest = mac.doFinal(plaintext.toByteArray(Charsets.UTF_8))
        return digest.joinToString("") { "%02x".format(it) }
    }
}

/**
 * Software AES-256-GCM + HMAC-SHA256 cipher for pure-JVM tests and Robolectric environments
 * where AndroidKeyStore hardware provider is absent. Uses java.util.Base64 cleanly.
 */
class SoftwareAesGcmVaultCipher(
    aesKeyBytes: ByteArray = ByteArray(32).apply { SecureRandom().nextBytes(this) },
    hmacKeyBytes: ByteArray = ByteArray(32).apply { SecureRandom().nextBytes(this) }
) : VaultCipher {

    private val random = SecureRandom()
    private val aesKey: SecretKey = SecretKeySpec(aesKeyBytes, "AES")
    private val hmacKey: SecretKey = SecretKeySpec(hmacKeyBytes, "HmacSHA256")

    override fun encryptString(plaintext: String): EncryptedPayload {
        val iv = ByteArray(12).also { random.nextBytes(it) }
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, aesKey, GCMParameterSpec(128, iv))
        val encrypted = cipher.doFinal(plaintext.toByteArray(Charsets.UTF_8))
        return EncryptedPayload(
            cipherTextBase64 = java.util.Base64.getEncoder().encodeToString(encrypted),
            ivBase64 = java.util.Base64.getEncoder().encodeToString(iv)
        )
    }

    override fun decryptString(cipherTextBase64: String, ivBase64: String): String {
        val iv = java.util.Base64.getDecoder().decode(ivBase64)
        val cipherText = java.util.Base64.getDecoder().decode(cipherTextBase64)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, aesKey, GCMParameterSpec(128, iv))
        return String(cipher.doFinal(cipherText), Charsets.UTF_8)
    }

    override fun computeReuseDigest(plaintext: String): String {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(hmacKey)
        return mac.doFinal(plaintext.toByteArray(Charsets.UTF_8))
            .joinToString("") { "%02x".format(it) }
    }
}

/**
 * Biometric / Device Credential authenticator usable from UI composables when host is FragmentActivity.
 */
@Singleton
class DeviceAuthHelper @Inject constructor() {

    enum class BiometricStatus { AVAILABLE, NOT_ENROLLED, NOT_AVAILABLE }

    sealed class AuthOutcome {
        data object Authenticated : AuthOutcome()
        data object Cancelled : AuthOutcome()
        data object NotEnrolled : AuthOutcome()
        data class Failed(val reason: String) : AuthOutcome()
    }

    private fun allowedAuthenticators(): Int {
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            BiometricManager.Authenticators.BIOMETRIC_STRONG or
                BiometricManager.Authenticators.DEVICE_CREDENTIAL
        } else {
            @Suppress("DEPRECATION")
            BiometricManager.Authenticators.BIOMETRIC_WEAK or
                BiometricManager.Authenticators.DEVICE_CREDENTIAL
        }
    }

    fun checkAvailability(context: Context): BiometricStatus {
        val manager = BiometricManager.from(context)
        return when (manager.canAuthenticate(allowedAuthenticators())) {
            BiometricManager.BIOMETRIC_SUCCESS -> BiometricStatus.AVAILABLE
            BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED -> BiometricStatus.NOT_ENROLLED
            else -> BiometricStatus.NOT_AVAILABLE
        }
    }

    fun findFragmentActivity(context: Context): FragmentActivity? {
        var current: Context? = context
        while (current is ContextWrapper) {
            if (current is FragmentActivity) return current
            current = current.baseContext
        }
        return current as? FragmentActivity
    }

    fun authenticate(
        context: Context,
        title: String = "Unlock Password Vault",
        subtitle: String = "Verify identity with biometrics or device PIN",
        onResult: (AuthOutcome) -> Unit
    ) {
        val availability = checkAvailability(context)
        if (availability == BiometricStatus.NOT_ENROLLED) {
            onResult(AuthOutcome.NotEnrolled)
            return
        }
        if (availability == BiometricStatus.NOT_AVAILABLE) {
            onResult(AuthOutcome.Failed("Device biometric or credential lock is unavailable."))
            return
        }
        val activity = findFragmentActivity(context)
        if (activity == null || activity.isFinishing || activity.isDestroyed) {
            onResult(AuthOutcome.Failed("Host activity is unavailable for biometric authentication."))
            return
        }

        val executor = ContextCompat.getMainExecutor(activity)
        val prompt = BiometricPrompt(
            activity,
            executor,
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    onResult(AuthOutcome.Authenticated)
                }

                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                    if (errorCode == BiometricPrompt.ERROR_USER_CANCELED ||
                        errorCode == BiometricPrompt.ERROR_NEGATIVE_BUTTON ||
                        errorCode == BiometricPrompt.ERROR_CANCELED
                    ) {
                        onResult(AuthOutcome.Cancelled)
                    } else {
                        onResult(AuthOutcome.Failed(errString.toString()))
                    }
                }
            }
        )

        val info = BiometricPrompt.PromptInfo.Builder()
            .setTitle(title)
            .setSubtitle(subtitle)
            .setAllowedAuthenticators(allowedAuthenticators())
            .build()

        prompt.authenticate(info)
    }
}

