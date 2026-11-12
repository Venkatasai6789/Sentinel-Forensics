package com.deepfakeshield.core.security

import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [28])
class PasswordAuditorAndCryptoTest {

    @Test
    fun `auditor rates common and short passwords as very weak`() {
        val common = PasswordAuditor.audit("password123")
        assertEquals(PasswordStrengthTier.VERY_WEAK, common.tier)
        assertTrue(common.score <= 20)
        assertTrue(common.warnings.any { it.contains("common", ignoreCase = true) })

        val shortWalk = PasswordAuditor.audit("qwerty2024")
        assertTrue(shortWalk.tier == PasswordStrengthTier.VERY_WEAK || shortWalk.tier == PasswordStrengthTier.WEAK)
        assertTrue(shortWalk.warnings.any { it.contains("keyboard", ignoreCase = true) })
        assertTrue(shortWalk.warnings.any { it.contains("year", ignoreCase = true) })
    }

    @Test
    fun `auditor rates long high-entropy password as strong or very strong`() {
        val report = PasswordAuditor.audit("K9!vX#4mQ2zP@8nL7wR$5cT")
        assertEquals(PasswordStrengthTier.VERY_STRONG, report.tier)
        assertTrue(report.score >= 85)
        assertTrue(report.shannonEntropyBits > 70.0)
        assertTrue(report.poolEntropyBits > 120.0)
        assertTrue(report.warnings.isEmpty())
    }

    @Test
    fun `generator produces non-deterministic random strings and multi-word diceware passphrases`() {
        val cfg = PasswordGenerationConfig(
            mode = GenerationMode.RANDOM_CHARACTERS,
            length = 20,
            includeUppercase = true,
            includeLowercase = true,
            includeDigits = true,
            includeSymbols = true,
            excludeAmbiguous = true
        )
        val p1 = PasswordAuditor.generate(cfg)
        val p2 = PasswordAuditor.generate(cfg)
        assertEquals(20, p1.length)
        assertNotEquals(p1, p2)
        assertTrue(p1.any { it.isUpperCase() })
        assertTrue(p1.any { it.isLowerCase() })
        assertTrue(p1.any { it.isDigit() })
        assertTrue(p1.any { !it.isLetterOrDigit() })
        assertFalse(p1.any { it in setOf('0', 'O', 'o', '1', 'l', 'I') })

        val diceCfg = PasswordGenerationConfig(
            mode = GenerationMode.DICEWARE_PASSPHRASE,
            wordCount = 5,
            wordSeparator = "-"
        )
        val phrase = PasswordAuditor.generate(diceCfg)
        val words = phrase.split("-")
        assertEquals(5, words.size)
        assertTrue(words.all { it.isNotBlank() })
    }

    @Test
    fun `SoftwareAesGcmVaultCipher encrypts with fresh IVs, decrypts accurately, and detects reuse`() {
        val cipher = SoftwareAesGcmVaultCipher()
        val secret = "Tr0ub4dor&3_SensitivePassword!"

        val enc1 = cipher.encryptString(secret)
        val enc2 = cipher.encryptString(secret)

        assertNotEquals("Fresh random IVs must produce distinct ciphertexts", enc1.ivBase64, enc2.ivBase64)
        assertNotEquals(enc1.cipherTextBase64, enc2.cipherTextBase64)
        assertFalse(enc1.cipherTextBase64.contains(secret))

        assertEquals(secret, cipher.decryptString(enc1.cipherTextBase64, enc1.ivBase64))
        assertEquals(secret, cipher.decryptString(enc2.cipherTextBase64, enc2.ivBase64))

        assertEquals(cipher.computeReuseDigest(secret), cipher.computeReuseDigest(secret))
        assertNotEquals(cipher.computeReuseDigest(secret), cipher.computeReuseDigest("DifferentPass123!"))

        var tamperedThrew = false
        try {
            cipher.decryptString(enc1.cipherTextBase64, enc2.ivBase64)
        } catch (_: Exception) {
            tamperedThrew = true
        }
        assertTrue("GCM authentication tag must reject mismatched IV", tamperedThrew)
    }
}

