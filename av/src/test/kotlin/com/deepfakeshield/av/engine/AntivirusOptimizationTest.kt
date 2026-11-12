package com.deepfakeshield.av.engine

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.io.ByteArrayInputStream
import java.io.File
import java.io.FileOutputStream
import java.security.MessageDigest
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [28])
class AntivirusOptimizationTest {

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
        engine.clearScanCache()
    }

    @Test
    fun `byte pattern matcher detects hex and case-insensitive ascii across chunk boundaries`() {
        val hexMatcher = BytePatternMatcher.Builder<String>(ignoreAsciiCase = false)
            .addHex("4a696167752e", "JiaguPacker")
            .build()

        val payload = ByteArray(70_000) { 0x41 }
        // Place "Jiagu." directly straddling the 64 KB (65536) chunk boundary
        val marker = byteArrayOf(0x4a, 0x69, 0x61, 0x67, 0x75, 0x2e)
        System.arraycopy(marker, 0, payload, 65_534, marker.size)

        val streamMatches = hexMatcher.scanStream(ByteArrayInputStream(payload))
        assertEquals(listOf("JiaguPacker"), streamMatches)

        val asciiMatcher = BytePatternMatcher.Builder<String>(ignoreAsciiCase = true)
            .addAscii("Your Files Have Been Encrypted", "RansomBanner")
            .build()
        val mixedCase = "header YOUR files HAVE been encrypted trailer".toByteArray()
        assertEquals(listOf("RansomBanner"), asciiMatcher.scanBytes(mixedCase))
        assertTrue(asciiMatcher.scanBytes("completely harmless document text".toByteArray()).isEmpty())
    }

    @Test
    fun `yara engine matches hex packer and prerequisite-gated eth clipboard regex cleanly`() {
        // Hex rule packed_apk (0x4a696167752e = "Jiagu.")
        val packedPayload = "prefix_4a696167752e_stub_Jiagu.dex_end".toByteArray()
        val hexMatches = yaraEngine.scanBytes(packedPayload)
        assertTrue(hexMatches.any { it.rule.name == "packed_apk" })

        // Negative: only regex ETH address without ClipboardManager & setPrimaryClip
        val cleanWallet = "Send test faucet coins to 0x1234567890abcdef1234567890abcdef12345678".toByteArray()
        assertFalse(yaraEngine.scanBytes(cleanWallet).any { it.rule.name == "clipboard_hijack_eth" })

        // Positive: ClipboardManager + setPrimaryClip + 40-hex ETH address
        val hijackCode = "val cm = ClipboardManager(); cm.setPrimaryClip(\"0x1234567890abcdef1234567890abcdef12345678\")".toByteArray()
        val regexMatches = yaraEngine.scanBytes(hijackCode)
        assertTrue(regexMatches.any { it.rule.name == "clipboard_hijack_eth" })
    }

    @Test
    fun `yara streaming file scan matches ransom strings past 64KB offset`() {
        val file = File(context.cacheDir, "chunk_yara_${System.nanoTime()}.bin")
        try {
            val content = ByteArray(128 * 1024) { ' '.code.toByte() }
            val note = "your files have been encrypted pay bitcoin to decrypt".toByteArray()
            System.arraycopy(note, 0, content, 65_530, note.size)
            file.writeBytes(content)

            val matches = yaraEngine.scanFile(file)
            assertTrue("Expected ransomware_note match across 64KB chunk boundary", matches.any { it.rule.name == "ransomware_note" })
        } finally {
            file.delete()
        }
    }

    @Test
    fun `zipfile archive inspection detects nested apk dropper and passes clean archive`() = runTest {
        val cleanZip = File(context.cacheDir, "clean_bundle_${System.nanoTime()}.zip")
        val dropperZip = File(context.cacheDir, "dropper_bundle_${System.nanoTime()}.zip")
        val zipSlipZip = File(context.cacheDir, "slip_bundle_${System.nanoTime()}.zip")
        try {
            ZipOutputStream(FileOutputStream(cleanZip)).use { zos ->
                zos.putNextEntry(ZipEntry("readme.txt"))
                zos.write("Harmless archive entry".toByteArray())
                zos.closeEntry()
                zos.putNextEntry(ZipEntry("org/joda/time/tz/data/etc/gmt"))
                zos.write("tzdata".toByteArray())
                zos.closeEntry()
            }
            ZipOutputStream(FileOutputStream(dropperZip)).use { zos ->
                zos.putNextEntry(ZipEntry("assets/hidden_payload.apk"))
                zos.write("nested-apk-stub".toByteArray())
                zos.closeEntry()
            }
            ZipOutputStream(FileOutputStream(zipSlipZip)).use { zos ->
                zos.putNextEntry(ZipEntry("../../etc/passwd"))
                zos.write("slip".toByteArray())
                zos.closeEntry()
            }

            val cleanResult = engine.scanFile(cleanZip.absolutePath, null, AntivirusEngine.SCAN_TYPE_ONDEMAND)
            assertEquals(ThreatLevel.CLEAN, cleanResult.threatLevel)

            val dropperResult = engine.scanFile(dropperZip.absolutePath, null, AntivirusEngine.SCAN_TYPE_ONDEMAND)
            assertEquals(ThreatLevel.INFECTED, dropperResult.threatLevel)
            assertTrue(dropperResult.indicators.any { it.title == "Nested APK" })

            val slipResult = engine.scanFile(zipSlipZip.absolutePath, null, AntivirusEngine.SCAN_TYPE_ONDEMAND)
            assertEquals(ThreatLevel.SUSPICIOUS, slipResult.threatLevel)
            assertTrue(slipResult.indicators.any { it.title == "Suspicious Archive Path" })
        } finally {
            cleanZip.delete()
            dropperZip.delete()
            zipSlipZip.delete()
        }
    }

    @Test
    fun `single pass scanFile detects dynamically loaded sha256 signature and reports accurate hash`() = runTest {
        val sampleFile = File(context.cacheDir, "hash_test_${System.nanoTime()}.dat")
        try {
            val bytes = "benign-looking bytes paired with known bad sha256 hash".toByteArray()
            sampleFile.writeBytes(bytes)
            val expectedHash = MessageDigest.getInstance("SHA-256").digest(bytes)
                .joinToString("") { "%02x".format(it) }

            // Clean before hash addition
            val before = engine.scanFile(sampleFile.absolutePath, null, AntivirusEngine.SCAN_TYPE_FILE)
            assertEquals(expectedHash, before.fileHash)
            assertEquals(ThreatLevel.CLEAN, before.threatLevel)

            // Inject hash into DB and rescan -> explicit single-file scan never serves stale cache
            signatureDb.loadFromContent(expectedHash)
            val after = engine.scanFile(sampleFile.absolutePath, null, AntivirusEngine.SCAN_TYPE_FILE)
            assertEquals(ThreatLevel.INFECTED, after.threatLevel)
            assertTrue(after.indicators.any { it.type == AvIndicatorType.SIGNATURE && it.evidence == expectedHash })
        } finally {
            sampleFile.delete()
        }
    }

    @Test
    fun `runFullScan executes asynchronously and reports monotonic progress completion`() = runTest {
        val progressEvents = mutableListOf<Pair<Int, Int>>()
        val results = engine.runFullScan(AntivirusEngine.SCAN_TYPE_ONDEMAND) { scanned, total, _ ->
            progressEvents.add(scanned to total)
        }
        assertTrue(progressEvents.isNotEmpty())
        val (lastScanned, lastTotal) = progressEvents.last()
        assertEquals(results.size, lastScanned)
        assertEquals(results.size, lastTotal)
    }
}

