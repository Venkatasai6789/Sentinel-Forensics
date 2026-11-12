package com.deepfakeshield.intelligence

import com.deepfakeshield.core.engine.UrlSafetyEngine
import com.deepfakeshield.core.intelligence.URLIntelligenceEngine
import com.deepfakeshield.core.model.AnalysisStatus
import com.deepfakeshield.core.model.SecurityVerdict
import com.deepfakeshield.intelligence.feed.OpenPhishFeed
import com.deepfakeshield.intelligence.feed.PhishTankFeed
import com.deepfakeshield.intelligence.feed.UrlHausFeed
import kotlinx.coroutines.test.runTest
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.io.BufferedReader
import java.io.InputStreamReader
import java.net.InetAddress
import java.net.ServerSocket
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.concurrent.thread

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [28])
class UnifiedUrlInspectionEngineTest {

    private lateinit var threatCache: UnifiedUrlThreatCache
    private lateinit var engine: UnifiedUrlInspectionEngine

    @Before
    fun setup() {
        threatCache = UnifiedUrlThreatCache(PhishTankFeed(), OpenPhishFeed(), UrlHausFeed())
        engine = UnifiedUrlInspectionEngine(
            urlSafetyEngine = UrlSafetyEngine(),
            urlIntelligenceEngine = URLIntelligenceEngine(),
            threatCache = threatCache
        )
    }

    @Test
    fun `blocks javascript and file schemes immediately as malicious`() = runTest {
        val jsReport = engine.inspectUrl("javascript:alert(1)", allowNetworkProbe = false)
        assertEquals(AnalysisStatus.COMPLETED, jsReport.analysisResult.status)
        assertEquals(SecurityVerdict.MALICIOUS, jsReport.analysisResult.verdict)
        assertNull("Rule-based scheme check has no ML confidence", jsReport.analysisResult.confidence)

        val fileReport = engine.inspectUrl("file:///data/data/com.deepfakeshield/db", allowNetworkProbe = false)
        assertEquals(SecurityVerdict.MALICIOUS, fileReport.analysisResult.verdict)
    }

    @Test
    fun `detects punycode homograph and userinfo credential masking`() = runTest {
        val report = engine.inspectUrl("https://trusted-bank.com@xn--pypal-4ve.tk/login.apk", allowNetworkProbe = false)
        assertTrue(report.analysisResult.verdict == SecurityVerdict.HIGH_RISK || report.analysisResult.verdict == SecurityVerdict.MALICIOUS)
        assertNotNull(report.punycodeDecoded)
        assertTrue(report.analysisResult.findings.any { it.title.contains("Embedded credentials") })
        assertTrue(report.analysisResult.findings.any { it.title.contains("Punycode", ignoreCase = true) })
        assertTrue(report.analysisResult.findings.any { it.title.contains("Executable", ignoreCase = true) })
    }

    @Test
    fun `follows real local HTTP redirect chain to malicious target and never hardcodes`() = runTest {
        val serverSocket = ServerSocket(0, 10, InetAddress.getByName("127.0.0.1"))
        val port = serverSocket.localPort
        val running = AtomicBoolean(true)
        val worker = thread(isDaemon = true) {
            while (running.get()) {
                try {
                    val client = serverSocket.accept()
                    client.use { sock ->
                        val reader = BufferedReader(InputStreamReader(sock.getInputStream()))
                        var line: String?
                        do {
                            line = reader.readLine()
                        } while (!line.isNullOrEmpty())
                        val response = "HTTP/1.1 302 Found\r\nLocation: http://paypal-verify.tk/login\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                        sock.getOutputStream().write(response.toByteArray())
                        sock.getOutputStream().flush()
                    }
                } catch (_: Exception) {
                }
            }
        }
        try {
            val redirected = engine.inspectUrl("http://127.0.0.1:$port/short", allowNetworkProbe = true)
            assertTrue(redirected.redirectInspection.attempted)
            assertTrue(redirected.redirectInspection.crossDomainRedirect)
            assertEquals("http://paypal-verify.tk/login", redirected.redirectInspection.finalUrl)
            assertTrue(redirected.analysisResult.findings.any { it.title.contains("redirect", ignoreCase = true) })
            assertTrue(
                redirected.analysisResult.verdict == SecurityVerdict.HIGH_RISK ||
                    redirected.analysisResult.verdict == SecurityVerdict.MALICIOUS ||
                    redirected.analysisResult.verdict == SecurityVerdict.SUSPICIOUS
            )
        } finally {
            running.set(false)
            runCatching { serverSocket.close() }
            worker.join(500)
        }
    }

    @Test
    fun `failed live network probe reports PARTIAL and INCONCLUSIVE instead of SAFE`() = runTest {
        val closedSocket = ServerSocket(0, 10, InetAddress.getByName("127.0.0.1"))
        val closedPort = closedSocket.localPort
        closedSocket.close()

        val report = engine.inspectUrl("https://127.0.0.1:$closedPort/login-check", allowNetworkProbe = true)
        assertEquals(AnalysisStatus.PARTIAL, report.analysisResult.status)
        assertNotEquals("Failed live probe must NEVER report SAFE", SecurityVerdict.SAFE, report.analysisResult.verdict)
    }

    @Test
    fun `malformed or blank URL fails cleanly without SAFE fallback`() = runTest {
        val blank = engine.inspectUrl("   ", allowNetworkProbe = false)
        assertEquals(AnalysisStatus.FAILED, blank.analysisResult.status)
        assertEquals(SecurityVerdict.NOT_ANALYZED, blank.analysisResult.verdict)

        val malformed = engine.inspectUrl("://missing-host", allowNetworkProbe = false)
        assertEquals(AnalysisStatus.FAILED, malformed.analysisResult.status)
        assertEquals(SecurityVerdict.INCONCLUSIVE, malformed.analysisResult.verdict)
    }
}
