package com.deepfakeshield.feature.shield

import com.deepfakeshield.core.engine.RiskIntelligenceEngine
import com.deepfakeshield.core.engine.UrlSafetyEngine
import com.deepfakeshield.core.intelligence.MultiLingualThreatDetector
import com.deepfakeshield.core.intelligence.URLIntelligenceEngine
import com.deepfakeshield.core.model.AnalysisStatus
import com.deepfakeshield.core.model.SecurityVerdict
import com.deepfakeshield.core.model.ThreatSource
import com.deepfakeshield.data.dao.ScamPatternDao
import com.deepfakeshield.intelligence.UnifiedUrlInspectionEngine
import com.deepfakeshield.intelligence.UnifiedUrlThreatCache
import com.deepfakeshield.intelligence.feed.OpenPhishFeed
import com.deepfakeshield.intelligence.feed.PhishTankFeed
import com.deepfakeshield.intelligence.feed.UrlHausFeed
import com.deepfakeshield.ml.text.GovernmentGradeTextDetector
import io.mockk.coEvery
import io.mockk.every
import io.mockk.mockk
import kotlinx.coroutines.test.runTest
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [28])
class MessageShieldAnalyzerTest {

    private lateinit var scamPatternDao: ScamPatternDao
    private lateinit var textDetector: GovernmentGradeTextDetector
    private lateinit var analyzer: MessageShieldAnalyzer

    @Before
    fun setup() {
        scamPatternDao = mockk(relaxed = true)
        coEvery { scamPatternDao.getPatternsByType(any()) } returns emptyList()
        textDetector = mockk(relaxed = true)
        coEvery { textDetector.analyzeText(any(), any(), any()) } returns mockk(relaxed = true) {
            every { mlModelsActive } returns false
        }

        val threatCache = UnifiedUrlThreatCache(PhishTankFeed(), OpenPhishFeed(), UrlHausFeed())
        val urlEngine = UnifiedUrlInspectionEngine(UrlSafetyEngine(), URLIntelligenceEngine(), threatCache)
        analyzer = MessageShieldAnalyzer(
            riskEngine = RiskIntelligenceEngine(),
            multiLingualDetector = MultiLingualThreatDetector(),
            scamPatternDao = scamPatternDao,
            textDetector = textDetector,
            urlInspectionEngine = urlEngine
        )
    }

    @Test
    fun `blank message fails cleanly and never returns SAFE`() = runTest {
        val bundle = analyzer.analyzeMessage("   ", ThreatSource.MANUAL_SCAN)
        assertEquals(AnalysisStatus.FAILED, bundle.analysisResult.status)
        assertNotEquals(SecurityVerdict.SAFE, bundle.analysisResult.verdict)
        assertNull(bundle.analysisResult.confidence)
    }

    @Test
    fun `single short word without threat triggers returns INCONCLUSIVE`() = runTest {
        val bundle = analyzer.analyzeMessage("ok", ThreatSource.SMS)
        assertEquals(AnalysisStatus.COMPLETED, bundle.analysisResult.status)
        assertEquals(SecurityVerdict.INCONCLUSIVE, bundle.analysisResult.verdict)
        assertNull(bundle.analysisResult.riskScore)
        assertNull(bundle.analysisResult.confidence)
        assertEquals("INSUFFICIENT_CONTEXT", bundle.scamCategory)
    }

    @Test
    fun `scam lure with lookalike URL returns high risk and extracts entity offsets`() = runTest {
        val text = "URGENT from Bank: Share your OTP now and verify at https://paypal-login.tk/verify or call +18005550199"
        val bundle = analyzer.analyzeMessage(text, ThreatSource.SMS, senderInfo = "+9991234", allowNetworkUrlProbe = false)

        assertEquals(AnalysisStatus.COMPLETED, bundle.analysisResult.status)
        assertTrue(
            bundle.analysisResult.verdict == SecurityVerdict.HIGH_RISK ||
                bundle.analysisResult.verdict == SecurityVerdict.MALICIOUS
        )
        assertTrue((bundle.analysisResult.riskScore ?: 0) >= 55)
        assertNull("Rule-only analysis must keep confidence null", bundle.analysisResult.confidence)
        assertTrue(bundle.extractedUrls.any { it.normalizedUrl.contains("paypal-login.tk") })
        assertTrue(bundle.extractedEntities.any { it.kind == "URL" && text.substring(it.startOffset, it.endOffset).contains("paypal-login.tk") })
        assertTrue(bundle.extractedEntities.any { it.kind == "PHONE" })
    }

    @Test
    fun `benign casual message returns SAFE with low score and no fabricated confidence`() = runTest {
        val bundle = analyzer.analyzeMessage("Hey, want to grab lunch at noon tomorrow near the park?", ThreatSource.MANUAL_SCAN)
        assertEquals(AnalysisStatus.COMPLETED, bundle.analysisResult.status)
        assertEquals(SecurityVerdict.SAFE, bundle.analysisResult.verdict)
        assertTrue((bundle.analysisResult.riskScore ?: 100) < 25)
        assertNull(bundle.analysisResult.confidence)
    }
}
