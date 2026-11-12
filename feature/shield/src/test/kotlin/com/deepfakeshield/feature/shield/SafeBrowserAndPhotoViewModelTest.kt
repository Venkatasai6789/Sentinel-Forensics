package com.deepfakeshield.feature.shield

import android.content.Context
import android.net.Uri
import androidx.test.core.app.ApplicationProvider
import com.deepfakeshield.core.engine.PageContentAnalyzer
import com.deepfakeshield.core.engine.UrlSafetyEngine
import com.deepfakeshield.core.intelligence.URLIntelligenceEngine
import com.deepfakeshield.core.model.AnalysisStatus
import com.deepfakeshield.core.model.SecurityModule
import com.deepfakeshield.core.model.SecurityVerdict
import com.deepfakeshield.data.preferences.UserPreferences
import com.deepfakeshield.data.repository.AlertRepository
import com.deepfakeshield.data.repository.ScanHistoryRepository
import com.deepfakeshield.intelligence.UnifiedUrlInspectionEngine
import com.deepfakeshield.intelligence.UnifiedUrlThreatCache
import com.deepfakeshield.intelligence.feed.OpenPhishFeed
import com.deepfakeshield.intelligence.feed.PhishTankFeed
import com.deepfakeshield.intelligence.feed.UrlHausFeed
import com.deepfakeshield.ml.engine.ImageForensicsEngine
import io.mockk.coVerify
import io.mockk.every
import io.mockk.mockk
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.flow.flowOf
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.test.setMain
import org.junit.After
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.io.File

@OptIn(ExperimentalCoroutinesApi::class)
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [28])
class SafeBrowserAndPhotoViewModelTest {

    private val testDispatcher = StandardTestDispatcher()
    private lateinit var context: Context

    @Before
    fun setup() {
        Dispatchers.setMain(testDispatcher)
        context = ApplicationProvider.getApplicationContext()
    }

    @After
    fun teardown() {
        Dispatchers.resetMain()
    }

    @Test
    fun `SafeBrowserViewModel inspects dangerous URIs and persists real result`() = runTest(testDispatcher) {
        val threatCache = UnifiedUrlThreatCache(PhishTankFeed(), OpenPhishFeed(), UrlHausFeed())
        val inspectionEngine = UnifiedUrlInspectionEngine(UrlSafetyEngine(), URLIntelligenceEngine(), threatCache)
        val scanHistoryRepo = mockk<ScanHistoryRepository>(relaxed = true)
        every { scanHistoryRepo.observeHistory(any(), any()) } returns flowOf(emptyList())
        val prefs = mockk<UserPreferences>(relaxed = true)

        val vm = SafeBrowserViewModel(
            urlInspectionEngine = inspectionEngine,
            urlSafetyEngine = UrlSafetyEngine(),
            urlThreatCache = threatCache,
            pageContentAnalyzer = PageContentAnalyzer(),
            scanHistoryRepository = scanHistoryRepo,
            userPreferences = prefs
        )

        vm.inspectUrl("javascript:alert('xss')", allowNetworkProbe = false)
        val deadline1 = System.currentTimeMillis() + 5_000L
        while (vm.uiState.value.inspectionReport == null && System.currentTimeMillis() < deadline1) {
            advanceUntilIdle()
            if (vm.uiState.value.inspectionReport != null) break
            Thread.sleep(20)
        }
        advanceUntilIdle()

        val report = vm.uiState.value.inspectionReport
        assertNotNull(report)
        assertEquals(SecurityVerdict.MALICIOUS, report!!.analysisResult.verdict)
        assertNull(report.analysisResult.confidence)
        coVerify { scanHistoryRepo.saveResult(match { it.module == SecurityModule.PHISHING_URL_SCAN && it.verdict == SecurityVerdict.MALICIOUS }) }
    }

    @Test
    fun `PhotoForensicsViewModel reports FAILED on corrupt file never SAFE`() = runTest(testDispatcher) {
        val scanHistoryRepo = mockk<ScanHistoryRepository>(relaxed = true)
        every { scanHistoryRepo.observeHistory(any(), any()) } returns flowOf(emptyList())
        val alertRepo = mockk<AlertRepository>(relaxed = true)

        val corruptFile = File(context.cacheDir, "bad_img_${System.nanoTime()}.jpg").apply {
            writeText("not-an-image")
        }
        try {
            val vm = PhotoForensicsViewModel(
                imageForensicsEngine = ImageForensicsEngine(),
                scanHistoryRepository = scanHistoryRepo,
                alertRepository = alertRepo,
                context = context
            )
            vm.analyzeImage(Uri.fromFile(corruptFile))
            val deadline2 = System.currentTimeMillis() + 5_000L
            while (vm.uiState.value.analysisResult == null && System.currentTimeMillis() < deadline2) {
                advanceUntilIdle()
                if (vm.uiState.value.analysisResult != null) break
                Thread.sleep(20)
            }
            advanceUntilIdle()

            val res = vm.uiState.value.analysisResult
            assertNotNull(res)
            assertEquals(AnalysisStatus.FAILED, res!!.status)
            assertNotEquals(SecurityVerdict.SAFE, res.verdict)
            assertNull(vm.uiState.value.elaBitmap)
        } finally {
            corruptFile.delete()
        }
    }
}
