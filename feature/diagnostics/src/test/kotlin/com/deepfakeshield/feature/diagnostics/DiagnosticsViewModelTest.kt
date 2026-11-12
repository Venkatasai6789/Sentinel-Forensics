package com.deepfakeshield.feature.diagnostics

import android.content.Context
import android.net.Uri
import androidx.test.core.app.ApplicationProvider
import com.deepfakeshield.av.engine.*
import com.deepfakeshield.core.model.SecurityModule
import com.deepfakeshield.core.model.SecurityVerdict
import com.deepfakeshield.data.preferences.UserPreferences
import com.deepfakeshield.data.repository.AlertRepository
import com.deepfakeshield.data.repository.ScanHistoryRepository
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
class DiagnosticsViewModelTest {

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
    fun `scanSingleUri detects malware payload and persists AV scan result`() = runTest(testDispatcher) {
        val signatureDb = MalwareSignatureDatabase(context)
        val heuristic = HeuristicMalwareAnalyzer(context)
        val yara = YaraRuleEngine()
        val avEngine = AntivirusEngine(context, signatureDb, heuristic, CloudHashChecker(), yara)
        val rootDetector = RootDetector()
        val updater = ThreatDatabaseUpdater(context, signatureDb)
        val qm = QuarantineManager(context, mockk(relaxed = true))
        val prefs = mockk<UserPreferences>(relaxed = true)
        val alertRepo = mockk<AlertRepository>(relaxed = true)
        val historyRepo = mockk<ScanHistoryRepository>(relaxed = true)
        every { historyRepo.observeHistory(any(), any()) } returns flowOf(emptyList())

        val vm = DiagnosticsViewModel(
            userPreferences = prefs,
            alertRepository = alertRepo,
            scanHistoryRepository = historyRepo,
            antivirusEngine = avEngine,
            rootDetector = rootDetector,
            signatureDb = signatureDb,
            threatDbUpdater = updater,
            quarantineManager = qm,
            context = context
        )
        advanceUntilIdle()

        val payloadFile = File(context.cacheDir, "diag_payload_${System.nanoTime()}.txt").apply {
            writeText("SMS_RECEIVED abortBroadcast getMessageBody")
        }
        try {
            vm.scanSingleUri(Uri.fromFile(payloadFile))
            val deadline = System.currentTimeMillis() + 5_000L
            while (vm.uiState.value.isRunningAvScan || vm.uiState.value.latestAnalysisResult == null) {
                advanceUntilIdle()
                if (!vm.uiState.value.isRunningAvScan && vm.uiState.value.latestAnalysisResult != null) break
                if (System.currentTimeMillis() >= deadline) break
                Thread.sleep(25)
            }
            advanceUntilIdle()

            val state = vm.uiState.value
            assertFalse(state.isRunningAvScan)
            assertEquals(1, state.avThreatsFound)
            assertNotNull(state.latestAnalysisResult)
            assertEquals(SecurityVerdict.MALICIOUS, state.latestAnalysisResult!!.verdict)
            assertTrue((state.scanScopeSummary?.scannedCount ?: 0) >= 1)
            coVerify { historyRepo.saveResult(match { it.module == SecurityModule.DEVICE_ANTIVIRUS && it.verdict == SecurityVerdict.MALICIOUS }) }
        } finally {
            payloadFile.delete()
        }
    }
}

