package com.deepfakeshield.feature.home

import com.deepfakeshield.core.model.RiskSeverity
import com.deepfakeshield.core.model.ThreatSource
import com.deepfakeshield.core.model.ThreatType
import com.deepfakeshield.data.entity.AlertEntity
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Test
import java.time.LocalDate

class DashboardStateTest {

    private fun createSampleAlert(
        id: Long = 1L,
        title: String = "Suspicious Link",
        severity: RiskSeverity = RiskSeverity.HIGH,
        source: ThreatSource = ThreatSource.SMS,
        threatType: ThreatType = ThreatType.PHISHING_ATTEMPT,
        timestamp: Long = System.currentTimeMillis(),
        isHandled: Boolean = false
    ): AlertEntity {
        return AlertEntity(
            id = id,
            threatType = threatType,
            source = source,
            severity = severity,
            score = 80,
            confidence = 0.9f,
            title = title,
            summary = "Phishing detected in SMS",
            content = "http://malicious-link.test",
            senderInfo = "+1234567890",
            timestamp = timestamp,
            isHandled = isHandled
        )
    }

    @Test
    fun testProtectionStatus_Active_WhenAllModulesEnabledAndNoAlerts() {
        val shields = ShieldStates(
            master = true,
            video = true,
            message = true,
            call = true,
            overlay = false
        )
        val stats = ScanStats(
            lastScanTime = System.currentTimeMillis() - 3600000,
            videoScans = 5,
            messageScans = 10,
            streak = 3
        )

        val state = HomeViewModel.buildDashboardUiState(
            shields = shields,
            stats = stats,
            unhandledAlerts = emptyList(),
            allAlerts = emptyList()
        )

        assertEquals(ProtectionStatus.ACTIVE, state.protectionState.status)
        assertEquals(3, state.protectionState.activeModules)
        assertEquals(3, state.protectionState.totalModules)
        assertEquals(100, state.metrics?.protectionScore)
        assertEquals(0, state.metrics?.issueCount)
        assertEquals(0, state.metrics?.unreadAlertCount)
        assertNull(state.alertSummary)
    }

    @Test
    fun testProtectionStatus_Partial_WhenOnlySomeModulesEnabled() {
        val shields = ShieldStates(
            master = true,
            video = true,
            message = false,
            call = true,
            overlay = false
        )
        val stats = ScanStats(lastScanTime = 0L, videoScans = 0, messageScans = 0, streak = 0)

        val state = HomeViewModel.buildDashboardUiState(
            shields = shields,
            stats = stats,
            unhandledAlerts = emptyList(),
            allAlerts = emptyList()
        )

        assertEquals(ProtectionStatus.PARTIAL, state.protectionState.status)
        assertEquals(2, state.protectionState.activeModules)
        // 1 module disabled -> 100 - 20 = 80
        assertEquals(80, state.metrics?.protectionScore)
    }

    @Test
    fun testProtectionStatus_Inactive_WhenMasterDisabled() {
        val shields = ShieldStates(
            master = false,
            video = true,
            message = true,
            call = true,
            overlay = true
        )
        val stats = ScanStats(lastScanTime = 0L, videoScans = 0, messageScans = 0, streak = 0)

        val state = HomeViewModel.buildDashboardUiState(
            shields = shields,
            stats = stats,
            unhandledAlerts = emptyList(),
            allAlerts = emptyList()
        )

        assertEquals(ProtectionStatus.INACTIVE, state.protectionState.status)
        assertEquals(0, state.metrics?.protectionScore)
    }

    @Test
    fun testProtectionStatus_AttentionRequired_WhenCriticalOrHighAlertsExist() {
        val shields = ShieldStates(
            master = true,
            video = true,
            message = true,
            call = true,
            overlay = false
        )
        val stats = ScanStats(lastScanTime = 0L, videoScans = 0, messageScans = 0, streak = 0)
        val unhandled = listOf(
            createSampleAlert(id = 1L, severity = RiskSeverity.HIGH, source = ThreatSource.SMS),
            createSampleAlert(id = 2L, severity = RiskSeverity.MEDIUM, source = ThreatSource.INCOMING_CALL)
        )

        val state = HomeViewModel.buildDashboardUiState(
            shields = shields,
            stats = stats,
            unhandledAlerts = unhandled,
            allAlerts = unhandled
        )

        assertEquals(ProtectionStatus.ATTENTION_REQUIRED, state.protectionState.status)
        assertEquals(2, state.metrics?.issueCount)
        assertEquals(2, state.metrics?.unreadAlertCount)
        // 100 - (15 for High) - (5 for Medium) = 80
        assertEquals(80, state.metrics?.protectionScore)
        assertNotNull(state.alertSummary)
        assertEquals(2, state.alertSummary?.unresolvedCount)
        assertEquals("2 items need your attention", state.alertSummary?.title)
        assertEquals("Review suspicious messages and a blocked call", state.alertSummary?.description)
    }

    @Test
    fun testAlertSummary_SingleAlert_PluralizationAndDescription() {
        val shields = ShieldStates(true, true, true, true, false)
        val stats = ScanStats(0L, 0, 0, 0)
        val unhandled = listOf(
            createSampleAlert(
                id = 99L,
                title = "Robocall Blocked",
                severity = RiskSeverity.HIGH,
                source = ThreatSource.INCOMING_CALL,
                threatType = ThreatType.SUSPICIOUS_CALL
            )
        )

        val state = HomeViewModel.buildDashboardUiState(shields, stats, unhandled, unhandled)

        assertNotNull(state.alertSummary)
        assertEquals(1, state.alertSummary?.unresolvedCount)
        assertEquals("1 item needs your attention", state.alertSummary?.title)
        assertEquals("Review blocked call and caller reputation", state.alertSummary?.description)
    }

    @Test
    fun testDailyActivity_CalculatesSevenDaysAccurately() {
        val now = System.currentTimeMillis()
        val alerts = listOf(
            createSampleAlert(id = 1L, timestamp = now, severity = RiskSeverity.HIGH),
            createSampleAlert(id = 2L, timestamp = now, severity = RiskSeverity.MEDIUM),
            createSampleAlert(id = 3L, timestamp = now - 86400000L, severity = RiskSeverity.LOW)
        )

        val activities = HomeViewModel.calculateDailyActivity(alerts, todayScans = 5)

        assertEquals(7, activities.size)
        val todayActivity = activities.last()
        assertEquals(LocalDate.now(), todayActivity.date)
        assertEquals(5, todayActivity.completedScans)
        assertEquals(2, todayActivity.detectedIssues) // HIGH and MEDIUM (excluding LOW)
    }

    @Test
    fun testFormatRelativeTime_Calculations() {
        val now = 1000000000L
        assertEquals("Never", formatRelativeTime(0L, now))
        assertEquals("Just now", formatRelativeTime(now - 30 * 1000L, now))
        assertEquals("15m ago", formatRelativeTime(now - 15 * 60 * 1000L, now))
        assertEquals("3h ago", formatRelativeTime(now - 3 * 3600 * 1000L, now))
        assertEquals("Yesterday", formatRelativeTime(now - 25 * 3600 * 1000L, now))
        assertEquals("4d ago", formatRelativeTime(now - 4 * 86400 * 1000L, now))
    }

    @Test
    fun `dashboard incorporates live persisted scanHistory and vaultHealth without hardcoded metrics`() {
        val now = System.currentTimeMillis()
        val scanHistory = listOf(
            com.deepfakeshield.core.model.SecurityAnalysisResult(
                analysisId = "s1",
                module = com.deepfakeshield.core.model.SecurityModule.MESSAGE_SHIELD,
                inputName = "SMS OTP lure",
                inputType = "text/plain",
                status = com.deepfakeshield.core.model.AnalysisStatus.COMPLETED,
                verdict = com.deepfakeshield.core.model.SecurityVerdict.HIGH_RISK,
                riskScore = 82,
                confidence = null,
                findings = emptyList(),
                analysisMethods = listOf("Rules"),
                limitations = emptyList(),
                processingDurationMs = 15L,
                analyzedAt = now - 120_000L,
                modelVersion = null,
                errorMessage = null
            ),
            com.deepfakeshield.core.model.SecurityAnalysisResult(
                analysisId = "s2",
                module = com.deepfakeshield.core.model.SecurityModule.PHOTO_FORENSICS,
                inputName = "photo.jpg",
                inputType = "image/jpeg",
                status = com.deepfakeshield.core.model.AnalysisStatus.COMPLETED,
                verdict = com.deepfakeshield.core.model.SecurityVerdict.INCONCLUSIVE,
                riskScore = 10,
                confidence = null,
                findings = emptyList(),
                analysisMethods = listOf("ELA"),
                limitations = emptyList(),
                processingDurationMs = 50L,
                analyzedAt = now - 60_000L,
                modelVersion = null,
                errorMessage = null
            )
        )
        val vaultHealth = com.deepfakeshield.data.repository.VaultHealthSummary(
            totalCredentials = 4,
            weakCount = 1,
            reusedCount = 2,
            breachedCount = 1,
            strongCount = 1
        )
        val shields = ShieldStates(master = true, video = true, message = true, call = true, overlay = false)
        val stats = ScanStats(lastScanTime = now - 60_000L, videoScans = 1, messageScans = 1, streak = 1)

        val state = HomeViewModel.buildDashboardUiState(
            shields = shields,
            stats = stats,
            unhandledAlerts = emptyList(),
            allAlerts = emptyList(),
            scanHistory = scanHistory,
            vaultHealth = vaultHealth
        )

        assertEquals(2, state.totalPersistedScans)
        assertEquals(vaultHealth, state.vaultHealth)
        assertEquals(2, state.recentScans.size)
        val msgSummary = state.moduleSummaries[com.deepfakeshield.core.model.SecurityModule.MESSAGE_SHIELD]
        assertEquals(1, msgSummary?.totalScans)
        assertEquals(com.deepfakeshield.core.model.SecurityVerdict.HIGH_RISK, msgSummary?.lastVerdict)
        assertEquals(82, msgSummary?.lastRiskScore)
        val photoSummary = state.moduleSummaries[com.deepfakeshield.core.model.SecurityModule.PHOTO_FORENSICS]
        assertEquals(com.deepfakeshield.core.model.SecurityVerdict.INCONCLUSIVE, photoSummary?.lastVerdict)
    }
}
