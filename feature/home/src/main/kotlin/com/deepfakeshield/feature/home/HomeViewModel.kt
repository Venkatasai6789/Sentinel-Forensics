package com.deepfakeshield.feature.home

import android.util.Log
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.deepfakeshield.core.model.AnalysisStatus
import com.deepfakeshield.core.model.RiskSeverity
import com.deepfakeshield.core.model.SecurityAnalysisResult
import com.deepfakeshield.core.model.SecurityModule
import com.deepfakeshield.core.model.SecurityVerdict
import com.deepfakeshield.core.model.ThreatSource
import com.deepfakeshield.core.model.toAlertWorthy
import com.deepfakeshield.data.entity.AlertEntity
import com.deepfakeshield.data.preferences.UserPreferences
import com.deepfakeshield.data.repository.AlertRepository
import com.deepfakeshield.data.repository.PasswordVaultRepository
import com.deepfakeshield.data.repository.ScanHistoryRepository
import com.deepfakeshield.data.repository.VaultHealthSummary
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.*
import kotlinx.coroutines.launch
import java.time.Instant
import java.time.LocalDate
import java.time.ZoneId
import java.time.format.DateTimeFormatter
import java.util.Locale
import javax.inject.Inject

enum class ProtectionStatus {
    ACTIVE,
    PARTIAL,
    ATTENTION_REQUIRED,
    INACTIVE,
    UNKNOWN
}

data class ProtectionState(
    val status: ProtectionStatus = ProtectionStatus.UNKNOWN,
    val activeModules: Int = 0,
    val totalModules: Int = 3,
    val lastUpdated: Long? = null
)

data class DashboardMetrics(
    val protectionStatus: ProtectionStatus = ProtectionStatus.UNKNOWN,
    val protectionScore: Int = 0,
    val activeModuleCount: Int = 0,
    val totalModuleCount: Int = 3,
    val issueCount: Int = 0,
    val unreadAlertCount: Int = 0,
    val lastScanTime: Long? = null
)

data class DailyActivity(
    val dayLabel: String,
    val date: LocalDate,
    val completedScans: Int,
    val detectedIssues: Int
)

data class DashboardAlertSummary(
    val unresolvedCount: Int,
    val title: String,
    val description: String,
    val severity: RiskSeverity
)

data class ModuleStatusSummary(
    val module: SecurityModule,
    val totalScans: Int = 0,
    val lastVerdict: SecurityVerdict? = null,
    val lastRiskScore: Int? = null,
    val lastScanAt: Long = 0L,
    val lastInputName: String? = null
)

data class HomeUiState(
    val isLoading: Boolean = true,
    val protectionState: ProtectionState = ProtectionState(),
    val metrics: DashboardMetrics? = null,
    val dailyActivities: List<DailyActivity> = emptyList(),
    val hasActivityHistory: Boolean = false,
    val alertSummary: DashboardAlertSummary? = null,
    val masterProtectionEnabled: Boolean = false,
    val videoShieldEnabled: Boolean = false,
    val messageShieldEnabled: Boolean = false,
    val callShieldEnabled: Boolean = false,
    val overlayBubbleEnabled: Boolean = false,
    val unhandledAlertCount: Int = 0,
    val totalThreatsBlocked: Int = 0,
    val streak: Int = 0,
    val totalScans: Int = 0,
    val totalPersistedScans: Int = 0,
    val lastScanTimestamp: Long = 0L,
    val moduleSummaries: Map<SecurityModule, ModuleStatusSummary> = emptyMap(),
    val recentScans: List<SecurityAnalysisResult> = emptyList(),
    val vaultHealth: VaultHealthSummary = VaultHealthSummary(),
    val errorMessage: String? = null
)

data class ShieldStates(
    val master: Boolean,
    val video: Boolean,
    val message: Boolean,
    val call: Boolean,
    val overlay: Boolean
)

data class ScanStats(
    val lastScanTime: Long,
    val videoScans: Int,
    val messageScans: Int,
    val streak: Int
)

@HiltViewModel
class HomeViewModel @Inject constructor(
    private val userPreferences: UserPreferences,
    private val alertRepository: AlertRepository,
    private val scanHistoryRepository: ScanHistoryRepository,
    private val passwordVaultRepository: PasswordVaultRepository
) : ViewModel() {

    companion object {
        private const val TAG = "HomeViewModel"
        const val TOTAL_MODULES = 3

        internal fun buildDashboardUiState(
            shields: ShieldStates,
            stats: ScanStats,
            unhandledAlerts: List<AlertEntity>,
            allAlerts: List<AlertEntity>,
            scanHistory: List<SecurityAnalysisResult> = emptyList(),
            vaultHealth: VaultHealthSummary = VaultHealthSummary()
        ): HomeUiState {
            val activeCount = listOf(shields.video, shields.message, shields.call).count { it }
            val criticalOrHighAlerts = unhandledAlerts.count {
                it.severity == RiskSeverity.CRITICAL || it.severity == RiskSeverity.HIGH
            }

            val status = when {
                !shields.master -> ProtectionStatus.INACTIVE
                criticalOrHighAlerts > 0 -> ProtectionStatus.ATTENTION_REQUIRED
                activeCount == TOTAL_MODULES -> ProtectionStatus.ACTIVE
                activeCount > 0 -> ProtectionStatus.PARTIAL
                else -> ProtectionStatus.INACTIVE
            }

            val criticalDeductions = unhandledAlerts.count { it.severity == RiskSeverity.CRITICAL } * 25
            val highDeductions = unhandledAlerts.count { it.severity == RiskSeverity.HIGH } * 15
            val mediumDeductions = unhandledAlerts.count { it.severity == RiskSeverity.MEDIUM } * 5
            val disabledEngineDeduction = (TOTAL_MODULES - activeCount) * 20

            val calculatedScore = if (!shields.master) {
                0
            } else {
                (100 - criticalDeductions - highDeductions - mediumDeductions - disabledEngineDeduction).coerceIn(0, 100)
            }

            val issuesFoundCount = unhandledAlerts.count { it.severity != RiskSeverity.LOW }
            val unreadAlertsCount = unhandledAlerts.size

            val latestPersistedTs = scanHistory.maxOfOrNull { it.analyzedAt } ?: 0L
            val effectiveLastScanTs = maxOf(stats.lastScanTime, latestPersistedTs)

            val protectionState = ProtectionState(
                status = status,
                activeModules = activeCount,
                totalModules = TOTAL_MODULES,
                lastUpdated = if (effectiveLastScanTs > 0) effectiveLastScanTs else null
            )

            val metrics = DashboardMetrics(
                protectionStatus = status,
                protectionScore = calculatedScore,
                activeModuleCount = activeCount,
                totalModuleCount = TOTAL_MODULES,
                issueCount = issuesFoundCount,
                unreadAlertCount = unreadAlertsCount,
                lastScanTime = if (effectiveLastScanTs > 0) effectiveLastScanTs else null
            )

            val legacyTotalScans = stats.videoScans + stats.messageScans
            val effectiveTotalScans = maxOf(legacyTotalScans, scanHistory.size)

            val dailyActivities = calculateDailyActivity(
                allAlerts = allAlerts,
                todayScans = legacyTotalScans,
                scanHistory = scanHistory
            )
            val hasActivity = dailyActivities.any { it.completedScans > 0 || it.detectedIssues > 0 } ||
                effectiveTotalScans > 0

            val moduleSummaries = SecurityModule.entries.associateWith { mod ->
                val forMod = scanHistory.filter { it.module == mod }
                val latest = forMod.maxByOrNull { it.analyzedAt }
                ModuleStatusSummary(
                    module = mod,
                    totalScans = forMod.size,
                    lastVerdict = latest?.verdict,
                    lastRiskScore = latest?.riskScore,
                    lastScanAt = latest?.analyzedAt ?: 0L,
                    lastInputName = latest?.inputName
                )
            }

            val alertSummary = if (unhandledAlerts.isNotEmpty()) {
                val topAlert = unhandledAlerts.first()
                val hasCall = unhandledAlerts.any { it.source == ThreatSource.INCOMING_CALL }
                val hasMessage = unhandledAlerts.any { (it.source == ThreatSource.SMS || it.source == ThreatSource.NOTIFICATION) }
                val desc = when {
                    hasCall && hasMessage -> "Review suspicious messages and a blocked call"
                    hasCall -> "Review blocked call and caller reputation"
                    hasMessage -> "Review suspicious message content"
                    topAlert.summary.isNotBlank() -> topAlert.summary
                    else -> topAlert.title
                }
                DashboardAlertSummary(
                    unresolvedCount = unhandledAlerts.size,
                    title = "${unhandledAlerts.size} item${if (unhandledAlerts.size > 1) "s" else ""} need${if (unhandledAlerts.size == 1) "s" else ""} your attention",
                    description = desc,
                    severity = topAlert.severity
                )
            } else null

            return HomeUiState(
                isLoading = false,
                protectionState = protectionState,
                metrics = metrics,
                dailyActivities = dailyActivities,
                hasActivityHistory = hasActivity,
                alertSummary = alertSummary,
                masterProtectionEnabled = shields.master,
                videoShieldEnabled = shields.video,
                messageShieldEnabled = shields.message,
                callShieldEnabled = shields.call,
                overlayBubbleEnabled = shields.overlay,
                unhandledAlertCount = unreadAlertsCount,
                totalThreatsBlocked = allAlerts.size,
                streak = stats.streak,
                totalScans = legacyTotalScans,
                totalPersistedScans = effectiveTotalScans,
                lastScanTimestamp = effectiveLastScanTs,
                moduleSummaries = moduleSummaries,
                recentScans = scanHistory.take(10),
                vaultHealth = vaultHealth,
                errorMessage = null
            )
        }

        internal fun calculateDailyActivity(
            allAlerts: List<AlertEntity>,
            todayScans: Int
        ): List<DailyActivity> = calculateDailyActivity(
            allAlerts = allAlerts,
            todayScans = todayScans,
            scanHistory = emptyList()
        )

        internal fun calculateDailyActivity(
            allAlerts: List<AlertEntity>,
            todayScans: Int,
            scanHistory: List<SecurityAnalysisResult>
        ): List<DailyActivity> {
            val today = LocalDate.now()
            val zone = ZoneId.systemDefault()
            val days = (6 downTo 0).map { today.minusDays(it.toLong()) }
            val dayFormat = DateTimeFormatter.ofPattern("EEE", Locale.getDefault())

            val alertsByDate = allAlerts.groupBy { alert ->
                Instant.ofEpochMilli(alert.timestamp).atZone(zone).toLocalDate()
            }
            val scansByDate = scanHistory.groupBy { scan ->
                Instant.ofEpochMilli(scan.analyzedAt).atZone(zone).toLocalDate()
            }

            return days.map { date ->
                val alertsForDay = alertsByDate[date] ?: emptyList()
                val scansForDay = scansByDate[date] ?: emptyList()
                val alertIssues = alertsForDay.count { it.severity != RiskSeverity.LOW }
                val scanIssues = scansForDay.count {
                    it.status != AnalysisStatus.FAILED && it.verdict.toAlertWorthy()
                }
                val detectedIssues = maxOf(alertIssues, scanIssues)
                val persistedCount = scansForDay.size
                val isToday = date == today
                val completedScans = if (isToday) {
                    maxOf(todayScans, persistedCount, alertsForDay.size)
                } else {
                    maxOf(persistedCount, alertsForDay.size)
                }
                DailyActivity(
                    dayLabel = date.format(dayFormat),
                    date = date,
                    completedScans = completedScans,
                    detectedIssues = detectedIssues
                )
            }
        }
    }

    private val shieldsFlow: Flow<ShieldStates> = combine(
        userPreferences.masterProtectionEnabled,
        userPreferences.videoShieldEnabled,
        userPreferences.messageShieldEnabled,
        userPreferences.callShieldEnabled,
        userPreferences.overlayBubbleEnabled
    ) { master, video, message, call, overlay ->
        ShieldStates(master, video, message, call, overlay)
    }

    private val scanStatsFlow: Flow<ScanStats> = combine(
        userPreferences.lastScanTimestamp,
        userPreferences.videoScansCount,
        userPreferences.messageScansCount,
        userPreferences.dailyChallengeStreak
    ) { lastScan, videoScans, messageScans, streak ->
        ScanStats(lastScan, videoScans, messageScans, streak)
    }

    private val historyAndVaultFlow: Flow<Pair<List<SecurityAnalysisResult>, VaultHealthSummary>> = combine(
        scanHistoryRepository.observeRecentAll(100),
        passwordVaultRepository.observeVaultHealth()
    ) { scans, health -> scans to health }

    val uiState: StateFlow<HomeUiState> = combine(
        shieldsFlow,
        scanStatsFlow,
        alertRepository.getUnhandledAlerts(),
        alertRepository.getAllAlerts(),
        historyAndVaultFlow
    ) { shields, stats, unhandledAlerts, allAlerts, (scans, health) ->
        buildDashboardUiState(shields, stats, unhandledAlerts, allAlerts, scans, health)
    }.catch { e ->
        if (e is kotlinx.coroutines.CancellationException) throw e
        Log.e(TAG, "Error calculating dashboard state", e)
        emit(HomeUiState(isLoading = false, errorMessage = e.message))
    }.distinctUntilChanged()
        .stateIn(
            scope = viewModelScope,
            started = SharingStarted.WhileSubscribed(5000),
            initialValue = HomeUiState(isLoading = true)
        )

    private var masterToggleJob: kotlinx.coroutines.Job? = null

    fun toggleMasterProtection(enabled: Boolean) {
        masterToggleJob?.cancel()
        masterToggleJob = viewModelScope.launch {
            try {
                userPreferences.setMasterProtection(enabled)
                if (enabled) {
                    userPreferences.setVideoShield(true)
                    userPreferences.setMessageShield(true)
                    userPreferences.setCallShield(true)
                } else {
                    userPreferences.setVideoShield(false)
                    userPreferences.setMessageShield(false)
                    userPreferences.setCallShield(false)
                }
            } catch (e: Exception) {
                if (e is kotlinx.coroutines.CancellationException) throw e
                Log.e(TAG, "Failed to toggle master protection", e)
            }
        }
    }

    fun toggleVideoShield(enabled: Boolean) {
        viewModelScope.launch {
            try {
                userPreferences.setVideoShield(enabled)
                checkMasterProtection()
            } catch (e: Exception) {
                if (e is kotlinx.coroutines.CancellationException) throw e
                Log.e(TAG, "Failed to toggle video shield", e)
            }
        }
    }

    fun toggleMessageShield(enabled: Boolean) {
        viewModelScope.launch {
            try {
                userPreferences.setMessageShield(enabled)
                checkMasterProtection()
            } catch (e: Exception) {
                if (e is kotlinx.coroutines.CancellationException) throw e
                Log.e(TAG, "Failed to toggle message shield", e)
            }
        }
    }

    fun toggleCallShield(enabled: Boolean) {
        viewModelScope.launch {
            try {
                userPreferences.setCallShield(enabled)
                checkMasterProtection()
            } catch (e: Exception) {
                if (e is kotlinx.coroutines.CancellationException) throw e
                Log.e(TAG, "Failed to toggle call shield", e)
            }
        }
    }

    fun toggleOverlayBubble(enabled: Boolean) {
        viewModelScope.launch {
            try {
                userPreferences.setOverlayBubbleEnabled(enabled)
            } catch (e: Exception) {
                if (e is kotlinx.coroutines.CancellationException) throw e
                Log.e(TAG, "Failed to toggle overlay bubble", e)
            }
        }
    }

    private suspend fun checkMasterProtection() {
        try {
            val video = userPreferences.videoShieldEnabled.first()
            val message = userPreferences.messageShieldEnabled.first()
            val call = userPreferences.callShieldEnabled.first()
            val anyEnabled = video || message || call
            userPreferences.setMasterProtection(anyEnabled)
        } catch (e: Exception) {
            if (e is kotlinx.coroutines.CancellationException) throw e
            Log.e(TAG, "Failed to check master protection state", e)
        }
    }
}
