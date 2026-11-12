package com.deepfakeshield.feature.shield

import android.content.Context
import android.content.Intent
import android.net.Uri
import android.provider.OpenableColumns
import android.util.Log
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.deepfakeshield.core.model.AnalysisStatus
import com.deepfakeshield.core.model.RiskSeverity
import com.deepfakeshield.core.model.SecurityAnalysisResult
import com.deepfakeshield.core.model.SecurityModule
import com.deepfakeshield.core.model.SecurityVerdict
import com.deepfakeshield.core.model.ThreatSource
import com.deepfakeshield.core.model.ThreatType
import com.deepfakeshield.core.model.toAlertWorthy
import com.deepfakeshield.core.notification.AlertNotifier
import com.deepfakeshield.data.entity.AlertEntity
import com.deepfakeshield.data.preferences.UserPreferences
import com.deepfakeshield.data.repository.AlertRepository
import com.deepfakeshield.data.repository.ScanHistoryRepository
import com.deepfakeshield.data.repository.VaultRepository
import com.deepfakeshield.ml.engine.VideoForensicReport
import com.deepfakeshield.ml.engine.VideoForensicsPipeline
import dagger.hilt.android.lifecycle.HiltViewModel
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import javax.inject.Inject

data class VideoShieldUiState(
    val systemWideEnabled: Boolean = false,
    val isScanning: Boolean = false,
    val scanProgress: Float = 0f,
    val statusMessage: String = "",
    val forensicReport: VideoForensicReport? = null,
    val analysisResult: SecurityAnalysisResult? = null,
    val recentHistory: List<SecurityAnalysisResult> = emptyList(),
    val error: String? = null
)

@HiltViewModel
class VideoShieldViewModel @Inject constructor(
    private val videoForensicsPipeline: VideoForensicsPipeline,
    private val scanHistoryRepository: ScanHistoryRepository,
    private val userPreferences: UserPreferences,
    private val alertRepository: AlertRepository,
    private val vaultRepository: VaultRepository,
    private val alertNotifier: AlertNotifier,
    @ApplicationContext private val context: Context
) : ViewModel() {

    private val _uiState = MutableStateFlow(VideoShieldUiState())
    val uiState: StateFlow<VideoShieldUiState> = _uiState.asStateFlow()

    private var scanJob: Job? = null

    init {
        viewModelScope.launch {
            userPreferences.videoShieldEnabled.collect { enabled ->
                _uiState.update { it.copy(systemWideEnabled = enabled) }
            }
        }
        viewModelScope.launch {
            scanHistoryRepository.observeHistory(SecurityModule.DEEPFAKE_VIDEO, 15).collect { history ->
                _uiState.update { it.copy(recentHistory = history) }
            }
        }
    }

    fun scanVideo(uri: Uri) {
        scanJob?.cancel()
        scanJob = viewModelScope.launch {
            val displayName = resolveDisplayName(uri)
            _uiState.update {
                it.copy(
                    isScanning = true,
                    scanProgress = 0.03f,
                    statusMessage = "Validating video stream...",
                    forensicReport = null,
                    analysisResult = null,
                    error = null
                )
            }

            try {
                val report = videoForensicsPipeline.analyzeVideoUri(
                    uri = uri,
                    displayName = displayName
                ) { progress, stage ->
                    _uiState.update {
                        it.copy(
                            scanProgress = progress.coerceIn(0f, 1f),
                            statusMessage = stage
                        )
                    }
                }

                val result = report.analysisResult
                scanHistoryRepository.saveResult(result)

                if (result.status != AnalysisStatus.FAILED) {
                    userPreferences.incrementVideoScans()
                }

                // Update floating bubble service with verified verdict (never fabricated)
                val scoreText = result.riskScore?.let { " ($it/100)" } ?: ""
                val bubbleSummary = "${result.verdict.label}$scoreText — ${displayName.take(24)}"
                runCatching {
                    val bubbleIntent = Intent("com.deepfakeshield.SCAN_RESULT").apply {
                        setClassName(context.packageName, "com.deepfakeshield.service.FloatingBubbleService")
                        putExtra("last_scan_result", bubbleSummary)
                        putExtra("last_scan_score", result.riskScore ?: 0)
                    }
                    context.startService(bubbleIntent)
                }

                if (result.verdict.toAlertWorthy()) {
                    val severity = when (result.verdict) {
                        SecurityVerdict.MALICIOUS, SecurityVerdict.LIKELY_AI_GENERATED -> RiskSeverity.CRITICAL
                        SecurityVerdict.HIGH_RISK -> RiskSeverity.HIGH
                        else -> RiskSeverity.MEDIUM
                    }
                    val evidenceSummary = buildString {
                        append("File: $displayName\n")
                        append("Verdict: ${result.verdict.label}\n")
                        append("Frames analyzed: ${report.framesExtracted}, faces detected: ${report.framesWithFaces}\n")
                        append("Luminance anomalies: ${report.temporalLuminanceAnomalies}\n")
                        result.findings.take(4).forEach { f ->
                            append("- ${f.title}: ${f.description}\n")
                        }
                    }
                    val alertId = alertRepository.insertAlert(
                        AlertEntity(
                            threatType = ThreatType.DEEPFAKE_VIDEO,
                            source = ThreatSource.VIDEO_FILE,
                            severity = severity,
                            score = result.riskScore ?: 50,
                            confidence = result.confidence ?: 0f,
                            title = "Video Forensics: ${result.verdict.label}",
                            summary = result.findings.firstOrNull()?.description ?: result.verdict.label,
                            content = evidenceSummary,
                            senderInfo = displayName,
                            timestamp = result.analyzedAt
                        )
                    )
                    vaultRepository.addEntry(
                        alertId = alertId,
                        entryType = "deepfake_video",
                        title = "Video Forensics: $displayName",
                        description = result.verdict.label,
                        severity = severity,
                        evidenceData = evidenceSummary
                    )
                    val count = alertRepository.getAlertCount()
                    alertNotifier.onAlertInserted(
                        count,
                        "Video Forensics Alert",
                        result.findings.firstOrNull()?.title ?: result.verdict.label
                    )
                }

                _uiState.update {
                    it.copy(
                        isScanning = false,
                        scanProgress = 1f,
                        statusMessage = if (result.status == AnalysisStatus.FAILED) {
                            result.errorMessage ?: "Video analysis failed"
                        } else {
                            "Analysis complete"
                        },
                        forensicReport = report,
                        analysisResult = result,
                        error = if (result.status == AnalysisStatus.FAILED) result.errorMessage else null
                    )
                }
            } catch (e: CancellationException) {
                throw e
            } catch (e: SecurityException) {
                Log.e("VideoShieldVM", "Permission denied opening video", e)
                _uiState.update {
                    it.copy(
                        isScanning = false,
                        scanProgress = 0f,
                        statusMessage = "",
                        error = "Permission denied while opening the selected video."
                    )
                }
            } catch (e: Exception) {
                Log.e("VideoShieldVM", "Video scan error", e)
                _uiState.update {
                    it.copy(
                        isScanning = false,
                        scanProgress = 0f,
                        statusMessage = "",
                        error = "Video scan failed: ${e.message ?: "Unsupported or corrupt video stream"}"
                    )
                }
            }
        }
    }

    fun cancelScan() {
        scanJob?.cancel()
        scanJob = null
        _uiState.update {
            it.copy(
                isScanning = false,
                scanProgress = 0f,
                statusMessage = "Analysis cancelled"
            )
        }
    }

    fun selectHistoryItem(item: SecurityAnalysisResult) {
        _uiState.update {
            it.copy(
                analysisResult = item,
                forensicReport = null,
                error = null
            )
        }
    }

    @Suppress("UNUSED_PARAMETER")
    fun startSystemWideScanning(data: Intent?) {
        viewModelScope.launch {
            userPreferences.setVideoShield(true)
            _uiState.update { it.copy(systemWideEnabled = true) }
        }
    }

    fun stopSystemWideScanning() {
        viewModelScope.launch {
            userPreferences.setVideoShield(false)
            _uiState.update { it.copy(systemWideEnabled = false) }
        }
    }

    fun clearError() {
        _uiState.update { it.copy(error = null) }
    }

    fun clearResult() {
        _uiState.update {
            it.copy(
                forensicReport = null,
                analysisResult = null,
                scanProgress = 0f,
                statusMessage = "",
                error = null
            )
        }
    }

    private fun resolveDisplayName(uri: Uri): String {
        runCatching {
            context.contentResolver.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME), null, null, null)?.use { c ->
                if (c.moveToFirst()) {
                    val idx = c.getColumnIndex(OpenableColumns.DISPLAY_NAME)
                    if (idx >= 0) {
                        val name = c.getString(idx)
                        if (!name.isNullOrBlank()) return name
                    }
                }
            }
        }
        return uri.lastPathSegment ?: "selected_video"
    }
}
