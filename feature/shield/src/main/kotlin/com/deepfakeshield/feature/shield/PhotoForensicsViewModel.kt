package com.deepfakeshield.feature.shield

import android.content.Context
import android.graphics.Bitmap
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
import com.deepfakeshield.data.entity.AlertEntity
import com.deepfakeshield.data.repository.AlertRepository
import com.deepfakeshield.data.repository.ScanHistoryRepository
import com.deepfakeshield.ml.engine.ImageForensicsEngine
import com.deepfakeshield.ml.engine.PhotoForensicReport
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

data class PhotoForensicsUiState(
    val selectedUri: Uri? = null,
    val selectedDisplayName: String = "",
    val isAnalyzing: Boolean = false,
    val progress: Float = 0f,
    val stageMessage: String = "",
    val report: PhotoForensicReport? = null,
    val analysisResult: SecurityAnalysisResult? = null,
    val elaBitmap: Bitmap? = null,
    val recentHistory: List<SecurityAnalysisResult> = emptyList(),
    val error: String? = null
)

@HiltViewModel
class PhotoForensicsViewModel @Inject constructor(
    private val imageForensicsEngine: ImageForensicsEngine,
    private val scanHistoryRepository: ScanHistoryRepository,
    private val alertRepository: AlertRepository,
    @ApplicationContext private val context: Context
) : ViewModel() {

    private val _uiState = MutableStateFlow(PhotoForensicsUiState())
    val uiState: StateFlow<PhotoForensicsUiState> = _uiState.asStateFlow()

    private var analyzeJob: Job? = null

    init {
        viewModelScope.launch {
            scanHistoryRepository.observeHistory(SecurityModule.PHOTO_FORENSICS, 15).collect { history ->
                _uiState.update { it.copy(recentHistory = history) }
            }
        }
    }

    fun analyzeImage(uri: Uri) {
        analyzeJob?.cancel()
        analyzeJob = viewModelScope.launch {
            val displayName = resolveDisplayName(uri)
            _uiState.update {
                it.copy(
                    selectedUri = uri,
                    selectedDisplayName = displayName,
                    isAnalyzing = true,
                    progress = 0.05f,
                    stageMessage = "Reading image file...",
                    report = null,
                    analysisResult = null,
                    elaBitmap = null,
                    error = null
                )
            }

            try {
                val report = imageForensicsEngine.analyzeImageUri(
                    context = context,
                    uri = uri,
                    displayName = displayName
                ) { prog, stage ->
                    _uiState.update {
                        it.copy(
                            progress = prog.coerceIn(0f, 1f),
                            stageMessage = stage
                        )
                    }
                }

                val result = report.analysisResult
                scanHistoryRepository.saveResult(result)

                if (result.verdict.toAlertWorthy()) {
                    val severity = when (result.verdict) {
                        SecurityVerdict.MALICIOUS, SecurityVerdict.LIKELY_AI_GENERATED -> RiskSeverity.HIGH
                        SecurityVerdict.HIGH_RISK -> RiskSeverity.HIGH
                        else -> RiskSeverity.MEDIUM
                    }
                    alertRepository.insertAlert(
                        AlertEntity(
                            threatType = ThreatType.DEEPFAKE_VIDEO,
                            source = ThreatSource.GALLERY,
                            severity = severity,
                            score = result.riskScore ?: 50,
                            confidence = result.confidence ?: 0f,
                            title = "Photo Forensics: ${result.verdict.label}",
                            summary = result.findings.firstOrNull()?.description ?: result.verdict.label,
                            content = buildString {
                                append("File: $displayName (${report.containerFormat}, ${report.width}x${report.height})\n")
                                report.sha256?.let { append("SHA-256: $it\n") }
                                result.findings.forEach { f ->
                                    append("- ${f.title}: ${f.description}\n")
                                }
                            },
                            senderInfo = displayName,
                            timestamp = result.analyzedAt
                        )
                    )
                }

                _uiState.update {
                    it.copy(
                        isAnalyzing = false,
                        progress = 1f,
                        stageMessage = if (result.status == AnalysisStatus.FAILED) {
                            result.errorMessage ?: "Image inspection failed"
                        } else {
                            "Forensic inspection complete"
                        },
                        report = report,
                        analysisResult = result,
                        elaBitmap = report.elaStats?.elaBitmap,
                        error = if (result.status == AnalysisStatus.FAILED) result.errorMessage else null
                    )
                }
            } catch (e: CancellationException) {
                throw e
            } catch (e: SecurityException) {
                Log.e("PhotoForensicsVM", "Permission error", e)
                _uiState.update {
                    it.copy(
                        isAnalyzing = false,
                        progress = 0f,
                        stageMessage = "",
                        error = "Permission denied accessing the selected image."
                    )
                }
            } catch (e: Exception) {
                Log.e("PhotoForensicsVM", "Analysis failed", e)
                _uiState.update {
                    it.copy(
                        isAnalyzing = false,
                        progress = 0f,
                        stageMessage = "",
                        error = "Image analysis failed: ${e.message ?: "Unsupported or corrupt image"}"
                    )
                }
            }
        }
    }

    fun cancelAnalysis() {
        analyzeJob?.cancel()
        analyzeJob = null
        _uiState.update {
            it.copy(
                isAnalyzing = false,
                progress = 0f,
                stageMessage = "Cancelled"
            )
        }
    }

    fun selectHistoryItem(item: SecurityAnalysisResult) {
        _uiState.update {
            it.copy(
                analysisResult = item,
                report = null,
                elaBitmap = null,
                error = null
            )
        }
    }

    fun clearResult() {
        _uiState.update {
            it.copy(
                selectedUri = null,
                selectedDisplayName = "",
                report = null,
                analysisResult = null,
                elaBitmap = null,
                progress = 0f,
                stageMessage = "",
                error = null
            )
        }
    }

    fun clearError() {
        _uiState.update { it.copy(error = null) }
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
        return uri.lastPathSegment ?: "selected_image"
    }
}
