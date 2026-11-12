package com.deepfakeshield.feature.shield

import android.util.Log
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.deepfakeshield.core.model.RiskResult
import com.deepfakeshield.core.model.SecurityAnalysisResult
import com.deepfakeshield.core.model.SecurityModule
import com.deepfakeshield.core.model.ThreatSource
import com.deepfakeshield.core.notification.AlertNotifier
import com.deepfakeshield.data.entity.AlertEntity
import com.deepfakeshield.data.preferences.UserPreferences
import com.deepfakeshield.data.repository.AlertRepository
import com.deepfakeshield.data.repository.ScanHistoryRepository
import com.deepfakeshield.data.repository.VaultRepository
import com.deepfakeshield.intelligence.UrlInspectionReport
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.collect
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import javax.inject.Inject

data class MessageShieldUiState(
    val smsEnabled: Boolean = false,
    val notificationEnabled: Boolean = false,
    val clipboardEnabled: Boolean = false,
    val allowLiveUrlProbe: Boolean = false,
    val isScanning: Boolean = false,
    val analysisResult: SecurityAnalysisResult? = null,
    val scanResult: RiskResult? = null,
    val extractedUrls: List<UrlInspectionReport> = emptyList(),
    val extractedEntities: List<ExtractedEntity> = emptyList(),
    val scamCategory: String = "NONE",
    val detectedLanguage: String = "unknown",
    val recentHistory: List<SecurityAnalysisResult> = emptyList(),
    val error: String? = null
)

@HiltViewModel
class MessageShieldViewModel @Inject constructor(
    private val messageShieldAnalyzer: MessageShieldAnalyzer,
    private val scanHistoryRepository: ScanHistoryRepository,
    private val userPreferences: UserPreferences,
    private val alertRepository: AlertRepository,
    private val vaultRepository: VaultRepository,
    private val alertNotifier: AlertNotifier
) : ViewModel() {

    private val _uiState = MutableStateFlow(MessageShieldUiState())
    val uiState: StateFlow<MessageShieldUiState> = _uiState.asStateFlow()

    init {
        viewModelScope.launch {
            combine(
                userPreferences.messageShieldEnabled,
                userPreferences.clipboardScanningEnabled,
                userPreferences.notificationsEnabled,
                scanHistoryRepository.observeHistory(SecurityModule.MESSAGE_SHIELD, 10)
            ) { message, clipboard, notification, history ->
                _uiState.update {
                    it.copy(
                        smsEnabled = message,
                        clipboardEnabled = clipboard,
                        notificationEnabled = notification,
                        recentHistory = history
                    )
                }
            }.collect()
        }
    }

    private var currentScanJob: Job? = null

    fun setLiveUrlProbe(enabled: Boolean) {
        _uiState.update { it.copy(allowLiveUrlProbe = enabled) }
    }

    fun scanText(text: String) {
        currentScanJob?.cancel()
        currentScanJob = viewModelScope.launch {
            _uiState.update {
                it.copy(
                    isScanning = true,
                    analysisResult = null,
                    scanResult = null,
                    extractedUrls = emptyList(),
                    extractedEntities = emptyList(),
                    error = null
                )
            }

            try {
                val bundle = messageShieldAnalyzer.analyzeMessage(
                    text = text,
                    source = ThreatSource.MANUAL_SCAN,
                    allowNetworkUrlProbe = _uiState.value.allowLiveUrlProbe
                )

                if (bundle.analysisResult.status != com.deepfakeshield.core.model.AnalysisStatus.FAILED) {
                    scanHistoryRepository.saveResult(bundle.analysisResult)
                    userPreferences.incrementMessageScans()
                }

                _uiState.update {
                    it.copy(
                        isScanning = false,
                        analysisResult = bundle.analysisResult,
                        scanResult = bundle.legacyRiskResult,
                        extractedUrls = bundle.extractedUrls,
                        extractedEntities = bundle.extractedEntities,
                        scamCategory = bundle.scamCategory,
                        detectedLanguage = bundle.detectedLanguage,
                        error = bundle.analysisResult.errorMessage
                    )
                }

                val finalResult = bundle.legacyRiskResult
                if (finalResult.shouldAlert && bundle.analysisResult.status != com.deepfakeshield.core.model.AnalysisStatus.FAILED) {
                    val alertId = alertRepository.insertAlert(
                        AlertEntity(
                            threatType = finalResult.threatType,
                            source = ThreatSource.MANUAL_SCAN,
                            severity = finalResult.severity,
                            score = finalResult.score,
                            confidence = finalResult.confidence,
                            title = "Suspicious ${finalResult.threatType.name.replace("_", " ").lowercase()}",
                            summary = finalResult.explainLikeImFive,
                            content = text,
                            senderInfo = null,
                            timestamp = System.currentTimeMillis()
                        )
                    )
                    vaultRepository.addEntry(
                        alertId = alertId,
                        entryType = "scam_message",
                        title = "Suspicious ${finalResult.threatType.name.replace("_", " ").lowercase()}",
                        description = finalResult.explainLikeImFive,
                        severity = finalResult.severity,
                        evidenceData = text
                    )
                    val count = alertRepository.getAlertCount()
                    alertNotifier.onAlertInserted(count, "Suspicious message detected", finalResult.explainLikeImFive)
                }
            } catch (e: Exception) {
                if (e is CancellationException) throw e
                Log.e("MessageShieldVM", "Message scan failed", e)
                _uiState.update {
                    it.copy(isScanning = false, error = "Scan failed: ${e.message ?: e::class.java.simpleName}")
                }
            }
        }
    }

    fun selectHistoryItem(item: SecurityAnalysisResult) {
        _uiState.update {
            it.copy(
                analysisResult = item,
                scanResult = null,
                error = null
            )
        }
    }

    fun clearResult() {
        _uiState.update {
            it.copy(
                analysisResult = null,
                scanResult = null,
                extractedUrls = emptyList(),
                extractedEntities = emptyList(),
                error = null
            )
        }
    }

    fun enableSmsScanning() {
        viewModelScope.launch { userPreferences.setMessageShield(true) }
    }

    fun disableSmsScanning() {
        viewModelScope.launch { userPreferences.setMessageShield(false) }
    }

    fun enableNotificationScanning() {
        viewModelScope.launch {
            try {
                userPreferences.setNotifications(true)
            } catch (e: Exception) {
                Log.e("MessageShieldVM", "Failed to enable notification scanning", e)
                _uiState.update { it.copy(error = "Failed to enable notifications: ${e.message}") }
            }
        }
    }

    fun toggleClipboardScanning(enabled: Boolean) {
        viewModelScope.launch { userPreferences.setClipboardScanning(enabled) }
    }

    fun clearError() {
        _uiState.update { it.copy(error = null) }
    }
}
