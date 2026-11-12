package com.deepfakeshield.feature.shield

import android.util.Log
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.deepfakeshield.core.engine.PageContentAnalyzer
import com.deepfakeshield.core.engine.UrlSafetyEngine
import com.deepfakeshield.core.model.AnalysisStatus
import com.deepfakeshield.core.model.SecurityAnalysisResult
import com.deepfakeshield.core.model.SecurityModule
import com.deepfakeshield.data.preferences.UserPreferences
import com.deepfakeshield.data.repository.ScanHistoryRepository
import com.deepfakeshield.intelligence.UnifiedUrlInspectionEngine
import com.deepfakeshield.intelligence.UnifiedUrlThreatCache
import com.deepfakeshield.intelligence.UrlInspectionReport
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.collect
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import javax.inject.Inject

data class SafeBrowserUiState(
    val isScanning: Boolean = false,
    val allowNetworkProbe: Boolean = false,
    val inspectionReport: UrlInspectionReport? = null,
    val legacyUrlAnalysis: UrlSafetyEngine.UrlAnalysis? = null,
    val recentHistory: List<SecurityAnalysisResult> = emptyList(),
    val cacheCount: Int = 0,
    val cachePhishingCount: Int = 0,
    val cacheMalwareCount: Int = 0,
    val cacheLastUpdatedAt: Long = 0L,
    val isRefreshingCache: Boolean = false,
    val cacheRefreshMessage: String? = null,
    val error: String? = null
)

@HiltViewModel
class SafeBrowserViewModel @Inject constructor(
    private val urlInspectionEngine: UnifiedUrlInspectionEngine,
    private val urlSafetyEngine: UrlSafetyEngine,
    private val urlThreatCache: UnifiedUrlThreatCache,
    private val pageContentAnalyzer: PageContentAnalyzer,
    private val scanHistoryRepository: ScanHistoryRepository,
    userPreferences: UserPreferences
) : ViewModel() {

    private val _uiState = MutableStateFlow(
        SafeBrowserUiState(
            cacheCount = urlThreatCache.getCachedCount(),
            cachePhishingCount = urlThreatCache.getPhishingCount(),
            cacheMalwareCount = urlThreatCache.getMalwareCount(),
            cacheLastUpdatedAt = urlThreatCache.getLastUpdatedAt()
        )
    )
    val uiState: StateFlow<SafeBrowserUiState> = _uiState.asStateFlow()

    private val _urlAnalysis = MutableStateFlow<UrlSafetyEngine.UrlAnalysis?>(null)
    val urlAnalysis: StateFlow<UrlSafetyEngine.UrlAnalysis?> = _urlAnalysis.asStateFlow()

    private val _blockAdultContent = MutableStateFlow(false)
    private var inspectJob: Job? = null

    init {
        viewModelScope.launch {
            userPreferences.familyProtectionEnabled.collect { _blockAdultContent.value = it }
        }
        viewModelScope.launch {
            scanHistoryRepository.observeHistory(SecurityModule.PHISHING_URL_SCAN, 12)
                .collect { history ->
                    _uiState.update { it.copy(recentHistory = history) }
                }
        }
    }

    fun setNetworkProbeEnabled(enabled: Boolean) {
        _uiState.update { it.copy(allowNetworkProbe = enabled) }
    }

    fun inspectUrl(rawUrl: String, allowNetworkProbe: Boolean = _uiState.value.allowNetworkProbe) {
        inspectJob?.cancel()
        inspectJob = viewModelScope.launch {
            _uiState.update {
                it.copy(
                    isScanning = true,
                    error = null,
                    cacheRefreshMessage = null
                )
            }
            try {
                val report = urlInspectionEngine.inspectUrl(
                    rawUrl = rawUrl,
                    allowNetworkProbe = allowNetworkProbe
                )
                val legacy = urlSafetyEngine.analyzeUrl(report.normalizedUrl, _blockAdultContent.value)
                val effectiveLegacy = if ((report.analysisResult.riskScore ?: 0) > legacy.riskScore) {
                    legacy.copy(
                        riskScore = report.analysisResult.riskScore ?: legacy.riskScore,
                        threats = report.analysisResult.findings.map { f ->
                            UrlSafetyEngine.UrlThreat(
                                type = f.title,
                                severity = f.severity.name,
                                description = f.description
                            )
                        }
                    )
                } else {
                    legacy
                }

                if (report.analysisResult.status != AnalysisStatus.FAILED) {
                    scanHistoryRepository.saveResult(report.analysisResult)
                }

                _urlAnalysis.value = effectiveLegacy
                _uiState.update {
                    it.copy(
                        isScanning = false,
                        inspectionReport = report,
                        legacyUrlAnalysis = effectiveLegacy,
                        cacheCount = report.cacheEntryCount,
                        cachePhishingCount = urlThreatCache.getPhishingCount(),
                        cacheMalwareCount = urlThreatCache.getMalwareCount(),
                        cacheLastUpdatedAt = report.cacheLastUpdatedAt,
                        error = report.analysisResult.errorMessage
                    )
                }
            } catch (e: Exception) {
                if (e is CancellationException) throw e
                Log.e("SafeBrowserVM", "URL inspection failed", e)
                _uiState.update {
                    it.copy(isScanning = false, error = "URL inspection failed: ${e.message ?: e::class.java.simpleName}")
                }
            }
        }
    }

    fun analyzeUrl(url: String) {
        inspectUrl(url, allowNetworkProbe = _uiState.value.allowNetworkProbe)
    }

    fun analyzeUrlSync(url: String, blockAdultContent: Boolean? = null): UrlSafetyEngine.UrlAnalysis {
        val blockAdult = blockAdultContent ?: _blockAdultContent.value
        var result = urlSafetyEngine.analyzeUrl(url, blockAdult)
        if (urlThreatCache.isUrlPhishing(url)) {
            result = result.copy(
                riskScore = maxOf(result.riskScore, 95),
                threats = result.threats + UrlSafetyEngine.UrlThreat(
                    "KNOWN_PHISHING", "CRITICAL",
                    "This URL matched cached phishing feed data"
                )
            )
        }
        if (urlThreatCache.isUrlMalware(url)) {
            result = result.copy(
                riskScore = maxOf(result.riskScore, 95),
                threats = result.threats + UrlSafetyEngine.UrlThreat(
                    "KNOWN_MALWARE", "CRITICAL",
                    "This URL matched cached malware feed data"
                )
            )
        }
        return result
    }

    fun refreshThreatCache(callback: (Result<UnifiedUrlThreatCache.RefreshStats>) -> Unit = {}) {
        viewModelScope.launch {
            _uiState.update { it.copy(isRefreshingCache = true, cacheRefreshMessage = null) }
            val result = withContext(Dispatchers.IO) { urlThreatCache.refresh() }
            result.onSuccess { stats ->
                _uiState.update {
                    it.copy(
                        isRefreshingCache = false,
                        cacheCount = urlThreatCache.getCachedCount(),
                        cachePhishingCount = urlThreatCache.getPhishingCount(),
                        cacheMalwareCount = urlThreatCache.getMalwareCount(),
                        cacheLastUpdatedAt = urlThreatCache.getLastUpdatedAt(),
                        cacheRefreshMessage = "Synced ${stats.totalCount} URLs (${stats.phishingCount} phishing, ${stats.malwareCount} malware)"
                    )
                }
            }.onFailure { err ->
                _uiState.update {
                    it.copy(
                        isRefreshingCache = false,
                        cacheRefreshMessage = "Feed sync failed (offline or unreachable): ${err.message ?: "Network error"}"
                    )
                }
            }
            callback(result)
        }
    }

    fun selectHistoryItem(item: SecurityAnalysisResult) {
        _uiState.update {
            it.copy(
                inspectionReport = null,
                error = null
            )
        }
        val target = item.metadata["normalizedUrl"] ?: item.inputName.orEmpty()
        if (target.isNotBlank()) {
            inspectUrl(target, allowNetworkProbe = false)
        }
    }

    fun clearInspection() {
        _urlAnalysis.value = null
        _uiState.update { it.copy(inspectionReport = null, legacyUrlAnalysis = null, error = null) }
    }

    fun needsCacheRefresh(): Boolean = urlThreatCache.needsRefresh()
    fun getCachedThreatCount(): Int = urlThreatCache.getCachedCount()

    fun analyzePageContent(text: String): PageContentAnalyzer.PageAnalysis =
        pageContentAnalyzer.analyze(text)
}
