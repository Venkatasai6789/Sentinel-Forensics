package com.deepfakeshield.feature.diagnostics

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.os.Environment
import android.provider.DocumentsContract
import android.provider.OpenableColumns
import androidx.core.content.ContextCompat
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.deepfakeshield.av.engine.AndroidStoragePaths
import com.deepfakeshield.av.engine.AntivirusEngine
import com.deepfakeshield.av.engine.AvEngineStats
import com.deepfakeshield.av.engine.AvScanResult
import com.deepfakeshield.av.engine.MalwareSignatureDatabase
import com.deepfakeshield.av.engine.QuarantineEntry
import com.deepfakeshield.av.engine.QuarantineManager
import com.deepfakeshield.av.engine.RootDetector
import com.deepfakeshield.av.engine.ThreatDatabaseUpdater
import com.deepfakeshield.av.engine.ThreatLevel
import com.deepfakeshield.core.model.AnalysisStatus
import com.deepfakeshield.core.model.FindingSeverity
import com.deepfakeshield.core.model.SecurityAnalysisResult
import com.deepfakeshield.core.model.SecurityFinding
import com.deepfakeshield.core.model.SecurityModule
import com.deepfakeshield.core.model.SecurityVerdict
import com.deepfakeshield.data.preferences.UserPreferences
import com.deepfakeshield.data.repository.AlertRepository
import com.deepfakeshield.data.repository.ScanHistoryRepository
import dagger.hilt.android.lifecycle.HiltViewModel
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.flow.*
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File
import java.util.UUID
import javax.inject.Inject

data class PermissionStatus(
    val name: String,
    val granted: Boolean,
    val required: Boolean = true
)

data class ThreatDbStatus(
    val totalHashes: Int = 0,
    val bundledHashes: Int = 0,
    val downloadedHashes: Int = 0,
    val lastUpdateTimeMs: Long = 0L,
    val lastUpdateStatus: String = "Bundled offline signatures active",
    val isUpdating: Boolean = false,
    val updateMessage: String? = null
)

data class AvScanScopeSummary(
    val scanModeLabel: String,
    val discoverableCount: Int,
    val scannedCount: Int,
    val skippedCount: Int,
    val hasFullStorageAccess: Boolean,
    val limitationDisclosure: String
)

data class DiagnosticsUiState(
    val allSystemsHealthy: Boolean = true,
    val antivirusStatus: String = "Engine ready",
    val isRunningAvScan: Boolean = false,
    val avScanProgress: String = "",
    val avScanProgressFraction: Float = 0f,
    val avScanResults: List<AvScanResult> = emptyList(),
    val avThreatsFound: Int = 0,
    val avErrorsCount: Int = 0,
    val scanScopeSummary: AvScanScopeSummary? = null,
    val latestAnalysisResult: SecurityAnalysisResult? = null,
    val recentHistory: List<SecurityAnalysisResult> = emptyList(),
    val engineStats: AvEngineStats = AvEngineStats(0, 0, 0, 0, 0, 0),
    val videoShieldStatus: String = "Checking...",
    val videoShieldHealthy: Boolean = true,
    val messageShieldStatus: String = "Checking...",
    val messageShieldHealthy: Boolean = true,
    val callShieldStatus: String = "Checking...",
    val callShieldHealthy: Boolean = true,
    val permissions: List<PermissionStatus> = emptyList(),
    val alertCount: Int = 0,
    val rootStatus: RootDetector.RootStatus? = null,
    val error: String? = null,
    val threatDbStatus: ThreatDbStatus = ThreatDbStatus(),
    val feedStatuses: List<ThreatDatabaseUpdater.FeedSyncStatus> = emptyList(),
    val quarantinedItems: List<QuarantineEntry> = emptyList(),
    val quarantineMessage: String? = null,
    val autoQuarantineEnabled: Boolean = true,
    val batteryOptimizedScan: Boolean = true
)

@HiltViewModel
class DiagnosticsViewModel @Inject constructor(
    private val userPreferences: UserPreferences,
    private val alertRepository: AlertRepository,
    private val scanHistoryRepository: ScanHistoryRepository,
    private val antivirusEngine: AntivirusEngine,
    private val rootDetector: RootDetector,
    private val signatureDb: MalwareSignatureDatabase,
    private val threatDbUpdater: ThreatDatabaseUpdater,
    private val quarantineManager: QuarantineManager,
    @ApplicationContext private val context: Context
) : ViewModel() {

    private val _uiState = MutableStateFlow(DiagnosticsUiState())
    val uiState: StateFlow<DiagnosticsUiState> = _uiState.asStateFlow()

    private var avScanJob: Job? = null
    private var dbUpdateJob: Job? = null

    init {
        loadInitialState()
    }

    private fun defaultFeedStatuses(): List<ThreatDatabaseUpdater.FeedSyncStatus> {
        val lastReport = threatDbUpdater.getLastFeedReport()
        if (lastReport != null) return lastReport.feedStatuses
        return ThreatDatabaseUpdater.DEFAULT_FEED_URLS.map { url ->
            ThreatDatabaseUpdater.FeedSyncStatus(
                feedName = url.substringAfter("://").substringBefore("/"),
                url = url,
                succeeded = false,
                hashesFetched = 0,
                error = "Not checked in current session",
                checkedAt = 0L
            )
        }
    }

    private fun loadInitialState() {
        refreshPermissions()
        refreshThreatDbStatus()
        _uiState.update {
            it.copy(
                engineStats = antivirusEngine.getEngineStats(),
                feedStatuses = defaultFeedStatuses()
            )
        }

        viewModelScope.launch {
            val rootStatus = withContext(Dispatchers.IO) { rootDetector.checkRootStatus() }
            _uiState.update { it.copy(rootStatus = rootStatus) }
        }

        viewModelScope.launch {
            refreshQuarantineList()
        }

        viewModelScope.launch {
            userPreferences.autoQuarantineOnThreat.collect { enabled ->
                _uiState.update { it.copy(autoQuarantineEnabled = enabled) }
            }
        }

        viewModelScope.launch {
            userPreferences.batteryOptimizedScan.collect { enabled ->
                _uiState.update { it.copy(batteryOptimizedScan = enabled) }
            }
        }

        viewModelScope.launch {
            scanHistoryRepository.observeHistory(SecurityModule.DEVICE_ANTIVIRUS, 15).collect { history ->
                _uiState.update { it.copy(recentHistory = history) }
            }
        }

        viewModelScope.launch {
            combine(
                userPreferences.videoShieldEnabled,
                userPreferences.messageShieldEnabled,
                userPreferences.callShieldEnabled,
                alertRepository.getUnhandledCount()
            ) { video, message, call, alertCount ->
                _uiState.update { current ->
                    val shieldsHealthy = video && message && call
                    current.copy(
                        videoShieldStatus = if (video) "Active" else "Disabled",
                        videoShieldHealthy = video,
                        messageShieldStatus = if (message) "Active" else "Disabled",
                        messageShieldHealthy = message,
                        callShieldStatus = if (call) "Active" else "Disabled",
                        callShieldHealthy = call,
                        allSystemsHealthy = shieldsHealthy && current.avThreatsFound == 0,
                        alertCount = alertCount
                    )
                }
            }.catch { e ->
                if (e is CancellationException) throw e
            }.collect()
        }
    }

    fun refreshPermissions() {
        val permissions = checkPermissions()
        _uiState.update { it.copy(permissions = permissions) }
    }

    private fun refreshThreatDbStatus() {
        _uiState.update { current ->
            current.copy(
                engineStats = antivirusEngine.getEngineStats(),
                threatDbStatus = ThreatDbStatus(
                    totalHashes = signatureDb.getHashCount(),
                    bundledHashes = signatureDb.bundledHashCount,
                    downloadedHashes = signatureDb.downloadedHashCount,
                    lastUpdateTimeMs = threatDbUpdater.getLastUpdateTimeMs(),
                    lastUpdateStatus = threatDbUpdater.getLastUpdateStatus(),
                    isUpdating = current.threatDbStatus.isUpdating,
                    updateMessage = current.threatDbStatus.updateMessage
                )
            )
        }
    }

    fun forceUpdateThreatDb() {
        if (dbUpdateJob?.isActive == true) return
        dbUpdateJob = viewModelScope.launch {
            _uiState.update {
                it.copy(
                    threatDbStatus = it.threatDbStatus.copy(
                        isUpdating = true,
                        updateMessage = "Synchronizing public threat feeds..."
                    )
                )
            }
            try {
                val report = threatDbUpdater.updateWithFeedBreakdown()
                val okFeeds = report.feedStatuses.count { it.succeeded }
                val totalFeeds = report.feedStatuses.size
                val msg = if (report.totalHashesAdded > 0) {
                    "Synced ${report.totalHashesAdded} hashes from $okFeeds/$totalFeeds feeds"
                } else {
                    "0/$totalFeeds feeds reachable — bundled offline database active"
                }
                _uiState.update { current ->
                    current.copy(
                        engineStats = antivirusEngine.getEngineStats(),
                        feedStatuses = report.feedStatuses,
                        threatDbStatus = ThreatDbStatus(
                            totalHashes = signatureDb.getHashCount(),
                            bundledHashes = signatureDb.bundledHashCount,
                            downloadedHashes = signatureDb.downloadedHashCount,
                            lastUpdateTimeMs = threatDbUpdater.getLastUpdateTimeMs(),
                            lastUpdateStatus = threatDbUpdater.getLastUpdateStatus(),
                            isUpdating = false,
                            updateMessage = msg
                        )
                    )
                }
            } catch (e: Exception) {
                if (e is CancellationException) throw e
                _uiState.update { current ->
                    current.copy(
                        engineStats = antivirusEngine.getEngineStats(),
                        threatDbStatus = ThreatDbStatus(
                            totalHashes = signatureDb.getHashCount(),
                            bundledHashes = signatureDb.bundledHashCount,
                            downloadedHashes = signatureDb.downloadedHashCount,
                            lastUpdateTimeMs = threatDbUpdater.getLastUpdateTimeMs(),
                            lastUpdateStatus = threatDbUpdater.getLastUpdateStatus(),
                            isUpdating = false,
                            updateMessage = "Feed sync error: ${e.message ?: "Network error"}"
                        )
                    )
                }
            }
        }
    }

    fun clearDbUpdateMessage() {
        _uiState.update { it.copy(threatDbStatus = it.threatDbStatus.copy(updateMessage = null)) }
    }

    private fun refreshQuarantineList() {
        viewModelScope.launch(Dispatchers.IO) {
            try {
                val items = quarantineManager.listQuarantined()
                _uiState.update { it.copy(quarantinedItems = items) }
            } catch (e: Exception) {
                if (e is CancellationException) throw e
            }
        }
    }

    fun quarantineScanResult(scanResult: AvScanResult) {
        viewModelScope.launch(Dispatchers.IO) {
            if (scanResult.isApp) {
                _uiState.update {
                    it.copy(quarantineMessage = "Installed apps cannot be quarantined internally — use Android Uninstall.")
                }
                return@launch
            }
            if (scanResult.path.startsWith("content://")) {
                val deleted = runCatching {
                    DocumentsContract.deleteDocument(context.contentResolver, Uri.parse(scanResult.path))
                }.getOrDefault(false)
                _uiState.update {
                    it.copy(
                        quarantineMessage = if (deleted) {
                            "Removed \"${scanResult.displayName}\" via document provider."
                        } else {
                            "Document provider refused deletion for \"${scanResult.displayName}\"."
                        }
                    )
                }
                return@launch
            }
            val entry = quarantineManager.quarantine(scanResult)
            val items = quarantineManager.listQuarantined()
            _uiState.update {
                it.copy(
                    quarantinedItems = items,
                    quarantineMessage = if (entry != null) {
                        "Quarantined: ${scanResult.displayName}"
                    } else {
                        "Could not isolate \"${scanResult.displayName}\" — file may be read-only or removed."
                    }
                )
            }
        }
    }

    fun restoreQuarantinedItem(entry: QuarantineEntry) {
        viewModelScope.launch(Dispatchers.IO) {
            try {
                val success = quarantineManager.restore(entry)
                val items = quarantineManager.listQuarantined()
                _uiState.update {
                    it.copy(
                        quarantineMessage = if (success) "Restored: ${entry.displayName}" else "Failed to restore: ${entry.displayName}",
                        quarantinedItems = items
                    )
                }
            } catch (e: Exception) {
                if (e is CancellationException) throw e
                _uiState.update { it.copy(quarantineMessage = "Error: ${e.message}") }
            }
        }
    }

    fun deleteQuarantinedItem(entry: QuarantineEntry) {
        viewModelScope.launch(Dispatchers.IO) {
            try {
                val success = quarantineManager.delete(entry)
                val items = quarantineManager.listQuarantined()
                _uiState.update {
                    it.copy(
                        quarantineMessage = if (success) "Deleted: ${entry.displayName}" else "Failed to delete: ${entry.displayName}",
                        quarantinedItems = items
                    )
                }
            } catch (e: Exception) {
                if (e is CancellationException) throw e
                _uiState.update { it.copy(quarantineMessage = "Error: ${e.message}") }
            }
        }
    }

    fun clearQuarantineMessage() {
        _uiState.update { it.copy(quarantineMessage = null) }
    }

    fun setAutoQuarantine(enabled: Boolean) {
        viewModelScope.launch { userPreferences.setAutoQuarantineOnThreat(enabled) }
    }

    fun setBatteryOptimizedScan(enabled: Boolean) {
        viewModelScope.launch { userPreferences.setBatteryOptimizedScan(enabled) }
    }

    fun cancelAvScan() {
        avScanJob?.cancel()
        avScanJob = null
        _uiState.update {
            it.copy(
                isRunningAvScan = false,
                avScanProgress = "Scan cancelled by user",
                avScanProgressFraction = 0f,
                antivirusStatus = "Cancelled"
            )
        }
    }

    fun scanSingleUri(uri: Uri) {
        avScanJob?.cancel()
        avScanJob = viewModelScope.launch {
            val displayName = resolveUriDisplayName(uri)
            _uiState.update {
                it.copy(
                    isRunningAvScan = true,
                    avScanProgress = "Inspecting $displayName...",
                    avScanProgressFraction = 0.25f,
                    avScanResults = emptyList(),
                    avThreatsFound = 0,
                    avErrorsCount = 0,
                    error = null,
                    antivirusStatus = "Scanning file..."
                )
            }
            try {
                val result = antivirusEngine.scanUri(uri, displayName, AntivirusEngine.SCAN_TYPE_FILE)
                val analysis = antivirusEngine.toSecurityAnalysisResult(
                    avResult = result,
                    extraLimitations = listOf("Scanned via Android Storage Access Framework document stream ($displayName).")
                )
                scanHistoryRepository.saveResult(analysis)
                val threats = if (result.isInfected) 1 else 0
                val errors = if (result.isScanError) 1 else 0
                val scope = AvScanScopeSummary(
                    scanModeLabel = "Single File / APK Inspection",
                    discoverableCount = 1,
                    scannedCount = if (result.isScanError) 0 else 1,
                    skippedCount = errors,
                    hasFullStorageAccess = AndroidStoragePaths.hasFullStorageAccess(context),
                    limitationDisclosure = "Android isolates /data/data/<pkg> belonging to other apps; only selected document bytes were inspected."
                )
                _uiState.update {
                    it.copy(
                        isRunningAvScan = false,
                        avScanProgress = if (result.isScanError) "Scan failed: ${result.threatName}" else "Inspection complete",
                        avScanProgressFraction = 1f,
                        avScanResults = listOf(result),
                        avThreatsFound = threats,
                        avErrorsCount = errors,
                        scanScopeSummary = scope,
                        latestAnalysisResult = analysis,
                        antivirusStatus = analysis.verdict.label
                    )
                }
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                _uiState.update {
                    it.copy(
                        isRunningAvScan = false,
                        avScanProgress = "Failed: ${e.message}",
                        avScanProgressFraction = 0f,
                        error = "File scan failed: ${e.message ?: "Unable to read document"}"
                    )
                }
            }
        }
    }

    fun scanSafFolder(treeUri: Uri) {
        avScanJob?.cancel()
        avScanJob = viewModelScope.launch {
            _uiState.update {
                it.copy(
                    isRunningAvScan = true,
                    avScanProgress = "Enumerating selected folder...",
                    avScanProgressFraction = 0.05f,
                    avScanResults = emptyList(),
                    avThreatsFound = 0,
                    avErrorsCount = 0,
                    error = null,
                    antivirusStatus = "Scanning folder..."
                )
            }
            val startTime = System.currentTimeMillis()
            try {
                val (filesToScan, skippedUnreadable) = withContext(Dispatchers.IO) {
                    collectSafDocuments(treeUri, maxFiles = 300, maxBytes = 50L * 1024L * 1024L)
                }
                if (filesToScan.isEmpty()) {
                    val emptyAnalysis = SecurityAnalysisResult(
                        module = SecurityModule.DEVICE_ANTIVIRUS,
                        inputName = treeUri.lastPathSegment ?: "Selected Folder",
                        inputType = "folder/saf",
                        status = AnalysisStatus.PARTIAL,
                        verdict = SecurityVerdict.INCONCLUSIVE,
                        riskScore = null,
                        confidence = null,
                        findings = emptyList(),
                        analysisMethods = listOf("SAF Document Enumeration"),
                        limitations = listOf(
                            "No scannable files <= 50 MB found in selected folder ($skippedUnreadable oversized or virtual entries skipped)."
                        ),
                        processingDurationMs = System.currentTimeMillis() - startTime
                    )
                    scanHistoryRepository.saveResult(emptyAnalysis)
                    _uiState.update {
                        it.copy(
                            isRunningAvScan = false,
                            avScanProgress = "No scannable files in folder",
                            avScanProgressFraction = 1f,
                            latestAnalysisResult = emptyAnalysis,
                            scanScopeSummary = AvScanScopeSummary(
                                scanModeLabel = "Selected Folder (SAF)",
                                discoverableCount = skippedUnreadable,
                                scannedCount = 0,
                                skippedCount = skippedUnreadable,
                                hasFullStorageAccess = AndroidStoragePaths.hasFullStorageAccess(context),
                                limitationDisclosure = "Selected folder had 0 readable files within the 50 MB scan limit."
                            )
                        )
                    }
                    return@launch
                }

                val results = mutableListOf<AvScanResult>()
                filesToScan.forEachIndexed { idx, (docUri, name) ->
                    currentCoroutineContext().ensureActive()
                    _uiState.update {
                        it.copy(
                            avScanProgress = "Scanning $name (${idx + 1}/${filesToScan.size})",
                            avScanProgressFraction = ((idx + 1).toFloat() / filesToScan.size).coerceIn(0.05f, 0.98f)
                        )
                    }
                    results += antivirusEngine.scanUri(docUri, name, AntivirusEngine.SCAN_TYPE_FILE)
                }

                val aggregate = buildAggregateResult(
                    modeName = treeUri.lastPathSegment ?: "SAF Folder Scan",
                    inputType = "folder/saf",
                    results = results,
                    skippedOutside = skippedUnreadable,
                    durationMs = System.currentTimeMillis() - startTime
                )
                scanHistoryRepository.saveResult(aggregate)

                val threats = results.count { it.isInfected }
                val errors = results.count { it.isScanError }
                _uiState.update {
                    it.copy(
                        isRunningAvScan = false,
                        avScanProgress = "Folder scan complete (${results.size - errors} scanned)",
                        avScanProgressFraction = 1f,
                        avScanResults = results,
                        avThreatsFound = threats,
                        avErrorsCount = errors,
                        latestAnalysisResult = aggregate,
                        scanScopeSummary = AvScanScopeSummary(
                            scanModeLabel = "Selected Folder (SAF)",
                            discoverableCount = filesToScan.size + skippedUnreadable,
                            scannedCount = results.size - errors,
                            skippedCount = skippedUnreadable + errors,
                            hasFullStorageAccess = AndroidStoragePaths.hasFullStorageAccess(context),
                            limitationDisclosure = "Android SAF restricts scanning outside the user-granted directory tree."
                        ),
                        antivirusStatus = aggregate.verdict.label
                    )
                }
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                _uiState.update {
                    it.copy(
                        isRunningAvScan = false,
                        avScanProgress = "Folder scan error: ${e.message}",
                        avScanProgressFraction = 0f,
                        error = "Folder scan failed: ${e.message ?: "Unable to read SAF folder"}"
                    )
                }
            }
        }
    }

    fun runFullAvScan() {
        if (avScanJob?.isActive == true) return
        avScanJob = viewModelScope.launch {
            val startTime = System.currentTimeMillis()
            val hasFullStorage = AndroidStoragePaths.hasFullStorageAccess(context)
            _uiState.update {
                it.copy(
                    isRunningAvScan = true,
                    avScanProgress = "Enumerating installed APKs & accessible storage...",
                    avScanProgressFraction = 0.04f,
                    avScanResults = emptyList(),
                    avThreatsFound = 0,
                    avErrorsCount = 0,
                    error = null,
                    antivirusStatus = "Scanning..."
                )
            }
            try {
                val results = antivirusEngine.runFullScan(
                    scanType = AntivirusEngine.SCAN_TYPE_ONDEMAND
                ) { scanned, total, current ->
                    val frac = if (total > 0) (scanned.toFloat() / total).coerceIn(0.05f, 0.99f) else 0.5f
                    _uiState.update {
                        it.copy(
                            avScanProgress = "Scanning $current ($scanned/$total)",
                            avScanProgressFraction = frac
                        )
                    }
                }

                // Only attempt auto-quarantine for writable local files (never APKs or SAF content:// URIs)
                if (_uiState.value.autoQuarantineEnabled) {
                    withContext(Dispatchers.IO) {
                        results.filter { it.isInfected && !it.isApp && !it.path.startsWith("content://") }
                            .forEach { threat ->
                                runCatching { quarantineManager.quarantine(threat) }
                            }
                    }
                }

                val threats = results.count { it.isInfected }
                val errors = results.count { it.isScanError }
                val scannedOk = results.size - errors
                val quarantineItems = withContext(Dispatchers.IO) {
                    runCatching { quarantineManager.listQuarantined() }.getOrDefault(emptyList())
                }

                val aggregate = buildAggregateResult(
                    modeName = if (hasFullStorage) "Installed APKs & Shared Storage" else "Installed APKs Only",
                    inputType = "device/storage-and-packages",
                    results = results,
                    skippedOutside = 0,
                    durationMs = System.currentTimeMillis() - startTime
                )
                scanHistoryRepository.saveResult(aggregate)

                _uiState.update {
                    it.copy(
                        isRunningAvScan = false,
                        avScanProgress = "Scan finished: $scannedOk scanned, $threats threats, $errors skipped/errors",
                        avScanProgressFraction = 1f,
                        avScanResults = results,
                        avThreatsFound = threats,
                        avErrorsCount = errors,
                        quarantinedItems = quarantineItems,
                        latestAnalysisResult = aggregate,
                        scanScopeSummary = AvScanScopeSummary(
                            scanModeLabel = if (hasFullStorage) "Installed APKs + Accessible Storage" else "Installed APKs Only (No Full Storage Permission)",
                            discoverableCount = results.size,
                            scannedCount = scannedOk,
                            skippedCount = errors,
                            hasFullStorageAccess = hasFullStorage,
                            limitationDisclosure = buildString {
                                append("Android app sandboxing blocks reading private /data/data directories of other installed apps. ")
                                if (!hasFullStorage) {
                                    append("Full Storage Access is not granted: shared Downloads/Documents folders were not scanned unless selected manually.")
                                }
                            }
                        ),
                        antivirusStatus = aggregate.verdict.label
                    )
                }
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                _uiState.update {
                    it.copy(
                        isRunningAvScan = false,
                        avScanProgress = "Error: ${e.message}",
                        avScanProgressFraction = 0f,
                        error = "Scan failed: ${e.message ?: "Unknown error"}"
                    )
                }
            }
        }
    }

    fun clearError() {
        _uiState.update { it.copy(error = null) }
    }

    private fun buildAggregateResult(
        modeName: String,
        inputType: String,
        results: List<AvScanResult>,
        skippedOutside: Int,
        durationMs: Long
    ): SecurityAnalysisResult {
        val infected = results.filter { it.isInfected }
        val suspicious = results.filter { it.threatLevel == ThreatLevel.SUSPICIOUS || it.threatLevel == ThreatLevel.PUA }
        val errors = results.filter { it.isScanError }
        val totalScannedOk = results.size - errors.size
        val hasStorage = AndroidStoragePaths.hasFullStorageAccess(context)

        val status = when {
            results.isEmpty() -> AnalysisStatus.FAILED
            errors.isNotEmpty() || skippedOutside > 0 || !hasStorage -> AnalysisStatus.PARTIAL
            else -> AnalysisStatus.COMPLETED
        }
        val verdict = when {
            results.isEmpty() -> SecurityVerdict.NOT_ANALYZED
            infected.isNotEmpty() -> SecurityVerdict.MALICIOUS
            suspicious.isNotEmpty() -> SecurityVerdict.HIGH_RISK
            results.any { it.threatLevel == ThreatLevel.LOW_RISK } -> SecurityVerdict.LOW_RISK
            totalScannedOk == 0 -> SecurityVerdict.INCONCLUSIVE
            else -> SecurityVerdict.SAFE
        }
        val riskScore = when {
            totalScannedOk == 0 -> null
            infected.isNotEmpty() -> 95
            suspicious.isNotEmpty() -> 65
            results.any { it.threatLevel == ThreatLevel.LOW_RISK } -> 25
            else -> 0
        }

        val allFindings = (infected + suspicious + errors.take(5)).flatMap { item ->
            if (item.isScanError) {
                listOf(
                    SecurityFinding(
                        title = "Skipped / Unreadable Item: ${item.displayName}",
                        description = item.threatName ?: "Unable to read item",
                        severity = FindingSeverity.INFO,
                        evidenceSource = "Filesystem / PackageManager",
                        detectionMethod = "Readability Check",
                        inputLocation = item.path,
                        explanation = "This item could not be inspected cleanly within Android sandbox rules.",
                        recommendedAction = "Verify permissions or pick the file directly using Document Picker."
                    )
                )
            } else {
                antivirusEngine.toSecurityAnalysisResult(item).findings.map {
                    it.copy(inputLocation = "${item.displayName} (${it.inputLocation ?: item.path})")
                }
            }
        }
        val findingsTruncated = allFindings.size > 40
        val findings = if (findingsTruncated) allFindings.take(40) else allFindings

        val stats = antivirusEngine.getEngineStats()
        val methods = listOf(
            "SHA-256 Local Signature Lookup (${stats.totalHashSignatures} hashes)",
            "Byte Pattern Matching (${stats.bytePatternCount} patterns)",
            "YARA Rules (${stats.yaraRuleCount} rules)",
            "Heuristic Structural/Permission Analysis (${stats.heuristicIndicatorCount} rules)"
        )
        val limitations = buildList {
            add("Android isolates private /data/data/<pkg> internal files of other apps; only discoverable APKs and accessible storage were inspected.")
            if (!hasStorage) {
                add("All-files storage permission not granted; shared storage directories were excluded.")
            }
            if (errors.isNotEmpty() || skippedOutside > 0) {
                add("${errors.size + skippedOutside} discovered items could not be read or exceeded the 50 MB size cap.")
            }
            if (findingsTruncated) {
                add("History summary truncated to the top 40 of ${allFindings.size} findings; inspect individual entries below.")
            }
        }

        return SecurityAnalysisResult(
            analysisId = UUID.randomUUID().toString(),
            module = SecurityModule.DEVICE_ANTIVIRUS,
            inputName = modeName,
            inputType = inputType,
            status = status,
            verdict = verdict,
            riskScore = riskScore,
            confidence = null,
            findings = findings,
            analysisMethods = methods,
            limitations = limitations,
            processingDurationMs = durationMs,
            metadata = mapOf(
                "totalItems" to results.size.toString(),
                "scannedOk" to totalScannedOk.toString(),
                "infectedCount" to infected.size.toString(),
                "suspiciousCount" to suspicious.size.toString(),
                "errorOrSkipped" to (errors.size + skippedOutside).toString()
            )
        )
    }

    private fun resolveUriDisplayName(uri: Uri): String {
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
        return uri.lastPathSegment ?: "selected_file"
    }

    private fun collectSafDocuments(
        treeUri: Uri,
        maxFiles: Int,
        maxBytes: Long
    ): Pair<List<Pair<Uri, String>>, Int> {
        val rootDocId = DocumentsContract.getTreeDocumentId(treeUri)
        val queue = ArrayDeque<String>().apply { add(rootDocId) }
        val files = mutableListOf<Pair<Uri, String>>()
        var skipped = 0

        val projection = arrayOf(
            DocumentsContract.Document.COLUMN_DOCUMENT_ID,
            DocumentsContract.Document.COLUMN_DISPLAY_NAME,
            DocumentsContract.Document.COLUMN_MIME_TYPE,
            DocumentsContract.Document.COLUMN_SIZE
        )

        while (queue.isNotEmpty() && files.size < maxFiles) {
            val currentDocId = queue.removeFirst()
            val childrenUri = DocumentsContract.buildChildDocumentsUriUsingTree(treeUri, currentDocId)
            try {
                context.contentResolver.query(childrenUri, projection, null, null, null)?.use { cursor ->
                    val idCol = cursor.getColumnIndex(DocumentsContract.Document.COLUMN_DOCUMENT_ID)
                    val nameCol = cursor.getColumnIndex(DocumentsContract.Document.COLUMN_DISPLAY_NAME)
                    val mimeCol = cursor.getColumnIndex(DocumentsContract.Document.COLUMN_MIME_TYPE)
                    val sizeCol = cursor.getColumnIndex(DocumentsContract.Document.COLUMN_SIZE)

                    while (cursor.moveToNext() && files.size < maxFiles) {
                        val childId = if (idCol >= 0) cursor.getString(idCol) else continue
                        val name = if (nameCol >= 0) cursor.getString(nameCol) ?: childId else childId
                        val mime = if (mimeCol >= 0) cursor.getString(mimeCol) ?: "" else ""
                        val size = if (sizeCol >= 0 && !cursor.isNull(sizeCol)) cursor.getLong(sizeCol) else 0L

                        if (mime == DocumentsContract.Document.MIME_TYPE_DIR) {
                            queue.addLast(childId)
                        } else if (mime.startsWith("vnd.android.document/") || size > maxBytes) {
                            skipped++
                        } else {
                            val docUri = DocumentsContract.buildDocumentUriUsingTree(treeUri, childId)
                            files += docUri to name
                        }
                    }
                } ?: run { skipped++ }
            } catch (_: Exception) {
                skipped++
            }
        }
        return files to skipped
    }

    private fun checkPermissions(): List<PermissionStatus> {
        val permissions = mutableListOf<PermissionStatus>()
        val hasStorageAccess = AndroidStoragePaths.hasFullStorageAccess(context)
        permissions.add(PermissionStatus("All-Files Storage Access", hasStorageAccess, required = false))
        permissions.add(
            PermissionStatus(
                "SMS Reading",
                ContextCompat.checkSelfPermission(context, Manifest.permission.RECEIVE_SMS) == PackageManager.PERMISSION_GRANTED,
                required = true
            )
        )
        permissions.add(
            PermissionStatus(
                "Phone State",
                ContextCompat.checkSelfPermission(context, Manifest.permission.READ_PHONE_STATE) == PackageManager.PERMISSION_GRANTED,
                required = true
            )
        )
        permissions.add(
            PermissionStatus(
                "Call Log",
                ContextCompat.checkSelfPermission(context, Manifest.permission.READ_CALL_LOG) == PackageManager.PERMISSION_GRANTED,
                required = false
            )
        )
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            permissions.add(
                PermissionStatus(
                    "Notifications",
                    ContextCompat.checkSelfPermission(context, Manifest.permission.POST_NOTIFICATIONS) == PackageManager.PERMISSION_GRANTED,
                    required = true
                )
            )
        }
        permissions.add(
            PermissionStatus(
                "Microphone",
                ContextCompat.checkSelfPermission(context, Manifest.permission.RECORD_AUDIO) == PackageManager.PERMISSION_GRANTED,
                required = false
            )
        )
        return permissions
    }
}
