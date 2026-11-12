package com.deepfakeshield.feature.diagnostics

import android.content.Intent
import android.net.Uri
import android.os.Build
import android.os.Environment
import android.provider.Settings
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.*
import androidx.compose.material.icons.outlined.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.hilt.navigation.compose.hiltViewModel
import com.deepfakeshield.av.engine.AvScanResult
import com.deepfakeshield.av.engine.ThreatLevel
import com.deepfakeshield.core.model.AnalysisStatus
import com.deepfakeshield.core.model.ScanProgressState
import com.deepfakeshield.core.ui.components.*
import com.deepfakeshield.core.ui.theme.*
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

private val TabularDiagStyle = TextStyle(fontFeatureSettings = "tnum")

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun DiagnosticsScreen(
    viewModel: DiagnosticsViewModel = hiltViewModel(),
    onNavigateBack: () -> Unit = {}
) {
    val uiState by viewModel.uiState.collectAsState()
    val context = LocalContext.current
    val snackbar = remember { SnackbarHostState() }
    var tab by remember { mutableIntStateOf(0) }

    val singleFilePicker = rememberLauncherForActivityResult(
        ActivityResultContracts.OpenDocument()
    ) { uri: Uri? ->
        uri?.let { viewModel.scanSingleUri(it) }
    }

    val folderPicker = rememberLauncherForActivityResult(
        ActivityResultContracts.OpenDocumentTree()
    ) { treeUri: Uri? ->
        treeUri?.let { viewModel.scanSafFolder(it) }
    }

    LaunchedEffect(uiState.quarantineMessage) {
        uiState.quarantineMessage?.let {
            snackbar.showSnackbar(it)
            viewModel.clearQuarantineMessage()
        }
    }
    LaunchedEffect(uiState.threatDbStatus.updateMessage) {
        uiState.threatDbStatus.updateMessage?.let {
            snackbar.showSnackbar(it)
            viewModel.clearDbUpdateMessage()
        }
    }

    val stats = uiState.engineStats

    Scaffold(
        topBar = {
            Column {
                TopAppBar(
                    title = {
                        Column {
                            Text(
                                "Device Antivirus",
                                style = MaterialTheme.typography.titleMedium,
                                fontWeight = FontWeight.SemiBold,
                                color = TextPrimary
                            )
                            Text(
                                "${stats.totalHashSignatures} Signatures • ${stats.yaraRuleCount} YARA • ${stats.heuristicIndicatorCount} Heuristics",
                                style = TabularDiagStyle.copy(fontSize = 12.sp),
                                color = TextSecondary
                            )
                        }
                    },
                    navigationIcon = {
                        IconButton(onClick = onNavigateBack) {
                            Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back", tint = TextPrimary)
                        }
                    },
                    colors = TopAppBarDefaults.topAppBarColors(containerColor = SurfaceLight)
                )
                HorizontalDivider(color = BorderColor)
            }
        },
        snackbarHost = { SnackbarHost(snackbar) },
        containerColor = BackgroundLight
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
        ) {
            SecondaryScrollableTabRow(
                selectedTabIndex = tab,
                edgePadding = 16.dp,
                containerColor = SurfaceLight,
                contentColor = SentinelPrimary,
                divider = { HorizontalDivider(color = BorderColor) }
            ) {
                listOf("Scanner", "Threat DB", "Quarantine (${uiState.quarantinedItems.size})", "Scope").forEachIndexed { i, title ->
                    Tab(
                        selected = tab == i,
                        onClick = { tab = i },
                        text = {
                            Text(
                                text = title,
                                fontSize = 13.sp,
                                fontWeight = if (tab == i) FontWeight.SemiBold else FontWeight.Medium,
                                color = if (tab == i) SentinelPrimary else TextSecondary
                            )
                        }
                    )
                }
            }

            when (tab) {
                0 -> ScannerTabContent(
                    uiState = uiState,
                    onRunFullScan = { viewModel.runFullAvScan() },
                    onPickFile = { singleFilePicker.launch(arrayOf("*/*")) },
                    onPickFolder = { folderPicker.launch(null) },
                    onCancelScan = { viewModel.cancelAvScan() },
                    onClearError = { viewModel.clearError() },
                    onQuarantineResult = { viewModel.quarantineScanResult(it) },
                    onUninstallPackage = { pkg ->
                        runCatching {
                            context.startActivity(
                                Intent(Intent.ACTION_DELETE, Uri.parse("package:$pkg")).apply {
                                    addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                                }
                            )
                        }
                    },
                    onOpenStoragePermission = {
                        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                            runCatching {
                                context.startActivity(
                                    Intent(
                                        Settings.ACTION_MANAGE_APP_ALL_FILES_ACCESS_PERMISSION,
                                        Uri.parse("package:${context.packageName}")
                                    )
                                )
                            }
                        }
                    }
                )
                1 -> ThreatDatabaseTabContent(
                    uiState = uiState,
                    onForceSync = { viewModel.forceUpdateThreatDb() }
                )
                2 -> QuarantineTabContent(
                    uiState = uiState,
                    onRestore = { viewModel.restoreQuarantinedItem(it) },
                    onDelete = { viewModel.deleteQuarantinedItem(it) }
                )
                else -> ScopeAndSettingsTabContent(
                    uiState = uiState,
                    onToggleAutoQuarantine = { viewModel.setAutoQuarantine(it) },
                    onToggleBatteryOpt = { viewModel.setBatteryOptimizedScan(it) },
                    onRefreshPermissions = { viewModel.refreshPermissions() },
                    onOpenStorageSettings = {
                        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                            runCatching {
                                context.startActivity(
                                    Intent(
                                        Settings.ACTION_MANAGE_APP_ALL_FILES_ACCESS_PERMISSION,
                                        Uri.parse("package:${context.packageName}")
                                    )
                                )
                            }
                        }
                    }
                )
            }
        }
    }
}

@Composable
private fun ScannerTabContent(
    uiState: DiagnosticsUiState,
    onRunFullScan: () -> Unit,
    onPickFile: () -> Unit,
    onPickFolder: () -> Unit,
    onCancelScan: () -> Unit,
    onClearError: () -> Unit,
    onQuarantineResult: (AvScanResult) -> Unit,
    onUninstallPackage: (String) -> Unit,
    onOpenStoragePermission: () -> Unit
) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(horizontal = 20.dp, vertical = 16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        ClinicalSurfaceCard {
            Text(
                text = "Malware & APK Forensics",
                style = MaterialTheme.typography.titleSmall,
                fontWeight = FontWeight.SemiBold,
                color = TextPrimary
            )
            Spacer(Modifier.height(4.dp))
            Text(
                text = "Inspects APKs, Documents, and Downloads against SHA-256 signatures, byte patterns, YARA rules, and APK permission heuristics.",
                style = MaterialTheme.typography.bodySmall,
                color = TextSecondary
            )

            Spacer(Modifier.height(14.dp))

            if (uiState.isRunningAvScan) {
                ForensicStageProgressCard(
                    progressState = ScanProgressState.Running(
                        stageTitle = "Antivirus Scan Running",
                        completedSteps = (uiState.avScanProgressFraction * 100f).toInt().coerceIn(0, 100),
                        totalSteps = 100,
                        detail = uiState.avScanProgress.ifBlank { "Scanning..." }
                    ),
                    onCancel = onCancelScan
                )
            } else {
                Button(
                    onClick = onRunFullScan,
                    modifier = Modifier
                        .fillMaxWidth()
                        .height(52.dp),
                    shape = RoundedCornerShape(12.dp),
                    colors = ButtonDefaults.buttonColors(
                    containerColor = SentinelPrimary,
                    contentColor = Color.White,
                    disabledContainerColor = SurfaceSubtle,
                    disabledContentColor = TextTertiary
                )
                ) {
                    Icon(Icons.Filled.Search, contentDescription = null, modifier = Modifier.size(18.dp))
                    Spacer(Modifier.width(8.dp))
                    Text("Scan Installed APKs & Storage", fontWeight = FontWeight.SemiBold)
                }

                Spacer(Modifier.height(10.dp))

                Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                    OutlinedButton(
                        onClick = onPickFile,
                        modifier = Modifier
                            .weight(1f)
                            .height(46.dp),
                        shape = RoundedCornerShape(12.dp),
                        border = BorderStroke(1.dp, BorderColor),
                        contentPadding = PaddingValues(horizontal = 8.dp)
                    ) {
                        Icon(Icons.Outlined.InsertDriveFile, contentDescription = null, modifier = Modifier.size(16.dp), tint = TextPrimary)
                        Spacer(Modifier.width(6.dp))
                        Text("Pick File", fontSize = 12.sp, color = TextPrimary, fontWeight = FontWeight.Medium, maxLines = 1, softWrap = false)
                    }
                    OutlinedButton(
                        onClick = onPickFolder,
                        modifier = Modifier
                            .weight(1f)
                            .height(46.dp),
                        shape = RoundedCornerShape(12.dp),
                        border = BorderStroke(1.dp, BorderColor),
                        contentPadding = PaddingValues(horizontal = 8.dp)
                    ) {
                        Icon(Icons.Outlined.FolderOpen, contentDescription = null, modifier = Modifier.size(16.dp), tint = TextPrimary)
                        Spacer(Modifier.width(6.dp))
                        Text("Scan Folder", fontSize = 12.sp, color = TextPrimary, fontWeight = FontWeight.Medium, maxLines = 1, softWrap = false)
                    }
                }
            }
        }

        // Honest Android Sandbox Scope Disclosure (Rule 8)
        val hasStoragePerm = Build.VERSION.SDK_INT < Build.VERSION_CODES.R || Environment.isExternalStorageManager()
        ClinicalSurfaceCard(
            containerColor = SurfaceSubtle,
            contentPadding = PaddingValues(14.dp)
        ) {
            Row(verticalAlignment = Alignment.Top, horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                Icon(Icons.Outlined.Info, contentDescription = null, tint = TextSecondary, modifier = Modifier.size(18.dp))
                Column(modifier = Modifier.weight(1f)) {
                    Text("Android Sandbox Boundary", fontSize = 12.sp, fontWeight = FontWeight.SemiBold, color = TextPrimary)
                    Spacer(Modifier.height(2.dp))
                    Text(
                        text = if (hasStoragePerm) {
                            "Inspects installed base APKs and readable shared storage. Private /data/data directories of other apps are strictly isolated by Android OS."
                        } else {
                            "All-Files Access is not granted: shared Downloads are excluded unless picked via 'Pick File / APK' or 'Scan Folder', and private /data/data of other apps cannot be read."
                        },
                        fontSize = 11.sp,
                        color = TextSecondary
                    )
                    if (!hasStoragePerm && Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                        Spacer(Modifier.height(6.dp))
                        TextButton(onClick = onOpenStoragePermission, contentPadding = PaddingValues(0.dp)) {
                            Text("Grant All-Files Storage Access", fontSize = 12.sp, color = SentinelPrimary, fontWeight = FontWeight.SemiBold)
                        }
                    }
                }
            }
        }

        uiState.error?.let { err ->
            ClinicalSurfaceCard(
                containerColor = DangerContainer,
                borderColor = DangerRed.copy(alpha = 0.25f),
                contentPadding = PaddingValues(14.dp)
            ) {
                Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                    Icon(Icons.Filled.Error, contentDescription = null, tint = DangerRed)
                    Text(err, style = MaterialTheme.typography.bodySmall, color = DangerRed, modifier = Modifier.weight(1f))
                    IconButton(onClick = onClearError) {
                        Icon(Icons.Filled.Close, contentDescription = "Dismiss", tint = DangerRed)
                    }
                }
            }
        }

        uiState.scanScopeSummary?.let { scope ->
            ClinicalSurfaceCard {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Column(modifier = Modifier.weight(1f)) {
                        Text(scope.scanModeLabel, style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.SemiBold, color = TextPrimary)
                        Text(uiState.avScanProgress, fontSize = 12.sp, color = TextSecondary)
                    }
                    uiState.latestAnalysisResult?.let { VerdictStatusPill(verdict = it.verdict) }
                }
                Spacer(Modifier.height(10.dp))
                Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    AvMetricChip("Found", "${scope.discoverableCount}", Modifier.weight(1f))
                    AvMetricChip("Scanned", "${scope.scannedCount}", Modifier.weight(1f))
                    AvMetricChip("Threats", "${uiState.avThreatsFound}", Modifier.weight(1f))
                    AvMetricChip("Skipped", "${scope.skippedCount}", Modifier.weight(1f))
                }
                if (scope.limitationDisclosure.isNotBlank()) {
                    Spacer(Modifier.height(8.dp))
                    Text(scope.limitationDisclosure, fontSize = 11.sp, color = TextSecondary)
                }
            }
        }

        // Flagged items (malware, suspicious, PUA, errors) first
        val flagged = uiState.avScanResults.filter { !it.isClean }
        if (flagged.isNotEmpty()) {
            SectionHeaderRow(
                title = "Flagged & Unreadable Items (${flagged.size})",
                subtitle = "Inspect indicators, quarantine files, or uninstall apps"
            )
            flagged.forEach { item ->
                AvScanResultCard(
                    result = item,
                    onQuarantine = { onQuarantineResult(item) },
                    onUninstall = { item.packageName?.let(onUninstallPackage) }
                )
            }
        }

        uiState.latestAnalysisResult?.let { analysis ->
            if (analysis.findings.isNotEmpty()) {
                SectionHeaderRow(title = "Evidence Details", subtitle = "Structured scan findings")
                analysis.findings.take(10).forEach { FindingEvidenceRow(it) }
            }
            LimitationDisclosureCard(methods = analysis.analysisMethods, limitations = analysis.limitations)
        }

        if (uiState.recentHistory.isNotEmpty()) {
            SectionHeaderRow(title = "Recent Antivirus Runs", subtitle = "Persisted in local Room database")
            ClinicalSurfaceCard(contentPadding = PaddingValues(0.dp)) {
                val fmt = remember { SimpleDateFormat("MMM d, HH:mm", Locale.getDefault()) }
                uiState.recentHistory.take(8).forEachIndexed { idx, item ->
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(horizontal = 16.dp, vertical = 12.dp),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(10.dp)
                    ) {
                        Column(modifier = Modifier.weight(1f)) {
                            Text(
                                text = item.inputName ?: "Antivirus Scan",
                                fontSize = 13.sp,
                                fontWeight = FontWeight.Medium,
                                color = TextPrimary,
                                maxLines = 1,
                                overflow = TextOverflow.Ellipsis
                            )
                            val scannedLabel = item.metadata["scannedOk"]
                                ?: if (item.status == AnalysisStatus.FAILED) "0" else "1"
                            Text(
                                text = "${fmt.format(Date(item.analyzedAt))} • ${item.status.name} • $scannedLabel scanned",
                                style = TabularDiagStyle.copy(fontSize = 11.sp),
                                color = TextSecondary
                            )
                        }
                        VerdictStatusPill(verdict = item.verdict)
                    }
                    if (idx < uiState.recentHistory.take(8).lastIndex) {
                        HorizontalDivider(color = BorderColor, modifier = Modifier.padding(horizontal = 16.dp))
                    }
                }
            }
        }
    }
}

@Composable
private fun AvScanResultCard(
    result: AvScanResult,
    onQuarantine: () -> Unit,
    onUninstall: () -> Unit
) {
    val badgeBg = when (result.threatLevel) {
        ThreatLevel.INFECTED -> DangerContainer
        ThreatLevel.SUSPICIOUS -> WarningContainer
        ThreatLevel.PUA, ThreatLevel.LOW_RISK -> SentinelPrimaryContainer
        ThreatLevel.SCAN_ERROR -> SurfaceSubtle
        ThreatLevel.CLEAN -> SuccessContainer
    }
    val badgeColor = when (result.threatLevel) {
        ThreatLevel.INFECTED -> DangerRed
        ThreatLevel.SUSPICIOUS -> WarningAmber
        ThreatLevel.PUA, ThreatLevel.LOW_RISK -> SentinelPrimary
        ThreatLevel.SCAN_ERROR -> TextSecondary
        ThreatLevel.CLEAN -> SuccessGreen
    }

    ClinicalSurfaceCard {
        Row(
            modifier = Modifier.fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(10.dp)
        ) {
            Column(modifier = Modifier.weight(1f)) {
                Text(result.displayName, style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.SemiBold, color = TextPrimary)
                Text(
                    text = result.threatName ?: result.path,
                    fontSize = 12.sp,
                    color = TextSecondary,
                    maxLines = 2,
                    overflow = TextOverflow.Ellipsis
                )
            }
            Surface(shape = RoundedCornerShape(999.dp), color = badgeBg) {
                Text(
                    text = result.threatLevel.name,
                    modifier = Modifier.padding(horizontal = 10.dp, vertical = 4.dp),
                    fontSize = 11.sp,
                    fontWeight = FontWeight.SemiBold,
                    color = badgeColor
                )
            }
        }

        if (result.indicators.isNotEmpty()) {
            Spacer(Modifier.height(8.dp))
            result.indicators.take(4).forEach { ind ->
                Text("- [${ind.type.name}/${ind.severity.name}] ${ind.title}: ${ind.description}", fontSize = 11.sp, color = TextSecondary)
            }
        }

        if (result.isInfected || result.threatLevel == ThreatLevel.SUSPICIOUS) {
            Spacer(Modifier.height(10.dp))
            Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.End) {
                if (result.isApp && !result.packageName.isNullOrBlank()) {
                    OutlinedButton(onClick = onUninstall, shape = RoundedCornerShape(10.dp), border = BorderStroke(1.dp, DangerRed)) {
                        Text("Uninstall App", color = DangerRed, fontSize = 12.sp, fontWeight = FontWeight.SemiBold)
                    }
                } else {
                    OutlinedButton(onClick = onQuarantine, shape = RoundedCornerShape(10.dp), border = BorderStroke(1.dp, DangerRed)) {
                        Text("Quarantine File", color = DangerRed, fontSize = 12.sp, fontWeight = FontWeight.SemiBold)
                    }
                }
            }
        }
    }
}

@Composable
private fun ThreatDatabaseTabContent(
    uiState: DiagnosticsUiState,
    onForceSync: () -> Unit
) {
    val db = uiState.threatDbStatus
    val stats = uiState.engineStats
    val fmt = remember { SimpleDateFormat("MMM d, yyyy HH:mm", Locale.getDefault()) }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(horizontal = 20.dp, vertical = 16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        ClinicalSurfaceCard {
            Text("Local & Public Signature Inventory", style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.SemiBold, color = TextPrimary)
            Spacer(Modifier.height(4.dp))
            Text(
                text = if (db.lastUpdateTimeMs > 0L) "Last feed sync: ${fmt.format(Date(db.lastUpdateTimeMs))}" else db.lastUpdateStatus,
                fontSize = 12.sp,
                color = TextSecondary
            )
            Spacer(Modifier.height(12.dp))
            Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                AvMetricChip("Bundled Hashes", "${stats.bundledHashCount}", Modifier.weight(1f))
                AvMetricChip("Synced Hashes", "${stats.downloadedHashCount}", Modifier.weight(1f))
                AvMetricChip("Total Hashes", "${stats.totalHashSignatures}", Modifier.weight(1f))
            }
            Spacer(Modifier.height(8.dp))
            Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                AvMetricChip("Byte Patterns", "${stats.bytePatternCount}", Modifier.weight(1f))
                AvMetricChip("YARA Rules", "${stats.yaraRuleCount}", Modifier.weight(1f))
                AvMetricChip("Heuristics", "${stats.heuristicIndicatorCount}", Modifier.weight(1f))
            }
            Spacer(Modifier.height(14.dp))
            Button(
                onClick = onForceSync,
                enabled = !db.isUpdating,
                modifier = Modifier
                    .fillMaxWidth()
                    .height(48.dp),
                shape = RoundedCornerShape(12.dp),
                colors = ButtonDefaults.buttonColors(
                    containerColor = SentinelPrimary,
                    contentColor = Color.White,
                    disabledContainerColor = SurfaceSubtle,
                    disabledContentColor = TextTertiary
                )
            ) {
                if (db.isUpdating) {
                    CircularProgressIndicator(Modifier.size(16.dp), strokeWidth = 2.dp, color = Color.White)
                    Spacer(Modifier.width(8.dp))
                    Text("Syncing Public Threat Feeds...")
                } else {
                    Icon(Icons.Filled.Sync, contentDescription = null, modifier = Modifier.size(18.dp))
                    Spacer(Modifier.width(8.dp))
                    Text("Sync Public Threat Intelligence Feeds")
                }
            }
        }

        SectionHeaderRow(
            title = "Configured Threat Feeds (${uiState.feedStatuses.size})",
            subtitle = "Real per-feed sync state — offline feeds never show healthy"
        )
        ClinicalSurfaceCard(contentPadding = PaddingValues(0.dp)) {
            uiState.feedStatuses.forEachIndexed { idx, feed ->
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(horizontal = 16.dp, vertical = 12.dp),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(10.dp)
                ) {
                    Box(
                        modifier = Modifier
                            .size(10.dp)
                            .background(
                                color = when {
                                    feed.succeeded -> SuccessGreen
                                    feed.checkedAt > 0L -> WarningAmber
                                    else -> TextTertiary
                                },
                                shape = CircleShape
                            )
                    )
                    Column(modifier = Modifier.weight(1f)) {
                        Text(feed.feedName, fontSize = 13.sp, fontWeight = FontWeight.Medium, color = TextPrimary)
                        Text(
                            text = when {
                                feed.succeeded -> "+${feed.hashesFetched} hashes synced"
                                !feed.error.isNullOrBlank() -> feed.error!!
                                else -> "Not synced yet"
                            },
                            fontSize = 11.sp,
                            color = TextSecondary,
                            maxLines = 2,
                            overflow = TextOverflow.Ellipsis
                        )
                    }
                    Text(
                        text = if (feed.succeeded) "Online" else if (feed.checkedAt > 0L) "Failed" else "Idle",
                        fontSize = 11.sp,
                        fontWeight = FontWeight.SemiBold,
                        color = if (feed.succeeded) SuccessGreen else if (feed.checkedAt > 0L) WarningAmber else TextSecondary
                    )
                }
                if (idx < uiState.feedStatuses.lastIndex) {
                    HorizontalDivider(color = BorderColor, modifier = Modifier.padding(horizontal = 16.dp))
                }
            }
        }
    }
}

@Composable
private fun QuarantineTabContent(
    uiState: DiagnosticsUiState,
    onRestore: (com.deepfakeshield.av.engine.QuarantineEntry) -> Unit,
    onDelete: (com.deepfakeshield.av.engine.QuarantineEntry) -> Unit
) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(horizontal = 20.dp, vertical = 16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        if (uiState.quarantinedItems.isEmpty()) {
            ClinicalEmptyState(
                icon = Icons.Outlined.Lock,
                title = "Quarantine Locker Empty",
                description = "Isolated files moved here are XOR-obfuscated and removed from shared storage."
            )
        } else {
            uiState.quarantinedItems.forEach { entry ->
                ClinicalSurfaceCard {
                    Text(entry.displayName, style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.SemiBold, color = TextPrimary)
                    Text(entry.threatName ?: "Quarantined Item", fontSize = 12.sp, color = DangerRed)
                    Text("Original: ${entry.originalPath}", fontSize = 11.sp, color = TextSecondary, maxLines = 1, overflow = TextOverflow.Ellipsis)
                    Spacer(Modifier.height(10.dp))
                    Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                        OutlinedButton(onClick = { onRestore(entry) }, modifier = Modifier.weight(1f), shape = RoundedCornerShape(10.dp)) {
                            Text("Restore")
                        }
                        OutlinedButton(
                            onClick = { onDelete(entry) },
                            modifier = Modifier.weight(1f),
                            shape = RoundedCornerShape(10.dp),
                            border = BorderStroke(1.dp, DangerRed)
                        ) {
                            Text("Delete", color = DangerRed)
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun ScopeAndSettingsTabContent(
    uiState: DiagnosticsUiState,
    onToggleAutoQuarantine: (Boolean) -> Unit,
    onToggleBatteryOpt: (Boolean) -> Unit,
    onRefreshPermissions: () -> Unit,
    onOpenStorageSettings: () -> Unit
) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(horizontal = 20.dp, vertical = 16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        ClinicalSurfaceCard(contentPadding = PaddingValues(0.dp)) {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 16.dp, vertical = 12.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                Column(modifier = Modifier.weight(1f)) {
                    Text("Auto-Quarantine Infected Files", fontWeight = FontWeight.SemiBold, fontSize = 14.sp, color = TextPrimary)
                    Text("Automatically isolate confirmed malware outside APKs", fontSize = 12.sp, color = TextSecondary)
                }
                Switch(checked = uiState.autoQuarantineEnabled, onCheckedChange = onToggleAutoQuarantine)
            }
            HorizontalDivider(color = BorderColor, modifier = Modifier.padding(horizontal = 16.dp))
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 16.dp, vertical = 12.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                Column(modifier = Modifier.weight(1f)) {
                    Text("Battery-Aware Background Scanning", fontWeight = FontWeight.SemiBold, fontSize = 14.sp, color = TextPrimary)
                    Text("Throttle heavy heuristics on low battery", fontSize = 12.sp, color = TextSecondary)
                }
                Switch(checked = uiState.batteryOptimizedScan, onCheckedChange = onToggleBatteryOpt)
            }
        }

        uiState.rootStatus?.let { root ->
            ClinicalSurfaceCard {
                Text("Device Integrity & Root Check", style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.SemiBold, color = TextPrimary)
                Spacer(Modifier.height(4.dp))
                Text(
                    text = if (root.isRooted) {
                        val details = root.reasons.takeIf { it.isNotEmpty() }?.joinToString(", ") ?: root.riskLevel
                        "Root / SU indicators detected ($details)"
                    } else {
                        "No root / SU indicators found"
                    },
                    fontSize = 12.sp,
                    color = if (root.isRooted) WarningAmber else SuccessGreen
                )
            }
        }

        SectionHeaderRow(
            title = "Runtime Permission Status",
            subtitle = "Live Android permission checks",
            actionLabel = "Refresh",
            onActionClick = onRefreshPermissions
        )
        ClinicalSurfaceCard(contentPadding = PaddingValues(0.dp)) {
            uiState.permissions.forEachIndexed { idx, perm ->
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(horizontal = 16.dp, vertical = 12.dp),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.SpaceBetween
                ) {
                    Text(perm.name, fontSize = 13.sp, fontWeight = FontWeight.Medium, color = TextPrimary)
                    Surface(
                        color = if (perm.granted) SuccessContainer else WarningContainer,
                        shape = RoundedCornerShape(999.dp)
                    ) {
                        Text(
                            text = if (perm.granted) "Granted" else "Not Granted",
                            modifier = Modifier.padding(horizontal = 10.dp, vertical = 3.dp),
                            fontSize = 11.sp,
                            fontWeight = FontWeight.SemiBold,
                            color = if (perm.granted) SuccessGreen else WarningAmber
                        )
                    }
                }
                if (idx < uiState.permissions.lastIndex) {
                    HorizontalDivider(color = BorderColor, modifier = Modifier.padding(horizontal = 16.dp))
                }
            }
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R && !Environment.isExternalStorageManager()) {
            OutlinedButton(onClick = onOpenStorageSettings, modifier = Modifier.fillMaxWidth(), shape = RoundedCornerShape(12.dp)) {
                Text("Open All-Files Storage Permission Settings", color = SentinelPrimary)
            }
        }
    }
}

@Composable
private fun AvMetricChip(label: String, value: String, modifier: Modifier = Modifier) {
    Surface(modifier = modifier, color = SurfaceSubtle, shape = RoundedCornerShape(10.dp)) {
        Column(modifier = Modifier.padding(10.dp)) {
            Text(label, fontSize = 10.sp, color = TextSecondary, maxLines = 1, overflow = TextOverflow.Ellipsis)
            Spacer(Modifier.height(2.dp))
            Text(value, style = TabularDiagStyle.copy(fontSize = 13.sp, fontWeight = FontWeight.Bold), color = TextPrimary, maxLines = 1)
        }
    }
}
