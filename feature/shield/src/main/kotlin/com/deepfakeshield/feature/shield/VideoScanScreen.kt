package com.deepfakeshield.feature.shield

import android.content.Intent
import android.net.Uri
import android.os.Build
import android.provider.Settings
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.Error
import androidx.compose.material.icons.filled.Layers
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.VideoFile
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
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.hilt.navigation.compose.hiltViewModel
import com.deepfakeshield.core.model.AnalysisStatus
import com.deepfakeshield.core.model.ScanProgressState
import com.deepfakeshield.core.model.SecurityAnalysisResult
import com.deepfakeshield.core.ui.components.*
import com.deepfakeshield.core.ui.theme.*
import com.deepfakeshield.ml.engine.VideoForensicReport
import kotlinx.coroutines.launch
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

private val TabularVideoStyle = TextStyle(fontFeatureSettings = "tnum")

@Composable
fun VideoScanScreen(
    viewModel: VideoShieldViewModel = hiltViewModel(),
    @Suppress("UNUSED_PARAMETER") onShowFullScreenOverlay: () -> Unit = {},
    onNavigateBack: () -> Unit = {}
) {
    val uiState by viewModel.uiState.collectAsState()
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var showOverlayDialog by remember { mutableStateOf(false) }

    val videoPickerLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.OpenDocument()
    ) { uri: Uri? ->
        uri?.let { viewModel.scanVideo(it) }
    }

    if (showOverlayDialog) {
        AlertDialog(
            onDismissRequest = { showOverlayDialog = false },
            containerColor = SurfaceLight,
            titleContentColor = TextPrimary,
            textContentColor = TextSecondary,
            icon = { Icon(Icons.Filled.Layers, contentDescription = null, tint = SentinelPrimary) },
            title = { Text("Enable Overlay Permission", fontWeight = FontWeight.SemiBold) },
            text = {
                Text(
                    "Floating Video Shield requires the Android 'Display over other apps' permission to sample video call views when enabled."
                )
            },
            confirmButton = {
                Button(
                    onClick = {
                        showOverlayDialog = false
                        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                            context.startActivity(
                                Intent(
                                    Settings.ACTION_MANAGE_OVERLAY_PERMISSION,
                                    Uri.parse("package:${context.packageName}")
                                )
                            )
                        }
                    },
                    colors = ButtonDefaults.buttonColors(containerColor = SentinelPrimary)
                ) {
                    Text("Open Android Settings")
                }
            },
            dismissButton = {
                TextButton(onClick = { showOverlayDialog = false }) { Text("Cancel") }
            }
        )
    }

    VideoScanContent(
        uiState = uiState,
        onPickVideo = { videoPickerLauncher.launch(arrayOf("video/*")) },
        onCancelScan = { viewModel.cancelScan() },
        onToggleSystemWide = { enabled ->
            if (enabled) {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M && !Settings.canDrawOverlays(context)) {
                    showOverlayDialog = true
                } else {
                    scope.launch { viewModel.startSystemWideScanning(null) }
                }
            } else {
                scope.launch { viewModel.stopSystemWideScanning() }
            }
        },
        onClearError = { viewModel.clearError() },
        onScanAnother = { viewModel.clearResult() },
        onSelectHistoryItem = { viewModel.selectHistoryItem(it) },
        onNavigateBack = onNavigateBack
    )
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun VideoScanContent(
    uiState: VideoShieldUiState,
    onPickVideo: () -> Unit = {},
    onCancelScan: () -> Unit = {},
    onToggleSystemWide: (Boolean) -> Unit = {},
    onClearError: () -> Unit = {},
    onScanAnother: () -> Unit = {},
    onSelectHistoryItem: (SecurityAnalysisResult) -> Unit = {},
    onNavigateBack: () -> Unit = {}
) {
    Scaffold(
        topBar = {
            Column {
                TopAppBar(
                    title = {
                        Column {
                            Text(
                                "Deepfake Video Detection",
                                style = MaterialTheme.typography.titleMedium,
                                fontWeight = FontWeight.SemiBold,
                                color = TextPrimary
                            )
                            Text(
                                "SRM Noise, 2D DCT, Boundary Seam & Temporal Checks",
                                style = MaterialTheme.typography.bodySmall,
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
        containerColor = BackgroundLight
    ) { paddingValues ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(paddingValues)
                .verticalScroll(rememberScrollState())
                .padding(horizontal = 20.dp, vertical = 16.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            ClinicalSurfaceCard {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(12.dp)
                ) {
                    Box(
                        modifier = Modifier
                            .size(44.dp)
                            .background(SentinelPrimaryContainer, CircleShape),
                        contentAlignment = Alignment.Center
                    ) {
                        Icon(Icons.Outlined.Videocam, contentDescription = null, tint = SentinelPrimary, modifier = Modifier.size(22.dp))
                    }
                    Column(modifier = Modifier.weight(1f)) {
                        Text(
                            text = "Select Video File for Forensics",
                            style = MaterialTheme.typography.titleSmall,
                            fontWeight = FontWeight.SemiBold,
                            color = TextPrimary
                        )
                        Text(
                            text = "Inspects decoded keyframes locally. Corrupt files or videos without visible faces report FAILED or INCONCLUSIVE honestly.",
                            style = MaterialTheme.typography.bodySmall,
                            color = TextSecondary
                        )
                    }
                }

                Spacer(Modifier.height(14.dp))

                if (uiState.isScanning) {
                    ForensicStageProgressCard(
                        progressState = ScanProgressState.Running(
                            stageTitle = "Extracting & Analyzing Video",
                            completedSteps = (uiState.scanProgress * 100f).toInt().coerceIn(0, 100),
                            totalSteps = 100,
                            detail = uiState.statusMessage.ifBlank { "Sampling frames..." }
                        ),
                        onCancel = onCancelScan
                    )
                } else {
                    Button(
                        onClick = onPickVideo,
                        modifier = Modifier
                            .fillMaxWidth()
                            .height(52.dp),
                        shape = RoundedCornerShape(12.dp),
                        colors = ButtonDefaults.buttonColors(
                            containerColor = SentinelPrimary,
                            contentColor = Color.White
                        )
                    ) {
                        Icon(Icons.Filled.VideoFile, contentDescription = null, modifier = Modifier.size(18.dp))
                        Spacer(Modifier.width(8.dp))
                        Text("Pick Video File", fontWeight = FontWeight.SemiBold)
                    }
                }
            }

            ClinicalSurfaceCard(contentPadding = PaddingValues(14.dp)) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Column(modifier = Modifier.weight(1f)) {
                        Text(
                            text = "Floating Call Overlay Monitor",
                            style = MaterialTheme.typography.titleSmall,
                            fontWeight = FontWeight.SemiBold,
                            color = TextPrimary
                        )
                        Text(
                            text = if (uiState.systemWideEnabled) "Overlay switch active" else "Disabled — manual video file inspection only",
                            style = MaterialTheme.typography.bodySmall,
                            color = TextSecondary
                        )
                    }
                    Spacer(Modifier.width(8.dp))
                    Switch(
                        checked = uiState.systemWideEnabled,
                        onCheckedChange = onToggleSystemWide,
                        colors = SwitchDefaults.colors(
                            checkedThumbColor = Color.White,
                            checkedTrackColor = SuccessGreen
                        )
                    )
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

            val analysis = uiState.analysisResult
            val report = uiState.forensicReport
            if (analysis != null) {
                VideoForensicResultPanel(
                    analysis = analysis,
                    report = report,
                    onScanAnother = onScanAnother
                )
            } else if (!uiState.isScanning) {
                ClinicalSurfaceCard {
                    Text(
                        text = "On-Device Video Forensics Pipeline",
                        style = MaterialTheme.typography.titleSmall,
                        fontWeight = FontWeight.SemiBold,
                        color = TextPrimary
                    )
                    Spacer(Modifier.height(10.dp))
                    PipelineStageLine("1. Container & Provenance Validation", "Reads codec, resolution, frame rate, audio track, and MP4/WebM AI tool/C2PA signatures.")
                    HorizontalDivider(color = BorderColor, modifier = Modifier.padding(vertical = 8.dp))
                    PipelineStageLine("2. Uniform + Dense-Burst Extraction", "Samples uniform keyframes plus a ~115ms temporal burst for micro-flicker, blink, and pulse analysis.")
                    HorizontalDivider(color = BorderColor, modifier = Modifier.padding(vertical = 8.dp))
                    PipelineStageLine("3. ML Kit Face Geometry & 3D Mesh", "Extracts face boxes, blink probabilities, lip kinematics, and 468-pt 3D mesh geometry.")
                    HorizontalDivider(color = BorderColor, modifier = Modifier.padding(vertical = 8.dp))
                    PipelineStageLine("4. Multi-Domain Signal Forensics", "Evaluates SRM noise residual disparity, 2D 8x8 DCT spectra, YCbCr blending seams, temporal shimmer, rPPG pulse coherence, and audio lip-sync.")
                }
            }

            if (uiState.recentHistory.isNotEmpty()) {
                SectionHeaderRow(
                    title = "Recent Video Inspections",
                    subtitle = "Saved in local Room database"
                )
                ClinicalSurfaceCard(contentPadding = PaddingValues(0.dp)) {
                    val fmt = remember { SimpleDateFormat("MMM d, HH:mm", Locale.getDefault()) }
                    uiState.recentHistory.take(8).forEachIndexed { idx, item ->
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .clickable { onSelectHistoryItem(item) }
                                .padding(horizontal = 16.dp, vertical = 12.dp),
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.spacedBy(10.dp)
                        ) {
                            Column(modifier = Modifier.weight(1f)) {
                                Text(
                                    text = item.inputName ?: "Video file",
                                    style = MaterialTheme.typography.titleSmall,
                                    fontSize = 13.sp,
                                    fontWeight = FontWeight.Medium,
                                    color = TextPrimary,
                                    maxLines = 1,
                                    overflow = TextOverflow.Ellipsis
                                )
                                Text(
                                    text = "${fmt.format(Date(item.analyzedAt))} • ${item.status.name}",
                                    style = TabularVideoStyle.copy(fontSize = 11.sp),
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
}

@Composable
private fun PipelineStageLine(title: String, detail: String) {
    Column(modifier = Modifier.fillMaxWidth()) {
        Text(title, fontSize = 13.sp, fontWeight = FontWeight.SemiBold, color = TextPrimary)
        Spacer(Modifier.height(2.dp))
        Text(detail, fontSize = 12.sp, color = TextSecondary)
    }
}

@Composable
private fun VideoForensicResultPanel(
    analysis: SecurityAnalysisResult,
    report: VideoForensicReport?,
    onScanAnother: () -> Unit
) {
    Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
        ClinicalSurfaceCard {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Column(modifier = Modifier.weight(1f)) {
                    Text(
                        text = analysis.inputName ?: "Video Analysis",
                        style = MaterialTheme.typography.titleMedium,
                        fontWeight = FontWeight.SemiBold,
                        color = TextPrimary,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis
                    )
                    Text(
                        text = "Status: ${analysis.status.name} • ${analysis.processingDurationMs} ms",
                        style = TabularVideoStyle.copy(fontSize = 12.sp),
                        color = TextSecondary
                    )
                }
                VerdictStatusPill(verdict = analysis.verdict)
            }

            if (analysis.status == AnalysisStatus.FAILED && analysis.errorMessage != null) {
                Spacer(Modifier.height(10.dp))
                Surface(color = DangerContainer, shape = RoundedCornerShape(8.dp), modifier = Modifier.fillMaxWidth()) {
                    Text(
                        text = analysis.errorMessage.orEmpty(),
                        modifier = Modifier.padding(10.dp),
                        fontSize = 12.sp,
                        color = DangerRed
                    )
                }
            }

            Spacer(Modifier.height(12.dp))
            HorizontalDivider(color = BorderColor)
            Spacer(Modifier.height(12.dp))

            Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                VideoStatCell(
                    label = "Risk Score",
                    value = analysis.riskScore?.let { "$it / 100" } ?: "N/A",
                    modifier = Modifier.weight(1f)
                )
                VideoStatCell(
                    label = "Confidence",
                    value = analysis.confidence?.let { "${(it * 100).toInt()}%" } ?: "Not calibrated",
                    modifier = Modifier.weight(1f)
                )
            }

            if (report != null) {
                Spacer(Modifier.height(8.dp))
                Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    VideoStatCell(
                        label = "Frames Sampled",
                        value = "${report.framesExtracted}",
                        modifier = Modifier.weight(1f)
                    )
                    VideoStatCell(
                        label = "Frames w/ Faces",
                        value = "${report.framesWithFaces}",
                        modifier = Modifier.weight(1f)
                    )
                }
                Spacer(Modifier.height(8.dp))
                Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    VideoStatCell(
                        label = "Temporal Anomalies",
                        value = "${report.temporalLuminanceAnomalies}",
                        modifier = Modifier.weight(1f)
                    )
                    VideoStatCell(
                        label = "Face Consistency",
                        value = report.faceConsistencyScore?.let { "${(it * 100).toInt()}%" } ?: "N/A",
                        modifier = Modifier.weight(1f)
                    )
                }

                report.mediaMetadata?.let { meta ->
                    Spacer(Modifier.height(12.dp))
                    HorizontalDivider(color = BorderColor)
                    Spacer(Modifier.height(10.dp))
                    Text("Container & Track Telemetry", fontSize = 12.sp, fontWeight = FontWeight.SemiBold, color = TextPrimary)
                    Spacer(Modifier.height(4.dp))
                    Text(
                        text = "${meta.width}x${meta.height} • ${meta.durationMs} ms • ${meta.mimeType ?: "unknown codec"} • Audio: ${if (meta.hasAudioTrack) "Yes (${meta.audioSampleRateHz ?: "?"} Hz)" else "None"}",
                        style = TabularVideoStyle.copy(fontSize = 12.sp),
                        color = TextSecondary
                    )
                }
            }
        }

        if (analysis.findings.isNotEmpty()) {
            SectionHeaderRow(
                title = "Forensic Evidence (${analysis.findings.size})",
                subtitle = "Expand any item for inspection details"
            )
            analysis.findings.forEach { finding ->
                FindingEvidenceRow(finding = finding)
            }
        }

        LimitationDisclosureCard(
            methods = analysis.analysisMethods,
            limitations = analysis.limitations
        )

        OutlinedButton(
            onClick = onScanAnother,
            modifier = Modifier
                .fillMaxWidth()
                .height(48.dp),
            shape = RoundedCornerShape(12.dp),
            border = BorderStroke(1.dp, BorderColor)
        ) {
            Icon(Icons.Filled.Refresh, contentDescription = null, modifier = Modifier.size(18.dp), tint = TextPrimary)
            Spacer(Modifier.width(8.dp))
            Text("Clear Result", color = TextPrimary, fontWeight = FontWeight.Medium)
        }
    }
}

@Composable
private fun VideoStatCell(
    label: String,
    value: String,
    modifier: Modifier = Modifier
) {
    Surface(modifier = modifier, color = SurfaceSubtle, shape = RoundedCornerShape(10.dp)) {
        Column(modifier = Modifier.padding(10.dp)) {
            Text(label, fontSize = 11.sp, color = TextSecondary)
            Spacer(Modifier.height(2.dp))
            Text(
                text = value,
                style = TabularVideoStyle.copy(fontSize = 13.sp, fontWeight = FontWeight.SemiBold),
                color = TextPrimary,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis
            )
        }
    }
}

@Preview(name = "Deepfake Video Screen (Clean Baseline)", showBackground = true, showSystemUi = true)
@Composable
fun VideoScanScreenPreview() {
    MaterialTheme {
        VideoScanContent(uiState = VideoShieldUiState())
    }
}
