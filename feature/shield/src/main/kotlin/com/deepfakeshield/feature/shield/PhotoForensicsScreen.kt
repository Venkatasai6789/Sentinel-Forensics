package com.deepfakeshield.feature.shield

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.net.Uri
import android.widget.Toast
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.AddPhotoAlternate
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.Error
import androidx.compose.material.icons.filled.Share
import androidx.compose.material.icons.outlined.Image
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.hilt.navigation.compose.hiltViewModel
import com.deepfakeshield.core.model.AnalysisStatus
import com.deepfakeshield.core.model.ScanProgressState
import com.deepfakeshield.core.model.SecurityAnalysisResult
import com.deepfakeshield.core.ui.components.*
import com.deepfakeshield.core.ui.theme.*
import com.deepfakeshield.ml.engine.PhotoForensicReport
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

private val TabularPhotoStyle = TextStyle(fontFeatureSettings = "tnum")

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun PhotoForensicsScreen(
    viewModel: PhotoForensicsViewModel = hiltViewModel(),
    onNavigateBack: () -> Unit = {}
) {
    val uiState by viewModel.uiState.collectAsState()
    val context = LocalContext.current

    val imagePicker = rememberLauncherForActivityResult(ActivityResultContracts.GetContent()) { uri: Uri? ->
        uri?.let { viewModel.analyzeImage(it) }
    }

    Scaffold(
        topBar = {
            Column {
                TopAppBar(
                    title = {
                        Column {
                            Text(
                                "Photo Forensics",
                                style = MaterialTheme.typography.titleMedium,
                                fontWeight = FontWeight.SemiBold,
                                color = TextPrimary
                            )
                            Text(
                                "EXIF/XMP/PNG Metadata, ELA & Spatial Noise Check",
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
                    actions = {
                        uiState.analysisResult?.let { res ->
                            IconButton(
                                onClick = {
                                    val summary = buildForensicsExportText(res, uiState.report)
                                    val cm = context.getSystemService(Context.CLIPBOARD_SERVICE) as? ClipboardManager
                                    cm?.setPrimaryClip(ClipData.newPlainText("photo_forensics_report", summary))
                                    Toast.makeText(context, "Forensic summary copied", Toast.LENGTH_SHORT).show()
                                }
                            ) {
                                Icon(Icons.Filled.Share, contentDescription = "Copy report", tint = SentinelPrimary)
                            }
                        }
                    },
                    colors = TopAppBarDefaults.topAppBarColors(containerColor = SurfaceLight)
                )
                HorizontalDivider(color = BorderColor)
            }
        },
        containerColor = BackgroundLight
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .verticalScroll(rememberScrollState())
                .padding(horizontal = 20.dp, vertical = 16.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            ClinicalSurfaceCard {
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(12.dp)
                ) {
                    Box(
                        modifier = Modifier
                            .size(44.dp)
                            .background(SentinelPrimaryContainer, CircleShape),
                        contentAlignment = Alignment.Center
                    ) {
                        Icon(Icons.Outlined.Image, contentDescription = null, tint = SentinelPrimary, modifier = Modifier.size(22.dp))
                    }
                    Column(modifier = Modifier.weight(1f)) {
                        Text(
                            text = "Select Image for Local Forensics",
                            style = MaterialTheme.typography.titleSmall,
                            fontWeight = FontWeight.SemiBold,
                            color = TextPrimary
                        )
                        Text(
                            text = "Computes SHA-256, extracts EXIF/XMP/C2PA/PNG metadata, runs JPEG Q90 Error Level Analysis, and evaluates spatial noise.",
                            style = MaterialTheme.typography.bodySmall,
                            color = TextSecondary
                        )
                    }
                }

                Spacer(Modifier.height(14.dp))

                if (uiState.isAnalyzing) {
                    ForensicStageProgressCard(
                        progressState = ScanProgressState.Running(
                            stageTitle = "Analyzing Image",
                            completedSteps = (uiState.progress * 100f).toInt().coerceIn(0, 100),
                            totalSteps = 100,
                            detail = uiState.stageMessage.ifBlank { "Processing pixels..." }
                        ),
                        onCancel = { viewModel.cancelAnalysis() }
                    )
                } else {
                    Button(
                        onClick = { imagePicker.launch("image/*") },
                        modifier = Modifier
                            .fillMaxWidth()
                            .height(52.dp),
                        shape = RoundedCornerShape(12.dp),
                        colors = ButtonDefaults.buttonColors(containerColor = SentinelPrimary, contentColor = Color.White)
                    ) {
                        Icon(Icons.Filled.AddPhotoAlternate, contentDescription = null, modifier = Modifier.size(18.dp))
                        Spacer(Modifier.width(8.dp))
                        Text("Pick Image (JPEG, PNG, WebP)", fontWeight = FontWeight.SemiBold)
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
                        IconButton(onClick = { viewModel.clearError() }) {
                            Icon(Icons.Filled.Close, contentDescription = "Dismiss", tint = DangerRed)
                        }
                    }
                }
            }

            val analysis = uiState.analysisResult
            val report = uiState.report
            if (analysis != null) {
                ClinicalSurfaceCard {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Column(modifier = Modifier.weight(1f)) {
                            Text(
                                text = analysis.inputName ?: "Selected Image",
                                style = MaterialTheme.typography.titleMedium,
                                fontWeight = FontWeight.SemiBold,
                                color = TextPrimary,
                                maxLines = 1,
                                overflow = TextOverflow.Ellipsis
                            )
                            Text(
                                text = "Status: ${analysis.status.name} • ${analysis.processingDurationMs} ms",
                                style = TabularPhotoStyle.copy(fontSize = 12.sp),
                                color = TextSecondary
                            )
                        }
                        VerdictStatusPill(verdict = analysis.verdict)
                    }

                    if (analysis.status == AnalysisStatus.FAILED && analysis.errorMessage != null) {
                        Spacer(Modifier.height(10.dp))
                        Surface(color = DangerContainer, shape = RoundedCornerShape(8.dp), modifier = Modifier.fillMaxWidth()) {
                            Text(analysis.errorMessage.orEmpty(), modifier = Modifier.padding(10.dp), fontSize = 12.sp, color = DangerRed)
                        }
                    }

                    Spacer(Modifier.height(12.dp))
                    HorizontalDivider(color = BorderColor)
                    Spacer(Modifier.height(12.dp))

                    Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        PhotoMetricBox("Risk Score", analysis.riskScore?.let { "$it / 100" } ?: "N/A", Modifier.weight(1f))
                        PhotoMetricBox("Confidence", analysis.confidence?.let { "${(it * 100).toInt()}%" } ?: "Not calibrated", Modifier.weight(1f))
                    }

                    if (report != null) {
                        Spacer(Modifier.height(8.dp))
                        Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                            PhotoMetricBox("Container", report.containerFormat, Modifier.weight(1f))
                            PhotoMetricBox("Resolution", "${report.width}x${report.height}", Modifier.weight(1f))
                            PhotoMetricBox("Camera EXIF", if (report.hasCameraExif) "Present" else "Absent", Modifier.weight(1f))
                        }

                        report.detectedGeneratorTag?.let { tag ->
                            Spacer(Modifier.height(10.dp))
                            Surface(color = DangerContainer, shape = RoundedCornerShape(8.dp), modifier = Modifier.fillMaxWidth()) {
                                Text(
                                    text = "Metadata generator/editing tag detected: $tag",
                                    modifier = Modifier.padding(10.dp),
                                    fontSize = 12.sp,
                                    fontWeight = FontWeight.Medium,
                                    color = DangerRed
                                )
                            }
                        }

                        report.sha256?.let { sha ->
                            Spacer(Modifier.height(10.dp))
                            Text("SHA-256 Digest", fontSize = 11.sp, color = TextSecondary)
                            Text(sha, fontFamily = FontFamily.Monospace, fontSize = 11.sp, color = TextPrimary)
                        }
                    }
                }

                // Real Error Level Analysis Bitmap Visualization
                val elaBmp = uiState.elaBitmap
                val elaStats = report?.elaStats
                if (elaBmp != null && !elaBmp.isRecycled && elaStats != null) {
                    val imgBitmap = remember(elaBmp) { elaBmp.asImageBitmap() }
                    ClinicalSurfaceCard {
                        Text(
                            text = "JPEG Q90 Error Level Analysis (ELA) Map",
                            style = MaterialTheme.typography.titleSmall,
                            fontWeight = FontWeight.SemiBold,
                            color = TextPrimary
                        )
                        Spacer(Modifier.height(4.dp))
                        Text(
                            text = "Visualizes localized compression residuals after Q90 re-encoding. Elevated residuals reflect compression/editing history — never standalone proof of AI generation.",
                            fontSize = 11.sp,
                            color = TextSecondary
                        )
                        Spacer(Modifier.height(10.dp))
                        Image(
                            bitmap = imgBitmap,
                            contentDescription = "Error Level Analysis residual heatmap",
                            contentScale = ContentScale.Fit,
                            modifier = Modifier
                                .fillMaxWidth()
                                .heightIn(max = 240.dp)
                                .clip(RoundedCornerShape(10.dp))
                                .background(Color.Black)
                        )
                        Spacer(Modifier.height(10.dp))
                        Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                            PhotoMetricBox("Mean Delta", "%.2f".format(elaStats.meanDifference), Modifier.weight(1f))
                            PhotoMetricBox("P95 Delta", "%.2f".format(elaStats.p95Difference), Modifier.weight(1f))
                            PhotoMetricBox("Outlier Blocks", "%.1f%%".format(elaStats.outlierBlockRatio * 100f), Modifier.weight(1f))
                        }
                    }
                }

                if (report != null && report.metadataMap.isNotEmpty()) {
                    ClinicalSurfaceCard {
                        Text(
                            text = "Extracted File & Metadata Table",
                            style = MaterialTheme.typography.titleSmall,
                            fontWeight = FontWeight.SemiBold,
                            color = TextPrimary
                        )
                        Spacer(Modifier.height(8.dp))
                        report.metadataMap.forEach { (k, v) ->
                            Row(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .padding(vertical = 3.dp),
                                horizontalArrangement = Arrangement.SpaceBetween
                            ) {
                                Text(k, fontSize = 12.sp, color = TextSecondary, modifier = Modifier.weight(0.4f))
                                Text(v, fontSize = 12.sp, color = TextPrimary, modifier = Modifier.weight(0.6f), maxLines = 3, overflow = TextOverflow.Ellipsis)
                            }
                        }
                    }
                }

                if (analysis.findings.isNotEmpty()) {
                    SectionHeaderRow(
                        title = "Forensic Evidence (${analysis.findings.size})",
                        subtitle = "Tap any item for methodology & source"
                    )
                    analysis.findings.forEach { FindingEvidenceRow(it) }
                }

                LimitationDisclosureCard(
                    methods = analysis.analysisMethods,
                    limitations = analysis.limitations
                )
            }

            if (uiState.recentHistory.isNotEmpty()) {
                SectionHeaderRow(title = "Recent Photo Inspections", subtitle = "Saved in local Room database")
                ClinicalSurfaceCard(contentPadding = PaddingValues(0.dp)) {
                    val fmt = remember { SimpleDateFormat("MMM d, HH:mm", Locale.getDefault()) }
                    uiState.recentHistory.take(8).forEachIndexed { idx, item ->
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .clickable { viewModel.selectHistoryItem(item) }
                                .padding(horizontal = 16.dp, vertical = 12.dp),
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.spacedBy(10.dp)
                        ) {
                            Column(modifier = Modifier.weight(1f)) {
                                Text(
                                    text = item.inputName ?: "Image File",
                                    fontSize = 13.sp,
                                    fontWeight = FontWeight.Medium,
                                    color = TextPrimary,
                                    maxLines = 1,
                                    overflow = TextOverflow.Ellipsis
                                )
                                Text(
                                    text = "${fmt.format(Date(item.analyzedAt))} • ${item.status.name}",
                                    style = TabularPhotoStyle.copy(fontSize = 11.sp),
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
private fun PhotoMetricBox(label: String, value: String, modifier: Modifier = Modifier) {
    Surface(modifier = modifier, color = SurfaceSubtle, shape = RoundedCornerShape(10.dp)) {
        Column(modifier = Modifier.padding(10.dp)) {
            Text(label, fontSize = 10.sp, color = TextSecondary, maxLines = 1, overflow = TextOverflow.Ellipsis)
            Spacer(Modifier.height(2.dp))
            Text(
                text = value,
                style = TabularPhotoStyle.copy(fontSize = 12.sp, fontWeight = FontWeight.SemiBold),
                color = TextPrimary,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis
            )
        }
    }
}

private fun buildForensicsExportText(res: SecurityAnalysisResult, report: PhotoForensicReport?): String = buildString {
    appendLine("=== Sentinel Forensics — Photo Report ===")
    appendLine("File: ${res.inputName ?: "Unknown"}")
    appendLine("Verdict: ${res.verdict.label} (Status: ${res.status.name})")
    appendLine("Risk Score: ${res.riskScore ?: "N/A"}/100")
    report?.sha256?.let { appendLine("SHA-256: $it") }
    if (res.findings.isNotEmpty()) {
        appendLine("Findings:")
        res.findings.forEach { appendLine("- [${it.severity.label}] ${it.title}: ${it.description}") }
    }
    if (res.limitations.isNotEmpty()) {
        appendLine("Limitations:")
        res.limitations.forEach { appendLine("- $it") }
    }
}
