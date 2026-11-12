package com.deepfakeshield.feature.shield

import android.Manifest
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.provider.Settings
import android.widget.Toast
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.ContentPaste
import androidx.compose.material.icons.filled.Error
import androidx.compose.material.icons.outlined.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.hilt.navigation.compose.hiltViewModel
import com.deepfakeshield.core.model.AnalysisStatus
import com.deepfakeshield.core.model.ScanProgressState
import com.deepfakeshield.core.model.SecurityAnalysisResult
import com.deepfakeshield.core.ui.components.*
import com.deepfakeshield.core.ui.theme.*
import com.deepfakeshield.intelligence.UrlInspectionReport
import kotlinx.coroutines.launch
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

private val TabularNumStyle = TextStyle(fontFeatureSettings = "tnum")

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun MessageScanScreen(
    viewModel: MessageShieldViewModel = hiltViewModel(),
    onNavigateBack: () -> Unit = {}
) {
    val uiState by viewModel.uiState.collectAsState()
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var textInput by rememberSaveable { mutableStateOf("") }

    val clipboardManager = remember {
        context.getSystemService(Context.CLIPBOARD_SERVICE) as? ClipboardManager
    }

    val smsPermissionLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.RequestMultiplePermissions()
    ) { permissions ->
        if (permissions.values.all { it }) {
            scope.launch { viewModel.enableSmsScanning() }
        } else {
            Toast.makeText(context, "SMS permissions required for automatic SMS screening", Toast.LENGTH_SHORT).show()
        }
    }

    Scaffold(
        topBar = {
            Column {
                TopAppBar(
                    title = {
                        Column {
                            Text(
                                "Message Shield",
                                style = MaterialTheme.typography.titleMedium,
                                fontWeight = FontWeight.SemiBold,
                                color = TextPrimary
                            )
                            Text(
                                "SMS, Notification & Phishing Link Inspector",
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
                Text(
                    text = "Inspect Message Content",
                    style = MaterialTheme.typography.titleSmall,
                    fontWeight = FontWeight.SemiBold,
                    color = TextPrimary
                )
                Spacer(Modifier.height(4.dp))
                Text(
                    text = "Paste an SMS, chat excerpt, or notification body to analyze scam phrases, URLs, and contact identifiers.",
                    style = MaterialTheme.typography.bodySmall,
                    color = TextSecondary
                )
                Spacer(Modifier.height(12.dp))

                OutlinedTextField(
                    value = textInput,
                    onValueChange = { textInput = it },
                    modifier = Modifier.fillMaxWidth(),
                    textStyle = com.deepfakeshield.core.ui.components.clinicalTextFieldStyle(),
                    label = { Text("Message content") },
                    placeholder = { Text("Paste message text here...") },
                    trailingIcon = {
                        if (textInput.isNotEmpty() && !uiState.isScanning) {
                            IconButton(onClick = {
                                textInput = ""
                                viewModel.clearResult()
                            }) {
                                Icon(Icons.Filled.Close, contentDescription = "Clear", tint = TextSecondary)
                            }
                        }
                    },
                    minLines = 4,
                    maxLines = 8,
                    shape = RoundedCornerShape(14.dp),
                    keyboardOptions = KeyboardOptions(imeAction = ImeAction.Done),
                    keyboardActions = KeyboardActions(
                        onDone = {
                            if (textInput.isNotBlank() && !uiState.isScanning) {
                                viewModel.scanText(textInput)
                            }
                        }
                    ),
                    colors = com.deepfakeshield.core.ui.components.clinicalOutlinedTextFieldColors()
                )

                Spacer(Modifier.height(12.dp))

                Row(
                    modifier = Modifier.fillMaxWidth(),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.SpaceBetween
                ) {
                    Column(modifier = Modifier.weight(1f)) {
                        Text(
                            text = "Live URL TLS & redirect probe",
                            style = MaterialTheme.typography.bodyMedium,
                            fontWeight = FontWeight.Medium,
                            color = TextPrimary
                        )
                        Text(
                            text = "When enabled, checks extracted links over HTTPS",
                            fontSize = 11.sp,
                            color = TextSecondary
                        )
                    }
                    Switch(
                        checked = uiState.allowLiveUrlProbe,
                        onCheckedChange = { viewModel.setLiveUrlProbe(it) },
                        enabled = !uiState.isScanning,
                        colors = SwitchDefaults.colors(
                            checkedThumbColor = Color.White,
                            checkedTrackColor = SentinelPrimary
                        )
                    )
                }

                Spacer(Modifier.height(14.dp))

                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(10.dp)
                ) {
                    OutlinedButton(
                        onClick = {
                            val clipData = clipboardManager?.primaryClip
                            val pasted = if (clipData != null && clipData.itemCount > 0) {
                                clipData.getItemAt(0).text?.toString()
                            } else null
                            if (pasted.isNullOrBlank()) {
                                Toast.makeText(context, "Clipboard has no text", Toast.LENGTH_SHORT).show()
                            } else {
                                textInput = pasted
                                viewModel.scanText(pasted)
                            }
                        },
                        modifier = Modifier
                            .weight(1f)
                            .height(50.dp),
                        enabled = !uiState.isScanning,
                        shape = RoundedCornerShape(12.dp),
                        border = BorderStroke(1.dp, BorderColor),
                        contentPadding = PaddingValues(horizontal = 10.dp)
                    ) {
                        Icon(Icons.Filled.ContentPaste, contentDescription = null, modifier = Modifier.size(18.dp), tint = TextPrimary)
                        Spacer(Modifier.width(6.dp))
                        Text(
                            text = "Paste & Scan",
                            color = TextPrimary,
                            fontSize = 13.sp,
                            fontWeight = FontWeight.Medium,
                            maxLines = 1,
                            softWrap = false,
                            overflow = TextOverflow.Ellipsis
                        )
                    }

                    Button(
                        onClick = { viewModel.scanText(textInput) },
                        modifier = Modifier
                            .weight(1f)
                            .height(50.dp),
                        enabled = textInput.isNotBlank() && !uiState.isScanning,
                        shape = RoundedCornerShape(12.dp),
                        colors = ButtonDefaults.buttonColors(
                            containerColor = SentinelPrimary,
                            contentColor = Color.White,
                            disabledContainerColor = SurfaceSubtle,
                            disabledContentColor = TextTertiary
                        ),
                        contentPadding = PaddingValues(horizontal = 10.dp)
                    ) {
                        Text(
                            text = if (uiState.isScanning) "Scanning..." else "Analyze",
                            fontSize = 14.sp,
                            fontWeight = FontWeight.SemiBold,
                            maxLines = 1,
                            softWrap = false
                        )
                    }
                }
            }

            if (uiState.isScanning) {
                ForensicStageProgressCard(
                    progressState = ScanProgressState.Running(
                        stageTitle = "Analyzing Message Payload",
                        detail = if (uiState.allowLiveUrlProbe) "Evaluating patterns, entities, and embedded URLs..." else "Running offline rule, multilingual, and pattern checks..."
                    )
                )
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

            uiState.analysisResult?.let { analysis ->
                MessageForensicResultSection(
                    analysis = analysis,
                    scamCategory = uiState.scamCategory,
                    detectedLanguage = uiState.detectedLanguage,
                    extractedEntities = uiState.extractedEntities,
                    extractedUrls = uiState.extractedUrls
                )
            }

            SectionHeaderRow(
                title = "Automatic Background Screening",
                subtitle = "On-device event hooks"
            )

            ClinicalSurfaceCard(contentPadding = PaddingValues(0.dp)) {
                ChannelToggleRow(
                    title = "SMS Inbox Screening",
                    subtitle = if (uiState.smsEnabled) "Active on incoming SMS broadcasts" else "Requires SMS read permission",
                    checked = uiState.smsEnabled,
                    onCheckedChange = { enabled ->
                        if (enabled) {
                            smsPermissionLauncher.launch(
                                arrayOf(Manifest.permission.RECEIVE_SMS, Manifest.permission.READ_SMS)
                            )
                        } else {
                            viewModel.disableSmsScanning()
                        }
                    }
                )
                HorizontalDivider(color = BorderColor, modifier = Modifier.padding(horizontal = 16.dp))
                ChannelNavigableRow(
                    title = "Notification Listener Access",
                    subtitle = "Opens Android Notification Access to screen WhatsApp / Telegram / SMS banners",
                    actionLabel = if (uiState.notificationEnabled) "Configure" else "Enable",
                    onClick = {
                        viewModel.enableNotificationScanning()
                        runCatching {
                            context.startActivity(Intent(Settings.ACTION_NOTIFICATION_LISTENER_SETTINGS))
                        }
                    }
                )
                HorizontalDivider(color = BorderColor, modifier = Modifier.padding(horizontal = 16.dp))
                ChannelToggleRow(
                    title = "Clipboard Guard",
                    subtitle = if (uiState.clipboardEnabled) "Monitoring copied URLs when opened" else "Only scans when manually triggered",
                    checked = uiState.clipboardEnabled,
                    onCheckedChange = { viewModel.toggleClipboardScanning(it) }
                )
            }

            if (uiState.recentHistory.isNotEmpty()) {
                SectionHeaderRow(
                    title = "Recent Message Inspections",
                    subtitle = "Saved in local Room database"
                )
                ClinicalSurfaceCard(contentPadding = PaddingValues(0.dp)) {
                    uiState.recentHistory.take(8).forEachIndexed { idx, item ->
                        MessageHistoryRow(
                            item = item,
                            onClick = { viewModel.selectHistoryItem(item) }
                        )
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
private fun MessageForensicResultSection(
    analysis: SecurityAnalysisResult,
    scamCategory: String,
    detectedLanguage: String,
    extractedEntities: List<ExtractedEntity>,
    extractedUrls: List<UrlInspectionReport>
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
                        text = "Inspection Verdict",
                        style = MaterialTheme.typography.titleMedium,
                        fontWeight = FontWeight.SemiBold,
                        color = TextPrimary
                    )
                    Text(
                        text = "Status: ${analysis.status.name} • ${analysis.processingDurationMs} ms",
                        style = TabularNumStyle.copy(fontSize = 12.sp),
                        color = TextSecondary
                    )
                }
                VerdictStatusPill(verdict = analysis.verdict)
            }

            Spacer(Modifier.height(12.dp))
            HorizontalDivider(color = BorderColor)
            Spacer(Modifier.height(12.dp))

            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                ResultStatBox(
                    label = "Risk Score",
                    value = analysis.riskScore?.let { "$it / 100" } ?: "—",
                    modifier = Modifier.weight(1f)
                )
                ResultStatBox(
                    label = "Confidence",
                    value = analysis.confidence?.let { "${(it * 100).toInt()}%" } ?: "Not calibrated",
                    modifier = Modifier.weight(1f)
                )
            }

            Spacer(Modifier.height(8.dp))

            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                ResultStatBox(
                    label = "Category",
                    value = scamCategory,
                    modifier = Modifier.weight(1f)
                )
                ResultStatBox(
                    label = "Language",
                    value = detectedLanguage.uppercase(Locale.US),
                    modifier = Modifier.weight(1f)
                )
            }

            if (analysis.status == AnalysisStatus.PARTIAL) {
                Spacer(Modifier.height(10.dp))
                Surface(
                    color = WarningContainer,
                    shape = RoundedCornerShape(8.dp),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Text(
                        text = "Partial analysis: one or more checks (e.g., live URL probe or pattern lookup) were unavailable.",
                        modifier = Modifier.padding(10.dp),
                        fontSize = 12.sp,
                        color = WarningAmber
                    )
                }
            }
        }

        if (extractedEntities.isNotEmpty()) {
            ClinicalSurfaceCard {
                Text(
                    text = "Extracted Entities (${extractedEntities.size})",
                    style = MaterialTheme.typography.titleSmall,
                    fontWeight = FontWeight.SemiBold,
                    color = TextPrimary
                )
                Spacer(Modifier.height(8.dp))
                extractedEntities.forEach { entity ->
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(vertical = 4.dp),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Column(modifier = Modifier.weight(1f)) {
                            Text(
                                text = entity.value,
                                fontSize = 13.sp,
                                fontWeight = FontWeight.Medium,
                                color = TextPrimary,
                                maxLines = 1,
                                overflow = TextOverflow.Ellipsis
                            )
                            Text(
                                text = "${entity.kind} • chars ${entity.startOffset}..${entity.endOffset}",
                                style = TabularNumStyle.copy(fontSize = 11.sp),
                                color = TextSecondary
                            )
                        }
                    }
                }
            }
        }

        if (extractedUrls.isNotEmpty()) {
            ClinicalSurfaceCard {
                Text(
                    text = "Embedded URLs Checked (${extractedUrls.size})",
                    style = MaterialTheme.typography.titleSmall,
                    fontWeight = FontWeight.SemiBold,
                    color = TextPrimary
                )
                Spacer(Modifier.height(8.dp))
                extractedUrls.forEach { report ->
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(vertical = 6.dp),
                        horizontalArrangement = Arrangement.spacedBy(8.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Column(modifier = Modifier.weight(1f)) {
                            Text(
                                text = report.normalizedUrl,
                                fontSize = 12.sp,
                                fontWeight = FontWeight.Medium,
                                color = TextPrimary,
                                maxLines = 2,
                                overflow = TextOverflow.Ellipsis
                            )
                            Text(
                                text = if (report.localCacheMatch) "Matched local threat cache" else "Host: ${report.asciiHost}",
                                fontSize = 11.sp,
                                color = TextSecondary
                            )
                        }
                        VerdictStatusPill(verdict = report.analysisResult.verdict)
                    }
                }
            }
        }

        if (analysis.findings.isNotEmpty()) {
            SectionHeaderRow(
                title = "Detection Evidence (${analysis.findings.size})",
                subtitle = "Tap any finding to inspect rule & offset"
            )
            analysis.findings.forEach { finding ->
                FindingEvidenceRow(finding = finding)
            }
        }

        LimitationDisclosureCard(
            methods = analysis.analysisMethods,
            limitations = analysis.limitations
        )
    }
}

@Composable
private fun ResultStatBox(
    label: String,
    value: String,
    modifier: Modifier = Modifier
) {
    Surface(
        modifier = modifier,
        color = SurfaceSubtle,
        shape = RoundedCornerShape(10.dp)
    ) {
        Column(modifier = Modifier.padding(10.dp)) {
            Text(text = label, fontSize = 11.sp, color = TextSecondary)
            Spacer(Modifier.height(2.dp))
            Text(
                text = value,
                style = TabularNumStyle.copy(fontSize = 13.sp, fontWeight = FontWeight.SemiBold),
                color = TextPrimary,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis
            )
        }
    }
}

@Composable
private fun ChannelToggleRow(
    title: String,
    subtitle: String,
    checked: Boolean,
    onCheckedChange: (Boolean) -> Unit
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 16.dp, vertical = 12.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Column(modifier = Modifier.weight(1f)) {
            Text(title, style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.Medium, color = TextPrimary)
            Text(subtitle, style = MaterialTheme.typography.bodySmall, color = TextSecondary)
        }
        Spacer(Modifier.width(12.dp))
        Switch(
            checked = checked,
            onCheckedChange = onCheckedChange,
            colors = SwitchDefaults.colors(
                checkedThumbColor = Color.White,
                checkedTrackColor = SuccessGreen
            )
        )
    }
}

@Composable
private fun ChannelNavigableRow(
    title: String,
    subtitle: String,
    actionLabel: String,
    onClick: () -> Unit
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clickable(onClick = onClick)
            .padding(horizontal = 16.dp, vertical = 12.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Column(modifier = Modifier.weight(1f)) {
            Text(title, style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.Medium, color = TextPrimary)
            Text(subtitle, style = MaterialTheme.typography.bodySmall, color = TextSecondary)
        }
        Spacer(Modifier.width(12.dp))
        TextButton(onClick = onClick) {
            Text(actionLabel, color = SentinelPrimary, fontWeight = FontWeight.SemiBold)
        }
    }
}

@Composable
private fun MessageHistoryRow(
    item: SecurityAnalysisResult,
    onClick: () -> Unit
) {
    val timeFormat = remember { SimpleDateFormat("MMM d, HH:mm", Locale.getDefault()) }
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clickable(onClick = onClick)
            .padding(horizontal = 16.dp, vertical = 12.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(10.dp)
    ) {
        Column(modifier = Modifier.weight(1f)) {
            Text(
                text = item.inputName ?: "Message Inspection",
                style = MaterialTheme.typography.titleSmall,
                fontSize = 13.sp,
                fontWeight = FontWeight.Medium,
                color = TextPrimary,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis
            )
            Text(
                text = "${timeFormat.format(Date(item.analyzedAt))} • ${item.findings.size} finding(s)",
                style = TabularNumStyle.copy(fontSize = 11.sp),
                color = TextSecondary
            )
        }
        VerdictStatusPill(verdict = item.verdict)
    }
}
