package com.deepfakeshield.feature.shield

import android.graphics.Bitmap
import android.net.Uri
import android.webkit.WebResourceRequest
import android.webkit.WebView
import android.webkit.WebViewClient
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.Error
import androidx.compose.material.icons.filled.Language
import androidx.compose.material.icons.filled.OpenInBrowser
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Search
import androidx.compose.material.icons.outlined.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.viewinterop.AndroidView
import androidx.hilt.navigation.compose.hiltViewModel
import com.deepfakeshield.core.model.AnalysisStatus
import com.deepfakeshield.core.model.ScanProgressState
import com.deepfakeshield.core.model.SecurityAnalysisResult
import com.deepfakeshield.core.model.SecurityVerdict
import com.deepfakeshield.core.ui.components.*
import com.deepfakeshield.core.ui.theme.*
import com.deepfakeshield.intelligence.UrlInspectionReport
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

private val TabularUrlStyle = TextStyle(fontFeatureSettings = "tnum")

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SafeBrowserScreen(
    initialUrl: String = "",
    onNavigateBack: () -> Unit = {},
    viewModel: SafeBrowserViewModel = hiltViewModel()
) {
    val uiState by viewModel.uiState.collectAsState()
    var urlInput by rememberSaveable { mutableStateOf(initialUrl) }
    var sandboxUrl by rememberSaveable { mutableStateOf<String?>(null) }
    var pageLoading by remember { mutableStateOf(false) }
    var blockedNavUrl by remember { mutableStateOf<String?>(null) }

    // Rule 10: if initialUrl is supplied externally, inspect it first; NEVER auto-open WebView
    LaunchedEffect(initialUrl) {
        if (initialUrl.isNotBlank()) {
            urlInput = initialUrl
            viewModel.inspectUrl(initialUrl, allowNetworkProbe = uiState.allowNetworkProbe)
        }
    }

    blockedNavUrl?.let { blocked ->
        AlertDialog(
            onDismissRequest = { blockedNavUrl = null },
            containerColor = SurfaceLight,
            titleContentColor = TextPrimary,
            textContentColor = TextSecondary,
            icon = { Icon(Icons.Filled.Error, contentDescription = null, tint = DangerRed) },
            title = { Text("Navigation Blocked", fontWeight = FontWeight.SemiBold) },
            text = {
                Text("Redirect inside sandboxed preview matched high-risk URL indicators and was blocked:\n\n$blocked")
            },
            confirmButton = {
                Button(
                    onClick = { blockedNavUrl = null },
                    colors = ButtonDefaults.buttonColors(containerColor = SentinelPrimary)
                ) {
                    Text("Close")
                }
            }
        )
    }

    Scaffold(
        topBar = {
            Column {
                TopAppBar(
                    title = {
                        Column {
                            Text(
                                text = if (sandboxUrl != null) "Sandboxed WebView (JS Disabled)" else "Phishing URL Scan",
                                style = MaterialTheme.typography.titleMedium,
                                fontWeight = FontWeight.SemiBold,
                                color = TextPrimary
                            )
                            Text(
                                text = sandboxUrl ?: "URL Syntax, Punycode, Threat Cache & TLS Inspector",
                                style = MaterialTheme.typography.bodySmall,
                                color = TextSecondary,
                                maxLines = 1,
                                overflow = TextOverflow.Ellipsis
                            )
                        }
                    },
                    navigationIcon = {
                        IconButton(
                            onClick = {
                                if (sandboxUrl != null) {
                                    sandboxUrl = null
                                } else {
                                    onNavigateBack()
                                }
                            }
                        ) {
                            Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back", tint = TextPrimary)
                        }
                    },
                    actions = {
                        if (sandboxUrl != null) {
                            TextButton(onClick = { sandboxUrl = null }) {
                                Text("Exit Preview", color = SentinelPrimary, fontWeight = FontWeight.SemiBold)
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
        if (sandboxUrl != null) {
            Column(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(padding)
            ) {
                if (pageLoading) {
                    LinearProgressIndicator(
                        modifier = Modifier.fillMaxWidth().height(3.dp),
                        color = SentinelPrimary
                    )
                }
                val target = sandboxUrl!!
                AndroidView(
                    factory = { ctx ->
                        WebView(ctx).apply {
                            settings.javaScriptEnabled = false
                            settings.domStorageEnabled = false
                            settings.allowFileAccess = false
                            settings.allowContentAccess = false
                            webViewClient = object : WebViewClient() {
                                override fun onPageStarted(view: WebView?, url: String?, favicon: Bitmap?) {
                                    pageLoading = true
                                }

                                override fun onPageFinished(view: WebView?, url: String?) {
                                    pageLoading = false
                                }

                                override fun shouldOverrideUrlLoading(
                                    view: WebView?,
                                    request: WebResourceRequest?
                                ): Boolean {
                                    val reqUrl = request?.url?.toString() ?: return true
                                    val scheme = request.url?.scheme?.lowercase()
                                    if (scheme !in listOf("http", "https")) {
                                        blockedNavUrl = reqUrl
                                        return true
                                    }
                                    val check = runCatching { viewModel.analyzeUrlSync(reqUrl) }.getOrNull()
                                    if (check != null && check.riskScore >= 55) {
                                        blockedNavUrl = reqUrl
                                        return true
                                    }
                                    return false
                                }
                            }
                            loadUrl(target)
                        }
                    },
                    modifier = Modifier.fillMaxSize(),
                    onRelease = { wv ->
                        wv.stopLoading()
                        wv.clearHistory()
                        wv.onPause()
                        wv.removeAllViews()
                        wv.destroy()
                    }
                )
            }
        } else {
            Column(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(padding)
                    .verticalScroll(rememberScrollState())
                    .padding(horizontal = 20.dp, vertical = 16.dp),
                verticalArrangement = Arrangement.spacedBy(16.dp)
            ) {
                ClinicalSurfaceCard {
                    Text(
                        text = "Inspect Link Before Opening",
                        style = MaterialTheme.typography.titleSmall,
                        fontWeight = FontWeight.SemiBold,
                        color = TextPrimary
                    )
                    Spacer(Modifier.height(4.dp))
                    Text(
                        text = "Validates scheme, IDN punycode homographs, local PhishTank/OpenPhish/URLhaus cache, and optional HTTPS redirect/certificate chain.",
                        style = MaterialTheme.typography.bodySmall,
                        color = TextSecondary
                    )
                    Spacer(Modifier.height(12.dp))

                    OutlinedTextField(
                        value = urlInput,
                        onValueChange = { urlInput = it },
                        modifier = Modifier.fillMaxWidth(),
                        textStyle = com.deepfakeshield.core.ui.components.clinicalTextFieldStyle(),
                        label = { Text("Website or phishing link") },
                        placeholder = { Text("https://example.com/path") },
                        leadingIcon = { Icon(Icons.Default.Search, contentDescription = null) },
                        trailingIcon = {
                            if (urlInput.isNotEmpty() && !uiState.isScanning) {
                                IconButton(onClick = {
                                    urlInput = ""
                                    viewModel.clearInspection()
                                }) {
                                    Icon(Icons.Filled.Close, contentDescription = "Clear", tint = TextSecondary)
                                }
                            }
                        },
                        singleLine = true,
                        shape = RoundedCornerShape(14.dp),
                        keyboardOptions = KeyboardOptions(
                            keyboardType = KeyboardType.Uri,
                            imeAction = ImeAction.Done
                        ),
                        keyboardActions = KeyboardActions(
                            onDone = {
                                if (urlInput.isNotBlank() && !uiState.isScanning) {
                                    viewModel.inspectUrl(urlInput, uiState.allowNetworkProbe)
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
                                text = "Live HTTPS TLS & redirect probe",
                                style = MaterialTheme.typography.bodyMedium,
                                fontWeight = FontWeight.Medium,
                                color = TextPrimary
                            )
                            Text(
                                text = "When off, checks run 100% locally and mark status PARTIAL",
                                fontSize = 11.sp,
                                color = TextSecondary
                            )
                        }
                        Switch(
                            checked = uiState.allowNetworkProbe,
                            onCheckedChange = { viewModel.setNetworkProbeEnabled(it) },
                            enabled = !uiState.isScanning,
                            colors = SwitchDefaults.colors(
                                checkedThumbColor = Color.White,
                                checkedTrackColor = SentinelPrimary
                            )
                        )
                    }

                    Spacer(Modifier.height(14.dp))

                    Button(
                        onClick = { viewModel.inspectUrl(urlInput, uiState.allowNetworkProbe) },
                        modifier = Modifier
                            .fillMaxWidth()
                            .height(52.dp),
                        enabled = urlInput.isNotBlank() && !uiState.isScanning,
                        shape = RoundedCornerShape(12.dp),
                        colors = ButtonDefaults.buttonColors(
                            containerColor = SentinelPrimary,
                            contentColor = Color.White,
                            disabledContainerColor = SurfaceSubtle,
                            disabledContentColor = TextTertiary
                        )
                    ) {
                        Text(
                            text = if (uiState.isScanning) "Inspecting URL..." else "Inspect URL Safety",
                            fontWeight = FontWeight.SemiBold
                        )
                    }
                }

                if (uiState.isScanning) {
                    ForensicStageProgressCard(
                        progressState = ScanProgressState.Running(
                            stageTitle = "Running URL Forensics",
                            detail = if (uiState.allowNetworkProbe) {
                                "Checking cache, tracing redirects, and reading TLS X.509 certificate..."
                            } else {
                                "Analyzing URL syntax, punycode & local threat cache..."
                            }
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
                        }
                    }
                }

                uiState.inspectionReport?.let { report ->
                    UrlInspectionResultPanel(
                        report = report,
                        onOpenSandboxed = { safeNormalized -> sandboxUrl = safeNormalized }
                    )
                }

                // Local Threat Feed Cache Status
                ClinicalSurfaceCard {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.SpaceBetween
                    ) {
                        Column(modifier = Modifier.weight(1f)) {
                            Text(
                                text = "Local Threat Intelligence Cache",
                                style = MaterialTheme.typography.titleSmall,
                                fontWeight = FontWeight.SemiBold,
                                color = TextPrimary
                            )
                            val syncDesc = if (uiState.cacheLastUpdatedAt > 0L) {
                                val fmt = SimpleDateFormat("MMM d, HH:mm", Locale.getDefault())
                                "Last synced: ${fmt.format(Date(uiState.cacheLastUpdatedAt))}"
                            } else {
                                "Feed sync not yet completed — built-in indicators active"
                            }
                            Text(syncDesc, fontSize = 11.sp, color = TextSecondary)
                        }
                        OutlinedButton(
                            onClick = { viewModel.refreshThreatCache() },
                            enabled = !uiState.isRefreshingCache,
                            shape = RoundedCornerShape(10.dp),
                            border = BorderStroke(1.dp, BorderColor)
                        ) {
                            if (uiState.isRefreshingCache) {
                                CircularProgressIndicator(Modifier.size(14.dp), strokeWidth = 2.dp, color = SentinelPrimary)
                            } else {
                                Icon(Icons.Filled.Refresh, contentDescription = null, modifier = Modifier.size(16.dp), tint = SentinelPrimary)
                            }
                            Spacer(Modifier.width(6.dp))
                            Text("Sync", fontSize = 12.sp, color = SentinelPrimary)
                        }
                    }

                    Spacer(Modifier.height(10.dp))

                    Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        UrlStatChip("Total Cached", "${uiState.cacheCount}", Modifier.weight(1f))
                        UrlStatChip("Phishing", "${uiState.cachePhishingCount}", Modifier.weight(1f))
                        UrlStatChip("Malware", "${uiState.cacheMalwareCount}", Modifier.weight(1f))
                    }

                    uiState.cacheRefreshMessage?.let { msg ->
                        Spacer(Modifier.height(8.dp))
                        Text(msg, fontSize = 12.sp, color = TextSecondary)
                    }
                }

                if (uiState.recentHistory.isNotEmpty()) {
                    SectionHeaderRow(
                        title = "Recent URL Inspections",
                        subtitle = "Persisted locally in Room"
                    )
                    ClinicalSurfaceCard(contentPadding = PaddingValues(0.dp)) {
                        val fmt = remember { SimpleDateFormat("MMM d, HH:mm", Locale.getDefault()) }
                        uiState.recentHistory.take(8).forEachIndexed { idx, item ->
                            Row(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .clickable {
                                        urlInput = item.metadata["normalizedUrl"] ?: item.inputName.orEmpty()
                                        viewModel.selectHistoryItem(item)
                                    }
                                    .padding(horizontal = 16.dp, vertical = 12.dp),
                                verticalAlignment = Alignment.CenterVertically,
                                horizontalArrangement = Arrangement.spacedBy(10.dp)
                            ) {
                                Column(modifier = Modifier.weight(1f)) {
                                    Text(
                                        text = item.inputName ?: "URL check",
                                        style = MaterialTheme.typography.titleSmall,
                                        fontSize = 13.sp,
                                        fontWeight = FontWeight.Medium,
                                        color = TextPrimary,
                                        maxLines = 1,
                                        overflow = TextOverflow.Ellipsis
                                    )
                                    Text(
                                        text = "${fmt.format(Date(item.analyzedAt))} • ${item.status.name}",
                                        style = TabularUrlStyle.copy(fontSize = 11.sp),
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
}

@Composable
private fun UrlInspectionResultPanel(
    report: UrlInspectionReport,
    onOpenSandboxed: (String) -> Unit
) {
    val analysis = report.analysisResult
    val scheme = runCatching { Uri.parse(report.normalizedUrl).scheme?.lowercase() }.getOrNull()
    val isWebScheme = scheme == "http" || scheme == "https"
    val canOpenInSandbox = isWebScheme &&
        (analysis.verdict == SecurityVerdict.SAFE || analysis.verdict == SecurityVerdict.LOW_RISK)

    Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
        ClinicalSurfaceCard {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Column(modifier = Modifier.weight(1f)) {
                    Text(
                        text = "URL Inspection Verdict",
                        style = MaterialTheme.typography.titleMedium,
                        fontWeight = FontWeight.SemiBold,
                        color = TextPrimary
                    )
                    Text(
                        text = "Status: ${analysis.status.name} • ${analysis.processingDurationMs} ms",
                        style = TabularUrlStyle.copy(fontSize = 12.sp),
                        color = TextSecondary
                    )
                }
                VerdictStatusPill(verdict = analysis.verdict)
            }

            Spacer(Modifier.height(12.dp))
            HorizontalDivider(color = BorderColor)
            Spacer(Modifier.height(12.dp))

            Text("Normalized Target", fontSize = 11.sp, color = TextSecondary)
            Text(
                text = report.normalizedUrl,
                fontFamily = FontFamily.Monospace,
                fontSize = 12.sp,
                color = TextPrimary
            )
            Spacer(Modifier.height(8.dp))

            Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                UrlStatChip(
                    label = "Risk Score",
                    value = analysis.riskScore?.let { "$it / 100" } ?: "—",
                    modifier = Modifier.weight(1f)
                )
                UrlStatChip(
                    label = "Confidence",
                    value = analysis.confidence?.let { "${(it * 100).toInt()}%" } ?: "Not calibrated",
                    modifier = Modifier.weight(1f)
                )
                UrlStatChip(
                    label = "Local Feed Hit",
                    value = if (report.localCacheMatch) "MATCHED" else "No hit",
                    modifier = Modifier.weight(1f)
                )
            }

            if (report.punycodeDecoded != null) {
                Spacer(Modifier.height(10.dp))
                Surface(color = WarningContainer, shape = RoundedCornerShape(8.dp), modifier = Modifier.fillMaxWidth()) {
                    Text(
                        text = "IDN / Punycode detected: ASCII '${report.asciiHost}' resolves to Unicode '${report.unicodeHost}' (${report.punycodeDecoded}). Verify carefully for homograph spoofing.",
                        modifier = Modifier.padding(10.dp),
                        fontSize = 12.sp,
                        color = WarningAmber
                    )
                }
            }

            if (analysis.status == AnalysisStatus.PARTIAL) {
                Spacer(Modifier.height(10.dp))
                Surface(color = WarningContainer, shape = RoundedCornerShape(8.dp), modifier = Modifier.fillMaxWidth()) {
                    Text(
                        text = "Partial inspection: live TLS certificate & HTTP redirect trace were skipped or offline.",
                        modifier = Modifier.padding(10.dp),
                        fontSize = 12.sp,
                        color = WarningAmber
                    )
                }
            }

            Spacer(Modifier.height(14.dp))

            if (canOpenInSandbox) {
                OutlinedButton(
                    onClick = { onOpenSandboxed(report.normalizedUrl) },
                    modifier = Modifier
                        .fillMaxWidth()
                        .height(48.dp),
                    shape = RoundedCornerShape(12.dp),
                    border = BorderStroke(1.dp, SentinelPrimary)
                ) {
                    Icon(Icons.Filled.OpenInBrowser, contentDescription = null, modifier = Modifier.size(18.dp), tint = SentinelPrimary)
                    Spacer(Modifier.width(8.dp))
                    Text("Open in Sandboxed WebView (No JS)", color = SentinelPrimary, fontWeight = FontWeight.SemiBold)
                }
            } else {
                Surface(
                    color = if (analysis.verdict == SecurityVerdict.MALICIOUS || analysis.verdict == SecurityVerdict.HIGH_RISK) DangerContainer else SurfaceSubtle,
                    shape = RoundedCornerShape(10.dp),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Text(
                        text = when {
                            !isWebScheme -> "Unsafe URI scheme blocked: only http/https URLs can be previewed."
                            else -> "Direct WebView opening is blocked for ${analysis.verdict.label} URLs."
                        },
                        modifier = Modifier.padding(12.dp),
                        fontSize = 12.sp,
                        fontWeight = FontWeight.Medium,
                        color = if (analysis.verdict == SecurityVerdict.MALICIOUS || analysis.verdict == SecurityVerdict.HIGH_RISK) DangerRed else TextSecondary
                    )
                }
            }
        }

        // Redirect & TLS cards when attempted
        val redir = report.redirectInspection
        val tls = report.tlsInspection
        if (redir.attempted || tls.attempted) {
            ClinicalSurfaceCard {
                Text(
                    text = "Live Network Forensics",
                    style = MaterialTheme.typography.titleSmall,
                    fontWeight = FontWeight.SemiBold,
                    color = TextPrimary
                )
                if (redir.attempted) {
                    Spacer(Modifier.height(8.dp))
                    Text(
                        text = if (redir.succeeded) {
                            "Redirect Hops (${redir.chain.size}) • Final HTTP ${redir.finalStatusCode ?: "—"}" +
                                if (redir.crossDomainRedirect) " • Cross-domain redirect" else ""
                        } else {
                            "Redirect check failed: ${redir.error ?: "Unreachable"}"
                        },
                        fontSize = 12.sp,
                        fontWeight = FontWeight.Medium,
                        color = if (redir.succeeded) TextPrimary else WarningAmber
                    )
                    redir.chain.forEachIndexed { idx, hop ->
                        Text(
                            text = "${idx + 1}. $hop",
                            fontFamily = FontFamily.Monospace,
                            fontSize = 11.sp,
                            color = TextSecondary,
                            modifier = Modifier.padding(top = 2.dp)
                        )
                    }
                }
                if (tls.attempted) {
                    Spacer(Modifier.height(10.dp))
                    HorizontalDivider(color = BorderColor)
                    Spacer(Modifier.height(10.dp))
                    Text(
                        text = when {
                            tls.succeeded && tls.certificateValid == true -> "TLS X.509 Certificate Verified"
                            tls.succeeded && tls.selfSigned == true -> "TLS Warning: Self-Signed Certificate"
                            tls.succeeded -> "TLS Certificate Invalid / Mismatch"
                            else -> "TLS Handshake Failed: ${tls.error ?: "Unreachable"}"
                        },
                        fontSize = 12.sp,
                        fontWeight = FontWeight.SemiBold,
                        color = when {
                            tls.succeeded && tls.certificateValid == true -> SuccessGreen
                            else -> DangerRed
                        }
                    )
                    tls.subject?.let { Text("Subject: $it", fontSize = 11.sp, color = TextSecondary) }
                    tls.issuer?.let { Text("Issuer: $it", fontSize = 11.sp, color = TextSecondary) }
                    if (tls.sanHostnames.isNotEmpty()) {
                        Text("SANs: ${tls.sanHostnames.take(5).joinToString(", ")}", fontSize = 11.sp, color = TextSecondary)
                    }
                    tls.notAfterMs?.let { exp ->
                        val fmt = SimpleDateFormat("yyyy-MM-dd", Locale.US)
                        Text("Valid until: ${fmt.format(Date(exp))}", fontSize = 11.sp, color = TextSecondary)
                    }
                }
            }
        }

        if (analysis.findings.isNotEmpty()) {
            SectionHeaderRow(
                title = "Detected URL Indicators (${analysis.findings.size})",
                subtitle = "Tap any finding to inspect evidence"
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
private fun UrlStatChip(
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
                style = TabularUrlStyle.copy(fontSize = 12.sp, fontWeight = FontWeight.SemiBold),
                color = TextPrimary,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis
            )
        }
    }
}
