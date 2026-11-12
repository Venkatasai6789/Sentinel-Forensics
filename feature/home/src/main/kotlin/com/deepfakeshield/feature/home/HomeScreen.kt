package com.deepfakeshield.feature.home

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
import androidx.compose.material.icons.filled.*
import androidx.compose.material.icons.outlined.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.hapticfeedback.HapticFeedbackType
import androidx.compose.ui.platform.LocalHapticFeedback
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.hilt.navigation.compose.hiltViewModel
import com.deepfakeshield.core.model.RiskSeverity
import com.deepfakeshield.core.model.SecurityAnalysisResult
import com.deepfakeshield.core.model.SecurityModule
import com.deepfakeshield.core.model.SecurityVerdict
import com.deepfakeshield.core.ui.components.ClinicalSurfaceCard
import com.deepfakeshield.core.ui.components.SectionHeaderRow
import com.deepfakeshield.core.ui.components.VerdictStatusPill
import com.deepfakeshield.core.ui.theme.*
import com.deepfakeshield.data.repository.VaultHealthSummary
import java.time.Instant
import java.time.ZoneId
import java.time.format.DateTimeFormatter
import java.util.Locale

private val TabularStyle = TextStyle(fontFeatureSettings = "tnum")

@Composable
fun HomeScreen(
    viewModel: HomeViewModel = hiltViewModel(),
    onNavigateToAlerts: () -> Unit = {},
    onNavigateToVault: () -> Unit = {},
    onNavigateToSettings: () -> Unit = {},
    onNavigateToDiagnostics: () -> Unit = {},
    onNavigateToVideoScan: () -> Unit = {},
    onNavigateToMessageScan: () -> Unit = {},
    onNavigateToScanHub: () -> Unit = {},
    onNavigateToAnalytics: () -> Unit = {},
    onNavigateToEducation: () -> Unit = {},
    onNavigateToCallProtection: () -> Unit = {},
    onNavigateToDailyChallenge: () -> Unit = {},
    onNavigateToQrScanner: () -> Unit = {},
    onNavigateToReferral: () -> Unit = {},
    onNavigateToFamilyCircle: () -> Unit = {},
    onNavigateToAchievements: () -> Unit = {},
    onNavigateToThreatMap: () -> Unit = {},
    onNavigateToSafeBrowser: () -> Unit = {},
    onNavigateToPermissionSetup: () -> Unit = {},
    onNavigateToIntelligenceDashboard: () -> Unit = {},
    onNavigateToPrivacyScore: () -> Unit = {},
    onNavigateToAppAuditor: () -> Unit = {},
    onNavigateToBreachMonitor: () -> Unit = {},
    onNavigateToWifiScanner: () -> Unit = {},
    onNavigateToPasswordChecker: () -> Unit = {},
    onNavigateToPhotoForensics: () -> Unit = {},
    onNavigateToEmergencySos: () -> Unit = {},
    onNavigateToDarkWebMonitor: () -> Unit = {},
    onNavigateToScamNumberLookup: () -> Unit = {},
    onNavigateToDigitalFootprint: () -> Unit = {},
    onNavigateToSecurityNewsFeed: () -> Unit = {},
    onNavigateToDeviceTimeline: () -> Unit = {},
    onNavigateToFakeReviewDetector: () -> Unit = {},
    onNavigateToSecureNotes: () -> Unit = {},
    onNavigateToNetworkMonitor: () -> Unit = {},
    onNavigateToTorSettings: () -> Unit = {},
    onStartOverlayBubble: () -> Unit = {},
    onStopOverlayBubble: () -> Unit = {}
) {
    val uiState by viewModel.uiState.collectAsState()
    val haptic = LocalHapticFeedback.current

    HomeScreenContent(
        uiState = uiState,
        onNavigateToAlerts = onNavigateToAlerts,
        onNavigateToSettings = onNavigateToSettings,
        onToggleProtection = { enabled ->
            haptic.performHapticFeedback(HapticFeedbackType.LongPress)
            viewModel.toggleMasterProtection(enabled)
        },
        onNavigateToDiagnostics = onNavigateToDiagnostics,
        onNavigateToSafeBrowser = onNavigateToSafeBrowser,
        onNavigateToVideoScan = onNavigateToVideoScan,
        onNavigateToPhotoForensics = onNavigateToPhotoForensics,
        onNavigateToMessageScan = onNavigateToMessageScan,
        onNavigateToScanHub = onNavigateToScanHub,
        onNavigateToCallProtection = onNavigateToCallProtection,
        onNavigateToPasswordChecker = onNavigateToPasswordChecker
    )
}

@Composable
fun HomeScreenContent(
    uiState: HomeUiState,
    onNavigateToAlerts: () -> Unit = {},
    onNavigateToSettings: () -> Unit = {},
    onToggleProtection: (Boolean) -> Unit = {},
    onNavigateToDiagnostics: () -> Unit = {},
    onNavigateToSafeBrowser: () -> Unit = {},
    onNavigateToVideoScan: () -> Unit = {},
    onNavigateToPhotoForensics: () -> Unit = {},
    onNavigateToMessageScan: () -> Unit = {},
    onNavigateToScanHub: () -> Unit = {},
    onNavigateToCallProtection: () -> Unit = {},
    onNavigateToPasswordChecker: () -> Unit = {}
) {
    val scrollState = rememberScrollState()

    Scaffold(
        topBar = {
            Column {
                DashboardHeader(
                    unreadCount = uiState.unhandledAlertCount,
                    onNotificationsClick = onNavigateToAlerts,
                    onSettingsClick = onNavigateToSettings
                )
                HorizontalDivider(color = BorderColor)
            }
        },
        containerColor = BackgroundLight
    ) { paddingValues ->
        if (uiState.isLoading) {
            Box(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(paddingValues),
                contentAlignment = Alignment.Center
            ) {
                Column(
                    horizontalAlignment = Alignment.CenterHorizontally,
                    verticalArrangement = Arrangement.spacedBy(12.dp)
                ) {
                    CircularProgressIndicator(
                        modifier = Modifier.size(36.dp),
                        color = SentinelPrimary,
                        strokeWidth = 3.dp
                    )
                    Text(
                        text = "Reading local forensic state...",
                        style = MaterialTheme.typography.bodyMedium,
                        color = TextSecondary
                    )
                }
            }
        } else {
            Column(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(paddingValues)
                    .verticalScroll(scrollState)
                    .padding(horizontal = 20.dp, vertical = 16.dp),
                verticalArrangement = Arrangement.spacedBy(16.dp)
            ) {
                DeviceProtectionStatusCard(
                    protectionState = uiState.protectionState,
                    isMasterEnabled = uiState.masterProtectionEnabled,
                    onToggleProtection = onToggleProtection
                )

                SecurityOverviewMetricsRow(
                    metrics = uiState.metrics,
                    totalPersistedScans = uiState.totalPersistedScans,
                    lastScanTimestamp = uiState.lastScanTimestamp,
                    onMetricClick = { index ->
                        when (index) {
                            0 -> onNavigateToDiagnostics()
                            1, 2 -> onNavigateToAlerts()
                            else -> onNavigateToScanHub()
                        }
                    }
                )

                AttentionRequiredCard(
                    unhandledCount = uiState.unhandledAlertCount,
                    totalScans = uiState.totalPersistedScans,
                    alertSummary = uiState.alertSummary,
                    onClick = if (uiState.unhandledAlertCount > 0) onNavigateToAlerts else onNavigateToScanHub
                )

                QuickScanSection(
                    moduleSummaries = uiState.moduleSummaries,
                    vaultHealth = uiState.vaultHealth,
                    onViewAllClick = onNavigateToScanHub,
                    onMessageShieldClick = onNavigateToMessageScan,
                    onPhishingClick = onNavigateToSafeBrowser,
                    onDeviceScanClick = onNavigateToDiagnostics,
                    onDeepfakeClick = onNavigateToVideoScan,
                    onPhotoForensicsClick = onNavigateToPhotoForensics,
                    onPasswordVaultClick = onNavigateToPasswordChecker
                )

                ProtectionActivitySection(
                    activities = uiState.dailyActivities,
                    hasHistory = uiState.hasActivityHistory,
                    totalScans = uiState.totalPersistedScans,
                    onStartScanClick = onNavigateToScanHub
                )

                if (uiState.recentScans.isNotEmpty()) {
                    RecentForensicActivitySection(
                        recentScans = uiState.recentScans.take(5),
                        onItemClick = { scan ->
                            when (scan.module) {
                                SecurityModule.MESSAGE_SHIELD -> onNavigateToMessageScan()
                                SecurityModule.PHISHING_URL_SCAN -> onNavigateToSafeBrowser()
                                SecurityModule.DEVICE_ANTIVIRUS -> onNavigateToDiagnostics()
                                SecurityModule.DEEPFAKE_VIDEO -> onNavigateToVideoScan()
                                SecurityModule.PHOTO_FORENSICS -> onNavigateToPhotoForensics()
                                SecurityModule.PASSWORD_VAULT -> onNavigateToPasswordChecker()
                            }
                        }
                    )
                }

                Spacer(Modifier.height(8.dp))
            }
        }
    }
}

@Preview(name = "Sentinel Forensics Dashboard (Empty Baseline)", showBackground = true, showSystemUi = true)
@Composable
fun HomeScreenPreview() {
    MaterialTheme {
        HomeScreenContent(
            uiState = HomeUiState(
                isLoading = false,
                protectionState = ProtectionState(
                    status = ProtectionStatus.INACTIVE,
                    activeModules = 0,
                    totalModules = HomeViewModel.TOTAL_MODULES,
                    lastUpdated = null
                )
            )
        )
    }
}

@Composable
fun DashboardHeader(
    unreadCount: Int,
    onNotificationsClick: () -> Unit,
    onSettingsClick: () -> Unit
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .background(SurfaceLight)
            .statusBarsPadding()
            .padding(horizontal = 20.dp, vertical = 12.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Image(
            painter = painterResource(com.deepfakeshield.core.R.drawable.ic_sentinel_emblem),
            contentDescription = "Sentinel Forensics emblem",
            modifier = Modifier
                .size(32.dp)
                .clip(RoundedCornerShape(8.dp))
        )

        Spacer(Modifier.width(12.dp))

        Column(modifier = Modifier.weight(1f)) {
            Text(
                text = "Sentinel Forensics",
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.SemiBold,
                color = TextPrimary
            )
            Text(
                text = "On-Device Inspection Suite",
                style = MaterialTheme.typography.bodySmall,
                color = TextSecondary
            )
        }

        BadgedBox(
            badge = {
                if (unreadCount > 0) {
                    Badge(
                        containerColor = DangerRed,
                        modifier = Modifier.offset(x = (-4).dp, y = 4.dp)
                    ) {
                        Text(
                            text = if (unreadCount > 99) "99+" else "$unreadCount",
                            color = Color.White,
                            fontSize = 10.sp,
                            fontWeight = FontWeight.SemiBold
                        )
                    }
                }
            }
        ) {
            IconButton(onClick = onNotificationsClick) {
                Icon(
                    imageVector = Icons.Outlined.Notifications,
                    contentDescription = "Security Alerts",
                    tint = TextPrimary
                )
            }
        }

        IconButton(onClick = onSettingsClick) {
            Icon(
                imageVector = Icons.Outlined.Settings,
                contentDescription = "Settings",
                tint = TextPrimary
            )
        }
    }
}

@Composable
fun DeviceProtectionStatusCard(
    protectionState: ProtectionState,
    isMasterEnabled: Boolean,
    onToggleProtection: (Boolean) -> Unit
) {
    val status = protectionState.status

    val accentColor = when (status) {
        ProtectionStatus.ACTIVE -> SuccessGreen
        ProtectionStatus.PARTIAL -> WarningAmber
        ProtectionStatus.ATTENTION_REQUIRED -> DangerRed
        ProtectionStatus.INACTIVE, ProtectionStatus.UNKNOWN -> TextSecondary
    }

    val badgeBg = when (status) {
        ProtectionStatus.ACTIVE -> SuccessContainer
        ProtectionStatus.PARTIAL -> WarningContainer
        ProtectionStatus.ATTENTION_REQUIRED -> DangerContainer
        ProtectionStatus.INACTIVE, ProtectionStatus.UNKNOWN -> SurfaceSubtle
    }

    val titleText = when (status) {
        ProtectionStatus.ACTIVE -> "Background Monitors Active"
        ProtectionStatus.PARTIAL -> "Partial Monitoring Active"
        ProtectionStatus.ATTENTION_REQUIRED -> "Findings Require Review"
        ProtectionStatus.INACTIVE -> "Background Monitors Off"
        ProtectionStatus.UNKNOWN -> "Evaluating Local State"
    }

    val subtitleText = when (status) {
        ProtectionStatus.ACTIVE -> "${protectionState.activeModules} of ${protectionState.totalModules} real-time listeners enabled"
        ProtectionStatus.PARTIAL -> "${protectionState.activeModules} of ${protectionState.totalModules} listeners enabled — on-demand tools available"
        ProtectionStatus.ATTENTION_REQUIRED -> "Unresolved threat alerts exist — open Alerts to inspect"
        ProtectionStatus.INACTIVE -> "Manual forensic scans remain available below"
        ProtectionStatus.UNKNOWN -> "Reading Room database and service flags"
    }

    ClinicalSurfaceCard(contentPadding = PaddingValues(16.dp)) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Box(
                modifier = Modifier
                    .size(44.dp)
                    .background(badgeBg, CircleShape),
                contentAlignment = Alignment.Center
            ) {
                Icon(
                    imageVector = when (status) {
                        ProtectionStatus.ACTIVE -> Icons.Filled.VerifiedUser
                        ProtectionStatus.PARTIAL -> Icons.Filled.Warning
                        ProtectionStatus.ATTENTION_REQUIRED -> Icons.Filled.Error
                        ProtectionStatus.INACTIVE -> Icons.Outlined.Shield
                        ProtectionStatus.UNKNOWN -> Icons.Outlined.HourglassTop
                    },
                    contentDescription = null,
                    tint = accentColor,
                    modifier = Modifier.size(22.dp)
                )
            }

            Spacer(Modifier.width(14.dp))

            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = titleText,
                    style = MaterialTheme.typography.titleSmall,
                    fontWeight = FontWeight.SemiBold,
                    color = TextPrimary
                )
                Spacer(Modifier.height(2.dp))
                Text(
                    text = subtitleText,
                    style = MaterialTheme.typography.bodySmall,
                    color = TextSecondary,
                    maxLines = 2,
                    overflow = TextOverflow.Ellipsis
                )
            }

            Spacer(Modifier.width(8.dp))

            Switch(
                checked = isMasterEnabled,
                onCheckedChange = onToggleProtection,
                colors = SwitchDefaults.colors(
                    checkedThumbColor = Color.White,
                    checkedTrackColor = if (status == ProtectionStatus.ACTIVE) SuccessGreen else SentinelPrimary,
                    uncheckedThumbColor = Color.White,
                    uncheckedTrackColor = Gray300
                )
            )
        }
    }
}

@Composable
fun SecurityOverviewMetricsRow(
    metrics: DashboardMetrics?,
    totalPersistedScans: Int = 0,
    lastScanTimestamp: Long,
    onMetricClick: (Int) -> Unit
) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.spacedBy(8.dp)
    ) {
        val scoreText = metrics?.protectionScore?.toString() ?: "—"
        val scoreInt = metrics?.protectionScore
        val scoreColor = when {
            scoreInt == null -> TextPrimary
            scoreInt >= 75 -> SuccessGreen
            scoreInt >= 50 -> WarningAmber
            else -> DangerRed
        }
        MetricCard(
            modifier = Modifier.weight(1f),
            icon = Icons.Outlined.Shield,
            iconTint = if (scoreInt == null) TextSecondary else scoreColor,
            value = scoreText,
            valueColor = scoreColor,
            label = "Readiness",
            onClick = { onMetricClick(0) }
        )

        MetricCard(
            modifier = Modifier.weight(1f),
            icon = Icons.Outlined.FactCheck,
            iconTint = SentinelPrimary,
            value = "$totalPersistedScans",
            valueColor = TextPrimary,
            label = "Scans Run",
            onClick = { onMetricClick(3) }
        )

        val unreadAlerts = metrics?.unreadAlertCount ?: 0
        MetricCard(
            modifier = Modifier.weight(1f),
            icon = Icons.Outlined.WarningAmber,
            iconTint = if (unreadAlerts > 0) DangerRed else TextSecondary,
            value = "$unreadAlerts",
            valueColor = if (unreadAlerts > 0) DangerRed else TextPrimary,
            label = "Alerts",
            onClick = { onMetricClick(2) }
        )

        val scanText = if (lastScanTimestamp > 0L) formatRelativeTime(lastScanTimestamp) else "—"
        MetricCard(
            modifier = Modifier.weight(1f),
            icon = Icons.Outlined.Schedule,
            iconTint = TextSecondary,
            value = scanText,
            valueColor = TextPrimary,
            label = "Last Scan",
            onClick = { onMetricClick(3) }
        )
    }
}

@Composable
private fun MetricCard(
    modifier: Modifier = Modifier,
    icon: ImageVector,
    iconTint: Color,
    value: String,
    valueColor: Color,
    label: String,
    onClick: () -> Unit
) {
    Surface(
        modifier = modifier
            .clip(RoundedCornerShape(14.dp))
            .clickable(onClick = onClick),
        shape = RoundedCornerShape(14.dp),
        color = SurfaceLight,
        border = BorderStroke(1.dp, BorderColor)
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 10.dp, vertical = 12.dp),
            verticalArrangement = Arrangement.spacedBy(6.dp)
        ) {
            Icon(
                imageVector = icon,
                contentDescription = null,
                tint = iconTint,
                modifier = Modifier.size(18.dp)
            )
            Text(
                text = value,
                style = TabularStyle.copy(fontSize = 18.sp, fontWeight = FontWeight.Bold),
                color = valueColor,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis
            )
            Text(
                text = label,
                fontSize = 11.sp,
                color = TextSecondary,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis
            )
        }
    }
}

@Composable
fun ProtectionActivitySection(
    activities: List<DailyActivity>,
    hasHistory: Boolean,
    totalScans: Int = 0,
    protectionScore: Int = 0,
    onStartScanClick: () -> Unit
) {
    ClinicalSurfaceCard(contentPadding = PaddingValues(16.dp)) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = "7-Day Scan Activity",
                    style = MaterialTheme.typography.titleSmall,
                    fontWeight = FontWeight.SemiBold,
                    color = TextPrimary
                )
                Text(
                    text = if (hasHistory) "Source: local Room scan history ($totalScans total)" else "Source: local Room database",
                    fontSize = 11.sp,
                    color = TextSecondary
                )
            }
            if (hasHistory) {
                Surface(
                    shape = RoundedCornerShape(999.dp),
                    color = SentinelPrimaryContainer
                ) {
                    Text(
                        text = "$totalScans scans",
                        modifier = Modifier.padding(horizontal = 10.dp, vertical = 4.dp),
                        style = TabularStyle.copy(fontSize = 12.sp, fontWeight = FontWeight.SemiBold),
                        color = SentinelPrimary
                    )
                }
            }
        }

        Spacer(Modifier.height(14.dp))

        if (!hasHistory || activities.isEmpty()) {
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(vertical = 10.dp),
                horizontalAlignment = Alignment.CenterHorizontally,
                verticalArrangement = Arrangement.spacedBy(10.dp)
            ) {
                Text(
                    text = "No completed scans recorded yet. Telemetry appears here after your first real inspection.",
                    style = MaterialTheme.typography.bodySmall,
                    color = TextSecondary,
                    textAlign = TextAlign.Center
                )
                OutlinedButton(
                    onClick = onStartScanClick,
                    shape = RoundedCornerShape(10.dp),
                    border = BorderStroke(1.dp, SentinelPrimary),
                    colors = ButtonDefaults.outlinedButtonColors(contentColor = SentinelPrimary)
                ) {
                    Text("Open Scan Center", fontWeight = FontWeight.Medium)
                }
            }
        } else {
            val maxTotal = activities.maxOf { maxOf(it.completedScans, it.detectedIssues) }.coerceAtLeast(1)
            val totalWeekIssues = activities.sumOf { it.detectedIssues }

            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .height(92.dp),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.Bottom
            ) {
                activities.forEachIndexed { idx, day ->
                    val count = maxOf(day.completedScans, day.detectedIssues)
                    val heightFraction = if (count == 0) 0.08f else (count.toFloat() / maxTotal.toFloat()).coerceIn(0.16f, 1f)
                    val barHeight = if (count == 0) 4.dp else (48f * heightFraction).dp
                    val isToday = idx == activities.lastIndex
                    val barColor = when {
                        day.detectedIssues > 0 -> DangerRed
                        count == 0 -> BorderColor
                        isToday -> SentinelPrimary
                        else -> SentinelPrimary.copy(alpha = 0.45f)
                    }

                    Column(
                        modifier = Modifier.weight(1f),
                        horizontalAlignment = Alignment.CenterHorizontally,
                        verticalArrangement = Arrangement.Bottom
                    ) {
                        if (count > 0) {
                            Text(
                                text = "$count",
                                style = TabularStyle.copy(fontSize = 10.sp, fontWeight = FontWeight.Medium),
                                color = if (day.detectedIssues > 0) DangerRed else TextSecondary
                            )
                            Spacer(Modifier.height(2.dp))
                        }
                        Box(
                            modifier = Modifier
                                .width(18.dp)
                                .height(barHeight)
                                .clip(RoundedCornerShape(topStart = 4.dp, topEnd = 4.dp))
                                .background(barColor)
                        )
                        Spacer(Modifier.height(6.dp))
                        Text(
                            text = day.dayLabel,
                            fontSize = 11.sp,
                            color = if (isToday) TextPrimary else TextSecondary,
                            fontWeight = if (isToday) FontWeight.SemiBold else FontWeight.Normal,
                            maxLines = 1
                        )
                    }
                }
            }

            if (totalWeekIssues > 0) {
                Spacer(Modifier.height(8.dp))
                Text(
                    text = "$totalWeekIssues alert(s) flagged in the past 7 days",
                    fontSize = 11.sp,
                    color = WarningAmber,
                    fontWeight = FontWeight.Medium
                )
            }
        }
    }
}

@Composable
fun AttentionRequiredCard(
    unhandledCount: Int,
    totalScans: Int = 0,
    alertSummary: DashboardAlertSummary?,
    onClick: () -> Unit
) {
    val hasAlerts = unhandledCount > 0
    val neverScanned = totalScans == 0 && !hasAlerts

    val borderColor = when {
        hasAlerts -> DangerRed.copy(alpha = 0.25f)
        neverScanned -> BorderColor
        else -> SuccessGreen.copy(alpha = 0.25f)
    }
    val containerColor = when {
        hasAlerts -> DangerContainer
        neverScanned -> SurfaceLight
        else -> SuccessContainer
    }
    val iconColor = when {
        hasAlerts -> DangerRed
        neverScanned -> SentinelPrimary
        else -> SuccessGreen
    }
    val icon = when {
        hasAlerts -> Icons.Filled.Warning
        neverScanned -> Icons.Outlined.Info
        else -> Icons.Filled.CheckCircle
    }
    val title = when {
        hasAlerts -> alertSummary?.title ?: "$unhandledCount item(s) require attention"
        neverScanned -> "No Scans Completed Yet"
        else -> "No Unresolved Threat Alerts"
    }
    val subtitle = when {
        hasAlerts -> alertSummary?.description ?: "Inspect flagged evidence in Alerts"
        neverScanned -> "Select a tool below to inspect messages, URLs, files, or media"
        else -> "Last completed checks raised 0 unresolved alerts"
    }

    ClinicalSurfaceCard(
        containerColor = containerColor,
        borderColor = borderColor,
        contentPadding = PaddingValues(14.dp),
        onClick = onClick
    ) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Icon(imageVector = icon, contentDescription = null, tint = iconColor, modifier = Modifier.size(22.dp))
            Spacer(Modifier.width(12.dp))
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = title,
                    style = MaterialTheme.typography.titleSmall,
                    fontWeight = FontWeight.SemiBold,
                    color = TextPrimary
                )
                Text(
                    text = subtitle,
                    style = MaterialTheme.typography.bodySmall,
                    color = TextSecondary,
                    maxLines = 2,
                    overflow = TextOverflow.Ellipsis
                )
            }
            Icon(imageVector = Icons.Default.ChevronRight, contentDescription = "Open", tint = iconColor)
        }
    }
}

@Composable
fun QuickScanSection(
    moduleSummaries: Map<SecurityModule, ModuleStatusSummary> = emptyMap(),
    vaultHealth: VaultHealthSummary = VaultHealthSummary(),
    onViewAllClick: () -> Unit,
    onMessageShieldClick: () -> Unit = {},
    onPhishingClick: () -> Unit,
    onDeviceScanClick: () -> Unit,
    onDeepfakeClick: () -> Unit,
    onPhotoForensicsClick: () -> Unit,
    onPasswordVaultClick: () -> Unit
) {
    Column(
        modifier = Modifier.fillMaxWidth(),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        SectionHeaderRow(
            title = "Core Security Modules",
            subtitle = "Six local forensic & hardening tools",
            actionLabel = "All Scans",
            onActionClick = onViewAllClick
        )

        Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(10.dp)) {
            ModuleGridCard(
                modifier = Modifier.weight(1f),
                title = "Message Shield",
                summary = moduleSummaries[SecurityModule.MESSAGE_SHIELD],
                icon = Icons.Outlined.Sms,
                onClick = onMessageShieldClick
            )
            ModuleGridCard(
                modifier = Modifier.weight(1f),
                title = "Phishing URL Scan",
                summary = moduleSummaries[SecurityModule.PHISHING_URL_SCAN],
                icon = Icons.Outlined.Link,
                onClick = onPhishingClick
            )
        }

        Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(10.dp)) {
            ModuleGridCard(
                modifier = Modifier.weight(1f),
                title = "Device Antivirus",
                summary = moduleSummaries[SecurityModule.DEVICE_ANTIVIRUS],
                icon = Icons.Outlined.Security,
                onClick = onDeviceScanClick
            )
            ModuleGridCard(
                modifier = Modifier.weight(1f),
                title = "Deepfake Video",
                summary = moduleSummaries[SecurityModule.DEEPFAKE_VIDEO],
                icon = Icons.Outlined.Videocam,
                onClick = onDeepfakeClick
            )
        }

        Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(10.dp)) {
            ModuleGridCard(
                modifier = Modifier.weight(1f),
                title = "Photo Forensics",
                summary = moduleSummaries[SecurityModule.PHOTO_FORENSICS],
                icon = Icons.Outlined.Image,
                onClick = onPhotoForensicsClick
            )
            ModuleGridCard(
                modifier = Modifier.weight(1f),
                title = "Password Vault",
                summary = moduleSummaries[SecurityModule.PASSWORD_VAULT],
                customStatusLine = when {
                    vaultHealth.breachedCount > 0 -> "${vaultHealth.breachedCount} breached"
                    vaultHealth.weakCount > 0 -> "${vaultHealth.weakCount} weak"
                    vaultHealth.totalCredentials > 0 -> "${vaultHealth.totalCredentials} encrypted"
                    else -> null
                },
                customStatusColor = when {
                    vaultHealth.breachedCount > 0 -> DangerRed
                    vaultHealth.weakCount > 0 -> WarningAmber
                    vaultHealth.totalCredentials > 0 -> SuccessGreen
                    else -> TextSecondary
                },
                icon = Icons.Outlined.VpnKey,
                onClick = onPasswordVaultClick
            )
        }
    }
}

@Composable
private fun ModuleGridCard(
    modifier: Modifier = Modifier,
    title: String,
    summary: ModuleStatusSummary?,
    icon: ImageVector,
    customStatusLine: String? = null,
    customStatusColor: Color? = null,
    onClick: () -> Unit
) {
    val verdict = summary?.lastVerdict
    val statusText = customStatusLine ?: when {
        verdict == null -> "Not scanned"
        else -> verdict.label
    }
    val statusColor = customStatusColor ?: when (verdict) {
        SecurityVerdict.SAFE, SecurityVerdict.LIKELY_AUTHENTIC -> SuccessGreen
        SecurityVerdict.LOW_RISK -> SentinelPrimary
        SecurityVerdict.SUSPICIOUS, SecurityVerdict.INCONCLUSIVE -> WarningAmber
        SecurityVerdict.HIGH_RISK, SecurityVerdict.MALICIOUS, SecurityVerdict.LIKELY_AI_GENERATED -> DangerRed
        null, SecurityVerdict.NOT_SUPPORTED, SecurityVerdict.NOT_ANALYZED -> TextSecondary
    }
    val timeText = if (summary != null && summary.lastScanAt > 0L) formatRelativeTime(summary.lastScanAt) else "Ready"

    Surface(
        modifier = modifier
            .defaultMinSize(minHeight = 110.dp)
            .clip(RoundedCornerShape(14.dp))
            .clickable(onClick = onClick),
        shape = RoundedCornerShape(14.dp),
        color = SurfaceLight,
        border = BorderStroke(1.dp, BorderColor)
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(14.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp)
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Box(
                    modifier = Modifier
                        .size(36.dp)
                        .background(SentinelPrimaryContainer, CircleShape),
                    contentAlignment = Alignment.Center
                ) {
                    Icon(icon, contentDescription = null, tint = SentinelPrimary, modifier = Modifier.size(18.dp))
                }
                Text(
                    text = timeText,
                    fontSize = 11.sp,
                    color = TextTertiary
                )
            }
            Column(verticalArrangement = Arrangement.spacedBy(2.dp)) {
                Text(
                    text = title,
                    style = MaterialTheme.typography.titleSmall,
                    fontSize = 14.sp,
                    fontWeight = FontWeight.SemiBold,
                    color = TextPrimary,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis
                )
                Text(
                    text = statusText,
                    fontSize = 12.sp,
                    fontWeight = FontWeight.Medium,
                    color = statusColor,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis
                )
            }
        }
    }
}

@Composable
private fun RecentForensicActivitySection(
    recentScans: List<SecurityAnalysisResult>,
    onItemClick: (SecurityAnalysisResult) -> Unit
) {
    Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
        SectionHeaderRow(
            title = "Recent Forensics Log",
            subtitle = "Latest persisted Room records"
        )
        ClinicalSurfaceCard(contentPadding = PaddingValues(0.dp)) {
            recentScans.forEachIndexed { idx, item ->
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .clickable { onItemClick(item) }
                        .padding(horizontal = 16.dp, vertical = 12.dp),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(12.dp)
                ) {
                    Column(modifier = Modifier.weight(1f)) {
                        Text(
                            text = item.inputName ?: item.module.displayName,
                            style = MaterialTheme.typography.titleSmall,
                            fontSize = 13.sp,
                            fontWeight = FontWeight.SemiBold,
                            color = TextPrimary,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis
                        )
                        Text(
                            text = "${item.module.displayName} • ${formatRelativeTime(item.analyzedAt)}",
                            fontSize = 11.sp,
                            color = TextSecondary,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis
                        )
                    }
                    VerdictStatusPill(verdict = item.verdict)
                }
                if (idx < recentScans.lastIndex) {
                    HorizontalDivider(color = BorderColor, modifier = Modifier.padding(horizontal = 16.dp))
                }
            }
        }
    }
}

internal fun formatRelativeTime(timestamp: Long, currentTime: Long = System.currentTimeMillis()): String {
    if (timestamp <= 0L) return "Never"
    val diff = (currentTime - timestamp).coerceAtLeast(0L)
    val seconds = diff / 1000
    val minutes = seconds / 60
    val hours = minutes / 60
    val days = hours / 24

    return when {
        minutes < 1 -> "Just now"
        minutes < 60 -> "${minutes}m ago"
        hours < 24 -> "${hours}h ago"
        days == 1L -> "Yesterday"
        days < 7 -> "${days}d ago"
        else -> {
            val date = Instant.ofEpochMilli(timestamp)
                .atZone(ZoneId.systemDefault())
                .toLocalDate()
            date.format(DateTimeFormatter.ofPattern("MMM d", Locale.getDefault()))
        }
    }
}
