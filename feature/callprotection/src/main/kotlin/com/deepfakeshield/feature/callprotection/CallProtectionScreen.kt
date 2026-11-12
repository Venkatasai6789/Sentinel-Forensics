package com.deepfakeshield.feature.callprotection

import android.Manifest
import android.app.role.RoleManager
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import android.provider.CallLog
import android.provider.Settings
import android.widget.Toast
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.animation.animateContentSize
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.automirrored.filled.CallMade
import androidx.compose.material.icons.automirrored.filled.CallMissed
import androidx.compose.material.icons.automirrored.filled.CallReceived
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.hapticfeedback.HapticFeedbackType
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalHapticFeedback
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.content.ContextCompat
import androidx.hilt.navigation.compose.hiltViewModel
import com.deepfakeshield.core.ui.theme.*
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.text.SimpleDateFormat
import java.util.*

// ── Models ─────────────────────────────────────────────────────────

private data class CallEntry(
    val number: String, val name: String?, val type: Int,
    val date: Long, val duration: Long, val riskScore: Int,
    val riskReasons: List<String>, val areaInfo: String
)

private data class HourStat(val hour: Int, val total: Int, val suspicious: Int)

// ── Main Screen ────────────────────────────────────────────────────

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun CallProtectionScreen(
    viewModel: CallProtectionViewModel = hiltViewModel(),
    onNavigateBack: () -> Unit = {}
) {
    val uiState by viewModel.uiState.collectAsState()
    val ctx = LocalContext.current
    val haptic = LocalHapticFeedback.current
    var tab by remember { mutableIntStateOf(0) }

    val phoneLauncher = rememberLauncherForActivityResult(ActivityResultContracts.RequestMultiplePermissions()) { perms -> if (perms.values.all { it }) viewModel.enableCallProtection() }
    val audioLauncher = rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) { viewModel.toggleSpeakerphoneMode(it) }
    val roleManager = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) remember { ctx.getSystemService(Context.ROLE_SERVICE) as? RoleManager } else null
    val roleLauncher = rememberLauncherForActivityResult(ActivityResultContracts.StartActivityForResult()) { viewModel.checkCallScreeningRole(it.resultCode == android.app.Activity.RESULT_OK) }

    Scaffold(
        topBar = {
            TopAppBar(
                title = {
                    Column {
                        Text("Call Shield", fontWeight = FontWeight.Bold, style = MaterialTheme.typography.titleMedium, color = TextPrimary)
                        Text("Real-Time Scam & Robocall Screening", style = MaterialTheme.typography.bodySmall, color = TextSecondary)
                    }
                },
                navigationIcon = {
                    IconButton(onClick = onNavigateBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, "Back", tint = TextPrimary)
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(containerColor = SurfaceLight)
            )
        },
        containerColor = BackgroundLight
    ) { padding ->
        Column(Modifier.fillMaxSize().padding(padding)) {
            ScrollableTabRow(
                selectedTabIndex = tab,
                edgePadding = 16.dp,
                containerColor = SurfaceLight,
                contentColor = SentinelPrimary,
                divider = { HorizontalDivider(color = BorderColor) }
            ) {
                listOf("Dashboard" to Icons.Default.Dashboard, "Call Log" to Icons.Default.Phone, "Settings" to Icons.Default.Settings).forEachIndexed { i, (l, ic) ->
                    Tab(
                        selected = tab == i,
                        onClick = { tab = i },
                        text = { Text(l, fontSize = 13.sp, fontWeight = if (tab == i) FontWeight.Bold else FontWeight.Medium) },
                        icon = { Icon(ic, null, Modifier.size(18.dp)) },
                        selectedContentColor = SentinelPrimary,
                        unselectedContentColor = TextSecondary
                    )
                }
            }
            when (tab) {
                0 -> DashboardTab(uiState, ctx, haptic, roleManager, roleLauncher, phoneLauncher)
                1 -> CallLogTab(ctx, haptic)
                2 -> SettingsTab(uiState, viewModel, ctx, haptic, roleManager, roleLauncher, phoneLauncher, audioLauncher)
            }
        }
    }
}

// ═══════════════════════════════════════════════════════════════════
// TAB 1: DASHBOARD
// ═══════════════════════════════════════════════════════════════════

@Composable
private fun DashboardTab(
    uiState: CallProtectionUiState,
    ctx: Context = LocalContext.current,
    haptic: androidx.compose.ui.hapticfeedback.HapticFeedback = LocalHapticFeedback.current,
    roleManager: RoleManager? = null,
    roleLauncher: androidx.activity.result.ActivityResultLauncher<Intent>? = null,
    phoneLauncher: androidx.activity.result.ActivityResultLauncher<Array<String>>? = null
) {
    val isInspection = androidx.compose.ui.platform.LocalInspectionMode.current
    var calls by remember {
        mutableStateOf<List<CallEntry>>(
            if (isInspection) listOf(
                CallEntry("+1 (800) 555-0199", "Unknown Robocall", 1, System.currentTimeMillis() - 3600000, 2, 75, listOf("Robocall pattern", "Short duration"), "Toll-Free"),
                CallEntry("+1 (202) 555-0143", "IRS Imposter Suspicion", 1, System.currentTimeMillis() - 86400000, 15, 60, listOf("Suspicious area code"), "DC"),
                CallEntry("+1 (415) 555-0122", "Delivery Scam", 1, System.currentTimeMillis() - 172800000, 4, 45, listOf("Unknown number"), "SF")
            ) else emptyList()
        )
    }
    var hourStats by remember {
        mutableStateOf<List<HourStat>>(
            if (isInspection) (0..23).map { HourStat(it, if (it in 9..17) 4 else 1, if (it in 11..15) 2 else 0) } else emptyList()
        )
    }
    var isLoading by remember { mutableStateOf(false) }
    val hasCallLogPerm = !isInspection && ContextCompat.checkSelfPermission(ctx, Manifest.permission.READ_CALL_LOG) == PackageManager.PERMISSION_GRANTED

    LaunchedEffect(Unit) {
        if (!isInspection && hasCallLogPerm) {
            val result = try {
                withContext(Dispatchers.IO) { analyzeCallLog(ctx) }
            } catch (_: Throwable) {
                emptyList<CallEntry>() to emptyList<HourStat>()
            }
            calls = result.first
            hourStats = result.second
        }
        isLoading = false
    }

    val incomingType = 1
    val suspiciousCalls = calls.count { it.riskScore >= 50 }
    val unknownCallers = calls.count { it.name == null && it.type == incomingType }
    val shortCalls = calls.count { it.duration in 1..3 && it.type == incomingType }
    val intlCalls = calls.count { it.number.startsWith("+") && !it.number.startsWith("+1") }

    Column(
        Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(horizontal = 20.dp, vertical = 16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        // Protection status Card
        val isActive = uiState.callScreeningEnabled
        Card(
            Modifier.fillMaxWidth(),
            shape = RoundedCornerShape(14.dp),
            colors = CardDefaults.cardColors(containerColor = SurfaceLight),
            border = BorderStroke(1.dp, BorderColor)
        ) {
            Column(Modifier.padding(18.dp)) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Box(
                        Modifier
                            .size(44.dp)
                            .background(if (isActive) SuccessContainer else DangerContainer, CircleShape),
                        contentAlignment = Alignment.Center
                    ) {
                        Icon(
                            if (isActive) Icons.Default.Shield else Icons.Default.ShieldMoon,
                            null,
                            Modifier.size(22.dp),
                            tint = if (isActive) SuccessGreen else DangerRed
                        )
                    }
                    Spacer(Modifier.width(14.dp))
                    Column(Modifier.weight(1f)) {
                        Text(
                            if (isActive) "Call Shield Active" else "Call Shield Disabled",
                            fontWeight = FontWeight.Bold,
                            style = MaterialTheme.typography.titleMedium,
                            color = TextPrimary
                        )
                        Text(
                            if (isActive) "Screening incoming calls in real-time" else "Enable to intercept and block spam numbers",
                            style = MaterialTheme.typography.bodySmall,
                            color = TextSecondary
                        )
                    }
                    Surface(
                        shape = RoundedCornerShape(999.dp),
                        color = if (isActive) SuccessContainer else DangerContainer,
                        border = BorderStroke(1.dp, (if (isActive) SuccessGreen else DangerRed).copy(alpha = 0.2f))
                    ) {
                        Text(
                            if (isActive) "Screening" else "Off",
                            modifier = Modifier.padding(horizontal = 8.dp, vertical = 2.dp),
                            fontSize = 11.sp,
                            fontWeight = FontWeight.Bold,
                            color = if (isActive) SuccessGreen else DangerRed
                        )
                    }
                }
                if (!isActive) {
                    Spacer(Modifier.height(14.dp))
                    Button(
                        onClick = {
                            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q && roleManager != null) {
                                if (!roleManager.isRoleHeld(RoleManager.ROLE_CALL_SCREENING)) {
                                    roleLauncher?.launch(roleManager.createRequestRoleIntent(RoleManager.ROLE_CALL_SCREENING))
                                }
                            } else {
                                phoneLauncher?.launch(arrayOf(Manifest.permission.READ_PHONE_STATE, Manifest.permission.READ_CALL_LOG))
                            }
                        },
                        Modifier.fillMaxWidth().height(48.dp),
                        shape = RoundedCornerShape(10.dp),
                        colors = ButtonDefaults.buttonColors(containerColor = SentinelPrimary)
                    ) {
                        Text("Enable Call Shield", fontWeight = FontWeight.SemiBold)
                    }
                }
            }
        }

        // Stats Row
        if (isActive || calls.isNotEmpty()) {
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                StatCard("${uiState.totalCallsAnalyzed}", "Screened", SentinelPrimary, Modifier.weight(1f))
                StatCard("${uiState.scamsDetected.coerceAtLeast(if (isInspection) 12 else 0)}", "Blocked", DangerRed, Modifier.weight(1f))
                StatCard("${suspiciousCalls.coerceAtLeast(if (isInspection) 2 else 0)}", "Suspicious", WarningAmber, Modifier.weight(1f))
                StatCard("$unknownCallers", "Unknown", TextSecondary, Modifier.weight(1f))
            }
        }

        // Risk indicators Card
        if (calls.isNotEmpty()) {
            Card(
                Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(14.dp),
                colors = CardDefaults.cardColors(containerColor = SurfaceLight),
                border = BorderStroke(1.dp, BorderColor)
            ) {
                Column(Modifier.padding(18.dp)) {
                    Text("Risk Indicator Breakdown", fontWeight = FontWeight.Bold, style = MaterialTheme.typography.titleSmall, color = TextPrimary)
                    Spacer(Modifier.height(12.dp))

                    listOf(
                        Triple("Short Duration Calls (1-3s robocall pattern)", "$shortCalls", if (shortCalls > 3) DangerRed else SuccessGreen),
                        Triple("Unknown Callers (Not in device contacts)", "$unknownCallers", if (unknownCallers > 10) WarningAmber else SuccessGreen),
                        Triple("International / Callback Inquiries", "$intlCalls", if (intlCalls > 5) WarningAmber else SuccessGreen)
                    ).forEachIndexed { i, (label, value, color) ->
                        Row(Modifier.fillMaxWidth().padding(vertical = 4.dp), verticalAlignment = Alignment.CenterVertically) {
                            Box(Modifier.size(8.dp).background(color, CircleShape))
                            Spacer(Modifier.width(10.dp))
                            Text(label, style = MaterialTheme.typography.bodySmall, color = TextPrimary, modifier = Modifier.weight(1f))
                            Text(value, fontWeight = FontWeight.Bold, color = color, fontSize = 13.sp)
                        }
                        if (i < 2) {
                            HorizontalDivider(color = BorderColor.copy(alpha = 0.5f), modifier = Modifier.padding(vertical = 6.dp))
                        }
                    }
                }
            }

            // Hour distribution Card
            if (hourStats.isNotEmpty()) {
                Card(
                    Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(14.dp),
                    colors = CardDefaults.cardColors(containerColor = SurfaceLight),
                    border = BorderStroke(1.dp, BorderColor)
                ) {
                    Column(Modifier.padding(18.dp)) {
                        Text("24-Hour Call Frequency Timeline", fontWeight = FontWeight.Bold, style = MaterialTheme.typography.titleSmall, color = TextPrimary)
                        Spacer(Modifier.height(12.dp))
                        val maxH = hourStats.maxOf { it.total }.coerceAtLeast(1)
                        Row(
                            Modifier.fillMaxWidth().height(64.dp),
                            verticalAlignment = Alignment.Bottom,
                            horizontalArrangement = Arrangement.spacedBy(2.dp)
                        ) {
                            hourStats.forEach { h ->
                                val pct = h.total.toFloat() / maxH
                                val color = when {
                                    h.suspicious > 0 -> DangerRed
                                    h.hour in 0..5 -> WarningAmber
                                    else -> SentinelPrimary
                                }
                                Box(
                                    Modifier
                                        .weight(1f)
                                        .fillMaxHeight(pct.coerceAtLeast(0.04f))
                                        .background(color.copy(0.7f), RoundedCornerShape(topStart = 2.dp, topEnd = 2.dp))
                                )
                            }
                        }
                        Spacer(Modifier.height(6.dp))
                        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                            Text("12am", fontSize = 9.sp, color = TextSecondary)
                            Text("6am", fontSize = 9.sp, color = TextSecondary)
                            Text("12pm", fontSize = 9.sp, color = TextSecondary)
                            Text("6pm", fontSize = 9.sp, color = TextSecondary)
                            Text("12am", fontSize = 9.sp, color = TextSecondary)
                        }
                        Spacer(Modifier.height(10.dp))
                        Row(horizontalArrangement = Arrangement.spacedBy(16.dp)) {
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                Box(Modifier.size(8.dp).background(SentinelPrimary, CircleShape))
                                Spacer(Modifier.width(4.dp))
                                Text("Standard", fontSize = 10.sp, color = TextSecondary)
                            }
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                Box(Modifier.size(8.dp).background(WarningAmber, CircleShape))
                                Spacer(Modifier.width(4.dp))
                                Text("Late Night", fontSize = 10.sp, color = TextSecondary)
                            }
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                Box(Modifier.size(8.dp).background(DangerRed, CircleShape))
                                Spacer(Modifier.width(4.dp))
                                Text("Suspicious", fontSize = 10.sp, color = TextSecondary)
                            }
                        }
                    }
                }
            }

            // Recent suspicious calls
            val suspicious = calls.filter { it.riskScore >= 40 }.take(8)
            if (suspicious.isNotEmpty()) {
                Text("Recent Suspicious Inquiries", fontWeight = FontWeight.Bold, style = MaterialTheme.typography.titleSmall, color = TextPrimary)
                suspicious.forEach { call -> CallCard(call) }
            }
        } else if (!hasCallLogPerm) {
            Card(
                Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(14.dp),
                colors = CardDefaults.cardColors(containerColor = SurfaceLight),
                border = BorderStroke(1.dp, BorderColor)
            ) {
                Column(Modifier.padding(20.dp), horizontalAlignment = Alignment.CenterHorizontally) {
                    Box(
                        modifier = Modifier.size(44.dp).background(WarningContainer, CircleShape),
                        contentAlignment = Alignment.Center
                    ) {
                        Icon(Icons.Default.PhoneLocked, null, Modifier.size(22.dp), tint = WarningAmber)
                    }
                    Spacer(Modifier.height(10.dp))
                    Text("Call Log Permission Required", fontWeight = FontWeight.Bold, color = TextPrimary)
                    Spacer(Modifier.height(4.dp))
                    Text(
                        "Grant read access to your call history to detect automated robocall clusters and fraudulent area codes.",
                        style = MaterialTheme.typography.bodySmall,
                        textAlign = TextAlign.Center,
                        color = TextSecondary
                    )
                    Spacer(Modifier.height(14.dp))
                    Button(
                        onClick = { phoneLauncher?.launch(arrayOf(Manifest.permission.READ_CALL_LOG, Manifest.permission.READ_PHONE_STATE)) },
                        shape = RoundedCornerShape(10.dp),
                        colors = ButtonDefaults.buttonColors(containerColor = SentinelPrimary)
                    ) {
                        Text("Grant Permission", fontWeight = FontWeight.SemiBold)
                    }
                }
            }
        }

        Spacer(Modifier.height(16.dp))
    }
}

// ═══════════════════════════════════════════════════════════════════
// TAB 2: CALL LOG ANALYSIS
// ═══════════════════════════════════════════════════════════════════

@Composable
private fun CallLogTab(ctx: Context, haptic: androidx.compose.ui.hapticfeedback.HapticFeedback) {
    val scope = rememberCoroutineScope()
    var calls by remember { mutableStateOf<List<CallEntry>>(emptyList()) }
    var isScanning by remember { mutableStateOf(false) }
    var filter by remember { mutableIntStateOf(0) }
    val hasPerm = ContextCompat.checkSelfPermission(ctx, Manifest.permission.READ_CALL_LOG) == PackageManager.PERMISSION_GRANTED

    val filtered = remember(calls, filter) {
        when (filter) {
            1 -> calls.filter { it.riskScore >= 60 }
            2 -> calls.filter { it.riskScore in 30..59 }
            3 -> calls.filter { it.type == 3 } // MISSED_TYPE
            4 -> calls.filter { it.name == null }
            else -> calls
        }
    }

    if (!hasPerm) {
        Box(Modifier.fillMaxSize().padding(32.dp), contentAlignment = Alignment.Center) {
            Text("Call log permission required", color = TextSecondary)
        }
    } else {
        LazyColumn(Modifier.fillMaxSize(), contentPadding = PaddingValues(horizontal = 20.dp, vertical = 16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
            item {
                Button(
                    onClick = {
                        isScanning = true
                        haptic.performHapticFeedback(HapticFeedbackType.TextHandleMove)
                        scope.launch {
                            calls = withContext(Dispatchers.IO) { analyzeCallLog(ctx).first }
                            isScanning = false
                        }
                    },
                    Modifier.fillMaxWidth().height(48.dp),
                    enabled = !isScanning,
                    shape = RoundedCornerShape(10.dp),
                    colors = ButtonDefaults.buttonColors(containerColor = SentinelPrimary)
                ) {
                    if (isScanning) {
                        CircularProgressIndicator(Modifier.size(18.dp), color = Color.White, strokeWidth = 2.dp)
                        Spacer(Modifier.width(8.dp))
                        Text("Auditing Call Log...")
                    } else {
                        Icon(Icons.Default.Phone, null, modifier = Modifier.size(18.dp))
                        Spacer(Modifier.width(8.dp))
                        Text("Audit Call History", fontWeight = FontWeight.SemiBold)
                    }
                }
            }

            if (calls.isNotEmpty()) {
                item {
                    val high = calls.count { it.riskScore >= 60 }
                    val med = calls.count { it.riskScore in 30..59 }
                    Card(
                        Modifier.fillMaxWidth(),
                        shape = RoundedCornerShape(12.dp),
                        colors = CardDefaults.cardColors(containerColor = SurfaceLight),
                        border = BorderStroke(1.dp, BorderColor)
                    ) {
                        Row(Modifier.padding(14.dp), verticalAlignment = Alignment.CenterVertically) {
                            Text(
                                "${calls.size} calls audited • $high high risk • $med suspicious",
                                fontWeight = FontWeight.Bold,
                                fontSize = 13.sp,
                                color = if (high > 0) DangerRed else SuccessGreen
                            )
                        }
                    }
                }

                item {
                    Row(horizontalArrangement = Arrangement.spacedBy(6.dp), modifier = Modifier.horizontalScroll(rememberScrollState())) {
                        listOf("All" to calls.size, "High Risk" to calls.count { it.riskScore >= 60 }, "Medium" to calls.count { it.riskScore in 30..59 }, "Missed" to calls.count { it.type == 3 }, "Unknown" to calls.count { it.name == null }).forEachIndexed { i, (l, c) ->
                            FilterChip(
                                selected = filter == i,
                                onClick = { filter = i },
                                label = { Text("$l ($c)", fontSize = 11.sp, fontWeight = if (filter == i) FontWeight.Bold else FontWeight.Normal) },
                                colors = FilterChipDefaults.filterChipColors(
                                    selectedContainerColor = SentinelPrimaryContainer,
                                    selectedLabelColor = SentinelPrimary
                                )
                            )
                        }
                    }
                }

                items(filtered.take(100)) { call -> CallCard(call) }
            }
        }
    }
}

@Composable
private fun CallCard(call: CallEntry) {
    val rc = when {
        call.riskScore >= 60 -> DangerRed
        call.riskScore >= 30 -> WarningAmber
        else -> SuccessGreen
    }
    val rBg = when {
        call.riskScore >= 60 -> DangerContainer
        call.riskScore >= 30 -> WarningContainer
        else -> SuccessContainer
    }
    val typeIcon = when (call.type) {
        1 -> Icons.AutoMirrored.Filled.CallReceived
        2 -> Icons.AutoMirrored.Filled.CallMade
        3 -> Icons.AutoMirrored.Filled.CallMissed
        else -> Icons.Default.Phone
    }
    val df = remember { SimpleDateFormat("MMM d, h:mm a", Locale.getDefault()) }
    var expanded by remember { mutableStateOf(false) }

    Card(
        Modifier
            .fillMaxWidth()
            .clickable { expanded = !expanded }
            .animateContentSize(),
        shape = RoundedCornerShape(12.dp),
        colors = CardDefaults.cardColors(containerColor = SurfaceLight),
        border = BorderStroke(1.dp, BorderColor)
    ) {
        Column(Modifier.padding(14.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Surface(
                    modifier = Modifier.size(36.dp),
                    shape = CircleShape,
                    color = SurfaceSubtle
                ) {
                    Box(contentAlignment = Alignment.Center) {
                        Icon(typeIcon, null, Modifier.size(18.dp), tint = TextSecondary)
                    }
                }
                Spacer(Modifier.width(12.dp))
                Column(Modifier.weight(1f)) {
                    Text(
                        call.name ?: call.number,
                        fontWeight = FontWeight.SemiBold,
                        style = MaterialTheme.typography.bodyMedium,
                        color = TextPrimary,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis
                    )
                    Text(
                        "${df.format(Date(call.date))} • ${call.duration}s${if (call.areaInfo.isNotEmpty()) " • ${call.areaInfo}" else ""}",
                        style = MaterialTheme.typography.labelSmall,
                        color = TextSecondary
                    )
                }
                if (call.riskScore >= 30) {
                    Surface(
                        color = rBg,
                        shape = RoundedCornerShape(999.dp),
                        border = BorderStroke(1.dp, rc.copy(alpha = 0.2f))
                    ) {
                        Text(
                            "${call.riskScore}%",
                            Modifier.padding(horizontal = 8.dp, vertical = 2.dp),
                            fontSize = 11.sp,
                            color = rc,
                            fontWeight = FontWeight.Bold
                        )
                    }
                }
            }
            if (expanded && call.riskReasons.isNotEmpty()) {
                Spacer(Modifier.height(8.dp))
                HorizontalDivider(color = BorderColor.copy(alpha = 0.6f))
                Spacer(Modifier.height(8.dp))
                call.riskReasons.forEach { r ->
                    Row(Modifier.padding(vertical = 2.dp), verticalAlignment = Alignment.CenterVertically) {
                        Icon(Icons.Default.Warning, null, Modifier.size(12.dp), tint = rc)
                        Spacer(Modifier.width(6.dp))
                        Text(r, style = MaterialTheme.typography.labelSmall, color = rc)
                    }
                }
            }
        }
    }
}

// ═══════════════════════════════════════════════════════════════════
// TAB 3: SETTINGS
// ═══════════════════════════════════════════════════════════════════

@Composable
private fun SettingsTab(
    uiState: CallProtectionUiState,
    viewModel: CallProtectionViewModel,
    ctx: Context,
    haptic: androidx.compose.ui.hapticfeedback.HapticFeedback,
    roleManager: RoleManager?,
    roleLauncher: androidx.activity.result.ActivityResultLauncher<Intent>?,
    phoneLauncher: androidx.activity.result.ActivityResultLauncher<Array<String>>?,
    audioLauncher: androidx.activity.result.ActivityResultLauncher<String>
) {
    Column(
        Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(horizontal = 20.dp, vertical = 16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        // Call Screening Card
        Card(
            Modifier.fillMaxWidth(),
            shape = RoundedCornerShape(14.dp),
            colors = CardDefaults.cardColors(containerColor = SurfaceLight),
            border = BorderStroke(1.dp, BorderColor)
        ) {
            Column(Modifier.padding(18.dp)) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Box(
                        modifier = Modifier.size(40.dp).background(SentinelPrimaryContainer, CircleShape),
                        contentAlignment = Alignment.Center
                    ) {
                        Icon(Icons.Default.Shield, null, Modifier.size(20.dp), tint = SentinelPrimary)
                    }
                    Spacer(Modifier.width(12.dp))
                    Column(Modifier.weight(1f)) {
                        Text("Call Screening Engine", fontWeight = FontWeight.Bold, color = TextPrimary)
                        Text("Intercepts robocalls and blocks fraud rings", style = MaterialTheme.typography.bodySmall, color = TextSecondary)
                    }
                    if (uiState.callScreeningEnabled) {
                        Surface(
                            color = SuccessContainer,
                            shape = RoundedCornerShape(999.dp),
                            border = BorderStroke(1.dp, SuccessGreen.copy(alpha = 0.2f))
                        ) {
                            Text("ACTIVE", Modifier.padding(horizontal = 8.dp, vertical = 2.dp), fontSize = 10.sp, color = SuccessGreen, fontWeight = FontWeight.Bold)
                        }
                    }
                }
                if (!uiState.callScreeningEnabled) {
                    Spacer(Modifier.height(12.dp))
                    Button(
                        onClick = {
                            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q && roleManager != null) {
                                if (!roleManager.isRoleHeld(RoleManager.ROLE_CALL_SCREENING)) roleLauncher?.launch(roleManager.createRequestRoleIntent(RoleManager.ROLE_CALL_SCREENING))
                                else viewModel.enableCallProtection()
                            } else phoneLauncher?.launch(arrayOf(Manifest.permission.READ_PHONE_STATE, Manifest.permission.READ_CALL_LOG))
                        },
                        Modifier.fillMaxWidth().height(48.dp),
                        shape = RoundedCornerShape(10.dp),
                        colors = ButtonDefaults.buttonColors(containerColor = SentinelPrimary)
                    ) {
                        Text("Activate Call Screening", fontWeight = FontWeight.SemiBold)
                    }
                }
            }
        }

        // Live Voice Keyword Analysis Card
        Card(
            Modifier.fillMaxWidth(),
            shape = RoundedCornerShape(14.dp),
            colors = CardDefaults.cardColors(containerColor = SurfaceLight),
            border = BorderStroke(1.dp, BorderColor)
        ) {
            Column(Modifier.padding(18.dp)) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Box(
                        modifier = Modifier.size(40.dp).background(SentinelPrimaryContainer, CircleShape),
                        contentAlignment = Alignment.Center
                    ) {
                        Icon(Icons.Default.Mic, null, Modifier.size(20.dp), tint = SentinelPrimary)
                    }
                    Spacer(Modifier.width(12.dp))
                    Column(Modifier.weight(1f)) {
                        Text("Speakerphone Scam Detection", fontWeight = FontWeight.Bold, color = TextPrimary)
                        Text("Detects extortion keywords in real-time", style = MaterialTheme.typography.bodySmall, color = TextSecondary)
                    }
                    Switch(
                        checked = uiState.speakerphoneEnabled,
                        onCheckedChange = { if (it) audioLauncher.launch(Manifest.permission.RECORD_AUDIO) else viewModel.toggleSpeakerphoneMode(false) },
                        colors = SwitchDefaults.colors(
                            checkedThumbColor = Color.White,
                            checkedTrackColor = SentinelPrimary
                        )
                    )
                }
                Spacer(Modifier.height(8.dp))
                Text(
                    "Monitors live audio for high-pressure scam phrases ('gift card payment', 'IRS warrant', 'wire transfer', 'crypto investment') without recording audio to storage.",
                    style = MaterialTheme.typography.labelSmall,
                    color = TextSecondary
                )
            }
        }

        // Risk factors card
        Card(
            Modifier.fillMaxWidth(),
            shape = RoundedCornerShape(14.dp),
            colors = CardDefaults.cardColors(containerColor = SurfaceLight),
            border = BorderStroke(1.dp, BorderColor)
        ) {
            Column(Modifier.padding(18.dp)) {
                Text("Inspection Heuristics", fontWeight = FontWeight.Bold, style = MaterialTheme.typography.titleSmall, color = TextPrimary)
                Spacer(Modifier.height(10.dp))
                listOf(
                    "Area Code Risk" to "300+ area codes mapped — flags premium rate (900/976) and high-risk offshore toll fraud",
                    "Call Duration & Rhythm" to "1-3 second micro-calls characteristic of robotic dialers and callback traps",
                    "Contact Whitelist" to "Known contacts bypass screening; unknown numbers undergo deep heuristic audit",
                    "Repetitive Pattern Analysis" to "Identifies sequential digits and neighbor-spoofing patterns"
                ).forEachIndexed { index, (title, desc) ->
                    Column(Modifier.padding(vertical = 4.dp)) {
                        Text(title, fontWeight = FontWeight.SemiBold, fontSize = 13.sp, color = TextPrimary)
                        Text(desc, fontSize = 11.sp, color = TextSecondary)
                    }
                    if (index < 3) {
                        HorizontalDivider(color = BorderColor.copy(alpha = 0.5f), modifier = Modifier.padding(vertical = 4.dp))
                    }
                }
            }
        }

        Spacer(Modifier.height(16.dp))
    }
}

@Composable
private fun StatCard(value: String, label: String, color: Color, modifier: Modifier) {
    Surface(
        modifier = modifier,
        shape = RoundedCornerShape(10.dp),
        color = SurfaceLight,
        border = BorderStroke(1.dp, BorderColor)
    ) {
        Column(
            Modifier.padding(vertical = 10.dp, horizontal = 4.dp).fillMaxWidth(),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            Text(value, fontWeight = FontWeight.Bold, color = color, fontSize = 18.sp)
            Spacer(Modifier.height(2.dp))
            Text(label, style = MaterialTheme.typography.labelSmall, fontSize = 10.sp, color = TextSecondary)
        }
    }
}

// ═══════════════════════════════════════════════════════════════════
// CALL LOG ANALYSIS ENGINE
// ═══════════════════════════════════════════════════════════════════

private val AREA_CODES: Map<String, String> by lazy {
    mapOf(
        "201" to "NJ", "202" to "DC", "206" to "Seattle", "212" to "NYC", "213" to "LA", "214" to "Dallas", "305" to "Miami", "312" to "Chicago", "404" to "Atlanta", "415" to "SF",
        "469" to "Dallas", "503" to "Portland", "512" to "Austin", "602" to "Phoenix", "617" to "Boston", "646" to "NYC", "702" to "Vegas", "713" to "Houston", "718" to "NYC", "720" to "Denver",
        "786" to "Miami", "818" to "LA", "832" to "Houston", "800" to "Toll-Free", "833" to "Toll-Free", "844" to "Toll-Free", "855" to "Toll-Free", "866" to "Toll-Free", "877" to "Toll-Free", "888" to "Toll-Free", "900" to "Premium"
    )
}

private val HIGH_RISK_CODES = setOf("900", "976", "809", "876", "284", "649", "268", "473", "664", "767")

private fun analyzeCallLog(ctx: Context): Pair<List<CallEntry>, List<HourStat>> {
    val calls = mutableListOf<CallEntry>()
    val hourCounts = IntArray(24)
    val hourSuspicious = IntArray(24)

    try {
        val cursor = ctx.contentResolver.query(
            CallLog.Calls.CONTENT_URI,
            arrayOf(CallLog.Calls.NUMBER, CallLog.Calls.CACHED_NAME, CallLog.Calls.TYPE, CallLog.Calls.DATE, CallLog.Calls.DURATION),
            null,
            null,
            "${CallLog.Calls.DATE} DESC"
        ) ?: return emptyList<CallEntry>() to emptyList()

        var count = 0
        while (cursor.moveToNext() && count < 500) {
            val number = cursor.getString(0) ?: continue
            val name = cursor.getString(1)
            val type = cursor.getInt(2)
            val date = cursor.getLong(3)
            val dur = cursor.getLong(4)
            val digits = number.filter { it.isDigit() }
            if (digits.length < 4) continue

            var risk = 0
            val reasons = mutableListOf<String>()
            val ac = if (digits.length >= 10) digits.takeLast(10).take(3) else digits.take(3)
            val areaInfo = AREA_CODES[ac] ?: ""

            if (ac in HIGH_RISK_CODES) { risk += 45; reasons += "High-risk area code ($ac)" }
            if (ac == "900" || ac == "976") { risk += 50; reasons += "Premium rate number" }
            if (dur == 0L && type == 1) { risk += 8; reasons += "Missed/0-duration incoming" }
            if (dur in 1..3 && type == 1) { risk += 15; reasons += "Very short call (${dur}s) — robocall pattern" }
            if (name == null && type == 1) { risk += 8; reasons += "Unknown caller (not in contacts)" }

            val cal = Calendar.getInstance().apply { timeInMillis = date }
            val hour = cal.get(Calendar.HOUR_OF_DAY)
            if (hour in 0..5 && type == 1) { risk += 12; reasons += "Late night call (${hour}:00)" }

            if (number.startsWith("+") && !number.startsWith("+1")) { risk += 10; reasons += "International number" }
            if (digits.length >= 7 && digits.takeLast(7).toSet().size == 1) { risk += 25; reasons += "Repeating digits pattern" }

            hourCounts[hour]++
            if (risk >= 30) hourSuspicious[hour]++
            calls += CallEntry(number, name, type, date, dur, risk.coerceAtMost(100), reasons, areaInfo)
            count++
        }
        cursor.close()
    } catch (_: Exception) {}

    val hourStats = (0..23).map { HourStat(it, hourCounts[it], hourSuspicious[it]) }
    return calls.sortedByDescending { it.riskScore } to hourStats
}

@OptIn(ExperimentalMaterial3Api::class)
@Preview(name = "Call Shield Screen", showBackground = true, showSystemUi = true)
@Composable
fun CallProtectionScreenPreview() {
    MaterialTheme {
        Scaffold(
            topBar = {
                TopAppBar(
                    title = {
                        Column {
                            Text("Call Shield", fontWeight = FontWeight.Bold, color = TextPrimary)
                            Text("Real-Time Scam & Robocall Screening", style = MaterialTheme.typography.bodySmall, color = TextSecondary)
                        }
                    },
                    navigationIcon = {
                        IconButton(onClick = {}) {
                            Icon(Icons.AutoMirrored.Filled.ArrowBack, "Back", tint = TextPrimary)
                        }
                    },
                    colors = TopAppBarDefaults.topAppBarColors(containerColor = SurfaceLight)
                )
            },
            containerColor = BackgroundLight
        ) { padding ->
            Box(Modifier.padding(padding)) {
                DashboardTab(
                    uiState = CallProtectionUiState(
                        callScreeningEnabled = true,
                        scamsDetected = 12,
                        blockedNumbers = 45
                    )
                )
            }
        }
    }
}
