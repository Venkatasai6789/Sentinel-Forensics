package com.deepfakeshield.feature.onboarding

import android.Manifest
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.os.Environment
import android.provider.Settings
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.animateColorAsState
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.tween
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowForward
import androidx.compose.material.icons.automirrored.outlined.Message
import androidx.compose.material.icons.outlined.Check
import androidx.compose.material.icons.outlined.FolderOpen
import androidx.compose.material.icons.outlined.Info
import androidx.compose.material.icons.outlined.Layers
import androidx.compose.material.icons.outlined.MarkEmailUnread
import androidx.compose.material.icons.outlined.Notifications
import androidx.compose.material.icons.outlined.PhoneInTalk
import androidx.compose.material.icons.outlined.Shield
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.hapticfeedback.HapticFeedbackType
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalHapticFeedback
import androidx.compose.ui.platform.LocalLifecycleOwner
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.content.ContextCompat
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver

// Design Tokens derived from Sentinel Forensics DESIGN.md (Single Source of Truth)
private val ColorPrimary = Color(0xFF4F72E8)
private val ColorPrimaryPressed = Color(0xFF3F60CF)
private val ColorPrimaryContainer = Color(0xFFE9EEFF)
private val ColorOnPrimary = Color(0xFFFFFFFF)

private val ColorBackground = Color(0xFFF5F6F8)
private val ColorSurface = Color(0xFFFFFFFF)
private val ColorSurfaceSubtle = Color(0xFFF2F4F7)
private val ColorBorder = Color(0xFFE6E9EF)

private val ColorTextPrimary = Color(0xFF17191F)
private val ColorTextSecondary = Color(0xFF747B87)
private val ColorTextTertiary = Color(0xFF969DA8)

private val ColorSuccess = Color(0xFF25A653)
private val ColorSuccessContainer = Color(0xFFE8F7ED)

private val ColorWarning = Color(0xFFB7791F)
private val ColorWarningContainer = Color(0xFFFFF4D9)

private val ColorDanger = Color(0xFFC83E4D)
private val ColorDangerContainer = Color(0xFFFCEBED)

/**
 * Redesigned Sentinel Forensics Permission Setup Experience.
 *
 * Implements a clean, trustworthy cybersecurity utility interface strictly aligned
 * with DESIGN.md tokens and patterns:
 * - Neutral light canvas (#F5F6F8) with elevated flat white cards (#FFFFFF)
 * - Clear visual hierarchy dividing Core Threat Defenses from Advanced Live Monitoring
 * - Distinct, purposeful icons per permission category (eliminating redundant checkmarks)
 * - Contextual on-device privacy rationale explaining why each capability is requested
 * - Precise step-by-step guidance for system settings toggles (e.g., Notification Listener)
 * - Preserves all underlying Android permission launchers, lifecycle triggers, and callbacks
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun PermissionSetupScreen(
    onComplete: () -> Unit,
    previewNotificationGranted: Boolean? = null,
    previewSmsGranted: Boolean? = null,
    previewPhoneGranted: Boolean? = null,
    previewStorageGranted: Boolean? = null,
    previewOverlayGranted: Boolean? = null,
    previewNotificationListenerGranted: Boolean? = null
) {
    val context = LocalContext.current
    val lifecycleOwner = LocalLifecycleOwner.current
    val haptic = LocalHapticFeedback.current
    val isInspection = androidx.compose.ui.platform.LocalInspectionMode.current

    // Track permission states - re-check on resume when user returns from system Settings
    var refreshTrigger by remember { mutableIntStateOf(0) }

    if (!isInspection) {
        DisposableEffect(lifecycleOwner) {
            val observer = LifecycleEventObserver { _, event ->
                if (event == Lifecycle.Event.ON_RESUME) {
                    refreshTrigger++
                }
            }
            lifecycleOwner.lifecycle.addObserver(observer)
            onDispose { lifecycleOwner.lifecycle.removeObserver(observer) }
        }
    }

    // Permission status checks (re-evaluated whenever refreshTrigger changes)
    val notificationGranted by remember(refreshTrigger, isInspection, previewNotificationGranted) {
        mutableStateOf(
            previewNotificationGranted ?: if (isInspection) true
            else try {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                    ContextCompat.checkSelfPermission(context, Manifest.permission.POST_NOTIFICATIONS) == PackageManager.PERMISSION_GRANTED
                } else true
            } catch (_: Throwable) { false }
        )
    }

    val smsGranted by remember(refreshTrigger, isInspection, previewSmsGranted) {
        mutableStateOf(
            previewSmsGranted ?: if (isInspection) false
            else try {
                ContextCompat.checkSelfPermission(context, Manifest.permission.RECEIVE_SMS) == PackageManager.PERMISSION_GRANTED &&
                    ContextCompat.checkSelfPermission(context, Manifest.permission.READ_SMS) == PackageManager.PERMISSION_GRANTED
            } catch (_: Throwable) { false }
        )
    }

    val phoneGranted by remember(refreshTrigger, isInspection, previewPhoneGranted) {
        mutableStateOf(
            previewPhoneGranted ?: if (isInspection) false
            else try {
                ContextCompat.checkSelfPermission(context, Manifest.permission.READ_PHONE_STATE) == PackageManager.PERMISSION_GRANTED &&
                    ContextCompat.checkSelfPermission(context, Manifest.permission.READ_CALL_LOG) == PackageManager.PERMISSION_GRANTED
            } catch (_: Throwable) { false }
        )
    }

    val overlayGranted by remember(refreshTrigger, isInspection, previewOverlayGranted) {
        mutableStateOf(
            previewOverlayGranted ?: if (isInspection) true
            else try {
                Settings.canDrawOverlays(context)
            } catch (_: Throwable) { false }
        )
    }

    val storageGranted by remember(refreshTrigger, isInspection, previewStorageGranted) {
        mutableStateOf(
            previewStorageGranted ?: if (isInspection) true
            else try {
                when {
                    Build.VERSION.SDK_INT >= Build.VERSION_CODES.R -> Environment.isExternalStorageManager()
                    Build.VERSION.SDK_INT >= Build.VERSION_CODES.M -> {
                        ContextCompat.checkSelfPermission(context, Manifest.permission.READ_EXTERNAL_STORAGE) == PackageManager.PERMISSION_GRANTED
                    }
                    else -> true
                }
            } catch (_: Throwable) { false }
        )
    }

    val notificationListenerGranted by remember(refreshTrigger, isInspection, previewNotificationListenerGranted) {
        mutableStateOf(
            previewNotificationListenerGranted ?: if (isInspection) false
            else try {
                val enabled = Settings.Secure.getString(context.contentResolver, "enabled_notification_listeners") ?: ""
                enabled.contains(context.packageName)
            } catch (_: Throwable) { false }
        )
    }

    val allCriticalGranted = notificationGranted && smsGranted && phoneGranted && storageGranted
    val grantedCount = listOf(notificationGranted, smsGranted, phoneGranted, storageGranted, overlayGranted, notificationListenerGranted).count { it }
    val totalCount = 6

    // Permission launchers
    val notificationLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) { refreshTrigger++ }

    val smsLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.RequestMultiplePermissions()
    ) { refreshTrigger++ }

    val phoneLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.RequestMultiplePermissions()
    ) { refreshTrigger++ }

    // Storage permission for AV file scanning
    val storageLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { refreshTrigger++ }

    val legacyStorageLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.RequestMultiplePermissions()
    ) { refreshTrigger++ }

    // Overlay settings intent
    val overlayLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { refreshTrigger++ }

    Surface(
        modifier = Modifier.fillMaxSize(),
        color = ColorBackground
    ) {
        Column(
            modifier = Modifier
                .fillMaxSize()
                .statusBarsPadding()
                .navigationBarsPadding()
        ) {
            // Scrollable Content
            Column(
                modifier = Modifier
                    .weight(1f)
                    .fillMaxWidth()
                    .verticalScroll(rememberScrollState())
                    .padding(horizontal = 20.dp),
                verticalArrangement = Arrangement.spacedBy(16.dp)
            ) {
                Spacer(modifier = Modifier.height(12.dp))

                // Hero Status Header
                StatusHeroSection()

                // Readiness Progress Card
                ReadinessProgressCard(
                    grantedCount = grantedCount,
                    totalCount = totalCount,
                    allCriticalGranted = allCriticalGranted
                )

                // Section 1: Core Threat Protection (Required)
                PermissionSectionHeader(
                    title = "Core Threat Protection",
                    subtitle = "Required for on-device defense"
                )

                // 1. Notifications
                PermissionCard(
                    icon = Icons.Outlined.Notifications,
                    title = "Notifications",
                    description = "Delivers immediate alerts the moment suspicious SMS links, fraudulent callers, or infected files are intercepted.",
                    isGranted = notificationGranted,
                    isCritical = true,
                    onRequest = {
                        haptic.performHapticFeedback(HapticFeedbackType.LongPress)
                        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                            notificationLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
                        }
                    },
                    onOpenSettings = {
                        haptic.performHapticFeedback(HapticFeedbackType.LongPress)
                        openAppSettings(context)
                    }
                )

                // 2. SMS Access
                PermissionCard(
                    icon = Icons.AutoMirrored.Outlined.Message,
                    title = "SMS Access",
                    description = "Scans incoming text messages locally to detect phishing URLs, impersonation attempts, and OTP theft in real time.",
                    isGranted = smsGranted,
                    isCritical = true,
                    onRequest = {
                        haptic.performHapticFeedback(HapticFeedbackType.LongPress)
                        smsLauncher.launch(
                            arrayOf(
                                Manifest.permission.RECEIVE_SMS,
                                Manifest.permission.READ_SMS
                            )
                        )
                    },
                    onOpenSettings = {
                        haptic.performHapticFeedback(HapticFeedbackType.LongPress)
                        openAppSettings(context)
                    }
                )

                // 3. Phone & Call Log
                PermissionCard(
                    icon = Icons.Outlined.PhoneInTalk,
                    title = "Phone & Call Log",
                    description = "Screens incoming calls against known scam numbers, spoofed identities, and impersonation attempts before you answer.",
                    isGranted = phoneGranted,
                    isCritical = true,
                    onRequest = {
                        haptic.performHapticFeedback(HapticFeedbackType.LongPress)
                        phoneLauncher.launch(
                            arrayOf(
                                Manifest.permission.READ_PHONE_STATE,
                                Manifest.permission.READ_CALL_LOG
                            )
                        )
                    },
                    onOpenSettings = {
                        haptic.performHapticFeedback(HapticFeedbackType.LongPress)
                        openAppSettings(context)
                    }
                )

                // 4. File Access
                PermissionCard(
                    icon = Icons.Outlined.FolderOpen,
                    title = "File Access",
                    description = "Scans downloads, APK packages, and media files for malware trojans and synthetic media tampering.",
                    isGranted = storageGranted,
                    isCritical = true,
                    onRequest = {
                        haptic.performHapticFeedback(HapticFeedbackType.LongPress)
                        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                            try {
                                val intent = Intent(Settings.ACTION_MANAGE_APP_ALL_FILES_ACCESS_PERMISSION).apply {
                                    data = Uri.parse("package:${context.packageName}")
                                }
                                storageLauncher.launch(intent)
                            } catch (_: Exception) {
                                try {
                                    val intent = Intent(Settings.ACTION_MANAGE_ALL_FILES_ACCESS_PERMISSION)
                                    storageLauncher.launch(intent)
                                } catch (_: Exception) {
                                    openAppSettings(context)
                                }
                            }
                        } else {
                            legacyStorageLauncher.launch(
                                arrayOf(
                                    Manifest.permission.READ_EXTERNAL_STORAGE,
                                    Manifest.permission.WRITE_EXTERNAL_STORAGE
                                )
                            )
                        }
                    },
                    onOpenSettings = {
                        haptic.performHapticFeedback(HapticFeedbackType.LongPress)
                        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                            try {
                                val intent = Intent(Settings.ACTION_MANAGE_APP_ALL_FILES_ACCESS_PERMISSION).apply {
                                    data = Uri.parse("package:${context.packageName}")
                                }
                                storageLauncher.launch(intent)
                            } catch (_: Exception) { openAppSettings(context) }
                        } else { openAppSettings(context) }
                    }
                )

                // Section 2: Enhanced Live Protection (Recommended)
                PermissionSectionHeader(
                    title = "Enhanced Live Protection",
                    subtitle = "Recommended for real-time monitoring"
                )

                // 5. Display Over Other Apps
                PermissionCard(
                    icon = Icons.Outlined.Layers,
                    title = "Display Over Other Apps",
                    description = "Displays a floating security badge and rapid warning overlay when an active scam or dangerous link is encountered.",
                    isGranted = overlayGranted,
                    isCritical = false,
                    onRequest = {
                        haptic.performHapticFeedback(HapticFeedbackType.LongPress)
                        val intent = Intent(
                            Settings.ACTION_MANAGE_OVERLAY_PERMISSION,
                            Uri.parse("package:${context.packageName}")
                        )
                        overlayLauncher.launch(intent)
                    },
                    onOpenSettings = {
                        haptic.performHapticFeedback(HapticFeedbackType.LongPress)
                        val intent = Intent(
                            Settings.ACTION_MANAGE_OVERLAY_PERMISSION,
                            Uri.parse("package:${context.packageName}")
                        )
                        overlayLauncher.launch(intent)
                    }
                )

                // 6. Notification Access (Listener)
                PermissionCard(
                    icon = Icons.Outlined.MarkEmailUnread,
                    title = "Notification Access",
                    description = "Inspects scam messages received via WhatsApp, Telegram, and email to detect fraud before you open links.",
                    isGranted = notificationListenerGranted,
                    isCritical = false,
                    stepGuide = "Tap Grant → Find Sentinel Forensics → Turn ON",
                    onRequest = {
                        haptic.performHapticFeedback(HapticFeedbackType.LongPress)
                        val intent = Intent(Settings.ACTION_NOTIFICATION_LISTENER_SETTINGS).apply {
                            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                        }
                        context.startActivity(intent)
                    },
                    onOpenSettings = {
                        haptic.performHapticFeedback(HapticFeedbackType.LongPress)
                        val intent = Intent(Settings.ACTION_NOTIFICATION_LISTENER_SETTINGS).apply {
                            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                        }
                        context.startActivity(intent)
                    }
                )

                Spacer(modifier = Modifier.height(12.dp))
            }

            // Fixed Bottom Action Area
            BottomActionArea(
                allCriticalGranted = allCriticalGranted,
                onComplete = {
                    haptic.performHapticFeedback(HapticFeedbackType.LongPress)
                    onComplete()
                }
            )
        }
    }
}

/**
 * Top Status Hero Section conforming to DESIGN.md StatusHero specifications.
 */
@Composable
private fun StatusHeroSection() {
    Column(
        modifier = Modifier.fillMaxWidth(),
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        // Centered Shield Emblem with quiet dual-ring container
        Box(
            modifier = Modifier
                .size(72.dp)
                .clip(CircleShape)
                .background(ColorPrimaryContainer)
                .border(1.dp, ColorPrimary.copy(alpha = 0.2f), CircleShape),
            contentAlignment = Alignment.Center
        ) {
            Icon(
                imageVector = Icons.Outlined.Shield,
                contentDescription = "Sentinel Forensics Shield",
                modifier = Modifier.size(36.dp),
                tint = ColorPrimary
            )
        }

        Spacer(modifier = Modifier.height(16.dp))

        Text(
            text = "Set Up Permissions",
            style = MaterialTheme.typography.headlineSmall.copy(
                fontSize = 24.sp,
                fontWeight = FontWeight.Bold,
                letterSpacing = (-0.3).sp
            ),
            textAlign = TextAlign.Center,
            color = ColorTextPrimary
        )

        Spacer(modifier = Modifier.height(6.dp))

        Text(
            text = "Sentinel Forensics performs on-device analysis to intercept scam calls, phishing SMS, malicious files, and fake media in real time.",
            style = MaterialTheme.typography.bodyMedium.copy(
                fontSize = 14.sp,
                lineHeight = 20.sp
            ),
            textAlign = TextAlign.Center,
            color = ColorTextSecondary,
            modifier = Modifier.padding(horizontal = 8.dp)
        )
    }
}

/**
 * Protection Readiness Progress Card with animated indicator and status badges.
 */
@Composable
private fun ReadinessProgressCard(
    grantedCount: Int,
    totalCount: Int,
    allCriticalGranted: Boolean
) {
    val animatedProgress by animateFloatAsState(
        targetValue = grantedCount.toFloat() / totalCount.toFloat(),
        animationSpec = tween(durationMillis = 400),
        label = "readiness_progress"
    )

    Surface(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(14.dp),
        color = ColorSurface,
        border = BorderStroke(1.dp, ColorBorder),
        shadowElevation = 0.dp
    ) {
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp)
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.SpaceBetween
            ) {
                Text(
                    text = "Protection Readiness",
                    style = MaterialTheme.typography.titleMedium.copy(
                        fontSize = 14.sp,
                        fontWeight = FontWeight.SemiBold
                    ),
                    color = ColorTextPrimary
                )

                // Readiness Badge
                Surface(
                    shape = RoundedCornerShape(999.dp),
                    color = when {
                        grantedCount == totalCount -> ColorSuccessContainer
                        allCriticalGranted -> ColorPrimaryContainer
                        else -> ColorSurfaceSubtle
                    }
                ) {
                    Row(
                        modifier = Modifier.padding(horizontal = 10.dp, vertical = 3.dp),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(4.dp)
                    ) {
                        if (allCriticalGranted) {
                            Icon(
                                imageVector = Icons.Outlined.Check,
                                contentDescription = null,
                                tint = if (grantedCount == totalCount) ColorSuccess else ColorPrimary,
                                modifier = Modifier.size(12.dp)
                            )
                        }
                        Text(
                            text = when {
                                grantedCount == totalCount -> "Full Protection Active"
                                allCriticalGranted -> "Core Safeguards Active"
                                else -> "$grantedCount of $totalCount Configured"
                            },
                            style = MaterialTheme.typography.labelSmall.copy(
                                fontSize = 11.sp,
                                fontWeight = FontWeight.SemiBold
                            ),
                            color = when {
                                grantedCount == totalCount -> ColorSuccess
                                allCriticalGranted -> ColorPrimary
                                else -> ColorTextSecondary
                            }
                        )
                    }
                }
            }

            // Smooth Progress Bar
            LinearProgressIndicator(
                progress = { animatedProgress },
                modifier = Modifier
                    .fillMaxWidth()
                    .height(6.dp)
                    .clip(CircleShape),
                color = if (allCriticalGranted) ColorSuccess else ColorPrimary,
                trackColor = ColorBorder
            )

            Text(
                text = if (allCriticalGranted) {
                    "All essential on-device protections are armed and ready."
                } else {
                    "Grant the 4 required permissions below to activate core device defenses."
                },
                style = MaterialTheme.typography.bodySmall.copy(
                    fontSize = 12.sp,
                    lineHeight = 16.sp
                ),
                color = ColorTextSecondary
            )
        }
    }
}

/**
 * Section Header for grouped permission categories.
 */
@Composable
private fun PermissionSectionHeader(
    title: String,
    subtitle: String
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(top = 8.dp, bottom = 2.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.SpaceBetween
    ) {
        Column {
            Text(
                text = title,
                style = MaterialTheme.typography.titleMedium.copy(
                    fontSize = 14.sp,
                    fontWeight = FontWeight.Bold
                ),
                color = ColorTextPrimary
            )
            Text(
                text = subtitle,
                style = MaterialTheme.typography.bodySmall.copy(
                    fontSize = 11.sp
                ),
                color = ColorTextSecondary
            )
        }
    }
}

/**
 * Individual Permission Card designed per DESIGN.md FeatureStatusRow specification:
 * - Specific outline category icon in 42dp container (tinted green on success, primary otherwise)
 * - Required / Recommended status badge
 * - Clear, honest explanation of on-device functionality
 * - Contextual step-by-step guidance when system settings navigation is required
 * - Discrete right-aligned action: Verified check badge or Grant button (no redundant checkmark)
 */
@Composable
private fun PermissionCard(
    icon: ImageVector,
    title: String,
    description: String,
    isGranted: Boolean,
    isCritical: Boolean,
    stepGuide: String? = null,
    onRequest: () -> Unit,
    onOpenSettings: () -> Unit
) {
    var hasBeenDenied by rememberSaveable { mutableStateOf(false) }

    val iconContainerColor by animateColorAsState(
        targetValue = if (isGranted) ColorSuccessContainer else ColorSurfaceSubtle,
        animationSpec = tween(durationMillis = 250),
        label = "icon_container_color"
    )

    val iconTintColor by animateColorAsState(
        targetValue = if (isGranted) ColorSuccess else ColorPrimary,
        animationSpec = tween(durationMillis = 250),
        label = "icon_tint_color"
    )

    Surface(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(14.dp),
        color = ColorSurface,
        border = BorderStroke(1.dp, ColorBorder),
        shadowElevation = 0.dp
    ) {
        Column(
            modifier = Modifier.padding(16.dp)
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically
            ) {
                // Leading Category Icon Container (Consistent 42dp rounded container)
                Box(
                    modifier = Modifier
                        .size(42.dp)
                        .clip(CircleShape)
                        .background(iconContainerColor),
                    contentAlignment = Alignment.Center
                ) {
                    Icon(
                        imageVector = icon,
                        contentDescription = title,
                        modifier = Modifier.size(22.dp),
                        tint = iconTintColor
                    )
                }

                Spacer(modifier = Modifier.width(14.dp))

                // Text & Badges
                Column(
                    modifier = Modifier.weight(1f)
                ) {
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(6.dp)
                    ) {
                        Text(
                            text = title,
                            style = MaterialTheme.typography.titleMedium.copy(
                                fontSize = 14.sp,
                                fontWeight = FontWeight.SemiBold
                            ),
                            color = ColorTextPrimary,
                            maxLines = 1,
                            modifier = Modifier.weight(1f, fill = false)
                        )

                        // Status Tag (Required / Recommended / Active)
                        if (isGranted) {
                            Surface(
                                shape = RoundedCornerShape(999.dp),
                                color = ColorSuccessContainer
                            ) {
                                Row(
                                    modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp),
                                    verticalAlignment = Alignment.CenterVertically,
                                    horizontalArrangement = Arrangement.spacedBy(3.dp)
                                ) {
                                    Icon(
                                        imageVector = Icons.Outlined.Check,
                                        contentDescription = null,
                                        tint = ColorSuccess,
                                        modifier = Modifier.size(10.dp)
                                    )
                                    Text(
                                        text = "Active",
                                        maxLines = 1,
                                        softWrap = false,
                                        style = MaterialTheme.typography.labelSmall.copy(
                                            fontSize = 10.sp,
                                            fontWeight = FontWeight.SemiBold
                                        ),
                                        color = ColorSuccess
                                    )
                                }
                            }
                        } else if (isCritical) {
                            Surface(
                                shape = RoundedCornerShape(6.dp),
                                color = ColorDangerContainer
                            ) {
                                Text(
                                    text = "Required",
                                    maxLines = 1,
                                    softWrap = false,
                                    modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp),
                                    style = MaterialTheme.typography.labelSmall.copy(
                                        fontSize = 10.sp,
                                        fontWeight = FontWeight.Bold
                                    ),
                                    color = ColorDanger
                                )
                            }
                        } else {
                            Surface(
                                shape = RoundedCornerShape(6.dp),
                                color = ColorPrimaryContainer
                            ) {
                                Text(
                                    text = "Recommended",
                                    maxLines = 1,
                                    softWrap = false,
                                    modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp),
                                    style = MaterialTheme.typography.labelSmall.copy(
                                        fontSize = 10.sp,
                                        fontWeight = FontWeight.Medium
                                    ),
                                    color = ColorPrimary
                                )
                            }
                        }
                    }

                    Spacer(modifier = Modifier.height(4.dp))

                    Text(
                        text = description,
                        style = MaterialTheme.typography.bodySmall.copy(
                            fontSize = 12.sp,
                            lineHeight = 17.sp
                        ),
                        color = ColorTextSecondary
                    )
                }

                Spacer(modifier = Modifier.width(10.dp))

                // Trailing Action: Clean Verified Badge OR Single Grant Button
                if (isGranted) {
                    Box(
                        modifier = Modifier
                            .size(32.dp)
                            .clip(CircleShape)
                            .background(ColorSuccessContainer),
                        contentAlignment = Alignment.Center
                    ) {
                        Icon(
                            imageVector = Icons.Outlined.Check,
                            contentDescription = "Permission granted",
                            tint = ColorSuccess,
                            modifier = Modifier.size(16.dp)
                        )
                    }
                } else {
                    Button(
                        onClick = {
                            if (hasBeenDenied) {
                                onOpenSettings()
                            } else {
                                hasBeenDenied = true
                                onRequest()
                            }
                        },
                        shape = RoundedCornerShape(10.dp),
                        colors = ButtonDefaults.buttonColors(
                            containerColor = ColorPrimary
                        ),
                        contentPadding = PaddingValues(horizontal = 14.dp, vertical = 0.dp),
                        modifier = Modifier.height(36.dp)
                    ) {
                        Text(
                            text = if (hasBeenDenied) "Settings" else "Grant",
                            style = MaterialTheme.typography.labelSmall.copy(
                                fontSize = 13.sp,
                                fontWeight = FontWeight.SemiBold
                            ),
                            color = ColorOnPrimary
                        )
                    }
                }
            }

            // Optional Step Guide (e.g. For Notification Access settings toggle)
            if (!isGranted && stepGuide != null) {
                Spacer(modifier = Modifier.height(10.dp))
                Surface(
                    shape = RoundedCornerShape(8.dp),
                    color = ColorSurfaceSubtle,
                    border = BorderStroke(1.dp, ColorBorder),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Row(
                        modifier = Modifier.padding(horizontal = 10.dp, vertical = 6.dp),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(6.dp)
                    ) {
                        Icon(
                            imageVector = Icons.Outlined.Info,
                            contentDescription = null,
                            tint = ColorPrimary,
                            modifier = Modifier.size(14.dp)
                        )
                        Text(
                            text = stepGuide,
                            style = MaterialTheme.typography.bodySmall.copy(
                                fontSize = 11.sp,
                                fontWeight = FontWeight.Medium
                            ),
                            color = ColorTextPrimary
                        )
                    }
                }
            }
        }
    }
}

/**
 * Fixed Bottom Action Area with responsive primary action and restrained warning guidance.
 */
@Composable
private fun BottomActionArea(
    allCriticalGranted: Boolean,
    onComplete: () -> Unit
) {
    Surface(
        modifier = Modifier.fillMaxWidth(),
        color = ColorSurface,
        border = BorderStroke(1.dp, ColorBorder),
        shadowElevation = 0.dp
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 20.dp, vertical = 14.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            Button(
                onClick = onComplete,
                modifier = Modifier
                    .fillMaxWidth()
                    .height(54.dp),
                shape = RoundedCornerShape(14.dp),
                colors = ButtonDefaults.buttonColors(
                    containerColor = if (allCriticalGranted) ColorSuccess else ColorPrimary
                ),
                elevation = ButtonDefaults.buttonElevation(defaultElevation = 0.dp)
            ) {
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.Center
                ) {
                    Text(
                        text = if (allCriticalGranted) "All Set — Continue" else "Continue Anyway",
                        style = MaterialTheme.typography.titleMedium.copy(
                            fontSize = 16.sp,
                            fontWeight = FontWeight.SemiBold
                        ),
                        color = ColorOnPrimary
                    )
                    Spacer(modifier = Modifier.width(8.dp))
                    Icon(
                        imageVector = if (allCriticalGranted) Icons.Outlined.Check else Icons.AutoMirrored.Filled.ArrowForward,
                        contentDescription = null,
                        tint = ColorOnPrimary,
                        modifier = Modifier.size(18.dp)
                    )
                }
            }

            // Evidence-led guidance instead of alarmist text
            if (!allCriticalGranted) {
                Surface(
                    shape = RoundedCornerShape(8.dp),
                    color = ColorWarningContainer.copy(alpha = 0.6f),
                    border = BorderStroke(1.dp, ColorWarning.copy(alpha = 0.2f)),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Row(
                        modifier = Modifier.padding(horizontal = 10.dp, vertical = 8.dp),
                        verticalAlignment = Alignment.Top,
                        horizontalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        Icon(
                            imageVector = Icons.Outlined.Info,
                            contentDescription = "Guidance notice",
                            tint = ColorWarning,
                            modifier = Modifier
                                .size(16.dp)
                                .padding(top = 1.dp)
                        )
                        Text(
                            text = "Core real-time protection requires SMS, Phone, Notifications, and Storage. You can grant remaining permissions anytime in Settings.",
                            style = MaterialTheme.typography.bodySmall.copy(
                                fontSize = 11.sp,
                                lineHeight = 16.sp
                            ),
                            color = ColorTextPrimary
                        )
                    }
                }
            }
        }
    }
}

private fun openAppSettings(context: Context) {
    val intent = Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS).apply {
        data = Uri.fromParts("package", context.packageName, null)
        addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
    }
    context.startActivity(intent)
}

@Preview(name = "1. Permissions - Partial Granted (Full Screen)", showBackground = true, widthDp = 390, heightDp = 1560)
@Composable
fun PermissionSetupScreenPreview() {
    PermissionSetupScreen(
        onComplete = {},
        previewNotificationGranted = true,
        previewSmsGranted = false,
        previewPhoneGranted = false,
        previewStorageGranted = true,
        previewOverlayGranted = true,
        previewNotificationListenerGranted = false
    )
}

@Preview(name = "2. Permissions - Full Protection Active (Full Screen)", showBackground = true, widthDp = 390, heightDp = 1460)
@Composable
fun PermissionSetupScreen_AllGranted_Preview() {
    PermissionSetupScreen(
        onComplete = {},
        previewNotificationGranted = true,
        previewSmsGranted = true,
        previewPhoneGranted = true,
        previewStorageGranted = true,
        previewOverlayGranted = true,
        previewNotificationListenerGranted = true
    )
}

@Preview(name = "3. Permissions - Standard Phone View", showBackground = true, widthDp = 390, heightDp = 844)
@Composable
fun PermissionSetupScreen_Phone_Preview() {
    PermissionSetupScreen(
        onComplete = {},
        previewNotificationGranted = true,
        previewSmsGranted = false,
        previewPhoneGranted = false,
        previewStorageGranted = true,
        previewOverlayGranted = true,
        previewNotificationListenerGranted = false
    )
}
