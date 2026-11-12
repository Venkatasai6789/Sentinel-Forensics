package com.deepfakeshield.feature.shield

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowForward
import androidx.compose.material.icons.outlined.*
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.deepfakeshield.core.ui.components.ClinicalSurfaceCard
import com.deepfakeshield.core.ui.components.SectionHeaderRow
import com.deepfakeshield.core.ui.theme.*

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ScanHubScreen(
    onNavigateToVideoScan: () -> Unit = {},
    onNavigateToMessageScan: () -> Unit = {},
    onNavigateToPhotoForensics: () -> Unit = {},
    onNavigateToQrScanner: () -> Unit = {},
    onNavigateToEmailScanner: () -> Unit = {},
    onNavigateToFakeReview: () -> Unit = {},
    onNavigateToUrlScanner: () -> Unit = {},
    onNavigateToDeviceScan: () -> Unit = {},
    onNavigateToPasswordVault: () -> Unit = {}
) {
    Scaffold(
        topBar = {
            Column {
                TopAppBar(
                    title = {
                        Column {
                            Text(
                                "Forensic Scan Center",
                                style = MaterialTheme.typography.titleMedium,
                                fontWeight = FontWeight.SemiBold,
                                color = TextPrimary
                            )
                            Text(
                                "Select an inspection module",
                                style = MaterialTheme.typography.bodySmall,
                                color = TextSecondary
                            )
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
            ClinicalSurfaceCard(
                contentPadding = PaddingValues(18.dp)
            ) {
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(14.dp)
                ) {
                    Box(
                        modifier = Modifier
                            .size(44.dp)
                            .background(SentinelPrimaryContainer, CircleShape),
                        contentAlignment = Alignment.Center
                    ) {
                        Icon(
                            imageVector = Icons.Outlined.VerifiedUser,
                            contentDescription = null,
                            tint = SentinelPrimary,
                            modifier = Modifier.size(22.dp)
                        )
                    }
                    Column(modifier = Modifier.weight(1f)) {
                        Text(
                            text = "On-Device Inspection",
                            style = MaterialTheme.typography.titleSmall,
                            fontWeight = FontWeight.SemiBold,
                            color = TextPrimary
                        )
                        Spacer(Modifier.height(2.dp))
                        Text(
                            text = "Files, images, videos, messages, and URLs are analyzed locally. Live network lookups run only when explicitly enabled.",
                            style = MaterialTheme.typography.bodySmall,
                            color = TextSecondary
                        )
                    }
                }
            }

            SectionHeaderRow(
                title = "Core Security Modules",
                subtitle = "Six primary forensic & protection engines"
            )

            ClinicalSurfaceCard(contentPadding = PaddingValues(0.dp)) {
                ScanEngineRow(
                    title = "Message Shield",
                    subtitle = "Scan SMS & notification text for phishing patterns & links",
                    requirementTag = "Offline heuristics + pattern rules",
                    icon = Icons.Outlined.Sms,
                    onClick = onNavigateToMessageScan
                )
                HorizontalDivider(color = BorderColor, modifier = Modifier.padding(horizontal = 16.dp))
                ScanEngineRow(
                    title = "Phishing URL Scan",
                    subtitle = "Inspect URL syntax, IDN punycode, TLS & redirect chain",
                    requirementTag = "Local cache; TLS/redirect needs network",
                    icon = Icons.Outlined.Link,
                    onClick = onNavigateToUrlScanner
                )
                HorizontalDivider(color = BorderColor, modifier = Modifier.padding(horizontal = 16.dp))
                ScanEngineRow(
                    title = "Device Antivirus",
                    subtitle = "Hash signatures, YARA rules, APK & selected storage scan",
                    requirementTag = "Android sandbox applies to other apps",
                    icon = Icons.Outlined.Security,
                    onClick = onNavigateToDeviceScan
                )
                HorizontalDivider(color = BorderColor, modifier = Modifier.padding(horizontal = 16.dp))
                ScanEngineRow(
                    title = "Deepfake Video Detection",
                    subtitle = "Frame sampling, face landmarks & luminance temporal checks",
                    requirementTag = "Requires video file selection",
                    icon = Icons.Outlined.Videocam,
                    onClick = onNavigateToVideoScan
                )
                HorizontalDivider(color = BorderColor, modifier = Modifier.padding(horizontal = 16.dp))
                ScanEngineRow(
                    title = "Photo Forensics",
                    subtitle = "EXIF/XMP/PNG metadata, Error Level Analysis (ELA) & noise check",
                    requirementTag = "Indicative only — not proof of origin",
                    icon = Icons.Outlined.Image,
                    onClick = onNavigateToPhotoForensics
                )
                HorizontalDivider(color = BorderColor, modifier = Modifier.padding(horizontal = 16.dp))
                ScanEngineRow(
                    title = "Password Vault",
                    subtitle = "Entropy audit, CSPRNG generator, HIBP k-Anonymity & encrypted vault",
                    requirementTag = "Biometric/PIN gate + AES-256-GCM",
                    icon = Icons.Outlined.VpnKey,
                    onClick = onNavigateToPasswordVault
                )
            }

            SectionHeaderRow(
                title = "Specialized Utilities",
                subtitle = "Additional content checks"
            )

            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(10.dp)
            ) {
                SecondaryScanTile(
                    label = "Email Header",
                    subtitle = "Phishing checks",
                    icon = Icons.Outlined.Email,
                    modifier = Modifier.weight(1f),
                    onClick = onNavigateToEmailScanner
                )
                SecondaryScanTile(
                    label = "QR Code",
                    subtitle = "Inspect link",
                    icon = Icons.Outlined.QrCodeScanner,
                    modifier = Modifier.weight(1f),
                    onClick = onNavigateToQrScanner
                )
                SecondaryScanTile(
                    label = "Reviews",
                    subtitle = "Text patterns",
                    icon = Icons.Outlined.RateReview,
                    modifier = Modifier.weight(1f),
                    onClick = onNavigateToFakeReview
                )
            }

            Spacer(Modifier.height(12.dp))
        }
    }
}

@Composable
private fun ScanEngineRow(
    title: String,
    subtitle: String,
    requirementTag: String,
    icon: ImageVector,
    onClick: () -> Unit
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clickable(onClick = onClick)
            .padding(horizontal = 16.dp, vertical = 14.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(14.dp)
    ) {
        Box(
            modifier = Modifier
                .size(40.dp)
                .background(SurfaceSubtle, CircleShape),
            contentAlignment = Alignment.Center
        ) {
            Icon(icon, contentDescription = null, tint = SentinelPrimary, modifier = Modifier.size(20.dp))
        }
        Column(modifier = Modifier.weight(1f)) {
            Text(
                text = title,
                style = MaterialTheme.typography.titleSmall,
                fontWeight = FontWeight.SemiBold,
                color = TextPrimary
            )
            Spacer(Modifier.height(2.dp))
            Text(
                text = subtitle,
                style = MaterialTheme.typography.bodySmall,
                color = TextSecondary,
                maxLines = 2,
                overflow = TextOverflow.Ellipsis
            )
            Spacer(Modifier.height(4.dp))
            Text(
                text = requirementTag,
                fontSize = 11.sp,
                color = TextTertiary
            )
        }
        Icon(
            imageVector = Icons.AutoMirrored.Filled.ArrowForward,
            contentDescription = "Open $title",
            tint = TextSecondary,
            modifier = Modifier.size(18.dp)
        )
    }
}

@Composable
private fun SecondaryScanTile(
    label: String,
    subtitle: String,
    icon: ImageVector,
    modifier: Modifier = Modifier,
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
            modifier = Modifier.padding(14.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            Box(
                modifier = Modifier
                    .size(34.dp)
                    .background(SentinelPrimaryContainer, CircleShape),
                contentAlignment = Alignment.Center
            ) {
                Icon(icon, contentDescription = null, tint = SentinelPrimary, modifier = Modifier.size(18.dp))
            }
            Column {
                Text(
                    text = label,
                    style = MaterialTheme.typography.titleSmall,
                    fontSize = 13.sp,
                    fontWeight = FontWeight.SemiBold,
                    color = TextPrimary,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis
                )
                Text(
                    text = subtitle,
                    fontSize = 11.sp,
                    color = TextSecondary,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis
                )
            }
        }
    }
}
