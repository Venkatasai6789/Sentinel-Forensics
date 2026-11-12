package com.deepfakeshield.feature.home

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
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ChevronRight
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.Search
import androidx.compose.material.icons.outlined.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.deepfakeshield.core.ui.components.ClinicalEmptyState
import com.deepfakeshield.core.ui.theme.*

private data class ToolItem(
    val name: String,
    val description: String,
    val icon: ImageVector,
    val route: String,
    val category: String
)

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ToolsHubScreen(onNavigateToTool: (String) -> Unit = {}, onNavigateToSearch: () -> Unit = {}) {
    var searchQuery by remember { mutableStateOf("") }
    var selectedCategory by remember { mutableIntStateOf(0) }
    val categories = listOf("All", "Security", "Privacy", "Network", "Monitor", "Recovery")

    val tools = remember {
        listOf(
            ToolItem("Device Antivirus", "Hash signatures, YARA & storage scan", Icons.Outlined.Security, "diagnostics", "Security"),
            ToolItem("Password Vault", "Strength audit, generator, HIBP & AES vault", Icons.Outlined.VpnKey, "password_checker", "Security"),
            ToolItem("Secure Notes", "Biometric-gated AES-256-GCM notes", Icons.Outlined.Description, "secure_notes", "Security"),
            ToolItem("Secure File Vault", "AES-256-GCM encrypted file storage", Icons.Outlined.FolderOpen, "secure_file_vault", "Security"),
            ToolItem("Privacy Audit", "Device permission & exposure review", Icons.Outlined.PrivacyTip, "privacy_score", "Privacy"),
            ToolItem("App Auditor", "Inspect installed app permissions", Icons.Outlined.Apps, "app_auditor", "Privacy"),
            ToolItem("Metadata Stripper", "Inspect and remove photo EXIF metadata", Icons.Outlined.RemoveRedEye, "metadata_stripper", "Privacy"),
            ToolItem("Clipboard Monitor", "Inspect clipboard access behavior", Icons.Outlined.ContentPaste, "clipboard_monitor", "Privacy"),
            ToolItem("Breach Monitor", "Check email/credential exposure records", Icons.Outlined.Shield, "breach_monitor", "Security"),
            ToolItem("Dark Web Monitor", "Scan dark web breach indicators", Icons.Outlined.VisibilityOff, "dark_web_monitor", "Security"),
            ToolItem("Scam Number Lookup", "Check reported phone number patterns", Icons.Outlined.Phone, "scam_number_lookup", "Security"),
            ToolItem("Fake Domain Monitor", "Check lookalike & typosquat domains", Icons.Outlined.Domain, "fake_domain_monitor", "Security"),
            ToolItem("Device Theft Protection", "Local anti-theft hardening checks", Icons.Outlined.PhoneLocked, "device_theft", "Security"),
            ToolItem("SIM Swap Protection", "Carrier & SIM hijacking safeguards", Icons.Outlined.SimCard, "sim_swap_protection", "Security"),
            ToolItem("Wi-Fi Analytics", "Local wireless network inspection", Icons.Outlined.Wifi, "wifi_scanner", "Network"),
            ToolItem("Network Monitor", "Monitor connection & DNS activity", Icons.Outlined.DataUsage, "network_monitor", "Network"),
            ToolItem("Tor Privacy Mode", "Configure Tor routing preferences", Icons.Outlined.VpnLock, "tor_settings", "Privacy"),
            ToolItem("Digital Footprint", "Review public account exposure", Icons.Outlined.Fingerprint, "digital_footprint", "Privacy"),
            ToolItem("Data Broker Opt-Out", "Opt-out checklists for data brokers", Icons.Outlined.DeleteSweep, "data_broker_optout", "Privacy"),
            ToolItem("Disposable Email", "Create alias recommendations", Icons.Outlined.AlternateEmail, "disposable_email", "Privacy"),
            ToolItem("Permission Timeline", "Track camera, mic & location usage", Icons.Outlined.Timeline, "permission_timeline", "Privacy"),
            ToolItem("Device Timeline", "Chronological local security activity", Icons.Outlined.History, "device_timeline", "Monitor"),
            ToolItem("Analytics", "Scan volume and detection breakdown", Icons.Outlined.BarChart, "analytics", "Monitor"),
            ToolItem("Weekly Report", "7-day forensic summary", Icons.Outlined.Assessment, "weekly_report", "Monitor"),
            ToolItem("Security News", "Threat advisories & security notices", Icons.Outlined.Newspaper, "security_news_feed", "Monitor"),
            ToolItem("Daily Challenge", "Practice phishing & scam recognition", Icons.Outlined.School, "daily_challenge", "Monitor"),
            ToolItem("Achievements", "Track completed security actions", Icons.Outlined.EmojiEvents, "achievements", "Monitor"),
            ToolItem("Threat Map", "Regional threat pattern reference", Icons.Outlined.Map, "threat_map", "Monitor"),
            ToolItem("Identity Monitor", "Consolidated identity exposure overview", Icons.Outlined.Person, "identity_dashboard_v2", "Privacy"),
            ToolItem("Emergency SOS", "Incident hotlines and quick actions", Icons.Outlined.Sos, "emergency_sos", "Recovery"),
            ToolItem("Scam Recovery", "Step-by-step incident containment guide", Icons.Outlined.HealthAndSafety, "scam_recovery", "Recovery"),
            ToolItem("Report a Scam", "Submit community scam indicators", Icons.Outlined.ReportProblem, "community_report", "Recovery")
        )
    }

    val filtered = remember(selectedCategory, searchQuery) {
        val byCat = if (selectedCategory == 0) tools else tools.filter { it.category == categories[selectedCategory] }
        if (searchQuery.isBlank()) byCat else byCat.filter {
            it.name.contains(searchQuery, ignoreCase = true) ||
                it.description.contains(searchQuery, ignoreCase = true)
        }
    }

    Scaffold(
        topBar = {
            Column {
                TopAppBar(
                    title = {
                        Column {
                            Text(
                                "Security Tools",
                                style = MaterialTheme.typography.titleMedium,
                                fontWeight = FontWeight.SemiBold,
                                color = TextPrimary
                            )
                            Text(
                                "${tools.size} local inspection & hardening utilities",
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
        LazyColumn(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding),
            contentPadding = PaddingValues(horizontal = 20.dp, vertical = 16.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp)
        ) {
            item {
                OutlinedTextField(
                    value = searchQuery,
                    onValueChange = { searchQuery = it },
                    textStyle = com.deepfakeshield.core.ui.components.clinicalTextFieldStyle(),
                    placeholder = { Text("Search security tools...") },
                    leadingIcon = { Icon(Icons.Default.Search, contentDescription = null) },
                    trailingIcon = {
                        if (searchQuery.isNotEmpty()) {
                            IconButton(onClick = { searchQuery = "" }) {
                                Icon(Icons.Default.Close, contentDescription = "Clear search", tint = TextSecondary)
                            }
                        }
                    },
                    modifier = Modifier.fillMaxWidth(),
                    singleLine = true,
                    shape = RoundedCornerShape(14.dp),
                    colors = com.deepfakeshield.core.ui.components.clinicalOutlinedTextFieldColors(
                        focusedContainerColor = SurfaceLight,
                        unfocusedContainerColor = SurfaceLight
                    )
                )
            }

            item {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .horizontalScroll(rememberScrollState()),
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    categories.forEachIndexed { index, category ->
                        FilterChip(
                            selected = selectedCategory == index,
                            onClick = { selectedCategory = index },
                            label = {
                                Text(
                                    text = category,
                                    fontSize = 12.sp,
                                    fontWeight = if (selectedCategory == index) FontWeight.SemiBold else FontWeight.Medium
                                )
                            },
                            colors = FilterChipDefaults.filterChipColors(
                                selectedContainerColor = SentinelPrimaryContainer,
                                selectedLabelColor = SentinelPrimary,
                                containerColor = SurfaceLight,
                                labelColor = TextSecondary
                            ),
                            border = FilterChipDefaults.filterChipBorder(
                                enabled = true,
                                selected = selectedCategory == index,
                                borderColor = BorderColor,
                                selectedBorderColor = SentinelPrimary.copy(alpha = 0.35f)
                            )
                        )
                    }
                }
            }

            item {
                Text(
                    text = "${filtered.size} tools shown",
                    style = MaterialTheme.typography.bodySmall,
                    color = TextSecondary
                )
            }

            if (filtered.isEmpty()) {
                item {
                    ClinicalEmptyState(
                        icon = Icons.Outlined.SearchOff,
                        title = "No matching tools",
                        description = "Clear the search query or switch category to view available security utilities."
                    )
                }
            } else {
                items(filtered, key = { it.route }) { tool ->
                    Surface(
                        modifier = Modifier
                            .fillMaxWidth()
                            .clip(RoundedCornerShape(14.dp))
                            .clickable { onNavigateToTool(tool.route) },
                        shape = RoundedCornerShape(14.dp),
                        color = SurfaceLight,
                        border = BorderStroke(1.dp, BorderColor)
                    ) {
                        Row(
                            modifier = Modifier.padding(14.dp),
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.spacedBy(12.dp)
                        ) {
                            Box(
                                modifier = Modifier
                                    .size(40.dp)
                                    .background(SurfaceSubtle, CircleShape),
                                contentAlignment = Alignment.Center
                            ) {
                                Icon(
                                    imageVector = tool.icon,
                                    contentDescription = null,
                                    modifier = Modifier.size(20.dp),
                                    tint = SentinelPrimary
                                )
                            }
                            Column(modifier = Modifier.weight(1f)) {
                                Text(
                                    text = tool.name,
                                    style = MaterialTheme.typography.titleSmall,
                                    fontWeight = FontWeight.SemiBold,
                                    color = TextPrimary
                                )
                                Text(
                                    text = tool.description,
                                    style = MaterialTheme.typography.bodySmall,
                                    color = TextSecondary
                                )
                            }
                            Surface(
                                color = SurfaceSubtle,
                                shape = RoundedCornerShape(6.dp)
                            ) {
                                Text(
                                    text = tool.category,
                                    modifier = Modifier.padding(horizontal = 8.dp, vertical = 3.dp),
                                    fontSize = 11.sp,
                                    fontWeight = FontWeight.Medium,
                                    color = TextSecondary
                                )
                            }
                            Icon(
                                imageVector = Icons.Default.ChevronRight,
                                contentDescription = null,
                                tint = TextTertiary,
                                modifier = Modifier.size(18.dp)
                            )
                        }
                    }
                }
            }
        }
    }
}
