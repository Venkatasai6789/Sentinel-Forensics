package com.deepfakeshield.feature.vault

import android.net.Uri
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
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
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.hilt.navigation.compose.hiltViewModel
import com.deepfakeshield.core.security.DeviceAuthHelper
import com.deepfakeshield.core.ui.components.ClinicalEmptyState
import com.deepfakeshield.core.ui.components.ClinicalSurfaceCard
import com.deepfakeshield.core.ui.theme.*
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

private val TabularFileStyle = TextStyle(fontFeatureSettings = "tnum")

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SecureFileVaultScreen(
    viewModel: SecureFileVaultViewModel = hiltViewModel(),
    onNavigateBack: () -> Unit = {}
) {
    val uiState by viewModel.uiState.collectAsState()
    val context = LocalContext.current
    val snackbar = remember { SnackbarHostState() }
    var deleteCandidate by remember { mutableStateOf<EncryptedVaultFileItem?>(null) }

    val filePicker = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri: Uri? ->
        uri?.let { viewModel.importAndEncryptFile(it) }
    }

    LaunchedEffect(uiState.statusMessage) {
        uiState.statusMessage?.let {
            snackbar.showSnackbar(it)
            viewModel.clearMessage()
        }
    }

    LaunchedEffect(uiState.error) {
        uiState.error?.let {
            snackbar.showSnackbar(it)
            viewModel.clearMessage()
        }
    }

    deleteCandidate?.let { item ->
        AlertDialog(
            onDismissRequest = { deleteCandidate = null },
            containerColor = SurfaceLight,
            titleContentColor = TextPrimary,
            textContentColor = TextSecondary,
            title = { Text("Delete Encrypted File", fontWeight = FontWeight.SemiBold) },
            text = { Text("Remove \"${item.displayName}\" and wipe its AES-256-GCM ciphertext from app storage?") },
            confirmButton = {
                Button(
                    onClick = {
                        viewModel.deleteEncryptedFile(item)
                        deleteCandidate = null
                    },
                    colors = ButtonDefaults.buttonColors(containerColor = DangerRed, contentColor = Color.White)
                ) {
                    Text("Delete")
                }
            },
            dismissButton = {
                TextButton(onClick = { deleteCandidate = null }) { Text("Cancel") }
            }
        )
    }

    Scaffold(
        topBar = {
            Column {
                TopAppBar(
                    title = {
                        Column {
                            Text("Secure File Vault", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold, color = TextPrimary)
                            Text("AES-256-GCM Chunked Private Storage", style = MaterialTheme.typography.bodySmall, color = TextSecondary)
                        }
                    },
                    navigationIcon = {
                        IconButton(onClick = onNavigateBack) {
                            Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back", tint = TextPrimary)
                        }
                    },
                    actions = {
                        if (uiState.isUnlocked) {
                            IconButton(onClick = { viewModel.lockVault() }) {
                                Icon(Icons.Filled.Lock, contentDescription = "Lock File Vault", tint = TextPrimary)
                            }
                        }
                    },
                    colors = TopAppBarDefaults.topAppBarColors(containerColor = SurfaceLight)
                )
                HorizontalDivider(color = BorderColor)
            }
        },
        floatingActionButton = {
            if (uiState.isUnlocked) {
                FloatingActionButton(
                    onClick = { filePicker.launch(arrayOf("*/*")) },
                    containerColor = SentinelPrimary,
                    contentColor = Color.White
                ) {
                    Icon(Icons.Filled.Add, contentDescription = "Encrypt & Store File")
                }
            }
        },
        snackbarHost = { SnackbarHost(snackbar) },
        containerColor = BackgroundLight
    ) { padding ->
        if (!uiState.isUnlocked) {
            Column(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(padding)
                    .padding(horizontal = 20.dp, vertical = 24.dp),
                verticalArrangement = Arrangement.spacedBy(16.dp)
            ) {
                ClinicalSurfaceCard {
                    Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(14.dp)) {
                        Box(
                            modifier = Modifier
                                .size(48.dp)
                                .background(SentinelPrimaryContainer, CircleShape),
                            contentAlignment = Alignment.Center
                        ) {
                            Icon(Icons.Outlined.FolderOpen, contentDescription = null, tint = SentinelPrimary, modifier = Modifier.size(24.dp))
                        }
                        Column(modifier = Modifier.weight(1f)) {
                            Text("Encrypted File Vault Locked", style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.SemiBold, color = TextPrimary)
                            Text(
                                text = "${uiState.files.size} encrypted document(s) stored in app-private storage (20 MB max per file).",
                                style = MaterialTheme.typography.bodySmall,
                                color = TextSecondary
                            )
                        }
                    }

                    Spacer(Modifier.height(14.dp))

                    if (uiState.biometricStatus == DeviceAuthHelper.BiometricStatus.NOT_ENROLLED) {
                        Surface(color = WarningContainer, shape = RoundedCornerShape(8.dp), modifier = Modifier.fillMaxWidth()) {
                            Text(
                                text = "Configure a screen lock, PIN, or biometric in Android Settings to unlock encrypted files.",
                                modifier = Modifier.padding(10.dp),
                                fontSize = 12.sp,
                                color = WarningAmber
                            )
                        }
                    } else {
                        Button(
                            onClick = { viewModel.authenticate(context) },
                            modifier = Modifier
                                .fillMaxWidth()
                                .height(50.dp),
                            shape = RoundedCornerShape(12.dp),
                            colors = ButtonDefaults.buttonColors(containerColor = SentinelPrimary, contentColor = Color.White)
                        ) {
                            Icon(Icons.Filled.Fingerprint, contentDescription = null, modifier = Modifier.size(18.dp))
                            Spacer(Modifier.width(8.dp))
                            Text("Unlock File Vault", fontWeight = FontWeight.SemiBold)
                        }
                    }
                }
            }
        } else {
            val dateFmt = remember { SimpleDateFormat("MMM d, HH:mm", Locale.getDefault()) }
            LazyColumn(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(padding),
                contentPadding = PaddingValues(horizontal = 20.dp, vertical = 16.dp),
                verticalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                item {
                    ClinicalSurfaceCard(containerColor = SurfaceSubtle, contentPadding = PaddingValues(14.dp)) {
                        Text(
                            text = "Imported files are streamed in 256 KB AES-256-GCM chunks into private filesDir/encrypted_vault/. Temporary preview copies are wiped when locked.",
                            fontSize = 12.sp,
                            color = TextSecondary
                        )
                    }
                }

                if (uiState.isProcessing) {
                    item {
                        LinearProgressIndicator(modifier = Modifier.fillMaxWidth(), color = SentinelPrimary)
                    }
                }

                if (uiState.files.isEmpty()) {
                    item {
                        ClinicalEmptyState(
                            icon = Icons.Outlined.FolderOpen,
                            title = "No Encrypted Documents Stored",
                            description = "Tap + to pick a file (up to 20 MB) and encrypt it locally with AES-256-GCM."
                        )
                    }
                } else {
                    items(uiState.files, key = { it.id }) { item ->
                        ClinicalSurfaceCard {
                            Text(item.displayName, style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.SemiBold, color = TextPrimary)
                            Text(
                                text = "${formatBytes(item.sizeBytes)} • ${item.mimeType} • ${dateFmt.format(Date(item.addedAt))}",
                                style = TabularFileStyle.copy(fontSize = 11.sp),
                                color = TextSecondary
                            )
                            if (item.sha256.isNotBlank()) {
                                Spacer(Modifier.height(4.dp))
                                Text(
                                    text = "SHA-256: ${item.sha256.take(24)}...",
                                    fontFamily = FontFamily.Monospace,
                                    fontSize = 11.sp,
                                    color = TextTertiary
                                )
                            }
                            Spacer(Modifier.height(10.dp))
                            Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                                OutlinedButton(
                                    onClick = { viewModel.openDecryptedFile(item) },
                                    modifier = Modifier.weight(1f),
                                    shape = RoundedCornerShape(10.dp),
                                    border = BorderStroke(1.dp, SentinelPrimary)
                                ) {
                                    Icon(Icons.Outlined.Visibility, contentDescription = null, modifier = Modifier.size(16.dp), tint = SentinelPrimary)
                                    Spacer(Modifier.width(6.dp))
                                    Text("Decrypt & View", color = SentinelPrimary, fontSize = 12.sp, fontWeight = FontWeight.Medium)
                                }
                                OutlinedButton(
                                    onClick = { deleteCandidate = item },
                                    modifier = Modifier.weight(1f),
                                    shape = RoundedCornerShape(10.dp),
                                    border = BorderStroke(1.dp, DangerRed)
                                ) {
                                    Text("Delete", color = DangerRed, fontSize = 12.sp, fontWeight = FontWeight.Medium)
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

private fun formatBytes(bytes: Long): String = when {
    bytes >= 1024 * 1024 -> "%.1f MB".format(bytes / (1024.0 * 1024.0))
    bytes >= 1024 -> "%.1f KB".format(bytes / 1024.0)
    else -> "$bytes B"
}
