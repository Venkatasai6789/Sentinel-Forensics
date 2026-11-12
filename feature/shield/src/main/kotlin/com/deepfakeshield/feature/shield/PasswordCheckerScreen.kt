package com.deepfakeshield.feature.shield

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
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
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.hilt.navigation.compose.hiltViewModel
import com.deepfakeshield.core.security.DeviceAuthHelper
import com.deepfakeshield.core.security.GenerationMode
import com.deepfakeshield.core.security.PasswordAuditReport
import com.deepfakeshield.core.security.PasswordStrengthTier
import com.deepfakeshield.core.ui.components.ClinicalEmptyState
import com.deepfakeshield.core.ui.components.ClinicalSurfaceCard
import com.deepfakeshield.core.ui.components.SectionHeaderRow
import com.deepfakeshield.core.ui.components.VerdictStatusPill
import com.deepfakeshield.core.ui.theme.*
import com.deepfakeshield.data.repository.DecryptedVaultCredential
import com.deepfakeshield.data.repository.VaultCredentialMetadata
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

private val TabularPwdStyle = TextStyle(fontFeatureSettings = "tnum")

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun PasswordCheckerScreen(
    initialPassword: String = "",
    onNavigateBack: () -> Unit = {},
    viewModel: PasswordVaultViewModel = hiltViewModel()
) {
    val uiState by viewModel.uiState.collectAsState()
    val context = LocalContext.current
    val snackbar = remember { SnackbarHostState() }
    var selectedTab by remember { mutableIntStateOf(0) }

    var showCredentialEditor by remember { mutableStateOf(false) }
    var editingCredential by remember { mutableStateOf<DecryptedVaultCredential?>(null) }
    var deleteCandidate by remember { mutableStateOf<VaultCredentialMetadata?>(null) }

    LaunchedEffect(initialPassword) {
        if (initialPassword.isNotEmpty() && uiState.passwordInput.isEmpty()) {
            viewModel.onPasswordChanged(initialPassword)
        }
    }

    LaunchedEffect(uiState.statusMessage) {
        uiState.statusMessage?.let {
            snackbar.showSnackbar(it)
            viewModel.clearNotices()
        }
    }

    LaunchedEffect(uiState.error) {
        uiState.error?.let {
            snackbar.showSnackbar(it)
            viewModel.clearNotices()
        }
    }

    deleteCandidate?.let { cred ->
        AlertDialog(
            onDismissRequest = { deleteCandidate = null },
            containerColor = SurfaceLight,
            titleContentColor = TextPrimary,
            textContentColor = TextSecondary,
            title = { Text("Delete Credential", fontWeight = FontWeight.SemiBold) },
            text = { Text("Permanently remove \"${cred.title}\" from your AES-256-GCM Password Vault?") },
            confirmButton = {
                Button(
                    onClick = {
                        viewModel.deleteCredential(cred.id)
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

    uiState.revealedCredential?.let { revealed ->
        RevealedCredentialDialog(
            credential = revealed,
            onDismiss = { viewModel.clearRevealedCredential() },
            onCopyUsername = { viewModel.copySensitiveSecret("username", revealed.username) },
            onCopyPassword = { viewModel.copySensitiveSecret("password", revealed.password) },
            onEdit = {
                editingCredential = revealed
                viewModel.clearRevealedCredential()
                showCredentialEditor = true
            }
        )
    }

    if (showCredentialEditor) {
        CredentialEditorDialog(
            existing = editingCredential,
            initialPassword = if (editingCredential == null) uiState.passwordInput else editingCredential!!.password,
            onDismiss = {
                showCredentialEditor = false
                editingCredential = null
            },
            onGeneratePassword = { viewModel.generatePassword() },
            onSave = { title, username, password, url, notes ->
                viewModel.saveCredential(
                    id = editingCredential?.id ?: 0L,
                    title = title,
                    username = username,
                    password = password,
                    url = url.ifBlank { null },
                    notes = notes
                )
                showCredentialEditor = false
                editingCredential = null
            }
        )
    }

    Scaffold(
        topBar = {
            Column {
                TopAppBar(
                    title = {
                        Column {
                            Text("Password Vault", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold, color = TextPrimary)
                            Text("Entropy Auditor, HIBP k-Anonymity & AES-256-GCM Vault", style = MaterialTheme.typography.bodySmall, color = TextSecondary)
                        }
                    },
                    navigationIcon = {
                        IconButton(onClick = onNavigateBack) {
                            Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back", tint = TextPrimary)
                        }
                    },
                    actions = {
                        if (selectedTab == 1 && uiState.isUnlocked) {
                            IconButton(onClick = { viewModel.lockVault() }) {
                                Icon(Icons.Filled.Lock, contentDescription = "Lock Vault", tint = TextPrimary)
                            }
                        }
                    },
                    colors = TopAppBarDefaults.topAppBarColors(containerColor = SurfaceLight)
                )
                HorizontalDivider(color = BorderColor)
            }
        },
        floatingActionButton = {
            if (selectedTab == 1 && uiState.isUnlocked) {
                FloatingActionButton(
                    onClick = {
                        editingCredential = null
                        showCredentialEditor = true
                    },
                    containerColor = SentinelPrimary,
                    contentColor = Color.White
                ) {
                    Icon(Icons.Filled.Add, contentDescription = "Add Encrypted Credential")
                }
            }
        },
        snackbarHost = { SnackbarHost(snackbar) },
        containerColor = BackgroundLight
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
        ) {
            SecondaryTabRow(
                selectedTabIndex = selectedTab,
                containerColor = SurfaceLight,
                contentColor = SentinelPrimary,
                divider = { HorizontalDivider(color = BorderColor) }
            ) {
                listOf("Auditor & Generator", "Vault (${uiState.vaultHealth.totalCredentials})").forEachIndexed { idx, title ->
                    Tab(
                        selected = selectedTab == idx,
                        onClick = { selectedTab = idx },
                        text = {
                            Text(
                                text = title,
                                fontSize = 13.sp,
                                fontWeight = if (selectedTab == idx) FontWeight.SemiBold else FontWeight.Medium,
                                color = if (selectedTab == idx) SentinelPrimary else TextSecondary
                            )
                        }
                    )
                }
            }

            when (selectedTab) {
                0 -> PasswordAuditorTab(
                    uiState = uiState,
                    onPasswordChanged = { viewModel.onPasswordChanged(it) },
                    onCheckBreach = { viewModel.checkPasswordBreach() },
                    onRecordAudit = { viewModel.auditAndRecordCurrentPassword() },
                    onCopyPassword = { viewModel.copySensitiveSecret("password", uiState.passwordInput) },
                    onUpdateConfig = { transform -> viewModel.updateGenConfig(transform) },
                    onGenerate = { viewModel.generatePassword() }
                )
                else -> EncryptedVaultTab(
                    uiState = uiState,
                    onUnlock = { viewModel.authenticateVault(context) },
                    onReveal = { viewModel.revealCredential(it.id) },
                    onCheckCredentialBreach = { viewModel.checkStoredCredentialBreach(it.id) },
                    onDeleteRequest = { deleteCandidate = it }
                )
            }
        }
    }
}

@Composable
private fun PasswordAuditorTab(
    uiState: PasswordVaultUiState,
    onPasswordChanged: (String) -> Unit,
    onCheckBreach: () -> Unit,
    onRecordAudit: () -> Unit,
    onCopyPassword: () -> Unit,
    onUpdateConfig: ((com.deepfakeshield.core.security.PasswordGenerationConfig) -> com.deepfakeshield.core.security.PasswordGenerationConfig) -> Unit,
    onGenerate: () -> Unit
) {
    var showPassword by remember { mutableStateOf(false) }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(horizontal = 20.dp, vertical = 16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        ClinicalSurfaceCard {
            Text("Password Strength & Entropy", style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.SemiBold, color = TextPrimary)
            Spacer(Modifier.height(4.dp))
            Text(
                text = "Mathematical Shannon + pool entropy audit. Plaintext passwords are never written to scan history logs.",
                style = MaterialTheme.typography.bodySmall,
                color = TextSecondary
            )
            Spacer(Modifier.height(12.dp))

            OutlinedTextField(
                value = uiState.passwordInput,
                onValueChange = onPasswordChanged,
                modifier = Modifier.fillMaxWidth(),
                textStyle = com.deepfakeshield.core.ui.components.clinicalTextFieldStyle(),
                label = { Text("Password to check") },
                placeholder = { Text("Type or generate password...") },
                singleLine = true,
                visualTransformation = if (showPassword) VisualTransformation.None else PasswordVisualTransformation(),
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
                trailingIcon = {
                    Row {
                        IconButton(onClick = { showPassword = !showPassword }) {
                            Icon(
                                imageVector = if (showPassword) Icons.Filled.VisibilityOff else Icons.Filled.Visibility,
                                contentDescription = if (showPassword) "Hide password" else "Show password",
                                tint = TextSecondary
                            )
                        }
                        if (uiState.passwordInput.isNotEmpty()) {
                            IconButton(onClick = { onPasswordChanged("") }) {
                                Icon(Icons.Filled.Close, contentDescription = "Clear", tint = TextSecondary)
                            }
                        }
                    }
                },
                shape = RoundedCornerShape(14.dp),
                colors = com.deepfakeshield.core.ui.components.clinicalOutlinedTextFieldColors()
            )

            uiState.auditReport?.let { report ->
                Spacer(Modifier.height(14.dp))
                PasswordAuditSummarySection(report)
                Spacer(Modifier.height(12.dp))
                Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                    OutlinedButton(
                        onClick = onCopyPassword,
                        modifier = Modifier.weight(1f),
                        shape = RoundedCornerShape(10.dp),
                        border = BorderStroke(1.dp, BorderColor)
                    ) {
                        Icon(Icons.Filled.ContentCopy, contentDescription = null, modifier = Modifier.size(16.dp), tint = TextPrimary)
                        Spacer(Modifier.width(6.dp))
                        Text("Copy", fontSize = 12.sp, color = TextPrimary)
                    }
                    OutlinedButton(
                        onClick = onRecordAudit,
                        modifier = Modifier.weight(1f),
                        shape = RoundedCornerShape(10.dp),
                        border = BorderStroke(1.dp, SentinelPrimary)
                    ) {
                        Text("Log Score", fontSize = 12.sp, color = SentinelPrimary, fontWeight = FontWeight.Medium)
                    }
                }
            }
        }

        // HIBP k-Anonymity Card
        ClinicalSurfaceCard {
            Text("Breach Exposure Check (k-Anonymity)", style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.SemiBold, color = TextPrimary)
            Spacer(Modifier.height(4.dp))
            Text(
                text = "Computes SHA-1 locally and queries api.pwnedpasswords.com using only the first 5 hex characters. Offline lookups report Failed honestly.",
                fontSize = 12.sp,
                color = TextSecondary
            )
            Spacer(Modifier.height(12.dp))

            when (val b = uiState.breachState) {
                BreachCheckState.Idle -> Unit
                BreachCheckState.Checking -> {
                    LinearProgressIndicator(modifier = Modifier.fillMaxWidth(), color = SentinelPrimary)
                    Spacer(Modifier.height(8.dp))
                }
                is BreachCheckState.Compromised -> {
                    Surface(color = DangerContainer, shape = RoundedCornerShape(8.dp), modifier = Modifier.fillMaxWidth()) {
                        Text(
                            text = "COMPROMISED: Observed ${b.occurrences} time(s) in known breach dumps. Do not reuse this password.",
                            modifier = Modifier.padding(10.dp),
                            fontSize = 12.sp,
                            fontWeight = FontWeight.SemiBold,
                            color = DangerRed
                        )
                    }
                    Spacer(Modifier.height(10.dp))
                }
                BreachCheckState.Clean -> {
                    Surface(color = SuccessContainer, shape = RoundedCornerShape(8.dp), modifier = Modifier.fillMaxWidth()) {
                        Text(
                            text = "No match found in HIBP k-Anonymity dataset.",
                            modifier = Modifier.padding(10.dp),
                            fontSize = 12.sp,
                            fontWeight = FontWeight.Medium,
                            color = SuccessGreen
                        )
                    }
                    Spacer(Modifier.height(10.dp))
                }
                is BreachCheckState.Failed -> {
                    Surface(color = WarningContainer, shape = RoundedCornerShape(8.dp), modifier = Modifier.fillMaxWidth()) {
                        Text(
                            text = b.reason,
                            modifier = Modifier.padding(10.dp),
                            fontSize = 12.sp,
                            color = WarningAmber
                        )
                    }
                    Spacer(Modifier.height(10.dp))
                }
            }

            Button(
                onClick = onCheckBreach,
                enabled = uiState.passwordInput.isNotEmpty() && uiState.breachState !is BreachCheckState.Checking,
                modifier = Modifier
                    .fillMaxWidth()
                    .height(48.dp),
                shape = RoundedCornerShape(12.dp),
                colors = ButtonDefaults.buttonColors(
                    containerColor = SentinelPrimary,
                    contentColor = Color.White,
                    disabledContainerColor = SurfaceSubtle,
                    disabledContentColor = TextTertiary
                )
            ) {
                Text("Check Breach Exposure", fontWeight = FontWeight.SemiBold)
            }
        }

        // CSPRNG Generator Card
        val cfg = uiState.genConfig
        ClinicalSurfaceCard {
            Text("CSPRNG Generator", style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.SemiBold, color = TextPrimary)
            Spacer(Modifier.height(10.dp))
            Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                FilterChip(
                    selected = cfg.mode == GenerationMode.RANDOM_CHARACTERS,
                    onClick = { onUpdateConfig { it.copy(mode = GenerationMode.RANDOM_CHARACTERS) } },
                    label = { Text("Random Chars", fontSize = 12.sp) }
                )
                FilterChip(
                    selected = cfg.mode == GenerationMode.DICEWARE_PASSPHRASE,
                    onClick = { onUpdateConfig { it.copy(mode = GenerationMode.DICEWARE_PASSPHRASE) } },
                    label = { Text("Diceware Passphrase", fontSize = 12.sp) }
                )
            }

            Spacer(Modifier.height(8.dp))
            if (cfg.mode == GenerationMode.RANDOM_CHARACTERS) {
                Text("Length: ${cfg.length} characters", style = TabularPwdStyle.copy(fontSize = 12.sp, fontWeight = FontWeight.Medium), color = TextPrimary)
                Slider(
                    value = cfg.length.toFloat(),
                    onValueChange = { onUpdateConfig { cur -> cur.copy(length = it.toInt()) } },
                    valueRange = 8f..48f
                )
                Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                    ToggleBadge("A-Z", cfg.includeUppercase) { onUpdateConfig { cur -> cur.copy(includeUppercase = !cur.includeUppercase) } }
                    ToggleBadge("a-z", cfg.includeLowercase) { onUpdateConfig { cur -> cur.copy(includeLowercase = !cur.includeLowercase) } }
                    ToggleBadge("0-9", cfg.includeDigits) { onUpdateConfig { cur -> cur.copy(includeDigits = !cur.includeDigits) } }
                    ToggleBadge("!@#", cfg.includeSymbols) { onUpdateConfig { cur -> cur.copy(includeSymbols = !cur.includeSymbols) } }
                }
            } else {
                Text("Words: ${cfg.wordCount} EFF Diceware terms", style = TabularPwdStyle.copy(fontSize = 12.sp, fontWeight = FontWeight.Medium), color = TextPrimary)
                Slider(
                    value = cfg.wordCount.toFloat(),
                    onValueChange = { onUpdateConfig { cur -> cur.copy(wordCount = it.toInt()) } },
                    valueRange = 3f..10f
                )
            }

            Spacer(Modifier.height(12.dp))
            Button(
                onClick = onGenerate,
                modifier = Modifier
                    .fillMaxWidth()
                    .height(48.dp),
                shape = RoundedCornerShape(12.dp),
                colors = ButtonDefaults.buttonColors(containerColor = SentinelPrimary, contentColor = Color.White)
            ) {
                Icon(Icons.Filled.AutoFixHigh, contentDescription = null, modifier = Modifier.size(18.dp))
                Spacer(Modifier.width(8.dp))
                Text("Generate CSPRNG Secret", fontWeight = FontWeight.SemiBold)
            }
        }

        if (uiState.recentHistory.isNotEmpty()) {
            SectionHeaderRow(title = "Recent Password Audits", subtitle = "Metadata-only logs (zero plaintext stored)")
            ClinicalSurfaceCard(contentPadding = PaddingValues(0.dp)) {
                val fmt = remember { SimpleDateFormat("MMM d, HH:mm", Locale.getDefault()) }
                uiState.recentHistory.take(8).forEachIndexed { idx, item ->
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(horizontal = 16.dp, vertical = 12.dp),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(10.dp)
                    ) {
                        Column(modifier = Modifier.weight(1f)) {
                            Text(item.inputName ?: "Password Audit", fontSize = 13.sp, fontWeight = FontWeight.Medium, color = TextPrimary)
                            Text(
                                text = "${fmt.format(Date(item.analyzedAt))} • Entropy: ${item.metadata["entropyBits"] ?: "?"} bits",
                                style = TabularPwdStyle.copy(fontSize = 11.sp),
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

@Composable
private fun PasswordAuditSummarySection(report: PasswordAuditReport) {
    val tierColor = when (report.tier) {
        PasswordStrengthTier.VERY_WEAK, PasswordStrengthTier.WEAK -> DangerRed
        PasswordStrengthTier.FAIR -> WarningAmber
        PasswordStrengthTier.STRONG, PasswordStrengthTier.VERY_STRONG -> SuccessGreen
    }
    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Text(report.tier.label, fontSize = 14.sp, fontWeight = FontWeight.SemiBold, color = tierColor)
            Text("${report.score} / 100", style = TabularPwdStyle.copy(fontSize = 14.sp, fontWeight = FontWeight.Bold), color = tierColor)
        }
        LinearProgressIndicator(
            progress = { (report.score / 100f).coerceIn(0f, 1f) },
            modifier = Modifier.fillMaxWidth().height(6.dp),
            color = tierColor,
            trackColor = SurfaceSubtle
        )
        Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            PwdStatCell("Length", "${report.length}", Modifier.weight(1f))
            PwdStatCell("Pool Entropy", "${"%.1f".format(report.poolEntropyBits)} b", Modifier.weight(1f))
            PwdStatCell("Shannon", "${"%.1f".format(report.shannonEntropyBits)} b", Modifier.weight(1f))
        }
        Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            PwdStatCell("Online Rate", report.crackTimeOnlineThrottled, Modifier.weight(1f))
            PwdStatCell("Fast GPU", report.crackTimeGpuFastHash, Modifier.weight(1f))
            PwdStatCell("Argon2id", report.crackTimeArgon2id, Modifier.weight(1f))
        }
        if (report.warnings.isNotEmpty()) {
            report.warnings.forEach { warn ->
                Text("- Warning: $warn", fontSize = 12.sp, color = DangerRed)
            }
        }
        if (report.suggestions.isNotEmpty()) {
            report.suggestions.forEach { sug ->
                Text("- Tip: $sug", fontSize = 12.sp, color = TextSecondary)
            }
        }
    }
}

@Composable
private fun EncryptedVaultTab(
    uiState: PasswordVaultUiState,
    onUnlock: () -> Unit,
    onReveal: (VaultCredentialMetadata) -> Unit,
    onCheckCredentialBreach: (VaultCredentialMetadata) -> Unit,
    onDeleteRequest: (VaultCredentialMetadata) -> Unit
) {
    val health = uiState.vaultHealth
    val fmt = remember { SimpleDateFormat("MMM d, HH:mm", Locale.getDefault()) }

    LazyColumn(
        modifier = Modifier.fillMaxSize(),
        contentPadding = PaddingValues(horizontal = 20.dp, vertical = 16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        item {
            ClinicalSurfaceCard {
                Text("Vault Health Overview", style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.SemiBold, color = TextPrimary)
                Spacer(Modifier.height(10.dp))
                Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    PwdStatCell("Saved", "${health.totalCredentials}", Modifier.weight(1f))
                    PwdStatCell("Strong", "${health.strongCount}", Modifier.weight(1f))
                    PwdStatCell("Weak", "${health.weakCount}", Modifier.weight(1f))
                    PwdStatCell("Reused", "${health.reusedCount}", Modifier.weight(1f))
                }
            }
        }

        if (!uiState.isUnlocked) {
            item {
                ClinicalSurfaceCard {
                    Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(14.dp)) {
                        Box(
                            modifier = Modifier.size(48.dp).background(SentinelPrimaryContainer, CircleShape),
                            contentAlignment = Alignment.Center
                        ) {
                            Icon(Icons.Outlined.Lock, contentDescription = null, tint = SentinelPrimary, modifier = Modifier.size(24.dp))
                        }
                        Column(modifier = Modifier.weight(1f)) {
                            Text("Credentials Encrypted at Rest", style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.SemiBold, color = TextPrimary)
                            Text(
                                text = "Stored with Android Keystore AES-256-GCM. Authenticate to view or edit stored logins.",
                                style = MaterialTheme.typography.bodySmall,
                                color = TextSecondary
                            )
                        }
                    }

                    uiState.authNotice?.let { notice ->
                        Spacer(Modifier.height(10.dp))
                        Surface(color = WarningContainer, shape = RoundedCornerShape(8.dp), modifier = Modifier.fillMaxWidth()) {
                            Text(notice, modifier = Modifier.padding(10.dp), fontSize = 12.sp, color = WarningAmber)
                        }
                    }

                    if (uiState.biometricStatus != DeviceAuthHelper.BiometricStatus.NOT_ENROLLED) {
                        Spacer(Modifier.height(14.dp))
                        Button(
                            onClick = onUnlock,
                            modifier = Modifier.fillMaxWidth().height(50.dp),
                            shape = RoundedCornerShape(12.dp),
                            colors = ButtonDefaults.buttonColors(containerColor = SentinelPrimary, contentColor = Color.White)
                        ) {
                            Icon(Icons.Filled.Fingerprint, contentDescription = null, modifier = Modifier.size(18.dp))
                            Spacer(Modifier.width(8.dp))
                            Text("Unlock Password Vault", fontWeight = FontWeight.SemiBold)
                        }
                    }
                }
            }
        } else if (uiState.credentials.isEmpty()) {
            item {
                ClinicalEmptyState(
                    icon = Icons.Outlined.VpnKey,
                    title = "Vault Is Empty",
                    description = "Tap + to encrypt and save an account credential locally with AES-256-GCM."
                )
            }
        } else {
            items(uiState.credentials, key = { it.id }) { cred ->
                ClinicalSurfaceCard {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Column(modifier = Modifier.weight(1f)) {
                            Text(cred.title, style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.SemiBold, color = TextPrimary)
                            if (!cred.url.isNullOrBlank()) {
                                Text(cred.url!!, fontSize = 11.sp, color = TextSecondary, maxLines = 1, overflow = TextOverflow.Ellipsis)
                            }
                            Text(
                                text = "Score ${cred.strengthScore}/100 • ${"%.0f".format(cred.entropyBits)} bits • Updated ${fmt.format(Date(cred.updatedAt))}",
                                style = TabularPwdStyle.copy(fontSize = 11.sp),
                                color = TextSecondary
                            )
                        }
                        if (cred.isReused || (cred.breachCount ?: 0) > 0) {
                            Surface(color = DangerContainer, shape = RoundedCornerShape(999.dp)) {
                                Text(
                                    text = if ((cred.breachCount ?: 0) > 0) "Breached (${cred.breachCount})" else "Reused",
                                    modifier = Modifier.padding(horizontal = 8.dp, vertical = 3.dp),
                                    fontSize = 11.sp,
                                    fontWeight = FontWeight.SemiBold,
                                    color = DangerRed
                                )
                            }
                        }
                    }

                    Spacer(Modifier.height(10.dp))

                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        OutlinedButton(
                            onClick = { onReveal(cred) },
                            modifier = Modifier.weight(1f),
                            shape = RoundedCornerShape(10.dp),
                            border = BorderStroke(1.dp, SentinelPrimary)
                        ) {
                            Text("Reveal", fontSize = 12.sp, color = SentinelPrimary, fontWeight = FontWeight.Medium)
                        }
                        OutlinedButton(
                            onClick = { onCheckCredentialBreach(cred) },
                            modifier = Modifier.weight(1f),
                            shape = RoundedCornerShape(10.dp),
                            border = BorderStroke(1.dp, BorderColor)
                        ) {
                            Text("HIBP Check", fontSize = 12.sp, color = TextPrimary, fontWeight = FontWeight.Medium)
                        }
                        IconButton(onClick = { onDeleteRequest(cred) }) {
                            Icon(Icons.Filled.DeleteOutline, contentDescription = "Delete", tint = DangerRed)
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun RevealedCredentialDialog(
    credential: DecryptedVaultCredential,
    onDismiss: () -> Unit,
    onCopyUsername: () -> Unit,
    onCopyPassword: () -> Unit,
    onEdit: () -> Unit
) {
    AlertDialog(
        onDismissRequest = onDismiss,
        containerColor = SurfaceLight,
        titleContentColor = TextPrimary,
        textContentColor = TextSecondary,
        title = { Text(credential.title, fontWeight = FontWeight.SemiBold) },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text("Username: ${credential.username}", fontSize = 13.sp, color = TextPrimary)
                Surface(color = SurfaceSubtle, shape = RoundedCornerShape(8.dp), modifier = Modifier.fillMaxWidth()) {
                    Text(
                        text = credential.password,
                        modifier = Modifier.padding(10.dp),
                        fontFamily = FontFamily.Monospace,
                        fontSize = 13.sp,
                        color = TextPrimary
                    )
                }
                if (!credential.url.isNullOrBlank()) {
                    Text("URL: ${credential.url}", fontSize = 12.sp, color = TextSecondary)
                }
                if (credential.notes.isNotBlank()) {
                    Text("Notes: ${credential.notes}", fontSize = 12.sp, color = TextSecondary)
                }
                Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    OutlinedButton(onClick = onCopyUsername, modifier = Modifier.weight(1f), border = BorderStroke(1.dp, BorderColor)) {
                        Text("Copy User", fontSize = 12.sp, color = TextPrimary)
                    }
                    OutlinedButton(onClick = onCopyPassword, modifier = Modifier.weight(1f), border = BorderStroke(1.dp, BorderColor)) {
                        Text("Copy Secret", fontSize = 12.sp, color = TextPrimary)
                    }
                }
            }
        },
        confirmButton = {
            Button(onClick = onEdit, colors = ButtonDefaults.buttonColors(containerColor = SentinelPrimary, contentColor = Color.White)) {
                Text("Edit")
            }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) { Text("Close") }
        }
    )
}

@Composable
private fun CredentialEditorDialog(
    existing: DecryptedVaultCredential?,
    initialPassword: String,
    onDismiss: () -> Unit,
    onGeneratePassword: () -> String,
    onSave: (title: String, username: String, password: String, url: String, notes: String) -> Unit
) {
    var title by remember { mutableStateOf(existing?.title ?: "") }
    var username by remember { mutableStateOf(existing?.username ?: "") }
    var password by remember { mutableStateOf(initialPassword) }
    var url by remember { mutableStateOf(existing?.url ?: "") }
    var notes by remember { mutableStateOf(existing?.notes ?: "") }
    val fieldTextStyle = com.deepfakeshield.core.ui.components.clinicalTextFieldStyle()
    val fieldColors = com.deepfakeshield.core.ui.components.clinicalOutlinedTextFieldColors()

    AlertDialog(
        onDismissRequest = onDismiss,
        containerColor = SurfaceLight,
        titleContentColor = TextPrimary,
        textContentColor = TextSecondary,
        title = { Text(if (existing == null) "Save Encrypted Credential" else "Update Credential", fontWeight = FontWeight.SemiBold) },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedTextField(value = title, onValueChange = { title = it }, label = { Text("Account / Site Name") }, singleLine = true, textStyle = fieldTextStyle, shape = RoundedCornerShape(12.dp), modifier = Modifier.fillMaxWidth(), colors = fieldColors)
                OutlinedTextField(value = username, onValueChange = { username = it }, label = { Text("Username or Email") }, singleLine = true, textStyle = fieldTextStyle, shape = RoundedCornerShape(12.dp), modifier = Modifier.fillMaxWidth(), colors = fieldColors)
                OutlinedTextField(
                    value = password,
                    onValueChange = { password = it },
                    label = { Text("Password") },
                    singleLine = true,
                    textStyle = fieldTextStyle,
                    shape = RoundedCornerShape(12.dp),
                    modifier = Modifier.fillMaxWidth(),
                    colors = fieldColors,
                    trailingIcon = {
                        IconButton(onClick = { password = onGeneratePassword() }) {
                            Icon(Icons.Filled.AutoFixHigh, contentDescription = "Generate", tint = SentinelPrimary)
                        }
                    }
                )
                OutlinedTextField(value = url, onValueChange = { url = it }, label = { Text("URL (optional)") }, singleLine = true, textStyle = fieldTextStyle, shape = RoundedCornerShape(12.dp), modifier = Modifier.fillMaxWidth(), colors = fieldColors)
                OutlinedTextField(value = notes, onValueChange = { notes = it }, label = { Text("Notes (optional)") }, maxLines = 3, textStyle = fieldTextStyle, shape = RoundedCornerShape(12.dp), modifier = Modifier.fillMaxWidth(), colors = fieldColors)
            }
        },
        confirmButton = {
            Button(
                onClick = { onSave(title, username, password, url, notes) },
                enabled = title.isNotBlank() && username.isNotBlank() && password.isNotBlank(),
                colors = ButtonDefaults.buttonColors(
                    containerColor = SentinelPrimary,
                    contentColor = Color.White,
                    disabledContainerColor = SurfaceSubtle,
                    disabledContentColor = TextTertiary
                )
            ) {
                Text("Encrypt & Save")
            }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) { Text("Cancel") }
        }
    )
}

@Composable
private fun ToggleBadge(label: String, selected: Boolean, onClick: () -> Unit) {
    FilterChip(
        selected = selected,
        onClick = onClick,
        label = { Text(label, fontSize = 11.sp) }
    )
}

@Composable
private fun PwdStatCell(label: String, value: String, modifier: Modifier = Modifier) {
    Surface(modifier = modifier, color = SurfaceSubtle, shape = RoundedCornerShape(10.dp)) {
        Column(modifier = Modifier.padding(10.dp)) {
            Text(label, fontSize = 10.sp, color = TextSecondary, maxLines = 1, overflow = TextOverflow.Ellipsis)
            Spacer(Modifier.height(2.dp))
            Text(
                text = value,
                style = TabularPwdStyle.copy(fontSize = 12.sp, fontWeight = FontWeight.SemiBold),
                color = TextPrimary,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis
            )
        }
    }
}
