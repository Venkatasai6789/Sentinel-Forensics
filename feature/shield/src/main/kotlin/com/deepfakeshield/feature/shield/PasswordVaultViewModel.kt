package com.deepfakeshield.feature.shield

import android.content.ClipData
import android.content.ClipDescription
import android.content.ClipboardManager
import android.content.Context
import android.os.Build
import android.os.PersistableBundle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.deepfakeshield.core.model.AnalysisStatus
import com.deepfakeshield.core.model.FindingSeverity
import com.deepfakeshield.core.model.SecurityAnalysisResult
import com.deepfakeshield.core.model.SecurityFinding
import com.deepfakeshield.core.model.SecurityModule
import com.deepfakeshield.core.model.SecurityVerdict
import com.deepfakeshield.core.security.DeviceAuthHelper
import com.deepfakeshield.core.security.GenerationMode
import com.deepfakeshield.core.security.PasswordAuditReport
import com.deepfakeshield.core.security.PasswordAuditor
import com.deepfakeshield.core.security.PasswordGenerationConfig
import com.deepfakeshield.core.security.PasswordStrengthTier
import com.deepfakeshield.data.repository.DecryptedVaultCredential
import com.deepfakeshield.data.repository.PasswordVaultRepository
import com.deepfakeshield.data.repository.ScanHistoryRepository
import com.deepfakeshield.data.repository.VaultCredentialMetadata
import com.deepfakeshield.data.repository.VaultHealthSummary
import dagger.hilt.android.lifecycle.HiltViewModel
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.net.HttpURLConnection
import java.net.URL
import java.security.MessageDigest
import java.util.UUID
import javax.inject.Inject

sealed class BreachCheckState {
    data object Idle : BreachCheckState()
    data object Checking : BreachCheckState()
    data class Compromised(val occurrences: Int) : BreachCheckState()
    data object Clean : BreachCheckState()
    data class Failed(val reason: String) : BreachCheckState()
}

data class PasswordVaultUiState(
    val passwordInput: String = "",
    val auditReport: PasswordAuditReport? = null,
    val genConfig: PasswordGenerationConfig = PasswordGenerationConfig(),
    val breachState: BreachCheckState = BreachCheckState.Idle,
    val biometricStatus: DeviceAuthHelper.BiometricStatus = DeviceAuthHelper.BiometricStatus.NOT_AVAILABLE,
    val isUnlocked: Boolean = false,
    val authNotice: String? = null,
    val vaultHealth: VaultHealthSummary = VaultHealthSummary(),
    val credentials: List<VaultCredentialMetadata> = emptyList(),
    val revealedCredential: DecryptedVaultCredential? = null,
    val recentHistory: List<SecurityAnalysisResult> = emptyList(),
    val statusMessage: String? = null,
    val error: String? = null
)

@HiltViewModel
class PasswordVaultViewModel @Inject constructor(
    private val passwordVaultRepository: PasswordVaultRepository,
    private val scanHistoryRepository: ScanHistoryRepository,
    private val deviceAuthHelper: DeviceAuthHelper,
    @ApplicationContext private val context: Context
) : ViewModel() {

    private val _uiState = MutableStateFlow(PasswordVaultUiState())
    val uiState: StateFlow<PasswordVaultUiState> = _uiState.asStateFlow()

    private var breachJob: Job? = null

    init {
        refreshBiometricStatus()
        viewModelScope.launch {
            passwordVaultRepository.observeCredentialMetadata().collect { list ->
                _uiState.update { it.copy(credentials = list) }
            }
        }
        viewModelScope.launch {
            passwordVaultRepository.observeVaultHealth().collect { health ->
                _uiState.update { it.copy(vaultHealth = health) }
            }
        }
        viewModelScope.launch {
            scanHistoryRepository.observeHistory(SecurityModule.PASSWORD_VAULT, 12).collect { history ->
                _uiState.update { it.copy(recentHistory = history) }
            }
        }
    }

    fun refreshBiometricStatus() {
        val status = deviceAuthHelper.checkAvailability(context)
        _uiState.update { it.copy(biometricStatus = status) }
    }

    fun onPasswordChanged(newPassword: String) {
        val report = if (newPassword.isNotEmpty()) PasswordAuditor.audit(newPassword) else null
        _uiState.update {
            it.copy(
                passwordInput = newPassword,
                auditReport = report,
                breachState = BreachCheckState.Idle,
                error = null
            )
        }
    }

    fun updateGenConfig(transform: (PasswordGenerationConfig) -> PasswordGenerationConfig) {
        _uiState.update { it.copy(genConfig = transform(it.genConfig)) }
    }

    fun generatePassword(mode: GenerationMode = _uiState.value.genConfig.mode): String {
        val cfg = _uiState.value.genConfig.copy(mode = mode)
        val generated = PasswordAuditor.generate(cfg)
        val report = PasswordAuditor.audit(generated)
        _uiState.update {
            it.copy(
                genConfig = cfg,
                passwordInput = generated,
                auditReport = report,
                breachState = BreachCheckState.Idle,
                statusMessage = if (mode == GenerationMode.DICEWARE_PASSPHRASE) {
                    "Generated ${cfg.wordCount}-word CSPRNG Diceware passphrase"
                } else {
                    "Generated ${generated.length}-char CSPRNG password"
                }
            )
        }
        return generated
    }

    fun auditAndRecordCurrentPassword(label: String = "Ad-hoc Password Check") {
        val pwd = _uiState.value.passwordInput
        if (pwd.isEmpty()) {
            _uiState.update { it.copy(error = "Enter or generate a password first.") }
            return
        }
        viewModelScope.launch {
            val report = PasswordAuditor.audit(pwd)
            val result = buildAuditAnalysisResult(
                label = label.ifBlank { "Password Audit" },
                report = report,
                breachCount = null
            )
            scanHistoryRepository.saveResult(result)
            _uiState.update { it.copy(statusMessage = "Audit recorded (${report.score}/100 — ${report.tier.label})") }
        }
    }

    fun checkPasswordBreach(
        passwordOverride: String? = null,
        credentialId: Long? = null,
        baseUrl: String = "https://api.pwnedpasswords.com/range/"
    ) {
        val target = passwordOverride ?: _uiState.value.passwordInput
        if (target.isEmpty()) {
            _uiState.update { it.copy(breachState = BreachCheckState.Failed("Password cannot be empty")) }
            return
        }
        breachJob?.cancel()
        breachJob = viewModelScope.launch {
            _uiState.update { it.copy(breachState = BreachCheckState.Checking, error = null) }
            try {
                val count = queryHibpRange(target, baseUrl)
                val state = if (count > 0) BreachCheckState.Compromised(count) else BreachCheckState.Clean
                _uiState.update { it.copy(breachState = state) }

                if (credentialId != null) {
                    passwordVaultRepository.recordBreachCount(credentialId, count)
                }

                val report = PasswordAuditor.audit(target)
                val result = buildAuditAnalysisResult(
                    label = if (credentialId != null) "Vault Credential #$credentialId (k-Anonymity)" else "k-Anonymity Breach Check",
                    report = report,
                    breachCount = count
                )
                scanHistoryRepository.saveResult(result)
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                val report = PasswordAuditor.audit(target)
                val failedResult = buildAuditAnalysisResult(
                    label = "k-Anonymity Breach Check",
                    report = report,
                    breachCount = null,
                    networkError = e.message ?: "Network error"
                )
                scanHistoryRepository.saveResult(failedResult)
                _uiState.update {
                    it.copy(
                        breachState = BreachCheckState.Failed(
                            "Breach lookup unavailable (${e.message ?: "network/TLS error"}). Never assumed safe."
                        )
                    )
                }
            }
        }
    }

    fun authenticateVault(hostContext: Context) {
        deviceAuthHelper.authenticate(
            context = hostContext,
            title = "Unlock Sentinel Password Vault",
            subtitle = "Authenticate to decrypt stored credentials"
        ) { outcome ->
            when (outcome) {
                DeviceAuthHelper.AuthOutcome.Authenticated -> {
                    _uiState.update {
                        it.copy(
                            isUnlocked = true,
                            authNotice = null,
                            error = null,
                            biometricStatus = DeviceAuthHelper.BiometricStatus.AVAILABLE
                        )
                    }
                }
                DeviceAuthHelper.AuthOutcome.Cancelled -> {
                    _uiState.update {
                        it.copy(authNotice = "Authentication cancelled. Vault remains locked.")
                    }
                }
                DeviceAuthHelper.AuthOutcome.NotEnrolled -> {
                    _uiState.update {
                        it.copy(
                            isUnlocked = false,
                            biometricStatus = DeviceAuthHelper.BiometricStatus.NOT_ENROLLED,
                            authNotice = "No screen lock, PIN, or biometric is enrolled in Android Settings. Configure a device lock to unlock encrypted credentials."
                        )
                    }
                }
                is DeviceAuthHelper.AuthOutcome.Failed -> {
                    _uiState.update {
                        it.copy(
                            isUnlocked = false,
                            error = "Authentication failed: ${outcome.reason}"
                        )
                    }
                }
            }
        }
    }

    fun lockVault() {
        _uiState.update {
            it.copy(
                isUnlocked = false,
                revealedCredential = null,
                statusMessage = "Vault locked"
            )
        }
    }

    fun saveCredential(
        id: Long = 0L,
        title: String,
        username: String,
        password: String,
        url: String?,
        notes: String
    ) {
        if (!_uiState.value.isUnlocked) {
            _uiState.update { it.copy(error = "Unlock the vault before saving or viewing credentials.") }
            return
        }
        viewModelScope.launch {
            try {
                val savedId = passwordVaultRepository.saveCredential(
                    id = id,
                    title = title,
                    username = username,
                    password = password,
                    url = url,
                    notes = notes
                )
                val report = PasswordAuditor.audit(password)
                scanHistoryRepository.saveResult(
                    buildAuditAnalysisResult(
                        label = "Saved Credential: ${title.trim().take(32)}",
                        report = report,
                        breachCount = null
                    )
                )
                _uiState.update {
                    it.copy(
                        statusMessage = "Credential saved & encrypted with AES-256-GCM (#$savedId)",
                        error = null
                    )
                }
            } catch (e: Exception) {
                _uiState.update { it.copy(error = e.message ?: "Failed to encrypt & save credential.") }
            }
        }
    }

    fun revealCredential(id: Long) {
        if (!_uiState.value.isUnlocked) {
            _uiState.update { it.copy(error = "Vault is locked. Authenticate to decrypt credential.") }
            return
        }
        viewModelScope.launch {
            try {
                val dec = passwordVaultRepository.decryptCredential(id)
                _uiState.update { it.copy(revealedCredential = dec, error = null) }
            } catch (e: Exception) {
                _uiState.update { it.copy(error = "Decryption failed: ${e.message}") }
            }
        }
    }

    fun clearRevealedCredential() {
        _uiState.update { it.copy(revealedCredential = null) }
    }

    fun deleteCredential(id: Long) {
        viewModelScope.launch {
            passwordVaultRepository.deleteCredential(id)
            if (_uiState.value.revealedCredential?.id == id) {
                _uiState.update { it.copy(revealedCredential = null) }
            }
            _uiState.update { it.copy(statusMessage = "Credential deleted from vault") }
        }
    }

    fun checkStoredCredentialBreach(id: Long, baseUrl: String = "https://api.pwnedpasswords.com/range/") {
        if (!_uiState.value.isUnlocked) {
            _uiState.update { it.copy(error = "Unlock the vault to inspect stored credential breach status.") }
            return
        }
        viewModelScope.launch {
            val dec = passwordVaultRepository.decryptCredential(id) ?: return@launch
            checkPasswordBreach(passwordOverride = dec.password, credentialId = id, baseUrl = baseUrl)
        }
    }

    fun copySensitiveSecret(label: String, secret: String) {
        val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as? ClipboardManager ?: return
        val clip = ClipData.newPlainText(label, secret).apply {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                description.extras = PersistableBundle().apply {
                    putBoolean(ClipDescription.EXTRA_IS_SENSITIVE, true)
                }
            }
        }
        clipboard.setPrimaryClip(clip)
        _uiState.update { it.copy(statusMessage = "Copied $label to clipboard (marked sensitive)") }
    }

    fun clearNotices() {
        _uiState.update { it.copy(statusMessage = null, error = null, authNotice = null) }
    }

    internal suspend fun queryHibpRange(password: String, baseUrl: String): Int = withContext(Dispatchers.IO) {
        val md = MessageDigest.getInstance("SHA-1")
        val sha1Hex = md.digest(password.toByteArray(Charsets.UTF_8)).joinToString("") { "%02X".format(it) }
        val prefix = sha1Hex.take(5)
        val suffix = sha1Hex.substring(5)

        val normalizedBase = if (baseUrl.endsWith("/")) baseUrl else "$baseUrl/"
        val conn = (URL("$normalizedBase$prefix").openConnection() as HttpURLConnection).apply {
            connectTimeout = 6000
            readTimeout = 6000
            requestMethod = "GET"
            setRequestProperty("User-Agent", "SentinelForensics-Android")
            setRequestProperty("Add-Padding", "true")
        }
        try {
            val code = conn.responseCode
            if (code !in 200..299) {
                throw IllegalStateException("HIBP HTTP $code")
            }
            val body = conn.inputStream.bufferedReader().use { it.readText() }
            for (line in body.lineSequence()) {
                val sep = line.indexOf(':')
                if (sep <= 0) continue
                val lineSuffix = line.substring(0, sep).trim()
                if (lineSuffix.equals(suffix, ignoreCase = true)) {
                    return@withContext line.substring(sep + 1).trim().toIntOrNull() ?: 1
                }
            }
            0
        } finally {
            conn.disconnect()
        }
    }

    private fun buildAuditAnalysisResult(
        label: String,
        report: PasswordAuditReport,
        breachCount: Int?,
        networkError: String? = null
    ): SecurityAnalysisResult {
        val status = if (networkError != null) AnalysisStatus.PARTIAL else AnalysisStatus.COMPLETED
        val verdict = when {
            breachCount != null && breachCount > 0 -> SecurityVerdict.MALICIOUS
            report.tier == PasswordStrengthTier.VERY_WEAK || report.tier == PasswordStrengthTier.WEAK -> SecurityVerdict.HIGH_RISK
            report.tier == PasswordStrengthTier.FAIR -> SecurityVerdict.SUSPICIOUS
            else -> SecurityVerdict.SAFE
        }
        val effectiveRisk = when {
            breachCount != null && breachCount > 0 -> 95
            else -> (100 - report.score).coerceIn(0, 100)
        }
        val findings = mutableListOf<SecurityFinding>()
        if (breachCount != null && breachCount > 0) {
            findings += SecurityFinding(
                title = "Password Found in Known Breach Corpus ($breachCount occurrences)",
                description = "SHA-1 k-Anonymity prefix lookup matched public breach records.",
                severity = FindingSeverity.CRITICAL,
                evidenceSource = "HIBP Pwned Passwords v3 (5-char SHA-1 prefix)",
                detectionMethod = "k-Anonymity Prefix Lookup",
                inputLocation = label,
                explanation = "No plaintext password or full hash leaves the device; only the first 5 hex characters of SHA-1 are queried.",
                recommendedAction = "Replace immediately using the CSPRNG or Diceware generator."
            )
        }
        report.warnings.forEach { warn ->
            findings += SecurityFinding(
                title = "Password Weakness Indicator",
                description = warn,
                severity = if (report.score < 45) FindingSeverity.HIGH else FindingSeverity.MEDIUM,
                evidenceSource = "PasswordAuditor",
                detectionMethod = "Entropy & Structural Audit",
                inputLocation = label,
                explanation = "Shannon entropy: ${"%.1f".format(report.shannonEntropyBits)} bits; pool entropy: ${"%.1f".format(report.poolEntropyBits)} bits.",
                recommendedAction = report.suggestions.firstOrNull() ?: "Use at least 14+ random characters or a 5-word passphrase."
            )
        }
        if (networkError != null) {
            findings += SecurityFinding(
                title = "Online Breach Check Incomplete",
                description = networkError,
                severity = FindingSeverity.INFO,
                evidenceSource = "HIBP Network Lookup",
                detectionMethod = "HTTPS Range Query",
                inputLocation = null,
                explanation = "Local entropy audit completed; online breach status remains unverified.",
                recommendedAction = "Retry HIBP lookup when internet access is available."
            )
        }

        val methods = buildList {
            add("Deterministic PasswordAuditor (Shannon + Pool Entropy + Dictionary/Pattern Checks)")
            if (breachCount != null) add("HIBP k-Anonymity 5-Char SHA-1 Prefix Lookup")
        }
        val limitations = buildList {
            add("Plaintext passwords are NEVER persisted in scan history or logs.")
            if (breachCount == null) add("Online breach exposure unverified until k-Anonymity check runs successfully.")
        }

        return SecurityAnalysisResult(
            analysisId = UUID.randomUUID().toString(),
            module = SecurityModule.PASSWORD_VAULT,
            inputName = label,
            inputType = "credential/metadata-only",
            status = status,
            verdict = verdict,
            riskScore = effectiveRisk,
            confidence = null,
            findings = findings,
            analysisMethods = methods,
            limitations = limitations,
            processingDurationMs = 1L,
            errorMessage = networkError,
            metadata = buildMap {
                put("strengthScore", report.score.toString())
                put("strengthTier", report.tier.label)
                put("length", report.length.toString())
                put("shannonBits", "%.1f".format(report.shannonEntropyBits))
                if (breachCount != null) put("breachCount", breachCount.toString())
            }
        )
    }
}
