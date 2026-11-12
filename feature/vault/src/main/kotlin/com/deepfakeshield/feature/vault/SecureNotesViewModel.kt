package com.deepfakeshield.feature.vault

import android.content.ClipData
import android.content.ClipDescription
import android.content.ClipboardManager
import android.content.Context
import android.os.Build
import android.os.PersistableBundle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.deepfakeshield.core.model.RiskSeverity
import com.deepfakeshield.core.security.DeviceAuthHelper
import com.deepfakeshield.core.security.VaultCipher
import com.deepfakeshield.data.repository.VaultRepository
import dagger.hilt.android.lifecycle.HiltViewModel
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import org.json.JSONObject
import javax.inject.Inject

data class DecryptedSecureNote(
    val id: Long,
    val title: String,
    val content: String,
    val category: String,
    val isPinned: Boolean,
    val charCount: Int,
    val createdAt: Long
)

data class EncryptedNoteMetadata(
    val id: Long,
    val title: String,
    val category: String,
    val isPinned: Boolean,
    val charCount: Int,
    val createdAt: Long
)

data class SecureNotesUiState(
    val isUnlocked: Boolean = false,
    val biometricStatus: DeviceAuthHelper.BiometricStatus = DeviceAuthHelper.BiometricStatus.NOT_AVAILABLE,
    val noteMetadata: List<EncryptedNoteMetadata> = emptyList(),
    val notes: List<DecryptedSecureNote> = emptyList(),
    val statusMessage: String? = null,
    val error: String? = null
)

@HiltViewModel
class SecureNotesViewModel @Inject constructor(
    private val vaultRepository: VaultRepository,
    private val vaultCipher: VaultCipher,
    private val deviceAuthHelper: DeviceAuthHelper,
    @ApplicationContext private val context: Context
) : ViewModel() {

    companion object {
        const val ENTRY_TYPE_SECURE_NOTE = "secure_note"
    }

    private val _uiState = MutableStateFlow(SecureNotesUiState())
    val uiState: StateFlow<SecureNotesUiState> = _uiState.asStateFlow()

    init {
        refreshBiometricStatus()
        viewModelScope.launch {
            vaultRepository.getEntriesByType(ENTRY_TYPE_SECURE_NOTE).collect { entries ->
                val metas = entries.map { e ->
                    val meta = runCatching { JSONObject(e.metadata ?: "{}") }.getOrNull()
                    EncryptedNoteMetadata(
                        id = e.id,
                        title = e.title,
                        category = e.tags ?: meta?.optString("category", "General") ?: "General",
                        isPinned = meta?.optBoolean("isPinned", false) ?: false,
                        charCount = meta?.optInt("charCount", 0) ?: 0,
                        createdAt = e.createdAt
                    )
                }
                val unlocked = _uiState.value.isUnlocked
                val decrypted = if (unlocked) decryptEntries(entries) else emptyList()
                _uiState.update { it.copy(noteMetadata = metas, notes = decrypted) }
            }
        }
    }

    fun refreshBiometricStatus() {
        _uiState.update { it.copy(biometricStatus = deviceAuthHelper.checkAvailability(context)) }
    }

    fun authenticate(hostContext: Context) {
        deviceAuthHelper.authenticate(
            context = hostContext,
            title = "Unlock Secure Notes",
            subtitle = "Authenticate to decrypt notes stored with AES-256-GCM"
        ) { outcome ->
            when (outcome) {
                DeviceAuthHelper.AuthOutcome.Authenticated -> {
                    viewModelScope.launch {
                        _uiState.update { it.copy(isUnlocked = true, error = null) }
                        vaultRepository.getEntriesByType(ENTRY_TYPE_SECURE_NOTE).collect { entries ->
                            _uiState.update { it.copy(notes = decryptEntries(entries)) }
                        }
                    }
                }
                DeviceAuthHelper.AuthOutcome.Cancelled -> {
                    _uiState.update { it.copy(statusMessage = "Authentication cancelled") }
                }
                DeviceAuthHelper.AuthOutcome.NotEnrolled -> {
                    _uiState.update {
                        it.copy(error = "Configure a screen lock / PIN / biometric in Android Settings to unlock Secure Notes.")
                    }
                }
                is DeviceAuthHelper.AuthOutcome.Failed -> {
                    _uiState.update { it.copy(error = "Authentication failed: ${outcome.reason}") }
                }
            }
        }
    }

    fun lockNotes() {
        _uiState.update { it.copy(isUnlocked = false, notes = emptyList(), statusMessage = "Secure Notes locked") }
    }

    fun saveNote(id: Long? = null, title: String, content: String, category: String, isPinned: Boolean = false) {
        if (!_uiState.value.isUnlocked) {
            _uiState.update { it.copy(error = "Unlock Secure Notes before creating or modifying entries.") }
            return
        }
        val cleanTitle = title.trim()
        if (cleanTitle.isEmpty()) {
            _uiState.update { it.copy(error = "Note title cannot be blank.") }
            return
        }
        viewModelScope.launch {
            try {
                val enc = vaultCipher.encryptString(content)
                val evidenceJson = JSONObject().apply {
                    put("cipherText", enc.cipherTextBase64)
                    put("iv", enc.ivBase64)
                }.toString()
                val metaJson = JSONObject().apply {
                    put("category", category)
                    put("isPinned", isPinned)
                    put("charCount", content.length)
                }.toString()

                if (id != null && id > 0L) {
                    val existing = vaultRepository.getEntryById(id)
                    if (existing != null) {
                        vaultRepository.updateEntry(
                            existing.copy(
                                title = cleanTitle,
                                description = "AES-256-GCM Encrypted Note ($category)",
                                evidenceData = evidenceJson,
                                metadata = metaJson,
                                tags = category
                            )
                        )
                        _uiState.update { it.copy(statusMessage = "Note updated & encrypted") }
                        return@launch
                    }
                }
                vaultRepository.addEntry(
                    alertId = null,
                    entryType = ENTRY_TYPE_SECURE_NOTE,
                    title = cleanTitle,
                    description = "AES-256-GCM Encrypted Note ($category)",
                    severity = RiskSeverity.LOW,
                    evidenceData = evidenceJson,
                    metadata = metaJson,
                    tags = category
                )
                _uiState.update { it.copy(statusMessage = "Note saved with AES-256-GCM encryption") }
            } catch (e: Exception) {
                _uiState.update { it.copy(error = "Failed to encrypt note: ${e.message}") }
            }
        }
    }

    fun togglePin(note: DecryptedSecureNote) {
        saveNote(
            id = note.id,
            title = note.title,
            content = note.content,
            category = note.category,
            isPinned = !note.isPinned
        )
    }

    fun deleteNote(id: Long) {
        viewModelScope.launch {
            val existing = vaultRepository.getEntryById(id) ?: return@launch
            vaultRepository.deleteEntry(existing)
            _uiState.update { it.copy(statusMessage = "Note deleted") }
        }
    }

    fun copyNoteToClipboard(note: DecryptedSecureNote) {
        val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as? ClipboardManager ?: return
        val clip = ClipData.newPlainText(note.title, note.content).apply {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                description.extras = PersistableBundle().apply {
                    putBoolean(ClipDescription.EXTRA_IS_SENSITIVE, true)
                }
            }
        }
        clipboard.setPrimaryClip(clip)
        _uiState.update { it.copy(statusMessage = "Copied note text (marked sensitive)") }
    }

    fun clearMessage() {
        _uiState.update { it.copy(statusMessage = null, error = null) }
    }

    private fun decryptEntries(entries: List<com.deepfakeshield.data.entity.VaultEntryEntity>): List<DecryptedSecureNote> {
        return entries.mapNotNull { entry ->
            try {
                val meta = runCatching { JSONObject(entry.metadata ?: "{}") }.getOrNull()
                val ev = JSONObject(entry.evidenceData)
                val cipherText = ev.getString("cipherText")
                val iv = ev.getString("iv")
                val plain = vaultCipher.decryptString(cipherText, iv)
                DecryptedSecureNote(
                    id = entry.id,
                    title = entry.title,
                    content = plain,
                    category = entry.tags ?: meta?.optString("category", "General") ?: "General",
                    isPinned = meta?.optBoolean("isPinned", false) ?: false,
                    charCount = plain.length,
                    createdAt = entry.createdAt
                )
            } catch (_: Exception) {
                null
            }
        }
    }
}

