package com.deepfakeshield.feature.vault

import android.content.Context
import android.content.Intent
import android.net.Uri
import android.provider.OpenableColumns
import androidx.core.content.FileProvider
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.deepfakeshield.core.model.RiskSeverity
import com.deepfakeshield.core.security.DeviceAuthHelper
import com.deepfakeshield.core.security.VaultCipher
import com.deepfakeshield.data.entity.VaultEntryEntity
import com.deepfakeshield.data.repository.VaultRepository
import dagger.hilt.android.lifecycle.HiltViewModel
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONObject
import java.io.File
import java.security.MessageDigest
import java.util.Base64
import java.util.UUID
import javax.inject.Inject

data class EncryptedVaultFileItem(
    val id: Long,
    val displayName: String,
    val mimeType: String,
    val sizeBytes: Long,
    val sha256: String,
    val encryptedFilePath: String,
    val addedAt: Long
)

data class SecureFileVaultUiState(
    val isUnlocked: Boolean = false,
    val biometricStatus: DeviceAuthHelper.BiometricStatus = DeviceAuthHelper.BiometricStatus.NOT_AVAILABLE,
    val files: List<EncryptedVaultFileItem> = emptyList(),
    val isProcessing: Boolean = false,
    val statusMessage: String? = null,
    val error: String? = null
)

@HiltViewModel
class SecureFileVaultViewModel @Inject constructor(
    private val vaultRepository: VaultRepository,
    private val vaultCipher: VaultCipher,
    private val deviceAuthHelper: DeviceAuthHelper,
    @ApplicationContext private val context: Context
) : ViewModel() {

    companion object {
        const val ENTRY_TYPE_ENCRYPTED_FILE = "encrypted_file"
        private const val MAX_FILE_BYTES = 20L * 1024L * 1024L // 20 MB bound
        private const val CHUNK_SIZE = 256 * 1024
    }

    private val _uiState = MutableStateFlow(SecureFileVaultUiState())
    val uiState: StateFlow<SecureFileVaultUiState> = _uiState.asStateFlow()

    init {
        refreshBiometricStatus()
        viewModelScope.launch {
            vaultRepository.getEntriesByType(ENTRY_TYPE_ENCRYPTED_FILE).collect { entries ->
                _uiState.update { it.copy(files = entries.mapNotNull(::parseEntry)) }
            }
        }
    }

    fun refreshBiometricStatus() {
        _uiState.update { it.copy(biometricStatus = deviceAuthHelper.checkAvailability(context)) }
    }

    fun authenticate(hostContext: Context) {
        deviceAuthHelper.authenticate(
            context = hostContext,
            title = "Unlock Secure File Vault",
            subtitle = "Authenticate to import, decrypt, or export vault files"
        ) { outcome ->
            when (outcome) {
                DeviceAuthHelper.AuthOutcome.Authenticated -> {
                    _uiState.update { it.copy(isUnlocked = true, error = null) }
                }
                DeviceAuthHelper.AuthOutcome.Cancelled -> {
                    _uiState.update { it.copy(statusMessage = "Authentication cancelled") }
                }
                DeviceAuthHelper.AuthOutcome.NotEnrolled -> {
                    _uiState.update {
                        it.copy(error = "Enroll a screen lock / PIN / biometric in Android Settings to unlock encrypted files.")
                    }
                }
                is DeviceAuthHelper.AuthOutcome.Failed -> {
                    _uiState.update { it.copy(error = "Authentication failed: ${outcome.reason}") }
                }
            }
        }
    }

    fun lockVault() {
        clearDecryptedCache()
        _uiState.update { it.copy(isUnlocked = false, statusMessage = "File vault locked") }
    }

    fun importAndEncryptFile(uri: Uri) {
        if (!_uiState.value.isUnlocked) {
            _uiState.update { it.copy(error = "Unlock the file vault first.") }
            return
        }
        viewModelScope.launch {
            _uiState.update { it.copy(isProcessing = true, error = null) }
            try {
                val (displayName, sizeBytes, mimeType) = resolveFileMeta(uri)
                if (sizeBytes > MAX_FILE_BYTES) {
                    _uiState.update {
                        it.copy(isProcessing = false, error = "File exceeds 20 MB single-file encryption limit.")
                    }
                    return@launch
                }

                val encryptedRecord = withContext(Dispatchers.IO) {
                    val vaultDir = File(context.filesDir, "encrypted_vault").apply { mkdirs() }
                    val outFile = File(vaultDir, "${UUID.randomUUID()}.enc")
                    val digest = MessageDigest.getInstance("SHA-256")
                    var actualBytes = 0L

                    val input = context.contentResolver.openInputStream(uri)
                        ?: throw IllegalStateException("Could not open selected document.")
                    try {
                        input.use { stream ->
                            outFile.bufferedWriter(Charsets.UTF_8).use { writer ->
                                val buf = ByteArray(CHUNK_SIZE)
                                while (true) {
                                    val read = stream.read(buf)
                                    if (read <= 0) break
                                    actualBytes += read
                                    if (actualBytes > MAX_FILE_BYTES) {
                                        throw IllegalStateException("File exceeds 20 MB limit.")
                                    }
                                    val slice = if (read == buf.size) buf else buf.copyOf(read)
                                    digest.update(slice)
                                    val b64Chunk = Base64.getEncoder().encodeToString(slice)
                                    val enc = vaultCipher.encryptString(b64Chunk)
                                    writer.write("${enc.ivBase64}|${enc.cipherTextBase64}")
                                    writer.newLine()
                                }
                            }
                        }
                    } catch (e: Exception) {
                        runCatching { outFile.delete() }
                        throw e
                    }

                    if (actualBytes == 0L) {
                        runCatching { outFile.delete() }
                        throw IllegalStateException("Cannot encrypt empty 0-byte file.")
                    }

                    val sha256 = digest.digest().joinToString("") { "%02x".format(it) }
                    Triple(outFile.absolutePath, actualBytes, sha256)
                }

                val evidenceJson = JSONObject().apply {
                    put("encryptedPath", encryptedRecord.first)
                    put("sha256", encryptedRecord.third)
                }.toString()
                val metaJson = JSONObject().apply {
                    put("mimeType", mimeType)
                    put("sizeBytes", encryptedRecord.second)
                }.toString()

                vaultRepository.addEntry(
                    alertId = null,
                    entryType = ENTRY_TYPE_ENCRYPTED_FILE,
                    title = displayName,
                    description = "AES-256-GCM Encrypted File ($mimeType)",
                    severity = RiskSeverity.LOW,
                    evidenceData = evidenceJson,
                    metadata = metaJson,
                    tags = mimeType
                )

                _uiState.update {
                    it.copy(
                        isProcessing = false,
                        statusMessage = "\"$displayName\" encrypted & stored in private vault"
                    )
                }
            } catch (e: Exception) {
                _uiState.update {
                    it.copy(isProcessing = false, error = "Encryption failed: ${e.message ?: "Unable to read file"}")
                }
            }
        }
    }

    fun openDecryptedFile(item: EncryptedVaultFileItem) {
        if (!_uiState.value.isUnlocked) {
            _uiState.update { it.copy(error = "Unlock the file vault to decrypt this document.") }
            return
        }
        viewModelScope.launch {
            _uiState.update { it.copy(isProcessing = true, error = null) }
            try {
                val encFile = File(item.encryptedFilePath)
                if (!encFile.exists()) {
                    _uiState.update { it.copy(isProcessing = false, error = "Encrypted file missing on disk.") }
                    return@launch
                }

                val decryptedTemp = withContext(Dispatchers.IO) {
                    val previewDir = File(context.cacheDir, "vault_preview").apply { mkdirs() }
                    val safeName = item.displayName.replace(Regex("[^A-Za-z0-9._-]"), "_")
                    val out = File(previewDir, safeName)
                    val encoder = Base64.getDecoder()
                    out.outputStream().use { output ->
                        encFile.bufferedReader(Charsets.UTF_8).useLines { lines ->
                            for (line in lines) {
                                if (line.isBlank()) continue
                                val sep = line.indexOf('|')
                                if (sep <= 0) throw IllegalStateException("Corrupt encrypted chunk")
                                val iv = line.substring(0, sep)
                                val cipher = line.substring(sep + 1)
                                val chunkB64 = vaultCipher.decryptString(cipher, iv)
                                output.write(encoder.decode(chunkB64))
                            }
                        }
                    }
                    out
                }

                val providerUri = FileProvider.getUriForFile(
                    context,
                    "${context.packageName}.fileprovider",
                    decryptedTemp
                )
                val viewIntent = Intent(Intent.ACTION_VIEW).apply {
                    setDataAndType(providerUri, item.mimeType)
                    addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
                    addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                }
                context.startActivity(Intent.createChooser(viewIntent, "Open Decrypted Copy").apply {
                    addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                })
                _uiState.update { it.copy(isProcessing = false, statusMessage = "Decrypted temporary copy for viewing") }
            } catch (e: Exception) {
                _uiState.update { it.copy(isProcessing = false, error = "Decryption/open failed: ${e.message}") }
            }
        }
    }

    fun deleteEncryptedFile(item: EncryptedVaultFileItem) {
        viewModelScope.launch {
            withContext(Dispatchers.IO) {
                runCatching { File(item.encryptedFilePath).delete() }
            }
            vaultRepository.getEntryById(item.id)?.let { vaultRepository.deleteEntry(it) }
            _uiState.update { it.copy(statusMessage = "Deleted \"${item.displayName}\" and its ciphertext") }
        }
    }

    fun clearMessage() {
        _uiState.update { it.copy(statusMessage = null, error = null) }
    }

    override fun onCleared() {
        clearDecryptedCache()
        super.onCleared()
    }

    private fun clearDecryptedCache() {
        runCatching {
            File(context.cacheDir, "vault_preview").deleteRecursively()
        }
    }

    private fun parseEntry(entry: VaultEntryEntity): EncryptedVaultFileItem? {
        return try {
            val ev = JSONObject(entry.evidenceData)
            val meta = JSONObject(entry.metadata ?: "{}")
            EncryptedVaultFileItem(
                id = entry.id,
                displayName = entry.title,
                mimeType = meta.optString("mimeType", entry.tags ?: "*/*"),
                sizeBytes = meta.optLong("sizeBytes", 0L),
                sha256 = ev.optString("sha256", ""),
                encryptedFilePath = ev.getString("encryptedPath"),
                addedAt = entry.createdAt
            )
        } catch (_: Exception) {
            null
        }
    }

    private fun resolveFileMeta(uri: Uri): Triple<String, Long, String> {
        var name = uri.lastPathSegment ?: "document.bin"
        var size = 0L
        val mime = context.contentResolver.getType(uri) ?: "application/octet-stream"
        runCatching {
            context.contentResolver.query(uri, null, null, null, null)?.use { c ->
                if (c.moveToFirst()) {
                    val nameIdx = c.getColumnIndex(OpenableColumns.DISPLAY_NAME)
                    val sizeIdx = c.getColumnIndex(OpenableColumns.SIZE)
                    if (nameIdx >= 0) name = c.getString(nameIdx) ?: name
                    if (sizeIdx >= 0 && !c.isNull(sizeIdx)) size = c.getLong(sizeIdx)
                }
            }
        }
        return Triple(name, size, mime)
    }
}

