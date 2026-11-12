package com.deepfakeshield.data.repository

import com.deepfakeshield.core.security.PasswordAuditor
import com.deepfakeshield.core.security.VaultCipher
import com.deepfakeshield.data.dao.VaultCredentialDao
import com.deepfakeshield.data.entity.VaultCredentialEntity
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.map
import javax.inject.Inject
import javax.inject.Singleton

data class VaultCredentialMetadata(
    val id: Long,
    val title: String,
    val url: String?,
    val strengthScore: Int,
    val entropyBits: Double,
    val breachCount: Int?,
    val lastBreachCheckedAt: Long?,
    val isReused: Boolean,
    val createdAt: Long,
    val updatedAt: Long
)

data class DecryptedVaultCredential(
    val id: Long,
    val title: String,
    val url: String?,
    val username: String,
    val password: String,
    val notes: String,
    val strengthScore: Int,
    val entropyBits: Double,
    val breachCount: Int?,
    val lastBreachCheckedAt: Long?,
    val isReused: Boolean,
    val createdAt: Long,
    val updatedAt: Long
)

data class VaultHealthSummary(
    val totalCredentials: Int = 0,
    val weakCount: Int = 0,
    val reusedCount: Int = 0,
    val breachedCount: Int = 0,
    val strongCount: Int = 0
)

/**
 * Repository managing AES-256-GCM encrypted credentials in Room.
 * Decrypts fields strictly on explicit caller request; metadata flows never materialize secrets.
 */
@Singleton
class PasswordVaultRepository @Inject constructor(
    private val dao: VaultCredentialDao,
    private val cipher: VaultCipher
) {

    fun observeCredentialMetadata(): Flow<List<VaultCredentialMetadata>> =
        dao.getAllCredentials().map { rows ->
            val digestCounts = rows.groupingBy { it.reuseDigest }.eachCount()
            rows.map { row ->
                VaultCredentialMetadata(
                    id = row.id,
                    title = row.title,
                    url = row.url,
                    strengthScore = row.strengthScore,
                    entropyBits = row.entropyBits,
                    breachCount = row.breachCount,
                    lastBreachCheckedAt = row.lastBreachCheckedAt,
                    isReused = (digestCounts[row.reuseDigest] ?: 0) > 1,
                    createdAt = row.createdAt,
                    updatedAt = row.updatedAt
                )
            }
        }

    fun observeVaultHealth(): Flow<VaultHealthSummary> =
        observeCredentialMetadata().map { items ->
            VaultHealthSummary(
                totalCredentials = items.size,
                weakCount = items.count { it.strengthScore < 55 },
                reusedCount = items.count { it.isReused },
                breachedCount = items.count { (it.breachCount ?: 0) > 0 },
                strongCount = items.count { it.strengthScore >= 75 && !it.isReused && (it.breachCount ?: 0) == 0 }
            )
        }

    suspend fun saveCredential(
        id: Long = 0L,
        title: String,
        username: String,
        password: String,
        url: String? = null,
        notes: String = "",
        breachCount: Int? = null
    ): Long {
        require(title.isNotBlank()) { "Account or label title cannot be blank." }
        require(password.isNotEmpty()) { "Password cannot be empty." }

        val now = System.currentTimeMillis()
        val audit = PasswordAuditor.audit(password)
        val encUsername = cipher.encryptString(username)
        val encPassword = cipher.encryptString(password)
        val encNotes = if (notes.isNotBlank()) cipher.encryptString(notes) else null
        val existing = if (id > 0L) dao.getCredentialById(id) else null

        val entity = VaultCredentialEntity(
            id = if (id > 0L) id else 0L,
            title = title.trim(),
            url = url?.trim()?.takeIf { it.isNotEmpty() },
            usernameEncrypted = encUsername.cipherTextBase64,
            usernameIv = encUsername.ivBase64,
            passwordEncrypted = encPassword.cipherTextBase64,
            passwordIv = encPassword.ivBase64,
            notesEncrypted = encNotes?.cipherTextBase64,
            notesIv = encNotes?.ivBase64,
            reuseDigest = cipher.computeReuseDigest(password),
            strengthScore = audit.score,
            entropyBits = audit.shannonEntropyBits,
            breachCount = breachCount ?: existing?.breachCount,
            lastBreachCheckedAt = if (breachCount != null) now else existing?.lastBreachCheckedAt,
            createdAt = existing?.createdAt ?: now,
            updatedAt = now
        )
        return if (id > 0L && existing != null) {
            dao.update(entity)
            id
        } else {
            dao.insert(entity)
        }
    }

    suspend fun decryptCredential(id: Long): DecryptedVaultCredential? {
        val row = dao.getCredentialById(id) ?: return null
        val username = cipher.decryptString(row.usernameEncrypted, row.usernameIv)
        val password = cipher.decryptString(row.passwordEncrypted, row.passwordIv)
        val notes = if (!row.notesEncrypted.isNullOrBlank() && !row.notesIv.isNullOrBlank()) {
            cipher.decryptString(row.notesEncrypted, row.notesIv)
        } else {
            ""
        }
        return DecryptedVaultCredential(
            id = row.id,
            title = row.title,
            url = row.url,
            username = username,
            password = password,
            notes = notes,
            strengthScore = row.strengthScore,
            entropyBits = row.entropyBits,
            breachCount = row.breachCount,
            lastBreachCheckedAt = row.lastBreachCheckedAt,
            isReused = false,
            createdAt = row.createdAt,
            updatedAt = row.updatedAt
        )
    }

    suspend fun recordBreachCount(id: Long, count: Int) {
        dao.updateBreachResult(id, count, System.currentTimeMillis())
    }

    suspend fun deleteCredential(id: Long) {
        dao.deleteById(id)
    }
}
