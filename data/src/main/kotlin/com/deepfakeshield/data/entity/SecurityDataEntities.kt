package com.deepfakeshield.data.entity

import androidx.room.Entity
import androidx.room.Index
import androidx.room.PrimaryKey
import com.deepfakeshield.core.model.AnalysisStatus
import com.deepfakeshield.core.model.SecurityModule
import com.deepfakeshield.core.model.SecurityVerdict

/**
 * Unified persisted scan result row for all 6 Sentinel Forensics modules.
 */
@Entity(
    tableName = "scan_history",
    indices = [
        Index(value = ["module"]),
        Index(value = ["analyzedAt"]),
        Index(value = ["verdict"])
    ]
)
data class ScanHistoryEntity(
    @PrimaryKey
    val analysisId: String,
    val module: SecurityModule,
    val inputName: String?,
    val inputType: String,
    val status: AnalysisStatus,
    val verdict: SecurityVerdict,
    val riskScore: Int?,
    val confidence: Float?,
    val findingsJson: String,
    val analysisMethodsJson: String,
    val limitationsJson: String,
    val metadataJson: String,
    val processingDurationMs: Long,
    val analyzedAt: Long,
    val modelVersion: String?,
    val errorMessage: String?
)

/**
 * Encrypted credential stored in the Password Vault.
 * Plaintext usernames, passwords, and notes are NEVER persisted in Room.
 */
@Entity(
    tableName = "vault_credentials",
    indices = [
        Index(value = ["title"]),
        Index(value = ["reuseDigest"]),
        Index(value = ["updatedAt"])
    ]
)
data class VaultCredentialEntity(
    @PrimaryKey(autoGenerate = true)
    val id: Long = 0,
    val title: String,
    val url: String?,
    val usernameEncrypted: String,
    val usernameIv: String,
    val passwordEncrypted: String,
    val passwordIv: String,
    val notesEncrypted: String?,
    val notesIv: String?,
    val reuseDigest: String,
    val strengthScore: Int,
    val entropyBits: Double,
    val breachCount: Int?,
    val lastBreachCheckedAt: Long?,
    val createdAt: Long,
    val updatedAt: Long
)

