package com.deepfakeshield.data.dao

import androidx.room.*
import com.deepfakeshield.core.model.SecurityModule
import com.deepfakeshield.data.entity.ScanHistoryEntity
import com.deepfakeshield.data.entity.VaultCredentialEntity
import kotlinx.coroutines.flow.Flow

@Dao
interface ScanHistoryDao {
    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsert(entry: ScanHistoryEntity)

    @Query("SELECT * FROM scan_history ORDER BY analyzedAt DESC LIMIT :limit")
    fun getRecentAll(limit: Int = 100): Flow<List<ScanHistoryEntity>>

    @Query("SELECT * FROM scan_history WHERE module = :module ORDER BY analyzedAt DESC LIMIT :limit")
    fun getHistoryByModule(module: SecurityModule, limit: Int = 50): Flow<List<ScanHistoryEntity>>

    @Query("SELECT * FROM scan_history WHERE analysisId = :analysisId LIMIT 1")
    suspend fun getById(analysisId: String): ScanHistoryEntity?

    @Query("SELECT * FROM scan_history WHERE module = :module ORDER BY analyzedAt DESC LIMIT 1")
    suspend fun getLatestForModule(module: SecurityModule): ScanHistoryEntity?

    @Query("SELECT COUNT(*) FROM scan_history")
    fun getTotalScanCountFlow(): Flow<Int>

    @Query("SELECT COUNT(*) FROM scan_history WHERE analyzedAt >= :sinceMs")
    fun getScanCountSinceFlow(sinceMs: Long): Flow<Int>

    @Query("SELECT * FROM scan_history WHERE analyzedAt >= :sinceMs ORDER BY analyzedAt DESC")
    fun getScansSinceFlow(sinceMs: Long): Flow<List<ScanHistoryEntity>>

    @Query("DELETE FROM scan_history WHERE analysisId = :analysisId")
    suspend fun deleteById(analysisId: String)

    @Query("DELETE FROM scan_history WHERE module = :module")
    suspend fun clearModuleHistory(module: SecurityModule)
}

@Dao
interface VaultCredentialDao {
    @Query("SELECT * FROM vault_credentials ORDER BY updatedAt DESC")
    fun getAllCredentials(): Flow<List<VaultCredentialEntity>>

    @Query("SELECT * FROM vault_credentials WHERE id = :id")
    suspend fun getCredentialById(id: Long): VaultCredentialEntity?

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insert(credential: VaultCredentialEntity): Long

    @Update
    suspend fun update(credential: VaultCredentialEntity)

    @Query("DELETE FROM vault_credentials WHERE id = :id")
    suspend fun deleteById(id: Long)

    @Query("SELECT COUNT(*) FROM vault_credentials")
    fun getCredentialCountFlow(): Flow<Int>

    @Query("UPDATE vault_credentials SET breachCount = :breachCount, lastBreachCheckedAt = :checkedAt, updatedAt = :checkedAt WHERE id = :id")
    suspend fun updateBreachResult(id: Long, breachCount: Int, checkedAt: Long)
}

