package com.deepfakeshield.data.repository

import com.deepfakeshield.core.model.*
import com.deepfakeshield.data.dao.ScanHistoryDao
import com.deepfakeshield.data.entity.ScanHistoryEntity
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.map
import javax.inject.Inject
import javax.inject.Singleton

@Singleton
class ScanHistoryRepository @Inject constructor(
    private val scanHistoryDao: ScanHistoryDao
) {
    suspend fun saveResult(result: SecurityAnalysisResult) {
        scanHistoryDao.upsert(result.toEntity())
    }

    fun observeHistory(module: SecurityModule, limit: Int = 50): Flow<List<SecurityAnalysisResult>> =
        scanHistoryDao.getHistoryByModule(module, limit).map { rows -> rows.map { it.toDomain() } }

    fun observeRecentAll(limit: Int = 100): Flow<List<SecurityAnalysisResult>> =
        scanHistoryDao.getRecentAll(limit).map { rows -> rows.map { it.toDomain() } }

    fun observeScansSince(sinceMs: Long): Flow<List<SecurityAnalysisResult>> =
        scanHistoryDao.getScansSinceFlow(sinceMs).map { rows -> rows.map { it.toDomain() } }

    fun observeTotalScanCount(): Flow<Int> = scanHistoryDao.getTotalScanCountFlow()

    suspend fun getById(analysisId: String): SecurityAnalysisResult? =
        scanHistoryDao.getById(analysisId)?.toDomain()

    suspend fun getLatestForModule(module: SecurityModule): SecurityAnalysisResult? =
        scanHistoryDao.getLatestForModule(module)?.toDomain()

    suspend fun deleteScan(analysisId: String) = scanHistoryDao.deleteById(analysisId)

    suspend fun clearModuleHistory(module: SecurityModule) = scanHistoryDao.clearModuleHistory(module)

    private fun SecurityAnalysisResult.toEntity(): ScanHistoryEntity = ScanHistoryEntity(
        analysisId = analysisId,
        module = module,
        inputName = inputName,
        inputType = inputType,
        status = status,
        verdict = verdict,
        riskScore = riskScore,
        confidence = confidence,
        findingsJson = SecurityJsonCodec.encodeFindings(findings),
        analysisMethodsJson = SecurityJsonCodec.encodeStringList(analysisMethods),
        limitationsJson = SecurityJsonCodec.encodeStringList(limitations),
        metadataJson = SecurityJsonCodec.encodeStringMap(metadata),
        processingDurationMs = processingDurationMs,
        analyzedAt = analyzedAt,
        modelVersion = modelVersion,
        errorMessage = errorMessage
    )

    private fun ScanHistoryEntity.toDomain(): SecurityAnalysisResult = SecurityAnalysisResult(
        analysisId = analysisId,
        module = module,
        inputName = inputName,
        inputType = inputType,
        status = status,
        verdict = verdict,
        riskScore = riskScore,
        confidence = confidence,
        findings = SecurityJsonCodec.decodeFindings(findingsJson),
        analysisMethods = SecurityJsonCodec.decodeStringList(analysisMethodsJson),
        limitations = SecurityJsonCodec.decodeStringList(limitationsJson),
        processingDurationMs = processingDurationMs,
        analyzedAt = analyzedAt,
        modelVersion = modelVersion,
        errorMessage = errorMessage,
        metadata = SecurityJsonCodec.decodeStringMap(metadataJson)
    )
}

