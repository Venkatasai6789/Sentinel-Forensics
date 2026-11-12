package com.deepfakeshield.core.model

import java.util.UUID

/**
 * Core Sentinel Forensics security engines.
 */
enum class SecurityModule(val displayName: String) {
    MESSAGE_SHIELD("Message Shield"),
    PHISHING_URL_SCAN("Phishing URL Scan"),
    DEVICE_ANTIVIRUS("Device Antivirus"),
    DEEPFAKE_VIDEO("Deepfake Video Detection"),
    PHOTO_FORENSICS("Photo Forensics"),
    PASSWORD_VAULT("Password Vault")
}

/**
 * Execution lifecycle status for any security analysis pipeline.
 */
enum class AnalysisStatus {
    QUEUED,
    PROCESSING,
    COMPLETED,
    PARTIAL,
    FAILED,
    CANCELLED
}

/**
 * Honest forensic verdict.
 * SAFE means performed checks found no known threat indicators; it is never a guarantee.
 */
enum class SecurityVerdict(val label: String) {
    SAFE("No Threats Found"),
    LOW_RISK("Low Risk"),
    SUSPICIOUS("Suspicious"),
    HIGH_RISK("High Risk"),
    MALICIOUS("Malicious"),
    LIKELY_AI_GENERATED("AI/Synthesis Markers Detected"),
    LIKELY_AUTHENTIC("Consistent with Original Media"),
    INCONCLUSIVE("Inconclusive"),
    NOT_SUPPORTED("Not Supported"),
    NOT_ANALYZED("Not Analyzed")
}

enum class FindingSeverity(val label: String) {
    INFO("Info"),
    LOW("Low"),
    MEDIUM("Medium"),
    HIGH("High"),
    CRITICAL("Critical")
}

/**
 * Individual evidence item emitted by an analyzer stage.
 */
data class SecurityFinding(
    val title: String,
    val description: String,
    val severity: FindingSeverity,
    val evidenceSource: String,
    val detectionMethod: String,
    val inputLocation: String? = null,
    val explanation: String,
    val recommendedAction: String
)

/**
 * Shared result contract produced by all 6 Sentinel Forensics modules.
 * Every displayed metric traces directly to an executed stage or remains null.
 */
data class SecurityAnalysisResult(
    val analysisId: String = UUID.randomUUID().toString(),
    val module: SecurityModule,
    val inputName: String?,
    val inputType: String,
    val status: AnalysisStatus,
    val verdict: SecurityVerdict,
    val riskScore: Int?,
    val confidence: Float?,
    val findings: List<SecurityFinding>,
    val analysisMethods: List<String>,
    val limitations: List<String>,
    val processingDurationMs: Long,
    val analyzedAt: Long = System.currentTimeMillis(),
    val modelVersion: String? = null,
    val errorMessage: String? = null,
    val metadata: Map<String, String> = emptyMap()
)

/**
 * Reactive processing state exposed by ViewModels via StateFlow.
 */
sealed class ScanProgressState {
    data object Idle : ScanProgressState()
    data class Validating(val message: String) : ScanProgressState()
    data class Running(
        val stageTitle: String,
        val completedSteps: Int = 0,
        val totalSteps: Int = 0,
        val detail: String = ""
    ) : ScanProgressState()
    data class Completed(val result: SecurityAnalysisResult) : ScanProgressState()
    data class Failed(val errorMessage: String, val retryable: Boolean = true) : ScanProgressState()
    data class Cancelled(val partialResult: SecurityAnalysisResult? = null) : ScanProgressState()
}

fun RiskSeverity.toFindingSeverity(): FindingSeverity = when (this) {
    RiskSeverity.LOW -> FindingSeverity.LOW
    RiskSeverity.MEDIUM -> FindingSeverity.MEDIUM
    RiskSeverity.HIGH -> FindingSeverity.HIGH
    RiskSeverity.CRITICAL -> FindingSeverity.CRITICAL
}

fun FindingSeverity.toRiskSeverity(): RiskSeverity = when (this) {
    FindingSeverity.INFO, FindingSeverity.LOW -> RiskSeverity.LOW
    FindingSeverity.MEDIUM -> RiskSeverity.MEDIUM
    FindingSeverity.HIGH -> RiskSeverity.HIGH
    FindingSeverity.CRITICAL -> RiskSeverity.CRITICAL
}

fun SecurityVerdict.toAlertWorthy(): Boolean = when (this) {
    SecurityVerdict.SUSPICIOUS,
    SecurityVerdict.HIGH_RISK,
    SecurityVerdict.MALICIOUS,
    SecurityVerdict.LIKELY_AI_GENERATED -> true
    else -> false
}

/**
 * Convert legacy RiskResult into unified SecurityAnalysisResult without synthesizing ML confidence
 * unless caller explicitly specifies an ML/statistical confidence source.
 */
fun RiskResult.toSecurityAnalysisResult(
    module: SecurityModule,
    inputName: String?,
    inputType: String,
    processingDurationMs: Long,
    analysisMethods: List<String>,
    limitations: List<String>,
    calibratedConfidence: Float? = null,
    modelVersion: String? = null,
    status: AnalysisStatus = AnalysisStatus.COMPLETED,
    metadata: Map<String, String> = emptyMap()
): SecurityAnalysisResult {
    val verdict = when {
        status == AnalysisStatus.FAILED -> SecurityVerdict.NOT_ANALYZED
        reasons.isEmpty() && score == 0 -> SecurityVerdict.SAFE
        score >= 75 -> SecurityVerdict.MALICIOUS
        score >= 55 -> SecurityVerdict.HIGH_RISK
        score >= 25 -> SecurityVerdict.SUSPICIOUS
        score > 0 -> SecurityVerdict.LOW_RISK
        else -> SecurityVerdict.SAFE
    }
    val primaryRecommendation = recommendedActions.firstOrNull { it.isPrimary }?.title
        ?: recommendedActions.firstOrNull()?.title
        ?: "Review details before taking action."

    val mappedFindings = reasons.map { reason ->
        SecurityFinding(
            title = reason.title,
            description = reason.explanation,
            severity = when {
                score >= 75 -> FindingSeverity.CRITICAL
                score >= 50 -> FindingSeverity.HIGH
                score >= 25 -> FindingSeverity.MEDIUM
                else -> FindingSeverity.LOW
            },
            evidenceSource = reason.type.name,
            detectionMethod = analysisMethods.firstOrNull() ?: "Heuristic Rule Check",
            inputLocation = reason.evidence,
            explanation = reason.explanation,
            recommendedAction = primaryRecommendation
        )
    }

    return SecurityAnalysisResult(
        module = module,
        inputName = inputName,
        inputType = inputType,
        status = status,
        verdict = verdict,
        riskScore = score.coerceIn(0, 100),
        confidence = calibratedConfidence,
        findings = mappedFindings,
        analysisMethods = analysisMethods,
        limitations = limitations,
        processingDurationMs = processingDurationMs,
        analyzedAt = timestamp,
        modelVersion = modelVersion,
        metadata = metadata
    )
}

