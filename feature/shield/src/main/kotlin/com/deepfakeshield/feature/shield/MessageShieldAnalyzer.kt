package com.deepfakeshield.feature.shield

import com.deepfakeshield.core.engine.RiskIntelligenceEngine
import com.deepfakeshield.core.intelligence.MultiLingualThreatDetector
import com.deepfakeshield.core.model.AnalysisStatus
import com.deepfakeshield.core.model.FindingSeverity
import com.deepfakeshield.core.model.Reason
import com.deepfakeshield.core.model.ReasonType
import com.deepfakeshield.core.model.RiskResult
import com.deepfakeshield.core.model.RiskSeverity
import com.deepfakeshield.core.model.SecurityAnalysisResult
import com.deepfakeshield.core.model.SecurityFinding
import com.deepfakeshield.core.model.SecurityModule
import com.deepfakeshield.core.model.SecurityVerdict
import com.deepfakeshield.core.model.ThreatSource
import com.deepfakeshield.core.model.ThreatType
import com.deepfakeshield.core.model.toSecurityAnalysisResult
import com.deepfakeshield.data.dao.ScamPatternDao
import com.deepfakeshield.intelligence.UnifiedUrlInspectionEngine
import com.deepfakeshield.intelligence.UrlInspectionReport
import com.deepfakeshield.ml.text.GovernmentGradeTextDetector
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.util.UUID
import javax.inject.Inject
import javax.inject.Singleton

data class ExtractedEntity(
    val kind: String,
    val value: String,
    val startOffset: Int,
    val endOffset: Int
)

data class MessageShieldAnalysisBundle(
    val analysisResult: SecurityAnalysisResult,
    val legacyRiskResult: RiskResult,
    val extractedUrls: List<UrlInspectionReport>,
    val extractedEntities: List<ExtractedEntity>,
    val scamCategory: String,
    val detectedLanguage: String
)

private val MESSAGE_URL_REGEX = Regex(
    """(?:https?://|www\.)[^\s<>"{}|\\^`\[\]]+|(?:bit\.ly|tinyurl\.com|t\.co|rb\.gy|cutt\.ly|is\.gd)/[^\s<>"]+""",
    RegexOption.IGNORE_CASE
)
private val MESSAGE_PHONE_REGEX = Regex("""(?<!\d)(?:\+?\d[\d\s\-()]{6,}\d)(?!\d)""")

@Singleton
class MessageShieldAnalyzer @Inject constructor(
    private val riskEngine: RiskIntelligenceEngine,
    private val multiLingualDetector: MultiLingualThreatDetector,
    private val scamPatternDao: ScamPatternDao,
    private val textDetector: GovernmentGradeTextDetector,
    private val urlInspectionEngine: UnifiedUrlInspectionEngine
) {

    suspend fun analyzeMessage(
        text: String,
        source: ThreatSource,
        senderInfo: String? = null,
        metadata: Map<String, Any> = emptyMap(),
        allowNetworkUrlProbe: Boolean = false
    ): MessageShieldAnalysisBundle = withContext(Dispatchers.Default) {
        val startedAt = System.currentTimeMillis()
        val analysisId = UUID.randomUUID().toString()
        val trimmed = text.trim()

        if (trimmed.isBlank()) {
            val emptyResult = SecurityAnalysisResult(
                analysisId = analysisId,
                module = SecurityModule.MESSAGE_SHIELD,
                inputName = "Empty message",
                inputType = "text/plain",
                status = AnalysisStatus.FAILED,
                verdict = SecurityVerdict.NOT_ANALYZED,
                riskScore = null,
                confidence = null,
                findings = emptyList(),
                analysisMethods = listOf("Input Validation"),
                limitations = listOf("No message content supplied for analysis."),
                processingDurationMs = System.currentTimeMillis() - startedAt,
                analyzedAt = System.currentTimeMillis(),
                modelVersion = null,
                errorMessage = "Enter or paste a message to analyze."
            )
            val fallbackRisk = riskEngine.analyzeText("", source, senderInfo, metadata)
            return@withContext MessageShieldAnalysisBundle(
                analysisResult = emptyResult,
                legacyRiskResult = fallbackRisk,
                extractedUrls = emptyList(),
                extractedEntities = emptyList(),
                scamCategory = "NONE",
                detectedLanguage = "unknown"
            )
        }

        // 1. Extract URLs and phone numbers with exact character offsets
        val entities = mutableListOf<ExtractedEntity>()
        val extractedUrlStrings = mutableListOf<String>()
        MESSAGE_URL_REGEX.findAll(trimmed).take(5).forEach { match ->
            val rawUrl = match.value.trimEnd('.', ',', ';', ')', '!')
            entities += ExtractedEntity("URL", rawUrl, match.range.first, match.range.last + 1)
            extractedUrlStrings += rawUrl
        }
        MESSAGE_PHONE_REGEX.findAll(trimmed).take(5).forEach { match ->
            val digits = match.value.filter { it.isDigit() }
            if (digits.length in 7..15) {
                entities += ExtractedEntity("PHONE", match.value.trim(), match.range.first, match.range.last + 1)
            }
        }

        // 2. Deterministic rule engines + multi-lingual + learned pattern DB
        val baseRisk = riskEngine.analyzeText(trimmed, source, senderInfo, metadata)
        val multiLingual = multiLingualDetector.analyzeText(trimmed)
        val textAnalysis = withContext(Dispatchers.IO) {
            runCatching { textDetector.analyzeText(trimmed, senderInfo) }.getOrNull()
        }

        // Learned ScamPatternEntity weights
        var learnedBoost = 0
        val learnedFindings = mutableListOf<SecurityFinding>()
        withContext(Dispatchers.IO) {
            runCatching {
                val lower = trimmed.lowercase()
                val patterns = scamPatternDao.getPatternsByType("text_phrase")
                patterns.forEach { entity ->
                    if (entity.pattern.isNotBlank() && lower.contains(entity.pattern.lowercase())) {
                        val contrib = (entity.weight * 12f).toInt().coerceIn(5, 30)
                        learnedBoost += contrib
                        learnedFindings += SecurityFinding(
                            title = "Matched persisted scam pattern",
                            description = "Matched local threat pattern '${entity.pattern}' (${entity.threatType.name}).",
                            severity = FindingSeverity.HIGH,
                            evidenceSource = "Room ScamPatternDao",
                            detectionMethod = "Learned Pattern Match",
                            inputLocation = null,
                            explanation = "This phrase matches a pattern recorded from prior detections/user reports.",
                            recommendedAction = "Treat message as high risk and verify independently."
                        )
                    }
                }
            }
        }

        // 3. Embedded URL inspection (offline-safe unless probe enabled)
        val urlReports = withContext(Dispatchers.IO) {
            extractedUrlStrings.distinct().map { url ->
                urlInspectionEngine.inspectUrl(url, allowNetworkProbe = allowNetworkUrlProbe)
            }
        }
        val maxUrlScore = urlReports.mapNotNull { it.analysisResult.riskScore }.maxOrNull() ?: 0

        // Too-brief ambiguity gate: < 6 chars & 1 word & zero matches/entities -> INCONCLUSIVE
        val words = trimmed.split(Regex("\\s+")).filter { it.isNotEmpty() }
        val totalHeuristicBase = maxOf(
            baseRisk.score,
            if (multiLingual.threatPatterns.isNotEmpty()) multiLingual.riskScore else 0
        )
        if (trimmed.length < 6 && words.size <= 1 && entities.isEmpty() &&
            totalHeuristicBase == 0 && learnedFindings.isEmpty()
        ) {
            val inconclusiveResult = SecurityAnalysisResult(
                analysisId = analysisId,
                module = SecurityModule.MESSAGE_SHIELD,
                inputName = trimmed.take(48),
                inputType = "text/plain",
                status = AnalysisStatus.COMPLETED,
                verdict = SecurityVerdict.INCONCLUSIVE,
                riskScore = null,
                confidence = null,
                findings = emptyList(),
                analysisMethods = listOf("Length & Context Sufficiency Check", "Deterministic Heuristic Rules"),
                limitations = listOf("Message contains fewer than 6 characters with no URLs or threat keywords; insufficient context for classification."),
                processingDurationMs = System.currentTimeMillis() - startedAt,
                analyzedAt = System.currentTimeMillis(),
                modelVersion = null,
                errorMessage = null
            )
            return@withContext MessageShieldAnalysisBundle(
                analysisResult = inconclusiveResult,
                legacyRiskResult = baseRisk.copy(
                    score = 0,
                    severity = RiskSeverity.LOW,
                    confidence = 0f,
                    explainLikeImFive = "Message is too brief to assess risk reliably. No links or threat patterns matched."
                ),
                extractedUrls = emptyList(),
                extractedEntities = emptyList(),
                scamCategory = "INSUFFICIENT_CONTEXT",
                detectedLanguage = multiLingual.detectedLanguage
            )
        }

        // 4. Score aggregation
        val mlBonus = if (textAnalysis?.mlModelsActive == true && textAnalysis.isScam) {
            (textAnalysis.confidence * 25f).toInt()
        } else {
            0
        }
        val heuristicSignalBonus = if (textAnalysis != null && textAnalysis.isScam && !textAnalysis.mlModelsActive) {
            ((textAnalysis.confidence - 0.5f).coerceAtLeast(0f) * 30f).toInt()
        } else {
            0
        }
        val multiLingualBonus = if (multiLingual.threatPatterns.isNotEmpty()) {
            (multiLingual.riskScore * 0.4f).toInt()
        } else {
            0
        }

        val combinedTextScore = (baseRisk.score + learnedBoost + multiLingualBonus + mlBonus + heuristicSignalBonus)
            .coerceIn(0, 100)
        val combinedScore = maxOf(combinedTextScore, maxUrlScore).coerceIn(0, 100)

        val combinedSeverity = when {
            combinedScore >= 80 -> RiskSeverity.CRITICAL
            combinedScore >= 55 -> RiskSeverity.HIGH
            combinedScore >= 30 -> RiskSeverity.MEDIUM
            else -> RiskSeverity.LOW
        }

        val effectiveThreatType = when {
            maxUrlScore >= 60 && combinedTextScore < maxUrlScore -> ThreatType.PHISHING_ATTEMPT
            baseRisk.threatType == ThreatType.UNKNOWN && maxUrlScore >= 30 -> ThreatType.PHISHING_ATTEMPT
            else -> baseRisk.threatType
        }

        // 5. Merge traceable findings & legacy Reasons
        val findings = mutableListOf<SecurityFinding>()
        val legacyReasons = baseRisk.reasons.toMutableList()

        baseRisk.toSecurityAnalysisResult(
            module = SecurityModule.MESSAGE_SHIELD,
            inputName = trimmed.take(48),
            inputType = "text/plain",
            processingDurationMs = 0L,
            analysisMethods = listOf("RiskIntelligenceEngine"),
            limitations = emptyList()
        ).findings.let { findings += it }

        if (multiLingual.threatPatterns.isNotEmpty()) {
            multiLingual.threatPatterns.forEach { pattern ->
                findings += SecurityFinding(
                    title = "Regional/multilingual scam indicator (${pattern.language})",
                    description = "Matched '${pattern.pattern}' (${pattern.threatType}, region ${pattern.region}).",
                    severity = if (pattern.severity >= 70) FindingSeverity.HIGH else FindingSeverity.MEDIUM,
                    evidenceSource = "MultiLingualThreatDetector",
                    detectionMethod = "Regional Keyword Rules",
                    inputLocation = null,
                    explanation = "Known regional scam/phishing phrasing detected.",
                    recommendedAction = "Verify the sender independently before acting."
                )
            }
        }

        findings += learnedFindings

        urlReports.forEach { report ->
            val entity = entities.firstOrNull { it.value == report.analysisResult.inputName }
            val loc = entity?.let { "chars ${it.startOffset}..${it.endOffset}" } ?: report.normalizedUrl
            report.analysisResult.findings.forEach { urlFinding ->
                findings += urlFinding.copy(inputLocation = loc)
            }
            if ((report.analysisResult.riskScore ?: 0) >= 30) {
                legacyReasons += Reason(
                    type = ReasonType.TECHNICAL,
                    title = "Embedded URL Risk (${report.asciiHost})",
                    explanation = report.analysisResult.findings.firstOrNull()?.description
                        ?: "Embedded URL scored ${report.analysisResult.riskScore}/100.",
                    evidence = report.normalizedUrl
                )
            }
        }

        // Extract manipulation techniques from text analyzer
        textAnalysis?.manipulationTechniques?.forEach { tech ->
            if (findings.none { it.title == tech.technique }) {
                findings += SecurityFinding(
                    title = tech.technique,
                    description = tech.examples.joinToString("; "),
                    severity = if (tech.severity >= 0.85f) FindingSeverity.HIGH else FindingSeverity.MEDIUM,
                    evidenceSource = "Linguistic Manipulation Analyzer",
                    detectionMethod = "Rule-Based Social Engineering Analysis",
                    inputLocation = null,
                    explanation = "Detected psychological manipulation framing.",
                    recommendedAction = "Pause and verify independently before complying."
                )
            }
        }

        val methods = buildList {
            add("Deterministic Scam/Phishing Rule Engine (RiskIntelligenceEngine)")
            add("Multi-Lingual Pattern Detector (${multiLingual.detectedLanguage})")
            add("Room Learned Pattern Store (ScamPatternDao)")
            if (extractedUrlStrings.isNotEmpty()) {
                add("Embedded URL Inspection (${extractedUrlStrings.size} link(s))")
            }
            textAnalysis?.analysisMethods?.forEach { if (it !in this) add(it) }
        }

        val limitations = buildList {
            textAnalysis?.limitations?.forEach { add(it) }
            urlReports.flatMap { it.analysisResult.limitations }.distinct().forEach { add(it) }
        }

        val calibratedConfidence = if (textAnalysis?.mlModelsActive == true) textAnalysis.calibratedConfidence else null // strictly null unless validated ML model ran
        val verdict = when {
            combinedScore >= 75 -> SecurityVerdict.MALICIOUS
            combinedScore >= 55 -> SecurityVerdict.HIGH_RISK
            combinedScore >= 30 -> SecurityVerdict.SUSPICIOUS
            combinedScore >= 15 -> SecurityVerdict.LOW_RISK
            else -> SecurityVerdict.SAFE
        }

        val durationMs = System.currentTimeMillis() - startedAt
        val summaryExplain = when {
            combinedScore >= 55 && maxUrlScore >= 55 ->
                "High-risk message containing suspicious or deceptive link(s). Do not tap links or share codes."
            combinedScore >= 55 -> baseRisk.explainLikeImFive
            combinedScore >= 30 ->
                "Suspicious indicators detected (${findings.size} finding(s)). Verify sender via an official number."
            else -> "Analyzed checks found no scam patterns or high-risk links in this message."
        }

        val updatedLegacyRisk = baseRisk.copy(
            score = combinedScore,
            severity = combinedSeverity,
            confidence = calibratedConfidence ?: (combinedScore / 100f),
            threatType = effectiveThreatType,
            reasons = legacyReasons.distinctBy { "${it.title}:${it.evidence}" },
            explainLikeImFive = summaryExplain,
            technicalDetails = buildString {
                append(baseRisk.technicalDetails)
                if (urlReports.isNotEmpty()) {
                    append("\nEmbedded URLs inspected: ")
                    append(urlReports.joinToString { "${it.asciiHost} (${it.analysisResult.riskScore ?: 0}/100)" })
                }
                if (textAnalysis != null) {
                    append("\nText Engine Mode: ${textAnalysis.certificationLevel}")
                }
            }
        )

        val securityResult = SecurityAnalysisResult(
            analysisId = analysisId,
            module = SecurityModule.MESSAGE_SHIELD,
            inputName = trimmed.take(48),
            inputType = "text/plain",
            status = AnalysisStatus.COMPLETED,
            verdict = verdict,
            riskScore = combinedScore,
            confidence = calibratedConfidence,
            findings = findings,
            analysisMethods = methods,
            limitations = limitations.distinct(),
            processingDurationMs = durationMs,
            analyzedAt = System.currentTimeMillis(),
            modelVersion = if (textAnalysis?.mlModelsActive == true) textAnalysis.activeModels.joinToString() else null,
            errorMessage = null,
            metadata = mapOf(
                "language" to multiLingual.detectedLanguage,
                "urlCount" to urlReports.size.toString(),
                "phoneCount" to entities.count { it.kind == "PHONE" }.toString(),
                "scamCategory" to (textAnalysis?.scamCategory?.name ?: "NONE")
            )
        )

        MessageShieldAnalysisBundle(
            analysisResult = securityResult,
            legacyRiskResult = updatedLegacyRisk,
            extractedUrls = urlReports,
            extractedEntities = entities,
            scamCategory = textAnalysis?.scamCategory?.name ?: "NONE",
            detectedLanguage = multiLingual.detectedLanguage
        )
    }
}

