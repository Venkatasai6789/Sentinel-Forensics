package com.deepfakeshield.core.model

import org.junit.Assert.*
import org.junit.Test

class SecurityAnalysisModelsTest {

    @Test
    fun `json codec round-trips findings, lists, and metadata with escaping`() {
        val findings = listOf(
            SecurityFinding(
                title = "Phishing \"Urgent\" Link\nLine 2",
                description = "Contains \\escaped\\ backslashes & quotes",
                severity = FindingSeverity.CRITICAL,
                evidenceSource = "UrlSafetyEngine",
                detectionMethod = "Lexical Heuristics",
                inputLocation = "https://example.tk/login?next=a&b=c",
                explanation = "Attempted credential harvest.",
                recommendedAction = "Do not open"
            ),
            SecurityFinding(
                title = "Clean EXIF absence",
                description = "Standard messaging strip",
                severity = FindingSeverity.INFO,
                evidenceSource = "ExifInterface",
                detectionMethod = "Tag Check",
                inputLocation = null,
                explanation = "Absence alone does not prove editing.",
                recommendedAction = "Verify source"
            )
        )
        val encodedFindings = SecurityJsonCodec.encodeFindings(findings)
        val decodedFindings = SecurityJsonCodec.decodeFindings(encodedFindings)
        assertEquals(findings, decodedFindings)

        val methods = listOf("SHA-256", "Heuristics \"v2\"\tfast")
        assertEquals(methods, SecurityJsonCodec.decodeStringList(SecurityJsonCodec.encodeStringList(methods)))

        val meta = linkedMapOf("sha256" to "abc123", "note" to "Line 1\nLine 2")
        assertEquals(meta, SecurityJsonCodec.decodeStringMap(SecurityJsonCodec.encodeStringMap(meta)))
    }

    @Test
    fun `RiskResult maps to honest SecurityAnalysisResult without fabricated confidence`() {
        val risk = RiskResult(
            score = 72,
            severity = RiskSeverity.HIGH,
            confidence = 0.85f,
            threatType = ThreatType.OTP_TRAP,
            reasons = listOf(
                Reason(
                    type = ReasonType.LANGUAGE,
                    title = "Urgent OTP lure",
                    explanation = "Requests one-time code",
                    evidence = "Share your OTP now"
                )
            ),
            recommendedActions = listOf(
                Action(
                    type = RecommendedAction.BLOCK_SENDER,
                    title = "Block Sender",
                    description = "Do not reply",
                    isPrimary = true
                )
            ),
            explainLikeImFive = "Do not share passcodes.",
            technicalDetails = "Heuristic score=72"
        )

        val heuristicMapped = risk.toSecurityAnalysisResult(
            module = SecurityModule.MESSAGE_SHIELD,
            inputName = "SMS Body",
            inputType = "text/plain",
            processingDurationMs = 12L,
            analysisMethods = listOf("Deterministic Heuristic Engine"),
            limitations = listOf("No external carrier lookup"),
            calibratedConfidence = null
        )

        assertEquals(SecurityVerdict.HIGH_RISK, heuristicMapped.verdict)
        assertEquals(72, heuristicMapped.riskScore)
        assertNull("Heuristic engine must never emit a calibrated ML confidence", heuristicMapped.confidence)
        assertEquals(1, heuristicMapped.findings.size)
        assertEquals("Share your OTP now", heuristicMapped.findings.first().inputLocation)
        assertTrue(heuristicMapped.verdict.toAlertWorthy())
    }
}
