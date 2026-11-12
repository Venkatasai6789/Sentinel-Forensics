package com.deepfakeshield.intelligence

import com.deepfakeshield.core.engine.UrlSafetyEngine
import com.deepfakeshield.core.intelligence.URLIntelligenceEngine
import com.deepfakeshield.core.model.AnalysisStatus
import com.deepfakeshield.core.model.FindingSeverity
import com.deepfakeshield.core.model.SecurityAnalysisResult
import com.deepfakeshield.core.model.SecurityFinding
import com.deepfakeshield.core.model.SecurityModule
import com.deepfakeshield.core.model.SecurityVerdict
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.IOException
import java.net.HttpURLConnection
import java.net.IDN
import java.net.URI
import java.net.URL
import java.net.URLDecoder
import java.security.cert.X509Certificate
import java.util.UUID
import javax.inject.Inject
import javax.inject.Singleton
import javax.net.ssl.HostnameVerifier
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SSLHandshakeException
import javax.net.ssl.SSLSocketFactory

data class LiveTlsInspection(
    val attempted: Boolean,
    val succeeded: Boolean,
    val certificateValid: Boolean?,
    val issuer: String? = null,
    val subject: String? = null,
    val sanHostnames: List<String> = emptyList(),
    val notAfterMs: Long? = null,
    val notBeforeMs: Long? = null,
    val selfSigned: Boolean? = null,
    val error: String? = null
)

data class RedirectInspection(
    val attempted: Boolean,
    val succeeded: Boolean,
    val chain: List<String> = emptyList(),
    val finalUrl: String? = null,
    val finalStatusCode: Int? = null,
    val crossDomainRedirect: Boolean = false,
    val error: String? = null
)

data class UrlInspectionReport(
    val analysisResult: SecurityAnalysisResult,
    val normalizedUrl: String,
    val asciiHost: String,
    val unicodeHost: String,
    val punycodeDecoded: String?,
    val tlsInspection: LiveTlsInspection,
    val redirectInspection: RedirectInspection,
    val localCacheMatch: Boolean,
    val cacheEntryCount: Int,
    val cacheLastUpdatedAt: Long
)

/**
 * Real phishing & malicious URL inspector combining:
 * 1. Canonical URI + IDN/punycode structural validation
 * 2. Local structural/brand-lookalike heuristics (`UrlSafetyEngine`, `URLIntelligenceEngine`)
 * 3. Cached local feed lookup (`UnifiedUrlThreatCache`: PhishTank / OpenPhish / URLhaus)
 * 4. Optional live HTTP redirect chain tracing & TLS X.509 certificate inspection
 *
 * Explicitly reports offline/partial states rather than simulating TLS or safe results.
 */
@Singleton
class UnifiedUrlInspectionEngine @Inject constructor(
    private val urlSafetyEngine: UrlSafetyEngine,
    private val urlIntelligenceEngine: URLIntelligenceEngine,
    private val threatCache: UnifiedUrlThreatCache
) {

    suspend fun inspectUrl(
        rawUrl: String,
        allowNetworkProbe: Boolean = false,
        customSslSocketFactory: SSLSocketFactory? = null,
        customHostnameVerifier: HostnameVerifier? = null
    ): UrlInspectionReport = withContext(Dispatchers.IO) {
        val startedAt = System.currentTimeMillis()
        val analysisId = UUID.randomUUID().toString()
        val trimmed = rawUrl.trim()

        if (trimmed.isBlank()) {
            return@withContext failureReport(
                analysisId = analysisId,
                inputName = rawUrl,
                startedAt = startedAt,
                verdict = SecurityVerdict.NOT_ANALYZED,
                error = "URL input is empty.",
                findings = emptyList()
            )
        }

        val lowerTrimmed = trimmed.lowercase()
        if (lowerTrimmed.startsWith("javascript:") ||
            lowerTrimmed.startsWith("data:") ||
            lowerTrimmed.startsWith("file:") ||
            lowerTrimmed.startsWith("blob:")
        ) {
            val schemeFinding = SecurityFinding(
                title = "Dangerous or unsupported URI scheme",
                description = "Submitted URI uses '${lowerTrimmed.substringBefore(':')}:' instead of http/https.",
                severity = FindingSeverity.CRITICAL,
                evidenceSource = "URI Scheme Parser",
                detectionMethod = "Canonical URI Check",
                inputLocation = "scheme",
                explanation = "javascript:, data:, file:, and blob: links can execute code or read unintended local contexts in web views.",
                recommendedAction = "Do not open this URI."
            )
            val result = SecurityAnalysisResult(
                analysisId = analysisId,
                module = SecurityModule.PHISHING_URL_SCAN,
                inputName = trimmed,
                inputType = "url",
                status = AnalysisStatus.COMPLETED,
                verdict = SecurityVerdict.MALICIOUS,
                riskScore = 95,
                confidence = null,
                findings = listOf(schemeFinding),
                analysisMethods = listOf("Canonical URI Scheme Validation"),
                limitations = listOf("Non-HTTP/HTTPS URI blocked prior to network connection."),
                processingDurationMs = System.currentTimeMillis() - startedAt,
                analyzedAt = System.currentTimeMillis(),
                modelVersion = null,
                errorMessage = null,
                metadata = mapOf("scheme" to lowerTrimmed.substringBefore(':'))
            )
            return@withContext UrlInspectionReport(
                analysisResult = result,
                normalizedUrl = trimmed,
                asciiHost = "",
                unicodeHost = "",
                punycodeDecoded = null,
                tlsInspection = LiveTlsInspection(attempted = false, succeeded = false, certificateValid = null, error = "Blocked scheme"),
                redirectInspection = RedirectInspection(attempted = false, succeeded = false, error = "Blocked scheme"),
                localCacheMatch = false,
                cacheEntryCount = threatCache.getCachedCount(),
                cacheLastUpdatedAt = threatCache.getLastUpdatedAt()
            )
        }

        val normalized = if (trimmed.contains("://")) trimmed else "https://$trimmed"
        val parsedUrl = try {
            URI(normalized).toURL()
        } catch (_: Exception) {
            null
        }
        val host = parsedUrl?.host?.lowercase().orEmpty()
        if (parsedUrl == null || host.isBlank() || (parsedUrl.protocol != "http" && parsedUrl.protocol != "https")) {
            return@withContext failureReport(
                analysisId = analysisId,
                inputName = trimmed,
                startedAt = startedAt,
                verdict = SecurityVerdict.INCONCLUSIVE,
                error = "Could not parse a valid HTTP/HTTPS domain from '$trimmed'.",
                findings = listOf(
                    SecurityFinding(
                        title = "Malformed URL syntax",
                        description = "URL could not be parsed as a valid web address.",
                        severity = FindingSeverity.MEDIUM,
                        evidenceSource = "URI Parser",
                        detectionMethod = "RFC 3986 Parse",
                        inputLocation = trimmed,
                        explanation = "Malformed URLs are sometimes crafted to evade link filters.",
                        recommendedAction = "Verify the address before opening it."
                    )
                )
            )
        }

        val asciiHost = runCatching { IDN.toASCII(host).lowercase() }.getOrDefault(host)
        val unicodeHost = runCatching { IDN.toUnicode(asciiHost) }.getOrDefault(host)
        val punycodeDecoded = if (asciiHost.contains("xn--") || asciiHost != unicodeHost) unicodeHost else null

        val findings = mutableListOf<SecurityFinding>()
        val methods = mutableListOf(
            "Canonical URI & IDN/Punycode Normalization",
            "On-Device URL Structural & Brand-Lookalike Analysis",
            "Offline Threat Feed Lookup (${threatCache.getCachedCount()} cached indicators)"
        )
        val limitations = mutableListOf<String>()
        var score = 0

        // 1. Userinfo credential masking check (http://bank.com@evil.com)
        if (!parsedUrl.userInfo.isNullOrBlank()) {
            score += 45
            findings += SecurityFinding(
                title = "Embedded credentials / @ obfuscation",
                description = "URL contains userinfo ('${parsedUrl.userInfo}@') before host '$asciiHost'.",
                severity = FindingSeverity.CRITICAL,
                evidenceSource = "URI Authority Parser",
                detectionMethod = "Credential-Masking Pattern",
                inputLocation = parsedUrl.authority,
                explanation = "Attackers put a trusted domain before '@' so browsers connect to the actual host after '@'.",
                recommendedAction = "Do not open this link."
            )
        }

        // 2. Punycode / IDN homograph check
        if (asciiHost.contains("xn--") || host != unicodeHost) {
            score += 35
            findings += SecurityFinding(
                title = "Internationalized Domain (IDN / Punycode)",
                description = "ASCII host '$asciiHost' decodes to '$unicodeHost'.",
                severity = FindingSeverity.HIGH,
                evidenceSource = "java.net.IDN",
                detectionMethod = "Punycode Decoding",
                inputLocation = host,
                explanation = "IDN domains can mix lookalike Unicode characters to spoof familiar brands.",
                recommendedAction = "Verify the exact Unicode characters carefully."
            )
        }

        // 3. Static structural + intel engines
        val staticSafety = urlSafetyEngine.analyzeUrl(normalized)
        val staticIntel = urlIntelligenceEngine.analyzeURL(normalized)
        score = maxOf(score, staticSafety.riskScore, staticIntel.riskScore)

        staticSafety.threats.forEach { t ->
            val sev = when (t.severity.uppercase()) {
                "CRITICAL" -> FindingSeverity.CRITICAL
                "HIGH" -> FindingSeverity.HIGH
                "MEDIUM" -> FindingSeverity.MEDIUM
                else -> FindingSeverity.LOW
            }
            findings += SecurityFinding(
                title = t.type.replace('_', ' '),
                description = t.description,
                severity = sev,
                evidenceSource = "UrlSafetyEngine",
                detectionMethod = "Lexical & Domain Heuristics",
                inputLocation = asciiHost,
                explanation = t.description,
                recommendedAction = if (sev >= FindingSeverity.HIGH) "Avoid entering credentials or downloading files from this URL." else "Verify domain ownership."
            )
        }

        staticIntel.warnings.forEach { warning ->
            if (findings.none { it.description == warning }) {
                findings += SecurityFinding(
                    title = "URL structural warning",
                    description = warning,
                    severity = FindingSeverity.MEDIUM,
                    evidenceSource = "URLIntelligenceEngine",
                    detectionMethod = "Domain & Query Parameter Inspection",
                    inputLocation = parsedUrl.query ?: asciiHost,
                    explanation = warning,
                    recommendedAction = "Inspect destination parameters before proceeding."
                )
            }
        }

        // Check executable/apk downloads in path
        val lowerPath = (parsedUrl.path ?: "").lowercase()
        val dangerousExt = listOf(".apk", ".exe", ".bat", ".cmd", ".ps1", ".vbs", ".msi", ".sh").firstOrNull { lowerPath.endsWith(it) }
        if (dangerousExt != null) {
            score = (score + 30).coerceAtMost(100)
            findings += SecurityFinding(
                title = "Executable / installer payload link",
                description = "URL path ends with '$dangerousExt'.",
                severity = FindingSeverity.HIGH,
                evidenceSource = "URL Path Analyzer",
                detectionMethod = "Payload Extension Check",
                inputLocation = parsedUrl.path,
                explanation = "Direct download links for '$dangerousExt' files from unverified sources are commonly used to distribute malware.",
                recommendedAction = "Do not download or install binaries from untrusted links."
            )
        }

        // Check query parameters for nested open redirects
        parsedUrl.query?.split("&")?.forEach { pair ->
            val decoded = runCatching { URLDecoder.decode(pair, "UTF-8") }.getOrDefault(pair)
            if (decoded.contains("http://", ignoreCase = true) || decoded.contains("https://", ignoreCase = true)) {
                val idx = findings.indexOfFirst { it.description.contains("another URL") }
                if (idx == -1) {
                    score = (score + 15).coerceAtMost(100)
                    findings += SecurityFinding(
                        title = "Nested redirect parameter",
                        description = "Query contains another URL inside '$pair'.",
                        severity = FindingSeverity.MEDIUM,
                        evidenceSource = "Query Parameter Parser",
                        detectionMethod = "Open-Redirect Check",
                        inputLocation = pair,
                        explanation = "Phishing campaigns wrap malicious destinations inside redirect parameters on benign-looking links.",
                        recommendedAction = "Inspect the embedded destination URL directly."
                    )
                }
            }
        }

        // 4. Local feed cache lookup
        var cacheHit = false
        val cachedPhishing = threatCache.isUrlPhishing(normalized)
        val cachedMalware = threatCache.isUrlMalware(normalized)
        if (cachedPhishing || cachedMalware) {
            cacheHit = true
            score = maxOf(score, 92)
            findings += SecurityFinding(
                title = if (cachedMalware) "Matched malware URL feed" else "Matched phishing URL feed",
                description = "URL matched locally cached threat intelligence feed (PhishTank / OpenPhish / URLhaus).",
                severity = FindingSeverity.CRITICAL,
                evidenceSource = "UnifiedUrlThreatCache",
                detectionMethod = "Exact & Prefix Feed Lookup",
                inputLocation = normalized,
                explanation = "This URL has been reported in public phishing/malware feeds synced to the local cache.",
                recommendedAction = "Block access and do not open this link."
            )
        } else if (threatCache.getCachedCount() == 0) {
            limitations += "Local phishing/malware feed cache is currently empty (0 cached entries); sync feeds online to populate it."
        }

        // 5. Optional live HTTP redirect + TLS certificate check
        var redirectInspection = RedirectInspection(attempted = false, succeeded = false)
        var tlsInspection = LiveTlsInspection(attempted = false, succeeded = false, certificateValid = null)
        var anyNetworkFailure = false

        if (allowNetworkProbe) {
            methods += "Live HTTP Redirect Chain Resolution (max 5 hops)"
            redirectInspection = traceRedirects(normalized, customSslSocketFactory, customHostnameVerifier)
            if (!redirectInspection.succeeded && redirectInspection.error != null) {
                anyNetworkFailure = true
                limitations += "Redirect resolution incomplete: ${redirectInspection.error}"
            }
            if (redirectInspection.crossDomainRedirect) {
                score = (score + 25).coerceAtMost(100)
                findings += SecurityFinding(
                    title = "Cross-domain HTTP redirect",
                    description = "URL redirects from '$asciiHost' across domain(s) to '${redirectInspection.finalUrl}'.",
                    severity = FindingSeverity.MEDIUM,
                    evidenceSource = "Live HTTP Redirect Tracer",
                    detectionMethod = "HTTP Location Header Following",
                    inputLocation = redirectInspection.finalUrl,
                    explanation = "Link shorteners or compromised redirectors conceal the true landing domain.",
                    recommendedAction = "Inspect the final landing domain before opening."
                )
            }

            // Re-check final resolved destination against threat cache and safety engine!
            val finalUrl = redirectInspection.finalUrl
            if (!finalUrl.isNullOrBlank() && finalUrl != normalized) {
                if (threatCache.isUrlKnownThreat(finalUrl)) {
                    cacheHit = true
                    score = maxOf(score, 95)
                    findings += SecurityFinding(
                        title = "Redirect destination matched threat feed",
                        description = "Final destination '$finalUrl' matched known phishing/malware feed.",
                        severity = FindingSeverity.CRITICAL,
                        evidenceSource = "UnifiedUrlThreatCache",
                        detectionMethod = "Post-Redirect Feed Lookup",
                        inputLocation = finalUrl,
                        explanation = "The initial link forwards users to a flagged malicious destination.",
                        recommendedAction = "Do not open this link."
                    )
                }
                val destAnalysis = urlSafetyEngine.analyzeUrl(finalUrl)
                val combinedDestScore = (destAnalysis.riskScore + if (redirectInspection.crossDomainRedirect) 25 else 0).coerceAtMost(100)
                if (combinedDestScore > score || destAnalysis.threats.isNotEmpty()) {
                    score = maxOf(score, combinedDestScore)
                    destAnalysis.threats.forEach { t ->
                        findings += SecurityFinding(
                            title = "Destination ${t.type.replace('_', ' ')}",
                            description = "Final destination ($finalUrl): ${t.description}",
                            severity = FindingSeverity.HIGH,
                            evidenceSource = "UrlSafetyEngine (Post-Redirect)",
                            detectionMethod = "Final Destination Heuristic Inspection",
                            inputLocation = finalUrl,
                            explanation = t.description,
                            recommendedAction = "Avoid the final destination."
                        )
                    }
                }
            }

            val tlsTarget = (finalUrl ?: normalized).takeIf { it.startsWith("https://", ignoreCase = true) }
            if (tlsTarget != null) {
                methods += "Live TLS X.509 Certificate Verification"
                tlsInspection = inspectTlsCertificate(tlsTarget, customSslSocketFactory, customHostnameVerifier)
                if (!tlsInspection.succeeded) {
                    anyNetworkFailure = true
                    if (tlsInspection.certificateValid == false) {
                        score = (score + 40).coerceAtMost(100)
                        findings += SecurityFinding(
                            title = "TLS certificate validation failed",
                            description = tlsInspection.error ?: "HTTPS handshake rejected untrusted or mismatched certificate.",
                            severity = FindingSeverity.HIGH,
                            evidenceSource = "HttpsURLConnection X.509",
                            detectionMethod = "TLS Handshake & Trust Verification",
                            inputLocation = tlsTarget,
                            explanation = "Untrusted, expired, self-signed, or hostname-mismatched certificates prevent authentic identity verification.",
                            recommendedAction = "Do not proceed or submit credentials on this site."
                        )
                    } else {
                        limitations += "Live TLS inspection failed: ${tlsInspection.error}"
                    }
                } else {
                    if (tlsInspection.selfSigned == true) {
                        score = (score + 30).coerceAtMost(100)
                        findings += SecurityFinding(
                            title = "Self-signed TLS certificate",
                            description = "Certificate subject equals issuer (${tlsInspection.issuer}).",
                            severity = FindingSeverity.HIGH,
                            evidenceSource = "X509Certificate",
                            detectionMethod = "Subject/Issuer Comparison",
                            inputLocation = tlsTarget,
                            explanation = "Legitimate public services rarely use self-signed leaf certificates directly.",
                            recommendedAction = "Do not trust this server without independent verification."
                        )
                    }
                    val notAfter = tlsInspection.notAfterMs
                    if (notAfter != null && notAfter < System.currentTimeMillis()) {
                        score = (score + 35).coerceAtMost(100)
                        findings += SecurityFinding(
                            title = "Expired TLS certificate",
                            description = "Certificate expired at epoch $notAfter.",
                            severity = FindingSeverity.HIGH,
                            evidenceSource = "X509Certificate",
                            detectionMethod = "Validity Window Check",
                            inputLocation = tlsTarget,
                            explanation = "Expired certificates fail cryptographic validity checks.",
                            recommendedAction = "Avoid entering sensitive data."
                        )
                    }
                }
            }
        } else {
            limitations += "Offline inspection mode: live HTTP redirects and X.509 TLS certificate handshake were not probed."
        }

        val finalScore = score.coerceIn(0, 100)
        val status = if (allowNetworkProbe && anyNetworkFailure) AnalysisStatus.PARTIAL else AnalysisStatus.COMPLETED
        val verdict = when {
            finalScore >= 75 -> SecurityVerdict.MALICIOUS
            finalScore >= 55 -> SecurityVerdict.HIGH_RISK
            finalScore >= 30 -> SecurityVerdict.SUSPICIOUS
            status == AnalysisStatus.PARTIAL -> SecurityVerdict.INCONCLUSIVE
            finalScore >= 15 -> SecurityVerdict.LOW_RISK
            else -> SecurityVerdict.SAFE
        }

        val metadata = linkedMapOf(
            "normalizedUrl" to normalized,
            "asciiHost" to asciiHost,
            "unicodeHost" to unicodeHost,
            "cacheCount" to threatCache.getCachedCount().toString(),
            "cacheHit" to cacheHit.toString()
        )
        punycodeDecoded?.let { metadata["punycodeDecoded"] = it }
        tlsInspection.issuer?.let { metadata["tlsIssuer"] = it }
        redirectInspection.finalUrl?.let { metadata["finalUrl"] = it }

        val analysisResult = SecurityAnalysisResult(
            analysisId = analysisId,
            module = SecurityModule.PHISHING_URL_SCAN,
            inputName = trimmed,
            inputType = "url",
            status = status,
            verdict = verdict,
            riskScore = finalScore,
            confidence = null, // Heuristic/rule + feed check; never report fabricated ML probability
            findings = findings,
            analysisMethods = methods,
            limitations = limitations,
            processingDurationMs = System.currentTimeMillis() - startedAt,
            analyzedAt = System.currentTimeMillis(),
            modelVersion = null,
            errorMessage = if (status == AnalysisStatus.PARTIAL) "Offline/network checks partially incomplete" else null,
            metadata = metadata
        )

        UrlInspectionReport(
            analysisResult = analysisResult,
            normalizedUrl = normalized,
            asciiHost = asciiHost,
            unicodeHost = unicodeHost,
            punycodeDecoded = punycodeDecoded,
            tlsInspection = tlsInspection,
            redirectInspection = redirectInspection,
            localCacheMatch = cacheHit,
            cacheEntryCount = threatCache.getCachedCount(),
            cacheLastUpdatedAt = threatCache.getLastUpdatedAt()
        )
    }

    private fun traceRedirects(
        startUrl: String,
        customSslSocketFactory: SSLSocketFactory?,
        customHostnameVerifier: HostnameVerifier?
    ): RedirectInspection {
        val chain = mutableListOf(startUrl)
        var current = startUrl
        val startHost = runCatching { URL(startUrl).host.lowercase() }.getOrDefault("")
        return try {
            var lastCode: Int? = null
            for (hop in 0 until 5) {
                val conn = openHttpConnection(current, customSslSocketFactory, customHostnameVerifier)
                try {
                    conn.requestMethod = "HEAD"
                    conn.instanceFollowRedirects = false
                    conn.connectTimeout = 6_000
                    conn.readTimeout = 6_000
                    conn.setRequestProperty("User-Agent", "SentinelForensics/1.0")
                    var code = conn.responseCode
                    if (code == 405) {
                        conn.disconnect()
                        val getConn = openHttpConnection(current, customSslSocketFactory, customHostnameVerifier)
                        try {
                            getConn.requestMethod = "GET"
                            getConn.instanceFollowRedirects = false
                            getConn.connectTimeout = 6_000
                            getConn.readTimeout = 6_000
                            code = getConn.responseCode
                            lastCode = code
                            val loc = getConn.getHeaderField("Location")
                            if (code in 300..399 && !loc.isNullOrBlank()) {
                                val next = URL(URL(current), loc).toString()
                                if (chain.contains(next)) {
                                    return RedirectInspection(
                                        attempted = true,
                                        succeeded = true,
                                        chain = chain,
                                        finalUrl = next,
                                        finalStatusCode = code,
                                        crossDomainRedirect = crossDomain(startHost, next),
                                        error = "Redirect loop detected"
                                    )
                                }
                                chain += next
                                current = next
                                continue
                            }
                            return RedirectInspection(
                                attempted = true,
                                succeeded = true,
                                chain = chain,
                                finalUrl = current,
                                finalStatusCode = code,
                                crossDomainRedirect = crossDomain(startHost, current)
                            )
                        } finally {
                            getConn.disconnect()
                        }
                    }
                    lastCode = code
                    val loc = conn.getHeaderField("Location")
                    if (code in 300..399 && !loc.isNullOrBlank()) {
                        val next = URL(URL(current), loc).toString()
                        if (chain.contains(next)) {
                            return RedirectInspection(
                                attempted = true,
                                succeeded = true,
                                chain = chain,
                                finalUrl = next,
                                finalStatusCode = code,
                                crossDomainRedirect = crossDomain(startHost, next),
                                error = "Redirect loop detected"
                            )
                        }
                        chain += next
                        current = next
                    } else {
                        return RedirectInspection(
                            attempted = true,
                            succeeded = true,
                            chain = chain,
                            finalUrl = current,
                            finalStatusCode = code,
                            crossDomainRedirect = crossDomain(startHost, current)
                        )
                    }
                } finally {
                    conn.disconnect()
                }
            }
            RedirectInspection(
                attempted = true,
                succeeded = true,
                chain = chain,
                finalUrl = current,
                finalStatusCode = lastCode,
                crossDomainRedirect = crossDomain(startHost, current),
                error = "Exceeded 5 redirect hops"
            )
        } catch (e: Exception) {
            RedirectInspection(
                attempted = true,
                succeeded = false,
                chain = chain,
                finalUrl = current,
                crossDomainRedirect = crossDomain(startHost, current),
                error = e.message ?: e::class.java.simpleName
            )
        }
    }

    private fun inspectTlsCertificate(
        httpsUrl: String,
        customSslSocketFactory: SSLSocketFactory?,
        customHostnameVerifier: HostnameVerifier?
    ): LiveTlsInspection {
        var conn: HttpsURLConnection? = null
        return try {
            conn = openHttpConnection(httpsUrl, customSslSocketFactory, customHostnameVerifier) as HttpsURLConnection
            conn.requestMethod = "HEAD"
            conn.connectTimeout = 6_000
            conn.readTimeout = 6_000
            conn.connect()
            val certs = conn.serverCertificates
            val leaf = certs.firstOrNull() as? X509Certificate
            if (leaf == null) {
                LiveTlsInspection(
                    attempted = true,
                    succeeded = false,
                    certificateValid = false,
                    error = "Server returned no X.509 certificate"
                )
            } else {
                val sans = runCatching {
                    leaf.subjectAlternativeNames?.mapNotNull { entry ->
                        entry.getOrNull(1)?.toString()
                    }.orEmpty()
                }.getOrDefault(emptyList())
                val subject = leaf.subjectX500Principal?.name
                val issuer = leaf.issuerX500Principal?.name
                val now = System.currentTimeMillis()
                val withinWindow = now in leaf.notBefore.time..leaf.notAfter.time
                LiveTlsInspection(
                    attempted = true,
                    succeeded = true,
                    certificateValid = withinWindow,
                    issuer = issuer,
                    subject = subject,
                    sanHostnames = sans,
                    notBeforeMs = leaf.notBefore.time,
                    notAfterMs = leaf.notAfter.time,
                    selfSigned = subject != null && subject == issuer
                )
            }
        } catch (e: SSLHandshakeException) {
            LiveTlsInspection(
                attempted = true,
                succeeded = false,
                certificateValid = false,
                error = "TLS handshake failed: ${e.message ?: "untrusted certificate"}"
            )
        } catch (e: IOException) {
            LiveTlsInspection(
                attempted = true,
                succeeded = false,
                certificateValid = null,
                error = "Network connection failed: ${e.message ?: e::class.java.simpleName}"
            )
        } catch (e: Exception) {
            LiveTlsInspection(
                attempted = true,
                succeeded = false,
                certificateValid = null,
                error = e.message ?: e::class.java.simpleName
            )
        } finally {
            conn?.disconnect()
        }
    }

    private fun openHttpConnection(
        url: String,
        customSslSocketFactory: SSLSocketFactory?,
        customHostnameVerifier: HostnameVerifier?
    ): HttpURLConnection {
        val conn = URL(url).openConnection(com.deepfakeshield.core.network.TorNetworkModule.getProxy()) as HttpURLConnection
        if (conn is HttpsURLConnection) {
            if (customSslSocketFactory != null) conn.sslSocketFactory = customSslSocketFactory
            if (customHostnameVerifier != null) conn.hostnameVerifier = customHostnameVerifier
        }
        return conn
    }

    private fun crossDomain(startHost: String, finalUrl: String): Boolean {
        val endHost = runCatching { URL(finalUrl).host.lowercase() }.getOrDefault("")
        return endHost.isNotBlank() && startHost.isNotBlank() && endHost != startHost && !endHost.endsWith(".$startHost")
    }

    private fun failureReport(
        analysisId: String,
        inputName: String,
        startedAt: Long,
        verdict: SecurityVerdict,
        error: String,
        findings: List<SecurityFinding>
    ): UrlInspectionReport {
        val result = SecurityAnalysisResult(
            analysisId = analysisId,
            module = SecurityModule.PHISHING_URL_SCAN,
            inputName = inputName,
            inputType = "url",
            status = AnalysisStatus.FAILED,
            verdict = verdict,
            riskScore = null,
            confidence = null,
            findings = findings,
            analysisMethods = listOf("URI Validation"),
            limitations = listOf(error),
            processingDurationMs = System.currentTimeMillis() - startedAt,
            analyzedAt = System.currentTimeMillis(),
            modelVersion = null,
            errorMessage = error
        )
        return UrlInspectionReport(
            analysisResult = result,
            normalizedUrl = inputName,
            asciiHost = "",
            unicodeHost = "",
            punycodeDecoded = null,
            tlsInspection = LiveTlsInspection(attempted = false, succeeded = false, certificateValid = null, error = error),
            redirectInspection = RedirectInspection(attempted = false, succeeded = false, error = error),
            localCacheMatch = false,
            cacheEntryCount = threatCache.getCachedCount(),
            cacheLastUpdatedAt = threatCache.getLastUpdatedAt()
        )
    }
}

