package com.deepfakeshield.av.engine

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.util.Log
import androidx.core.content.pm.PackageInfoCompat
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
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import java.io.File
import java.io.InputStream
import java.io.RandomAccessFile
import java.security.MessageDigest
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong
import java.util.zip.ZipEntry
import java.util.zip.ZipFile
import java.util.zip.ZipInputStream
import javax.inject.Inject
import javax.inject.Singleton

data class AvEngineStats(
    val totalHashSignatures: Int,
    val bundledHashCount: Int,
    val downloadedHashCount: Int,
    val bytePatternCount: Int,
    val yaraRuleCount: Int,
    val heuristicIndicatorCount: Int
)

/**
 * FULL-BLOWN ANTIVIRUS ENGINE
 *
 * Industry-leading AV capabilities:
 * - Signature-based malware detection (MD5/SHA256 of known malware, byte patterns)
 * - Heuristic detection (suspicious behavior, permissions, structure)
 * - PUA/PUP detection (Potentially Unwanted Applications)
 * - Ransomware pattern detection
 * - Trojan/backdoor indicators
 * - Adware/Spyware detection
 * - Real-time + on-demand scanning
 */
@Singleton
class AntivirusEngine @Inject constructor(
    @ApplicationContext private val context: Context,
    private val signatureDb: MalwareSignatureDatabase,
    private val heuristicAnalyzer: HeuristicMalwareAnalyzer,
    private val cloudHashChecker: CloudHashChecker,
    val yaraEngine: YaraRuleEngine
) {

    companion object {
        private const val TAG = "AntivirusEngine"
        private const val STREAM_BUFFER_SIZE = 64 * 1024
        private const val SCAN_CACHE_FILE = "av_scan_cache_v1.txt"
        private const val MAX_CACHE_ENTRIES = 2000
        private const val MAX_SCAN_DIR_FILES = 2000
        private const val MAX_ARCHIVE_ENTRIES = 20_000
        private const val PROGRESS_THROTTLE_MS = 80L
        private val HEX_CHARS = charArrayOf(
            '0', '1', '2', '3', '4', '5', '6', '7',
            '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'
        )

        const val SCAN_TYPE_REALTIME = "realtime"
        const val SCAN_TYPE_ONDEMAND = "ondemand"
        const val SCAN_TYPE_SCHEDULED = "scheduled"
        const val SCAN_TYPE_APP = "app"
        const val SCAN_TYPE_FILE = "file"
        
        // Files/directories that belong to the AV engine itself — must never be scanned.
        // Delegates to the centralized AvExclusions to stay in sync with RealTimeAvMonitor.

        // Patterns that are genuinely suspicious and NOT common in legitimate apps.
        // Words like "port", "sms", "call", "login", "connect", "android", "session",
        // "location", "contacts", "camera" etc. appear in virtually EVERY app and must be excluded.
        private val HIGH_SPECIFICITY_PATTERNS = setOf(
            "metasploit", "exploit", "payload", "stealer", "keylogger", "backdoor",
            "reverse", "c2", "beacon", "implant", "botnet", "ddos",
            "ransom", "ransomware_note", "pay_ransom_note", "your_files_encrypted",
            "decrypt_instructions", "ransom_note", "encrypted_ext", "locked_ext",
            "xhook", "substrate", "frida", "plt_hook", "got_hook",
            "bin_sh", "root_shell", "netcat", "xmrig", "stratum",
            "proc_self", "syscall", "stealth", "unhook",
            "PE_executable", "ELF_executable", "kill_shellcode",
            "trojan", "worm", "virus", "rat", "remote_admin",
            "perm_abuse", "vibe_exploit"
        )
    }

    private data class ScanCacheEntry(
        val key: String,
        val versionCode: Long,
        val updateTime: Long,
        val lastModified: Long,
        val fileSize: Long,
        val dbStamp: String,
        val sha256: String,
        val displayName: String,
        val isApp: Boolean
    )

    private val cleanScanCache = ConcurrentHashMap<String, ScanCacheEntry>()
    @Volatile
    private var cacheLoaded = false
    private val cacheIoLock = Any()

    fun clearScanCache() {
        cleanScanCache.clear()
        runCatching { File(context.filesDir, SCAN_CACHE_FILE).delete() }
    }

    fun getEngineStats(): AvEngineStats = AvEngineStats(
        totalHashSignatures = signatureDb.getHashCount(),
        bundledHashCount = signatureDb.bundledHashCount,
        downloadedHashCount = signatureDb.downloadedHashCount,
        bytePatternCount = signatureDb.getBytePatternCount(),
        yaraRuleCount = yaraEngine.getRuleCount(),
        heuristicIndicatorCount = heuristicAnalyzer.getHeuristicRuleGroupCount()
    )

    suspend fun scanUri(
        uri: Uri,
        displayName: String? = null,
        scanType: String = SCAN_TYPE_FILE
    ): AvScanResult = withContext(Dispatchers.IO) {
        val startTime = System.currentTimeMillis()
        val label = displayName ?: uri.lastPathSegment ?: uri.toString()
        val tempDir = File(context.cacheDir, "av_uri_scan").apply { mkdirs() }
        val suffix = label.substringAfterLast('.', "").takeIf { it.isNotBlank() && it.length <= 10 }?.let { ".$it" } ?: ".bin"
        val tempFile = File.createTempFile("scan_", suffix, tempDir)
        try {
            val stream = context.contentResolver.openInputStream(uri)
                ?: return@withContext AvScanResult.ERROR(
                    path = uri.toString(),
                    scanType = scanType,
                    displayName = label,
                    durationMs = System.currentTimeMillis() - startTime,
                    error = "Could not open content URI stream"
                )
            stream.use { input ->
                tempFile.outputStream().use { out ->
                    input.copyTo(out)
                }
            }
            if (tempFile.length() == 0L) {
                return@withContext AvScanResult.ERROR(
                    path = uri.toString(),
                    scanType = scanType,
                    displayName = label,
                    durationMs = System.currentTimeMillis() - startTime,
                    error = "File is empty (0 bytes)"
                )
            }
            val result = scanFile(tempFile.absolutePath, uri, scanType)
            result.copy(path = uri.toString(), displayName = label)
        } catch (e: Exception) {
            AvScanResult.ERROR(
                path = uri.toString(),
                scanType = scanType,
                displayName = label,
                durationMs = System.currentTimeMillis() - startTime,
                error = e.message ?: "Failed to read URI"
            )
        } finally {
            runCatching { tempFile.delete() }
        }
    }

    /**
     * Scan a file for malware
     */
    private data class SinglePassReadResult(
        val sha256: String,
        val patternMatches: List<String>,
        val yaraMatches: List<YaraRuleEngine.YaraMatch>,
        val headerBytes: ByteArray?
    )

    private suspend fun performSinglePassFileRead(
        file: File,
        includeByteAndYara: Boolean,
        readHeader: Boolean
    ): SinglePassReadResult {
        val digest = MessageDigest.getInstance("SHA-256")
        val fileLen = file.length()
        val sigSession = if (includeByteAndYara && fileLen in 1L..(100L * 1024 * 1024)) {
            signatureDb.createByteScanSession()
        } else null
        val yaraEvaluator = if (includeByteAndYara && fileLen > 0L) {
            yaraEngine.createStreamEvaluator(YaraRuleEngine.DEFAULT_MAX_BYTES)
        } else null
        val headerBuf = if (readHeader && fileLen > 1024L) ByteArray(4096) else null
        var headerFilled = 0
        var totalBytesRead = 0L

        file.inputStream().buffered(STREAM_BUFFER_SIZE).use { input ->
            val buffer = ByteArray(STREAM_BUFFER_SIZE)
            while (true) {
                currentCoroutineContext().ensureActive()
                val read = input.read(buffer)
                if (read <= 0) break
                digest.update(buffer, 0, read)

                if (headerBuf != null && headerFilled < headerBuf.size) {
                    val copyLen = minOf(read, headerBuf.size - headerFilled)
                    System.arraycopy(buffer, 0, headerBuf, headerFilled, copyLen)
                    headerFilled += copyLen
                }

                if (sigSession != null && totalBytesRead < MalwareSignatureDatabase.MAX_BYTE_PATTERN_SCAN_BYTES) {
                    val sigSlice = minOf(
                        read.toLong(),
                        MalwareSignatureDatabase.MAX_BYTE_PATTERN_SCAN_BYTES - totalBytesRead
                    ).toInt()
                    if (sigSlice > 0) sigSession.update(buffer, 0, sigSlice)
                }

                if (yaraEvaluator != null && totalBytesRead < YaraRuleEngine.DEFAULT_MAX_BYTES) {
                    val yaraSlice = minOf(
                        read.toLong(),
                        YaraRuleEngine.DEFAULT_MAX_BYTES - totalBytesRead
                    ).toInt()
                    if (yaraSlice > 0) yaraEvaluator.update(buffer, 0, yaraSlice)
                }

                totalBytesRead += read
            }
        }

        val sha256 = sha256ToHex(digest.digest())
        val patterns = sigSession?.matchedLabels()?.distinct().orEmpty()
        val yaraMatches = try {
            yaraEvaluator?.finish { readBoundedFileBytes(file, YaraRuleEngine.DEFAULT_MAX_BYTES) }.orEmpty()
        } catch (_: Exception) {
            emptyList()
        }
        val finalHeader = if (headerBuf != null && headerFilled > 0) {
            if (headerFilled < headerBuf.size) headerBuf.copyOf(headerFilled) else headerBuf
        } else null

        return SinglePassReadResult(
            sha256 = sha256,
            patternMatches = patterns,
            yaraMatches = yaraMatches,
            headerBytes = finalHeader
        )
    }

    private fun readBoundedFileBytes(file: File, maxBytes: Long): ByteArray? {
        val len = minOf(file.length(), maxBytes).toInt()
        if (len <= 0) return null
        return ByteArray(len).also { buf ->
            RandomAccessFile(file, "r").use { raf -> raf.readFully(buf) }
        }
    }

    private fun sha256ToHex(bytes: ByteArray): String {
        val chars = CharArray(bytes.size * 2)
        for (i in bytes.indices) {
            val v = bytes[i].toInt() and 0xFF
            chars[i * 2] = HEX_CHARS[v ushr 4]
            chars[i * 2 + 1] = HEX_CHARS[v and 0x0F]
        }
        return String(chars)
    }

    @Suppress("UNUSED_PARAMETER")
    suspend fun scanFile(
        filePath: String,
        _fileUri: Uri? = null,
        scanType: String = SCAN_TYPE_REALTIME
    ): AvScanResult = withContext(Dispatchers.IO) {
        scanFileInternal(File(filePath), filePath, scanType)
    }

    private suspend fun scanFileInternal(
        file: File,
        filePath: String,
        scanType: String
    ): AvScanResult {
        val startTime = System.currentTimeMillis()
        val indicators = mutableListOf<AvIndicator>()
        var threatLevel = ThreatLevel.CLEAN
        var detectedThreat: String? = null

        try {
            if (!file.exists() || !file.isFile || !file.canRead()) {
                return AvScanResult.ERROR(
                    path = filePath,
                    scanType = scanType,
                    displayName = file.name.ifBlank { filePath },
                    durationMs = System.currentTimeMillis() - startTime,
                    error = if (!file.exists()) "File not found" else "File is unreadable or not a regular file"
                )
            }

            // Skip our own data files — the hash database contains malware signatures
            // and will obviously match pattern/signature scans. Quarantine dir contains
            // XOR-obfuscated malware copies that would also trigger detections.
            if (isOwnDataFile(file)) {
                return AvScanResult.CLEAN(filePath, scanType, file.name, 0)
            }

            // 1. Single-pass streaming inspection: SHA-256 + byte patterns + YARA + 4 KB entropy header
            val streamOut = performSinglePassFileRead(
                file = file,
                includeByteAndYara = true,
                readHeader = file.length() > 1024L
            )
            val fileHash = streamOut.sha256

            val signatureMatch = signatureDb.lookupHash(fileHash)
            if (signatureMatch != null) {
                indicators.add(AvIndicator(
                    type = AvIndicatorType.SIGNATURE,
                    severity = AvSeverity.CRITICAL,
                    title = "Known Malware Detected",
                    description = "File matches known malware signature: $signatureMatch",
                    evidence = fileHash
                ))
                threatLevel = ThreatLevel.INFECTED
                detectedThreat = signatureMatch
            }

            // 2. Byte pattern scan - only flag HIGH-SPECIFICITY patterns
            // Common words like "port", "sms", "login" match every legitimate app, so
            // we only treat byte patterns as meaningful when many high-specificity ones match.
            // Legitimate apps will match 5-15 generic patterns; true malware matches 20+.
            val highSpecificityPatterns = streamOut.patternMatches.filter { name ->
                name in HIGH_SPECIFICITY_PATTERNS
            }
            for (pm in highSpecificityPatterns) {
                indicators.add(AvIndicator(
                    type = AvIndicatorType.SIGNATURE,
                    severity = if (highSpecificityPatterns.size >= 5) AvSeverity.HIGH else AvSeverity.MEDIUM,
                    title = "Suspicious Pattern",
                    description = "File contains suspicious byte pattern: $pm",
                    evidence = pm
                ))
            }
            if (highSpecificityPatterns.isNotEmpty() && threatLevel == ThreatLevel.CLEAN) {
                val primaryMatch = highSpecificityPatterns.first()
                threatLevel = when {
                    highSpecificityPatterns.size >= 25 -> ThreatLevel.INFECTED
                    highSpecificityPatterns.size >= 18 -> ThreatLevel.SUSPICIOUS
                    highSpecificityPatterns.size >= 12 -> ThreatLevel.LOW_RISK
                    else -> ThreatLevel.CLEAN
                }
                if (threatLevel != ThreatLevel.CLEAN) {
                    detectedThreat = if (highSpecificityPatterns.size > 1) "$primaryMatch+${highSpecificityPatterns.size - 1}more" else primaryMatch
                }
            }

            // 3. Heuristic analysis (reuses headerBytes captured during stream pass)
            val heuristicResult = heuristicAnalyzer.analyzeFile(file, filePath, streamOut.headerBytes)
            indicators.addAll(heuristicResult.indicators)
            if (heuristicResult.threatLevel.ordinal > threatLevel.ordinal) {
                threatLevel = heuristicResult.threatLevel
                if (detectedThreat == null) detectedThreat = heuristicResult.threatName
            }

            // 4. YARA rule matching (already evaluated in single pass)
            for (match in streamOut.yaraMatches) {
                indicators.add(AvIndicator(
                    type = AvIndicatorType.HEURISTIC,
                    severity = when (match.rule.severity) { "CRITICAL" -> AvSeverity.CRITICAL; "HIGH" -> AvSeverity.HIGH; else -> AvSeverity.MEDIUM },
                    title = "YARA: ${match.rule.name}",
                    description = "${match.rule.description} [${match.rule.family}]",
                    evidence = "Matched: ${match.matchedStrings.joinToString(", ")}"
                ))
                val yaraLevel = when (match.rule.severity) { "CRITICAL" -> ThreatLevel.INFECTED; "HIGH" -> ThreatLevel.SUSPICIOUS; else -> ThreatLevel.PUA }
                if (yaraLevel.ordinal > threatLevel.ordinal) { threatLevel = yaraLevel; detectedThreat = "YARA/${match.rule.family}" }
            }

            // 5. For APK/ZIP: inspect Central Directory entries without decompressing contents
            val lowerPath = filePath.lowercase()
            if (lowerPath.endsWith(".apk") || lowerPath.endsWith(".zip")) {
                val archiveResult = scanArchiveForMalware(file)
                indicators.addAll(archiveResult.indicators)
                if (archiveResult.threatLevel.ordinal > threatLevel.ordinal) {
                    threatLevel = archiveResult.threatLevel
                    detectedThreat = archiveResult.threatName
                }
            }

            val duration = System.currentTimeMillis() - startTime
            return AvScanResult(
                path = filePath,
                scanType = scanType,
                displayName = file.name,
                durationMs = duration,
                threatLevel = threatLevel,
                threatName = detectedThreat,
                indicators = indicators,
                fileSize = file.length(),
                fileHash = fileHash
            )
        } catch (e: kotlinx.coroutines.CancellationException) {
            throw e
        } catch (e: Exception) {
            Log.e(TAG, "Scan failed for $filePath", e)
            return AvScanResult.ERROR(filePath, scanType, File(filePath).name, System.currentTimeMillis() - startTime, e.message ?: "Unknown error")
        }
    }

    /**
     * Packages from major, trusted publishers.
     * These apps are from Google Play / major companies. We still do a hash
     * (signature) check to catch supply-chain compromises, but skip heuristics
     * because their permission profiles WILL trigger false positives.
     */
    private val trustedPublisherPrefixes = setOf(
        "com.deepfakeshield",
        "com.google.", "com.android.", "com.samsung.", "com.sec.android.",
        "com.spotify.", "com.netflix.", "com.whatsapp", "com.facebook.",
        "com.instagram.", "com.twitter.", "com.snapchat.", "com.discord",
        "com.microsoft.", "com.apple.", "com.amazon.", "com.ebay.",
        "org.telegram.", "com.paypal.", "com.ubercab.", "com.linkedin.",
        "com.pinterest.", "com.reddit.", "tv.twitch.", "com.zhiliaoapp.",
        "com.viber.", "jp.naver.line.", "com.tencent.", "com.adobe.",
        "com.slack", "us.zoom.", "com.dropbox.", "com.evernote.",
        "com.booking.", "com.airbnb.", "com.duolingo", "com.pandora.",
        "com.soundcloud.", "com.shazam.", "com.hbo.", "com.disney.",
        "com.squareup.", "com.venmo", "com.grubhub.", "com.dd.doordash",
        "com.imo.", "com.skype.", "org.mozilla.", "com.brave.",
        "com.opera.", "com.duckduckgo.",
    )

    /**
     * Scan installed app (APK) for malware.
     *
     * B2C-SAFE: For known trusted publishers, only do hash-based signature
     * checks (catches actual malware) but skip heuristic analysis (avoids
     * false positives on permission combos that legitimate apps need).
     */
    suspend fun scanInstalledApp(
        packageName: String,
        scanType: String = SCAN_TYPE_APP
    ): AvScanResult = withContext(Dispatchers.IO) {
        try {
            val pm = context.packageManager
            val appInfo = pm.getApplicationInfo(packageName, 0)
            scanInstalledAppInfo(pm, appInfo, packageName, scanType)
        } catch (e: kotlinx.coroutines.CancellationException) {
            throw e
        } catch (e: Exception) {
            Log.e(TAG, "App scan failed for $packageName", e)
            AvScanResult.ERROR(packageName, scanType, packageName, 0L, e.message ?: "Unknown error")
        }
    }

    private suspend fun scanInstalledAppInfo(
        pm: PackageManager,
        appInfo: ApplicationInfo,
        packageName: String,
        scanType: String,
        knownAppName: String? = null
    ): AvScanResult {
        val startTime = System.currentTimeMillis()
        val indicators = mutableListOf<AvIndicator>()
        var threatLevel = ThreatLevel.CLEAN
        var detectedThreat: String? = null

        try {
            val appName = knownAppName ?: runCatching { pm.getApplicationLabel(appInfo).toString() }.getOrDefault(packageName)
            val sourceDir = appInfo.sourceDir
            val sourceFile = if (!sourceDir.isNullOrBlank()) File(sourceDir) else null
            if (sourceFile == null || !sourceFile.exists() || !sourceFile.canRead()) {
                return AvScanResult.ERROR(
                    path = packageName,
                    scanType = scanType,
                    displayName = appName,
                    durationMs = System.currentTimeMillis() - startTime,
                    error = "APK path unavailable or unreadable"
                )
            }

            val isTrusted = trustedPublisherPrefixes.any { packageName.startsWith(it) }
            val fileHash: String

            if (isTrusted) {
                // Trusted publishers: fast single-pass hash verification without redundant reads/heuristics
                fileHash = computeFileHash(sourceFile)
                val signatureMatch = signatureDb.lookupHash(fileHash)
                if (signatureMatch != null) {
                    indicators.add(AvIndicator(
                        type = AvIndicatorType.SIGNATURE,
                        severity = AvSeverity.CRITICAL,
                        title = "Known Malware Detected",
                        description = "APK matches known malware: $signatureMatch",
                        evidence = fileHash
                    ))
                    threatLevel = ThreatLevel.INFECTED
                    detectedThreat = signatureMatch
                }
            } else {
                // Single-pass scanFileInternal handles SHA-256 + patterns + YARA + ZipFile ONCE
                // (eliminates duplicate full-APK hash reads).
                val fileResult = scanFileInternal(sourceFile, sourceDir!!, scanType)
                if (fileResult.isScanError) {
                    return AvScanResult.ERROR(
                        path = packageName,
                        scanType = scanType,
                        displayName = appName,
                        durationMs = System.currentTimeMillis() - startTime,
                        error = fileResult.threatName ?: "Failed to read APK"
                    )
                }
                fileHash = fileResult.fileHash ?: computeFileHash(sourceFile)
                indicators.addAll(fileResult.indicators)
                if (fileResult.threatLevel.ordinal > threatLevel.ordinal) {
                    threatLevel = fileResult.threatLevel
                    detectedThreat = fileResult.threatName
                }

                val appHeuristic = heuristicAnalyzer.analyzeInstalledApp(context, packageName, appInfo)
                indicators.addAll(appHeuristic.indicators)
                if (appHeuristic.threatLevel.ordinal > threatLevel.ordinal) {
                    threatLevel = appHeuristic.threatLevel
                    detectedThreat = appHeuristic.threatName
                }
            }

            val duration = System.currentTimeMillis() - startTime
            return AvScanResult(
                path = packageName,
                scanType = scanType,
                displayName = appName,
                durationMs = duration,
                threatLevel = threatLevel,
                threatName = detectedThreat,
                indicators = indicators,
                fileSize = sourceFile.length(),
                fileHash = fileHash,
                isApp = true,
                packageName = packageName
            )
        } catch (e: kotlinx.coroutines.CancellationException) {
            throw e
        } catch (e: Exception) {
            Log.e(TAG, "App scan failed for $packageName", e)
            return AvScanResult.ERROR(packageName, scanType, knownAppName ?: packageName, System.currentTimeMillis() - startTime, e.message ?: "Unknown error")
        }
    }

    private sealed class ScanWorkItem {
        data class AppTarget(
            val packageName: String,
            val appName: String,
            val appInfo: ApplicationInfo,
            val sourceFile: File?,
            val versionCode: Long,
            val lastUpdateTime: Long
        ) : ScanWorkItem()

        data class FileTarget(val file: File) : ScanWorkItem()
    }

    suspend fun runFullScan(
        scanType: String = SCAN_TYPE_ONDEMAND,
        onProgress: (suspend (scanned: Int, total: Int, current: String) -> Unit)? = null
    ): List<AvScanResult> = runFullScan(scanType = scanType, forceRescan = false, onProgress = onProgress)

    /**
     * Asynchronous bounded full device scan:
     * - Enumerates non-system APKs (without bloated meta-data bundles) + accessible storage files.
     * - Runs up to 3 parallel Dispatchers.IO workers with O(n) single-pass scanning.
     * - Skips re-hashing unchanged previously-CLEAN items unless [forceRescan] is true or
     *   signatures/YARA/heuristics have changed (AVG/Avast Smart Fingerprint pattern).
     */
    suspend fun runFullScan(
        scanType: String = SCAN_TYPE_ONDEMAND,
        forceRescan: Boolean,
        onProgress: (suspend (scanned: Int, total: Int, current: String) -> Unit)? = null
    ): List<AvScanResult> = withContext(Dispatchers.IO) {
        val fullScanStartMs = System.currentTimeMillis()
        ensureCacheLoaded()
        val pm = context.packageManager
        val ownPackageName = context.packageName

        val pkgInfos: List<PackageInfo> = getInstalledPackagesSafe(pm)
        val appTargets = pkgInfos.mapNotNull { pkg ->
            val appInfo = pkg.applicationInfo ?: return@mapNotNull null
            if ((appInfo.flags and ApplicationInfo.FLAG_SYSTEM) != 0) return@mapNotNull null
            if (pkg.packageName == ownPackageName) return@mapNotNull null
            val appName = runCatching { pm.getApplicationLabel(appInfo).toString() }.getOrDefault(pkg.packageName)
            val src = appInfo.sourceDir?.takeIf { it.isNotBlank() }?.let { File(it) }
            ScanWorkItem.AppTarget(
                packageName = pkg.packageName,
                appName = appName,
                appInfo = appInfo,
                sourceFile = src,
                versionCode = PackageInfoCompat.getLongVersionCode(pkg),
                lastUpdateTime = pkg.lastUpdateTime
            )
        }

        val hasStorageAccess = AndroidStoragePaths.hasFullStorageAccess(context)
        val scanPaths = AndroidStoragePaths.getFullScanPaths(context)
        val maxFileSize = 50L * 1024 * 1024 // 50MB
        val scanExtensions = setOf(
            "apk", "dex", "jar", "so", "odex", "vdex", "oat", "art",
            "exe", "bat", "sh", "bin", "dll", "zip", "tar", "gz",
            "locky", "crypt", "encrypted", "locked", "crypto"
        )

        val visitedCanonicalDirs = HashSet<String>()
        val filesToScan = mutableListOf<File>()
        for (dirPath in scanPaths) {
            currentCoroutineContext().ensureActive()
            val dir = File(dirPath)
            if (!dir.exists() || !dir.isDirectory) continue
            collectFilesBounded(
                dir = dir,
                maxSize = maxFileSize,
                extensions = scanExtensions,
                outFiles = filesToScan,
                visitedCanonicalDirs = visitedCanonicalDirs,
                maxFiles = MAX_SCAN_DIR_FILES
            )
            if (filesToScan.size >= MAX_SCAN_DIR_FILES) break
        }

        val workItems = ArrayList<ScanWorkItem>(appTargets.size + filesToScan.size).apply {
            addAll(appTargets)
            filesToScan.forEach { add(ScanWorkItem.FileTarget(it)) }
        }

        val total = workItems.size
        Log.i(TAG, "Full scan starting: ${appTargets.size} apps, ${filesToScan.size} files, " +
            "storage access=$hasStorageAccess, scan paths=${scanPaths.size}, forceRescan=$forceRescan")

        if (!hasStorageAccess) {
            onProgress?.invoke(0, total, "WARNING: No storage permission - only scanning apps")
            Log.w(TAG, "No storage permission granted. AV scan limited to installed apps only.")
        } else if (total > 0) {
            onProgress?.invoke(0, total, "Starting parallel scan ($total items)...")
        }

        if (total == 0) {
            onProgress?.invoke(0, 0, "Complete: 0 items scanned")
            return@withContext emptyList()
        }

        val dbStamp = currentDbStamp()
        val resultsArray = arrayOfNulls<AvScanResult>(total)
        val nextIndex = AtomicInteger(0)
        val completedCount = AtomicInteger(0)
        val cacheHitsCount = AtomicInteger(0)
        val cacheModified = java.util.concurrent.atomic.AtomicBoolean(false)
        val lastProgressMs = AtomicLong(0L)
        val progressMutex = Mutex()
        var maxReportedDone = 0
        val workerCount = minOf(3, Runtime.getRuntime().availableProcessors().coerceAtLeast(2))

        coroutineScope {
            repeat(workerCount) {
                launch(Dispatchers.IO) {
                    while (true) {
                        currentCoroutineContext().ensureActive()
                        val idx = nextIndex.getAndIncrement()
                        if (idx >= total) break

                        val item = workItems[idx]
                        val itemLabel: String
                        val result: AvScanResult

                        when (item) {
                            is ScanWorkItem.AppTarget -> {
                                itemLabel = item.packageName
                                val cacheKey = "app:${item.packageName}"
                                val srcFile = item.sourceFile
                                val cached = if (!forceRescan && srcFile != null && srcFile.exists()) {
                                    val entry = cleanScanCache[cacheKey]
                                    if (entry != null &&
                                        entry.versionCode == item.versionCode &&
                                        entry.updateTime == item.lastUpdateTime &&
                                        entry.lastModified == srcFile.lastModified() &&
                                        entry.fileSize == srcFile.length() &&
                                        entry.dbStamp == dbStamp &&
                                        signatureDb.lookupHash(entry.sha256) == null
                                    ) entry else null
                                } else null

                                if (cached != null) {
                                    cacheHitsCount.incrementAndGet()
                                    result = AvScanResult(
                                        path = item.packageName,
                                        scanType = scanType,
                                        displayName = cached.displayName.ifBlank { item.appName },
                                        durationMs = 1L,
                                        threatLevel = ThreatLevel.CLEAN,
                                        threatName = null,
                                        indicators = emptyList(),
                                        fileSize = cached.fileSize,
                                        fileHash = cached.sha256,
                                        isApp = true,
                                        packageName = item.packageName
                                    )
                                } else {
                                    result = scanInstalledAppInfo(
                                        pm = pm,
                                        appInfo = item.appInfo,
                                        packageName = item.packageName,
                                        scanType = scanType,
                                        knownAppName = item.appName
                                    )
                                    val hash = result.fileHash
                                    if (result.threatLevel == ThreatLevel.CLEAN && srcFile != null && !hash.isNullOrBlank()) {
                                        cleanScanCache[cacheKey] = ScanCacheEntry(
                                            key = cacheKey,
                                            versionCode = item.versionCode,
                                            updateTime = item.lastUpdateTime,
                                            lastModified = srcFile.lastModified(),
                                            fileSize = srcFile.length(),
                                            dbStamp = dbStamp,
                                            sha256 = hash,
                                            displayName = result.displayName,
                                            isApp = true
                                        )
                                        cacheModified.set(true)
                                    } else if (cleanScanCache.remove(cacheKey) != null) {
                                        cacheModified.set(true)
                                    }
                                }
                            }

                            is ScanWorkItem.FileTarget -> {
                                val file = item.file
                                itemLabel = file.name
                                val cacheKey = "file:${file.absolutePath}"
                                val cached = if (!forceRescan && file.exists()) {
                                    val entry = cleanScanCache[cacheKey]
                                    if (entry != null &&
                                        entry.lastModified == file.lastModified() &&
                                        entry.fileSize == file.length() &&
                                        entry.dbStamp == dbStamp &&
                                        signatureDb.lookupHash(entry.sha256) == null
                                    ) entry else null
                                } else null

                                if (cached != null) {
                                    cacheHitsCount.incrementAndGet()
                                    result = AvScanResult(
                                        path = file.absolutePath,
                                        scanType = scanType,
                                        displayName = file.name,
                                        durationMs = 1L,
                                        threatLevel = ThreatLevel.CLEAN,
                                        threatName = null,
                                        indicators = emptyList(),
                                        fileSize = cached.fileSize,
                                        fileHash = cached.sha256,
                                        isApp = false
                                    )
                                } else {
                                    result = try {
                                        scanFileInternal(file, file.absolutePath, scanType)
                                    } catch (e: kotlinx.coroutines.CancellationException) {
                                        throw e
                                    } catch (e: Exception) {
                                        Log.w(TAG, "Failed to scan ${file.absolutePath}: ${e.message}")
                                        AvScanResult.ERROR(file.absolutePath, scanType, file.name, 0L, e.message ?: "Scan failed")
                                    }
                                    val hash = result.fileHash
                                    if (result.threatLevel == ThreatLevel.CLEAN && !hash.isNullOrBlank() && !isOwnDataFile(file)) {
                                        cleanScanCache[cacheKey] = ScanCacheEntry(
                                            key = cacheKey,
                                            versionCode = 0L,
                                            updateTime = 0L,
                                            lastModified = file.lastModified(),
                                            fileSize = file.length(),
                                            dbStamp = dbStamp,
                                            sha256 = hash,
                                            displayName = file.name,
                                            isApp = false
                                        )
                                        cacheModified.set(true)
                                    } else if (cleanScanCache.remove(cacheKey) != null) {
                                        cacheModified.set(true)
                                    }
                                }
                            }
                        }

                        resultsArray[idx] = result
                        val done = completedCount.incrementAndGet()

                        if (onProgress != null) {
                            val now = System.currentTimeMillis()
                            val prev = lastProgressMs.get()
                            if (done == 1 || done == total || now - prev >= PROGRESS_THROTTLE_MS) {
                                lastProgressMs.set(now)
                                progressMutex.withLock {
                                    if (done > maxReportedDone) {
                                        maxReportedDone = done
                                        onProgress.invoke(done, total, itemLabel)
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        if (cacheModified.get()) {
            persistCleanCache()
        }

        val results = resultsArray.filterNotNull()
        val elapsedMs = System.currentTimeMillis() - fullScanStartMs
        val cachedCount = cacheHitsCount.get()
        val deepScannedCount = (results.size - cachedCount).coerceAtLeast(0)

        onProgress?.invoke(
            results.size,
            total,
            "Complete: ${results.size} items scanned in ${elapsedMs}ms" +
                if (!hasStorageAccess) " (limited - grant storage access for full scan)" else ""
        )

        Log.i(
            TAG,
            "Full scan complete in ${elapsedMs}ms: ${results.size} scanned " +
                "($deepScannedCount deep-scanned, $cachedCount verified unchanged), " +
                "${results.count { it.isInfected }} threats found"
        )
        results
    }

    @Suppress("DEPRECATION")
    private fun getInstalledPackagesSafe(pm: PackageManager): List<PackageInfo> {
        return try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                pm.getInstalledPackages(PackageManager.PackageInfoFlags.of(0L))
            } else {
                pm.getInstalledPackages(0)
            }
        } catch (e: Exception) {
            Log.w(TAG, "getInstalledPackages failed, falling back to getInstalledApplications: ${e.message}")
            pm.getInstalledApplications(0).mapNotNull { appInfo ->
                runCatching { pm.getPackageInfo(appInfo.packageName, 0) }.getOrNull()
            }
        }
    }

    private fun currentDbStamp(): String =
        "${signatureDb.getHashCount()}:${signatureDb.downloadedHashLastModified()}:" +
            "${signatureDb.getBytePatternCount()}:${yaraEngine.getRuleCount()}:${heuristicAnalyzer.getHeuristicRuleGroupCount()}"

    private fun ensureCacheLoaded() {
        if (cacheLoaded) return
        synchronized(cacheIoLock) {
            if (cacheLoaded) return
            val file = File(context.filesDir, SCAN_CACHE_FILE)
            if (file.exists() && file.canRead()) {
                runCatching {
                    file.bufferedReader().useLines { lines ->
                        lines.forEach { line ->
                            val parts = line.split('\t')
                            if (parts.size >= 9) {
                                val key = parts[0]
                                val vCode = parts[1].toLongOrNull() ?: return@forEach
                                val upd = parts[2].toLongOrNull() ?: return@forEach
                                val mtime = parts[3].toLongOrNull() ?: return@forEach
                                val size = parts[4].toLongOrNull() ?: return@forEach
                                cleanScanCache[key] = ScanCacheEntry(
                                    key = key,
                                    versionCode = vCode,
                                    updateTime = upd,
                                    lastModified = mtime,
                                    fileSize = size,
                                    dbStamp = parts[5],
                                    sha256 = parts[6],
                                    displayName = parts[7],
                                    isApp = parts[8] == "1"
                                )
                            }
                        }
                    }
                }
            }
            cacheLoaded = true
        }
    }

    private fun persistCleanCache() {
        synchronized(cacheIoLock) {
            runCatching {
                val target = File(context.filesDir, SCAN_CACHE_FILE)
                val tmp = File(context.filesDir, "$SCAN_CACHE_FILE.tmp")
                val entries = cleanScanCache.values.take(MAX_CACHE_ENTRIES)
                tmp.bufferedWriter().use { out ->
                    for (e in entries) {
                        val safeKey = e.key.replace('\t', ' ').replace('\n', ' ').replace('\r', ' ')
                        val safeName = e.displayName.replace('\t', ' ').replace('\n', ' ').replace('\r', ' ')
                        out.append(safeKey).append('\t')
                            .append(e.versionCode.toString()).append('\t')
                            .append(e.updateTime.toString()).append('\t')
                            .append(e.lastModified.toString()).append('\t')
                            .append(e.fileSize.toString()).append('\t')
                            .append(e.dbStamp).append('\t')
                            .append(e.sha256).append('\t')
                            .append(safeName).append('\t')
                            .append(if (e.isApp) "1" else "0")
                            .append('\n')
                    }
                }
                if (!tmp.renameTo(target)) {
                    tmp.copyTo(target, overwrite = true)
                    tmp.delete()
                }
            }.onFailure {
                Log.w(TAG, "Failed to persist clean scan cache: ${it.message}")
            }
        }
    }

    /**
     * Returns true if the file belongs to the AV engine's own data — hash databases,
     * quarantine storage, export files. Scanning these would cause false positives since
     * the hash DB literally contains malware signatures and the quarantine dir holds
     * XOR-obfuscated copies of detected malware.
     */
    private fun isOwnDataFile(file: File): Boolean {
        val abs = file.absolutePath
        val uriScanDir = File(context.cacheDir, "av_uri_scan").absolutePath
        if (abs.startsWith(uriScanDir)) return false
        if (AvExclusions.isExcluded(file.name)) return true
        val quarantineDir = File(context.filesDir, "quarantine").absolutePath
        val vaultFilesDir = File(context.filesDir, "vault_files").absolutePath
        val hashDb = File(context.filesDir, "malware_hashes_downloaded.txt").absolutePath
        if (abs.startsWith(quarantineDir) || abs.startsWith(vaultFilesDir) || abs == hashDb) return true
        // Exclude own signature/database/code-cache internal directories, while allowing explicit cache temp scans
        val ownDataDir = context.dataDir?.absolutePath
        if (ownDataDir != null && abs.startsWith(ownDataDir)) {
            val rel = abs.removePrefix(ownDataDir).trimStart(File.separatorChar)
            if (rel.startsWith("databases") || rel.startsWith("shared_prefs") ||
                rel.startsWith("files") || rel.startsWith("code_cache") || rel.startsWith("no_backup")
            ) {
                return true
            }
        }
        try {
            val ownApk = context.packageManager.getApplicationInfo(context.packageName, 0).sourceDir
            if (ownApk != null && abs == ownApk) return true
        } catch (_: Exception) { }
        return false
    }

    private suspend fun collectFilesBounded(
        dir: File,
        maxSize: Long,
        extensions: Set<String>,
        outFiles: MutableList<File>,
        visitedCanonicalDirs: MutableSet<String>,
        maxFiles: Int,
        maxDepth: Int = 4,
        depth: Int = 0
    ) {
        if (depth >= maxDepth || outFiles.size >= maxFiles) return
        currentCoroutineContext().ensureActive()

        val canonical = runCatching { dir.canonicalPath }.getOrNull() ?: return
        if (!visitedCanonicalDirs.add(canonical)) return

        val quarantineDir = File(context.filesDir, "quarantine").absolutePath
        if (dir.absolutePath == quarantineDir) return

        val children = dir.listFiles() ?: return
        for (f in children) {
            if (outFiles.size >= maxFiles) break
            if (f.isFile) {
                if (f.length() in 1L..maxSize && !isOwnDataFile(f)) {
                    val ext = f.extension.lowercase()
                    if (ext in extensions || extensions.isEmpty()) {
                        outFiles.add(f)
                    }
                }
            } else if (f.isDirectory && !f.name.startsWith(".")) {
                collectFilesBounded(
                    dir = f,
                    maxSize = maxSize,
                    extensions = extensions,
                    outFiles = outFiles,
                    visitedCanonicalDirs = visitedCanonicalDirs,
                    maxFiles = maxFiles,
                    maxDepth = maxDepth,
                    depth = depth + 1
                )
            }
        }
    }

    private fun computeFileHash(file: File): String {
        val digest = MessageDigest.getInstance("SHA-256")
        file.inputStream().buffered(STREAM_BUFFER_SIZE).use { input ->
            val buffer = ByteArray(STREAM_BUFFER_SIZE)
            while (true) {
                val read = input.read(buffer)
                if (read <= 0) break
                digest.update(buffer, 0, read)
            }
        }
        return sha256ToHex(digest.digest())
    }

    /**
     * Reads ZIP/APK Central Directory metadata via [ZipFile] without decompressing entry payloads
     * (~100x faster on large APKs than sequentially scanning via ZipInputStream).
     * Falls back to buffered [ZipInputStream] only if [ZipFile] fails on a malformed container.
     */
    private fun scanArchiveForMalware(file: File): HeuristicResult {
        val indicators = mutableListOf<AvIndicator>()
        val state = ArchiveScanState()

        val zipFileSucceeded = try {
            ZipFile(file).use { zip ->
                val entries = zip.entries()
                var inspected = 0
                while (entries.hasMoreElements() && inspected < MAX_ARCHIVE_ENTRIES) {
                    inspectZipEntryName(entries.nextElement().name, indicators, state)
                    inspected++
                }
            }
            true
        } catch (e: Exception) {
            Log.d(TAG, "ZipFile open failed for ${file.name}, trying ZipInputStream fallback: ${e.message}")
            false
        }

        if (!zipFileSucceeded) {
            try {
                ZipInputStream(file.inputStream().buffered(32 * 1024)).use { zip ->
                    var inspected = 0
                    while (inspected < MAX_ARCHIVE_ENTRIES) {
                        val current = zip.nextEntry ?: break
                        inspectZipEntryName(current.name, indicators, state)
                        zip.closeEntry()
                        inspected++
                    }
                }
            } catch (e: Exception) {
                Log.w(TAG, "Archive scan failed for ${file.name}: ${e.message}")
            }
        }

        return HeuristicResult(indicators, state.threatLevel, state.threatName)
    }

    private class ArchiveScanState {
        var threatLevel: ThreatLevel = ThreatLevel.CLEAN
        var threatName: String? = null
        var suspiciousCount: Int = 0
    }

    private fun isSuspiciousArchivePath(entryName: String): Boolean {
        if (entryName == ".." || entryName.contains("../") || entryName.contains("..\\")) return true
        return ARCHIVE_ABSOLUTE_SYSTEM_PREFIXES.any { entryName.startsWith(it) }
    }

    private fun inspectZipEntryName(
        rawEntryName: String,
        indicators: MutableList<AvIndicator>,
        state: ArchiveScanState
    ) {
        val entryName = rawEntryName.lowercase()
        val canAddIndicator = indicators.size < 25
        // Path traversal (Zip Slip) or root-anchored system paths (excludes relative paths like tz/data/etc/)
        if (isSuspiciousArchivePath(entryName)) {
            if (canAddIndicator) {
                indicators.add(AvIndicator(
                    type = AvIndicatorType.HEURISTIC,
                    severity = AvSeverity.HIGH,
                    title = "Suspicious Archive Path",
                    description = "Archive contains path traversal or system path: $entryName",
                    evidence = entryName
                ))
            }
            state.suspiciousCount++
            if (state.threatLevel.ordinal < ThreatLevel.SUSPICIOUS.ordinal) {
                state.threatLevel = ThreatLevel.SUSPICIOUS
                state.threatName = "SuspiciousArchivePath"
            }
        }
        // Hidden / malicious DEX
        if (entryName.endsWith(".dex") && ARCHIVE_SUSPICIOUS_DEX.any { entryName.contains(it) }) {
            if (canAddIndicator) {
                indicators.add(AvIndicator(
                    type = AvIndicatorType.HEURISTIC,
                    severity = AvSeverity.HIGH,
                    title = "Suspicious DEX",
                    description = "Potential hidden DEX: $entryName",
                    evidence = entryName
                ))
            }
            state.suspiciousCount++
            if (state.threatLevel.ordinal < ThreatLevel.SUSPICIOUS.ordinal) {
                state.threatLevel = ThreatLevel.SUSPICIOUS
                state.threatName = "SuspiciousDex"
            }
        }
        // Injection / hook native libs
        if (entryName.endsWith(".so") && ARCHIVE_INJECTION_LIBS.any { entryName.contains(it) }) {
            if (canAddIndicator) {
                indicators.add(AvIndicator(
                    type = AvIndicatorType.HEURISTIC,
                    severity = AvSeverity.CRITICAL,
                    title = "Potential Injection Library",
                    description = "Native library with injection indicators: $entryName",
                    evidence = entryName
                ))
            }
            state.threatLevel = ThreatLevel.INFECTED
            state.threatName = "InjectionLibrary"
        }
        // Hidden classes in root
        if (entryName.endsWith(".dex") && !entryName.contains("classes") && entryName.count { it == '/' } == 0) {
            if (canAddIndicator) {
                indicators.add(AvIndicator(
                    type = AvIndicatorType.HEURISTIC,
                    severity = AvSeverity.MEDIUM,
                    title = "Unusual DEX Location",
                    description = "DEX in root: $entryName",
                    evidence = entryName
                ))
            }
            state.suspiciousCount++
        }
        // Nested APK (dropper)
        if (entryName.endsWith(".apk") && entryName.count { it == '/' } > 0) {
            if (canAddIndicator) {
                indicators.add(AvIndicator(
                    type = AvIndicatorType.HEURISTIC,
                    severity = AvSeverity.CRITICAL,
                    title = "Nested APK",
                    description = "Archive contains nested APK - dropper: $entryName",
                    evidence = entryName
                ))
            }
            state.threatLevel = ThreatLevel.INFECTED
            state.threatName = "Dropper"
        }
        if (state.suspiciousCount >= 3 && state.threatLevel.ordinal < ThreatLevel.INFECTED.ordinal) {
            state.threatLevel = ThreatLevel.INFECTED
        }
    }

    private val ARCHIVE_ABSOLUTE_SYSTEM_PREFIXES = setOf("/etc/", "/system/", "/bin/", "/sbin/", "/proc/", "/root/")
    private val ARCHIVE_SUSPICIOUS_DEX = setOf("secondary", "malware", "payload", "hidden", "obfuscated", "encrypted", "crypto")
    private val ARCHIVE_INJECTION_LIBS = setOf("hook", "inject", "frida", "substrate", "xposed", "inline", "patch")

    fun toRiskResult(avResult: AvScanResult): RiskResult? {
        if (avResult.threatLevel == ThreatLevel.CLEAN) return null
        val severity = when (avResult.threatLevel) {
            ThreatLevel.CLEAN -> return null
            ThreatLevel.SCAN_ERROR -> return null // Don't create risk result for scan errors
            ThreatLevel.LOW_RISK -> RiskSeverity.LOW
            ThreatLevel.SUSPICIOUS -> RiskSeverity.MEDIUM
            ThreatLevel.PUA -> RiskSeverity.MEDIUM
            ThreatLevel.INFECTED -> RiskSeverity.CRITICAL
        }
        val threatType = when (avResult.threatName?.lowercase()) {
            null -> ThreatType.MALWARE
            "adware" -> ThreatType.ADWARE
            "spyware" -> ThreatType.SPYWARE
            "trojan" -> ThreatType.TROJAN
            "ransomware" -> ThreatType.RANSOMWARE
            else -> ThreatType.MALWARE
        }
        val reasons = avResult.indicators.map {
            Reason(
                type = ReasonType.TECHNICAL,
                title = it.title,
                explanation = it.description,
                evidence = it.evidence
            )
        }
        return RiskResult(
            score = when (avResult.threatLevel) {
                ThreatLevel.INFECTED -> 95
                ThreatLevel.PUA -> 70
                ThreatLevel.SUSPICIOUS -> 55
                else -> 30
            },
            severity = severity,
            confidence = 0.9f,
            threatType = threatType,
            reasons = reasons,
            recommendedActions = listOf(
                com.deepfakeshield.core.model.Action(
                    type = com.deepfakeshield.core.model.RecommendedAction.QUARANTINE,
                    title = "Quarantine",
                    description = "Isolate this file",
                    isPrimary = true
                ),
                com.deepfakeshield.core.model.Action(
                    type = com.deepfakeshield.core.model.RecommendedAction.DELETE_FILE,
                    title = "Delete",
                    description = "Remove the file",
                    isPrimary = false
                )
            ),
            explainLikeImFive = "This file appears to be harmful. ${avResult.threatName ?: "Malware"} detected.",
            technicalDetails = avResult.indicators.joinToString("\n") { "${it.title}: ${it.description}" }
        )
    }

    fun toSecurityAnalysisResult(
        avResult: AvScanResult,
        extraLimitations: List<String> = emptyList(),
        analysisId: String = UUID.randomUUID().toString()
    ): SecurityAnalysisResult {
        val status = if (avResult.threatLevel == ThreatLevel.SCAN_ERROR) {
            AnalysisStatus.FAILED
        } else {
            AnalysisStatus.COMPLETED
        }
        val verdict = when (avResult.threatLevel) {
            ThreatLevel.CLEAN -> SecurityVerdict.SAFE
            ThreatLevel.SCAN_ERROR -> SecurityVerdict.NOT_ANALYZED
            ThreatLevel.LOW_RISK -> SecurityVerdict.LOW_RISK
            ThreatLevel.PUA, ThreatLevel.SUSPICIOUS -> SecurityVerdict.HIGH_RISK
            ThreatLevel.INFECTED -> SecurityVerdict.MALICIOUS
        }
        val riskScore = when (avResult.threatLevel) {
            ThreatLevel.CLEAN -> 0
            ThreatLevel.SCAN_ERROR -> null
            ThreatLevel.LOW_RISK -> 25
            ThreatLevel.PUA -> 50
            ThreatLevel.SUSPICIOUS -> 70
            ThreatLevel.INFECTED -> 95
        }
        val findings = avResult.indicators.map { ind ->
            val sev = when (ind.severity) {
                AvSeverity.CRITICAL -> FindingSeverity.CRITICAL
                AvSeverity.HIGH -> FindingSeverity.HIGH
                AvSeverity.MEDIUM -> FindingSeverity.MEDIUM
                AvSeverity.LOW -> FindingSeverity.LOW
            }
            SecurityFinding(
                title = ind.title,
                description = ind.description,
                severity = sev,
                evidenceSource = ind.type.name,
                detectionMethod = ind.type.name,
                inputLocation = ind.evidence,
                explanation = ind.description,
                recommendedAction = if (sev >= FindingSeverity.HIGH) "Quarantine or remove item." else "Review indicator."
            )
        }
        val stats = getEngineStats()
        val methods = buildList {
            add("SHA-256 Local Hash Matching (${stats.totalHashSignatures} hashes)")
            add("Byte Pattern Scan (${stats.bytePatternCount} patterns)")
            add("YARA Rule Matching (${stats.yaraRuleCount} rules)")
            add("Heuristic Structural/Permission Analysis (${stats.heuristicIndicatorCount} rules)")
            if (avResult.path.lowercase().endsWith(".apk") || avResult.path.lowercase().endsWith(".zip") || avResult.isApp) {
                add("ZIP/APK Archive & Native/DEX Layout Inspection")
            }
        }
        val limitations = buildList {
            add("Android sandbox restricts scanning private app internal directories (/data/data) belonging to other installed apps.")
            addAll(extraLimitations)
        }
        return SecurityAnalysisResult(
            analysisId = analysisId,
            module = SecurityModule.DEVICE_ANTIVIRUS,
            inputName = avResult.displayName,
            inputType = if (avResult.isApp) "application/vnd.android.package-archive" else "file",
            status = status,
            verdict = verdict,
            riskScore = riskScore,
            confidence = null, // Signature/YARA/heuristic AV — not a calibrated ML probability
            findings = findings,
            analysisMethods = methods,
            limitations = limitations,
            processingDurationMs = avResult.durationMs,
            analyzedAt = System.currentTimeMillis(),
            modelVersion = null,
            errorMessage = if (status == AnalysisStatus.FAILED) avResult.threatName else null,
            metadata = buildMap {
                put("path", avResult.path)
                put("scanType", avResult.scanType)
                put("scannedOk", if (avResult.isScanError) "0" else "1")
                avResult.fileHash?.let { put("sha256", it) }
                avResult.packageName?.let { put("packageName", it) }
                put("fileSize", avResult.fileSize.toString())
            }
        )
    }
}

// ─── Data classes ─────────────────────────────────────────────────────────

data class AvScanResult(
    val path: String,
    val scanType: String,
    val displayName: String,
    val durationMs: Long,
    val threatLevel: ThreatLevel = ThreatLevel.CLEAN,
    val threatName: String? = null,
    val indicators: List<AvIndicator> = emptyList(),
    val fileSize: Long = 0,
    val fileHash: String? = null,
    val isApp: Boolean = false,
    val packageName: String? = null
) {
    // B2C-SAFE: PUA (Potentially Unwanted App) is NOT the same as INFECTED.
    // Only flag actual malware as infected. PUA should be informational only —
    // users choose apps like VPNs, cleaners etc. deliberately.
    val isInfected: Boolean get() = threatLevel == ThreatLevel.INFECTED
    val isClean: Boolean get() = threatLevel == ThreatLevel.CLEAN
    val isScanError: Boolean get() = threatLevel == ThreatLevel.SCAN_ERROR

    companion object {
        fun CLEAN(path: String, scanType: String, displayName: String, durationMs: Long) =
            AvScanResult(path, scanType, displayName, durationMs, ThreatLevel.CLEAN)
        fun ERROR(path: String, scanType: String, displayName: String, durationMs: Long, error: String) =
            AvScanResult(path, scanType, displayName, durationMs, ThreatLevel.SCAN_ERROR, threatName = "ScanError: $error")
    }
}


enum class ThreatLevel { CLEAN, SCAN_ERROR, LOW_RISK, SUSPICIOUS, PUA, INFECTED }

enum class AvIndicatorType { SIGNATURE, HEURISTIC, BEHAVIOR, PERMISSION }

enum class AvSeverity { LOW, MEDIUM, HIGH, CRITICAL }

data class AvIndicator(
    val type: AvIndicatorType,
    val severity: AvSeverity,
    val title: String,
    val description: String,
    val evidence: String? = null
)

data class HeuristicResult(
    val indicators: List<AvIndicator>,
    val threatLevel: ThreatLevel,
    val threatName: String?
)
