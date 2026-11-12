package com.deepfakeshield.av.engine

import android.util.Log
import java.io.File
import java.io.RandomAccessFile
import javax.inject.Inject
import javax.inject.Singleton

/**
 * YARA-like rule engine for pattern matching against file contents.
 *
 * Rules consist of:
 *   - name: unique identifier
 *   - strings: named patterns (text, hex, or regex) to search for
 *   - condition: how many strings must match (all, any, N of them)
 *   - severity: CRITICAL, HIGH, MEDIUM, LOW
 *   - family: threat family name
 *
 * This is a simplified but functional YARA implementation that runs on-device.
 */
@Singleton
class YaraRuleEngine @Inject constructor() {

    data class YaraString(val id: String, val pattern: String, val type: StringType)
    enum class StringType { TEXT, HEX, REGEX }
    enum class Condition { ALL, ANY, TWO_OF, THREE_OF }

    data class YaraRule(
        val name: String, val family: String, val severity: String,
        val description: String, val strings: List<YaraString>,
        val condition: Condition
    )

    data class YaraMatch(
        val rule: YaraRule, val matchedStrings: List<String>, val offset: Long = 0
    )

    private val rulesLock = Any()
    private val rules = mutableListOf<YaraRule>()

    @Volatile
    private var compiledIndex: CompiledIndex = CompiledIndex.EMPTY

    init {
        loadBuiltinRules()
        rebuildIndex()
    }

    fun getRuleCount(): Int = synchronized(rulesLock) { rules.size }

    fun getRuleNames(): List<String> = synchronized(rulesLock) { rules.map { it.name } }

    fun createStreamEvaluator(maxBytes: Long = DEFAULT_MAX_BYTES): StreamEvaluator {
        return StreamEvaluator(compiledIndex, maxBytes)
    }

    fun scanFile(file: File, maxBytes: Long = DEFAULT_MAX_BYTES): List<YaraMatch> {
        if (!file.exists() || !file.canRead() || file.length() == 0L || maxBytes <= 0L) return emptyList()

        return try {
            val evaluator = createStreamEvaluator(maxBytes)
            file.inputStream().buffered(64 * 1024).use { stream ->
                val buffer = ByteArray(64 * 1024)
                var remaining = maxBytes
                while (remaining > 0L) {
                    val toRead = minOf(buffer.size.toLong(), remaining).toInt()
                    val read = stream.read(buffer, 0, toRead)
                    if (read <= 0) break
                    evaluator.update(buffer, 0, read)
                    remaining -= read
                }
            }
            evaluator.finish {
                val readLen = minOf(file.length(), maxBytes).toInt()
                if (readLen <= 0) return@finish null
                ByteArray(readLen).also { buf ->
                    RandomAccessFile(file, "r").use { raf -> raf.readFully(buf) }
                }
            }
        } catch (e: Exception) {
            Log.w("YARA", "Scan error ${file.name}: ${e.message}")
            emptyList()
        }
    }

    fun scanBytes(content: ByteArray, fileName: String = ""): List<YaraMatch> {
        if (content.isEmpty()) return emptyList()
        val evaluator = createStreamEvaluator(content.size.toLong())
        evaluator.update(content, 0, content.size)
        return evaluator.finish { content }
    }

    fun addRule(rule: YaraRule) {
        synchronized(rulesLock) {
            rules.add(rule)
            rebuildIndexLocked()
        }
    }

    private fun rebuildIndex() {
        synchronized(rulesLock) { rebuildIndexLocked() }
    }

    private fun rebuildIndexLocked() {
        val textBuilder = BytePatternMatcher.Builder<Long>(ignoreAsciiCase = true)
        val hexBuilder = BytePatternMatcher.Builder<Long>(ignoreAsciiCase = false)
        val metas = ArrayList<RuleMeta>(rules.size)

        for ((ruleIdx, rule) in rules.withIndex()) {
            val regexEntries = mutableListOf<CompiledRegex>()
            for ((strIdx, s) in rule.strings.withIndex()) {
                val key = (ruleIdx.toLong() shl 20) or strIdx.toLong()
                when (s.type) {
                    StringType.TEXT -> textBuilder.addAscii(s.pattern, key)
                    StringType.HEX -> hexBuilder.addHex(s.pattern.replace(" ", ""), key)
                    StringType.REGEX -> {
                        val regex = try {
                            Regex(s.pattern, RegexOption.IGNORE_CASE)
                        } catch (_: Exception) {
                            null
                        }
                        if (regex != null) {
                            regexEntries += CompiledRegex(strIdx, regex)
                        }
                    }
                }
            }
            val minReq = when (rule.condition) {
                Condition.ALL -> rule.strings.size
                Condition.ANY -> 1
                Condition.TWO_OF -> 2
                Condition.THREE_OF -> 3
            }
            metas += RuleMeta(
                rule = rule,
                minRequired = minReq,
                regexEntries = regexEntries
            )
        }

        compiledIndex = CompiledIndex(
            rules = metas,
            textMatcher = textBuilder.build(),
            hexMatcher = hexBuilder.build()
        )
    }

    internal data class CompiledRegex(val stringIdx: Int, val regex: Regex)

    internal data class RuleMeta(
        val rule: YaraRule,
        val minRequired: Int,
        val regexEntries: List<CompiledRegex>
    )

    internal class CompiledIndex(
        val rules: List<RuleMeta>,
        val textMatcher: BytePatternMatcher<Long>,
        val hexMatcher: BytePatternMatcher<Long>
    ) {
        companion object {
            val EMPTY = CompiledIndex(
                rules = emptyList(),
                textMatcher = BytePatternMatcher.Builder<Long>(ignoreAsciiCase = true).build(),
                hexMatcher = BytePatternMatcher.Builder<Long>(ignoreAsciiCase = false).build()
            )
        }
    }

    class StreamEvaluator internal constructor(
        private val index: CompiledIndex,
        private val maxBytes: Long
    ) {
        private var remaining: Long = maxBytes
        private val textSession = index.textMatcher.createSession()
        private val hexSession = index.hexMatcher.createSession()

        fun update(buffer: ByteArray, offset: Int = 0, length: Int = buffer.size) {
            if (remaining <= 0L || length <= 0 || offset >= buffer.size) return
            val sliceLen = minOf(length.toLong(), remaining, (buffer.size - offset).toLong()).toInt()
            if (sliceLen <= 0) return
            textSession.update(buffer, offset, sliceLen)
            hexSession.update(buffer, offset, sliceLen)
            remaining -= sliceLen
        }

        fun finish(regexBytesProvider: () -> ByteArray?): List<YaraMatch> {
            val ruleCount = index.rules.size
            if (ruleCount == 0) return emptyList()

            val matchedFlags = arrayOfNulls<BooleanArray>(ruleCount)
            val matchedCounts = IntArray(ruleCount)

            fun recordMatches(keys: List<Long>) {
                for (key in keys) {
                    val ruleIdx = (key ushr 20).toInt()
                    val strIdx = (key and 0xFFFFFL).toInt()
                    if (ruleIdx !in 0 until ruleCount) continue
                    val meta = index.rules[ruleIdx]
                    val flags = matchedFlags[ruleIdx] ?: BooleanArray(meta.rule.strings.size).also {
                        matchedFlags[ruleIdx] = it
                    }
                    if (strIdx in flags.indices && !flags[strIdx]) {
                        flags[strIdx] = true
                        matchedCounts[ruleIdx]++
                    }
                }
            }

            recordMatches(textSession.matchedLabels())
            recordMatches(hexSession.matchedLabels())

            // Evaluate regex strings ONLY for rules whose non-regex matches make passing possible.
            var decodedText: String? = null
            var textLoaded = false

            for (ruleIdx in 0 until ruleCount) {
                val meta = index.rules[ruleIdx]
                if (meta.regexEntries.isEmpty()) continue
                val currentCount = matchedCounts[ruleIdx]
                if (currentCount + meta.regexEntries.size < meta.minRequired) continue

                if (!textLoaded) {
                    decodedText = regexBytesProvider()?.decodeToString(throwOnInvalidSequence = false)
                    textLoaded = true
                }
                val text = decodedText ?: continue
                val flags = matchedFlags[ruleIdx] ?: BooleanArray(meta.rule.strings.size).also {
                    matchedFlags[ruleIdx] = it
                }
                for (entry in meta.regexEntries) {
                    if (!flags[entry.stringIdx] && entry.regex.containsMatchIn(text)) {
                        flags[entry.stringIdx] = true
                        matchedCounts[ruleIdx]++
                    }
                }
            }

            val matches = mutableListOf<YaraMatch>()
            for (ruleIdx in 0 until ruleCount) {
                val meta = index.rules[ruleIdx]
                val count = matchedCounts[ruleIdx]
                val conditionMet = when (meta.rule.condition) {
                    Condition.ALL -> count == meta.rule.strings.size
                    Condition.ANY -> count >= 1
                    Condition.TWO_OF -> count >= 2
                    Condition.THREE_OF -> count >= 3
                }
                if (conditionMet) {
                    val flags = matchedFlags[ruleIdx]
                    val matchedIds = ArrayList<String>(count)
                    if (flags != null) {
                        for (strIdx in flags.indices) {
                            if (flags[strIdx]) matchedIds.add(meta.rule.strings[strIdx].id)
                        }
                    }
                    matches.add(YaraMatch(meta.rule, matchedIds))
                }
            }
            return matches
        }
    }

    companion object {
        const val DEFAULT_MAX_BYTES = 1024L * 1024L
    }

    private fun loadBuiltinRules() {
        // ── Ransomware ───────────────────────────────────────
        rules += YaraRule("ransomware_note", "Ransomware", "CRITICAL", "Ransomware ransom note detected",
            listOf(YaraString("s1", "your files have been encrypted", StringType.TEXT), YaraString("s2", "bitcoin", StringType.TEXT), YaraString("s3", "decrypt", StringType.TEXT)),
            Condition.TWO_OF)

        rules += YaraRule("ransomware_crypto", "Ransomware", "CRITICAL", "File encryption routine detected",
            listOf(YaraString("s1", "javax.crypto.Cipher", StringType.TEXT), YaraString("s2", "AES/CBC/PKCS5Padding", StringType.TEXT), YaraString("s3", ".encrypted", StringType.TEXT), YaraString("s4", "ransom", StringType.TEXT)),
            Condition.THREE_OF)

        // ── Banking Trojans ──────────────────────────────────
        rules += YaraRule("banker_overlay", "BankingTrojan", "CRITICAL", "Banking overlay attack pattern",
            listOf(YaraString("s1", "SYSTEM_ALERT_WINDOW", StringType.TEXT), YaraString("s2", "getRunningTasks", StringType.TEXT), YaraString("s3", "card_number", StringType.TEXT), YaraString("s4", "AccessibilityService", StringType.TEXT)),
            Condition.THREE_OF)

        rules += YaraRule("banker_sms", "BankingTrojan", "CRITICAL", "SMS OTP interception pattern",
            listOf(YaraString("s1", "SMS_RECEIVED", StringType.TEXT), YaraString("s2", "abortBroadcast", StringType.TEXT), YaraString("s3", "getMessageBody", StringType.TEXT)),
            Condition.ALL)

        // ── Spyware ──────────────────────────────────────────
        rules += YaraRule("spyware_location", "Spyware", "HIGH", "Continuous location tracking",
            listOf(YaraString("s1", "requestLocationUpdates", StringType.TEXT), YaraString("s2", "getLastKnownLocation", StringType.TEXT), YaraString("s3", "http", StringType.TEXT)),
            Condition.ALL)

        rules += YaraRule("spyware_recorder", "Spyware", "CRITICAL", "Audio/screen recording spyware",
            listOf(YaraString("s1", "MediaRecorder", StringType.TEXT), YaraString("s2", "setAudioSource", StringType.TEXT), YaraString("s3", "startRecording", StringType.TEXT), YaraString("s4", "upload", StringType.TEXT)),
            Condition.THREE_OF)

        rules += YaraRule("spyware_keylogger", "Spyware", "CRITICAL", "Keylogger pattern",
            listOf(YaraString("s1", "AccessibilityEvent", StringType.TEXT), YaraString("s2", "TYPE_VIEW_TEXT_CHANGED", StringType.TEXT), YaraString("s3", "getText", StringType.TEXT)),
            Condition.ALL)

        // ── RAT (Remote Access Trojan) ───────────────────────
        rules += YaraRule("rat_c2", "RAT", "CRITICAL", "Remote access trojan with C2 communication",
            listOf(YaraString("s1", "socket", StringType.TEXT), YaraString("s2", "connect", StringType.TEXT), YaraString("s3", "getRuntime", StringType.TEXT), YaraString("s4", "exec", StringType.TEXT)),
            Condition.ALL)

        rules += YaraRule("rat_reverse_shell", "RAT", "CRITICAL", "Reverse shell payload",
            listOf(YaraString("s1", "/bin/sh", StringType.TEXT), YaraString("s2", "getInputStream", StringType.TEXT), YaraString("s3", "getOutputStream", StringType.TEXT)),
            Condition.ALL)

        // ── Dropper ──────────────────────────────────────────
        rules += YaraRule("dropper_dex", "Dropper", "HIGH", "Dynamic DEX loading (second stage payload)",
            listOf(YaraString("s1", "DexClassLoader", StringType.TEXT), YaraString("s2", "loadClass", StringType.TEXT), YaraString("s3", "InMemoryDexClassLoader", StringType.TEXT)),
            Condition.TWO_OF)

        rules += YaraRule("dropper_download", "Dropper", "HIGH", "Downloads and executes code",
            listOf(YaraString("s1", "URLConnection", StringType.TEXT), YaraString("s2", ".apk", StringType.TEXT), YaraString("s3", "PackageInstaller", StringType.TEXT)),
            Condition.ALL)

        // ── Adware / PUA ─────────────────────────────────────
        rules += YaraRule("adware_aggressive", "Adware", "MEDIUM", "Aggressive advertising SDK",
            listOf(YaraString("s1", "interstitial", StringType.TEXT), YaraString("s2", "rewardedAd", StringType.TEXT), YaraString("s3", "loadAd", StringType.TEXT), YaraString("s4", "fullscreen", StringType.TEXT)),
            Condition.THREE_OF)

        // ── Crypto Mining ────────────────────────────────────
        rules += YaraRule("cryptominer", "Cryptominer", "HIGH", "Cryptocurrency mining code",
            listOf(YaraString("s1", "stratum+tcp", StringType.TEXT), YaraString("s2", "hashrate", StringType.TEXT), YaraString("s3", "mining_pool", StringType.TEXT)),
            Condition.TWO_OF)

        rules += YaraRule("cryptominer_wasm", "Cryptominer", "HIGH", "WebAssembly-based crypto miner",
            listOf(YaraString("s1", "coinhive", StringType.TEXT), YaraString("s2", "CryptoNight", StringType.TEXT)),
            Condition.ANY)

        // ── Exploit / Packer ─────────────────────────────────
        rules += YaraRule("packed_apk", "Packer", "MEDIUM", "Packed/obfuscated APK (common in malware)",
            listOf(YaraString("s1", "62616964752e", StringType.HEX), YaraString("s2", "7061636b65722e", StringType.HEX), YaraString("s3", "4a696167752e", StringType.HEX)),
            Condition.ANY)

        rules += YaraRule("root_exploit", "Exploit", "CRITICAL", "Root exploit payload",
            listOf(YaraString("s1", "CVE-20", StringType.TEXT), YaraString("s2", "exploit", StringType.TEXT), YaraString("s3", "escalat", StringType.TEXT), YaraString("s4", "privilege", StringType.TEXT)),
            Condition.THREE_OF)

        // ── Phishing ─────────────────────────────────────────
        rules += YaraRule("phishing_webview", "Phishing", "HIGH", "WebView-based phishing page",
            listOf(YaraString("s1", "evaluateJavascript", StringType.TEXT), YaraString("s2", "password", StringType.TEXT), YaraString("s3", "document.getElementById", StringType.TEXT), YaraString("s4", "submit", StringType.TEXT)),
            Condition.THREE_OF)

        // ── Stalkerware ──────────────────────────────────────
        rules += YaraRule("stalkerware", "Stalkerware", "CRITICAL", "Stalkerware/monitoring app",
            listOf(YaraString("s1", "getCallLog", StringType.TEXT), YaraString("s2", "getSmsMessages", StringType.TEXT), YaraString("s3", "getContacts", StringType.TEXT), YaraString("s4", "uploadToServer", StringType.TEXT)),
            Condition.THREE_OF)

        // ── SIM Swap / Toll Fraud ────────────────────────────
        rules += YaraRule("toll_fraud", "TollFraud", "HIGH", "Premium SMS/toll fraud",
            listOf(YaraString("s1", "sendTextMessage", StringType.TEXT), YaraString("s2", "SEND_SMS", StringType.TEXT), YaraString("s3", "900", StringType.TEXT)),
            Condition.ALL)

        // ── Clipboard Hijacker ───────────────────────────────
        rules += YaraRule("clipboard_hijack", "ClipboardHijacker", "HIGH", "Cryptocurrency address replacement",
            listOf(YaraString("s1", "ClipboardManager", StringType.TEXT), YaraString("s2", "setPrimaryClip", StringType.TEXT), YaraString("s3", "bc1q", StringType.TEXT)),
            Condition.ALL)

        rules += YaraRule("clipboard_hijack_eth", "ClipboardHijacker", "HIGH", "ETH address clipboard swap",
            listOf(YaraString("s1", "ClipboardManager", StringType.TEXT), YaraString("s2", "setPrimaryClip", StringType.TEXT), YaraString("s3", "0x[a-fA-F0-9]{40}", StringType.REGEX)),
            Condition.ALL)

        // ── Standard EICAR Antivirus Test File ───────────────
        rules += YaraRule("eicar_standard_test_file", "EICAR-Test-File", "CRITICAL", "Standard EICAR antivirus test signature detected",
            listOf(
                YaraString("s1", "X5O!P%@AP[4\\PZX54(P^)7CC)7}\$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!\$H+H*", StringType.TEXT),
                YaraString("s2", "EICAR-STANDARD-ANTIVIRUS-TEST-FILE", StringType.TEXT)
            ),
            Condition.ANY)

        Log.i("YARA", "Loaded ${rules.size} built-in rules")
    }
}
