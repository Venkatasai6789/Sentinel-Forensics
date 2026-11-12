package com.deepfakeshield.ml.text

import android.content.Context
import com.deepfakeshield.ml.engine.ModelValidationReport
import com.deepfakeshield.ml.engine.TfliteModelSpec
import com.deepfakeshield.ml.engine.TfliteModelValidator
import dagger.hilt.android.qualifiers.ApplicationContext
import org.tensorflow.lite.DataType
import org.tensorflow.lite.Interpreter
import org.tensorflow.lite.gpu.GpuDelegate
import java.nio.ByteBuffer
import java.nio.ByteOrder
import javax.inject.Inject
import javax.inject.Singleton

/**
 * ON-DEVICE TEXT SCAM & PHISHING ANALYZER
 *
 * Uses TfliteModelValidator to verify bundled `.tflite` NLP models before
 * claiming ML inference. When validated `.tflite` models are unavailable or
 * degenerate, executes transparently in deterministic heuristic-only mode.
 */

data class GovernmentGradeTextAnalysis(
    val isScam: Boolean,
    val confidence: Float,              // Heuristic intensity or ML score (check calibratedConfidence)
    val modelScores: Map<String, Float>, // ONLY populated when a validated TFLite model ran
    val scamCategory: ScamCategory,
    val manipulationTechniques: List<ManipulationTechnique>,
    val urgencyScore: Float,
    val emotionalManipulationScore: Float,
    val linguisticFeatures: LinguisticFeatures,
    val threatIndicators: List<ThreatIndicator>,
    val certificationLevel: String,
    val forensicEvidence: List<String>,
    val recommendedResponse: ResponseStrategy,
    val calibratedConfidence: Float? = null,
    val heuristicSignals: Map<String, Float> = emptyMap(),
    val mlModelsActive: Boolean = false,
    val activeModels: List<String> = emptyList(),
    val analysisMethods: List<String> = emptyList(),
    val limitations: List<String> = emptyList()
)

enum class ScamCategory {
    PHISHING,
    VISHING,                    // Voice phishing prep
    SMISHING,                   // SMS phishing
    BUSINESS_EMAIL_COMPROMISE,
    ROMANCE_SCAM,
    INVESTMENT_FRAUD,
    LOTTERY_PRIZE_SCAM,
    TAX_IRS_SCAM,
    TECH_SUPPORT_SCAM,
    IMPERSONATION,
    EXTORTION,
    CREDENTIAL_HARVESTING,
    MALWARE_DISTRIBUTION,
    CRYPTOCURRENCY_SCAM,
    NONE
}

data class ManipulationTechnique(
    val technique: String,
    val severity: Float,
    val examples: List<String>
)

data class LinguisticFeatures(
    val language: String,
    val readingLevel: Int,               // Flesch-Kincaid grade level
    val sentenceComplexity: Float,
    val vocabularyRichness: Float,
    val grammarErrors: Int,
    val typingSpeed: Float?,             // Characters per second (if available)
    val emotionalWords: List<String>,
    val actionWords: List<String>
)

data class ThreatIndicator(
    val type: String,
    val description: String,
    val riskLevel: String,               // "LOW", "MEDIUM", "HIGH", "CRITICAL"
    val evidence: List<String>
)

data class ResponseStrategy(
    val action: String,                  // "BLOCK", "REPORT", "VERIFY", "IGNORE"
    val reasoning: String,
    val reportingAgencies: List<String>,
    val safetySteps: List<String>
)

@Singleton
class GovernmentGradeTextDetector @Inject constructor(
    @ApplicationContext private val context: Context,
    private val modelValidator: TfliteModelValidator
) {

    private var distilBertInterpreter: Interpreter? = null
    private var robertaInterpreter: Interpreter? = null
    private var xlmRobertaInterpreter: Interpreter? = null
    private var gptDetectorInterpreter: Interpreter? = null
    private val validationReports = mutableListOf<ModelValidationReport>()
    private var loadedVocabFromAsset = false

    private var gpuDelegate: GpuDelegate? = try { GpuDelegate() } catch (_: Throwable) { null }

    private val vocabulary = mutableMapOf<String, Int>()
    private val maxSequenceLength = 512

    @Volatile
    private var modelsInitialized = false

    private fun ensureInitialized() {
        if (!modelsInitialized) {
            synchronized(this) {
                if (!modelsInitialized) {
                    initializeModels()
                    loadVocabulary()
                    modelsInitialized = true
                }
            }
        }
    }

    private fun initializeModels() {
        validationReports.clear()
        val options = try {
            Interpreter.Options().apply {
                gpuDelegate?.let { addDelegate(it) }
                setNumThreads(4)
            }
        } catch (_: Exception) {
            Interpreter.Options().apply { setNumThreads(4) }
        }

        distilBertInterpreter = loadValidatedModel(
            "distilbert_scam_classifier.tflite",
            "DistilBERT Scam Classifier",
            expectedOutputMinLength = 2,
            options = options
        )
        robertaInterpreter = loadValidatedModel(
            "roberta_phishing_detector.tflite",
            "RoBERTa Phishing Detector",
            expectedOutputMinLength = 2,
            options = options
        )
        xlmRobertaInterpreter = loadValidatedModel(
            "xlm_roberta_multilingual.tflite",
            "XLM-RoBERTa Multilingual",
            expectedOutputMinLength = 2,
            options = options
        )
        gptDetectorInterpreter = loadValidatedModel(
            "gpt_text_detector.tflite",
            "GPT Text Detector",
            expectedOutputMinLength = 1,
            options = options
        )
    }

    private fun loadValidatedModel(
        filename: String,
        displayName: String,
        expectedOutputMinLength: Int,
        options: Interpreter.Options
    ): Interpreter? {
        val result = modelValidator.loadAndValidateAsset(
            context = context,
            spec = TfliteModelSpec(
                filename = filename,
                displayName = displayName,
                expectedInputShape = intArrayOf(1, maxSequenceLength),
                expectedOutputMinLength = expectedOutputMinLength,
                expectedInputDataType = DataType.INT32
            ),
            options = options
        )
        validationReports += result.report
        if (!result.report.isValid) {
            android.util.Log.i("TextDetector", "${result.report.filename} inactive: ${result.report.reason}")
        }
        return result.interpreter
    }

    fun getValidationReports(): List<ModelValidationReport> {
        ensureInitialized()
        return validationReports.toList()
    }
    
    /**
     * Build a word-to-index vocabulary from common English words and scam-related terms.
     * In a production deployment with actual .tflite models, this would load from a
     * model-specific vocab.txt file. Since we're running heuristic fallbacks,
     * this vocabulary powers the tokenization for any future model integration.
     */
    private fun loadVocabulary() {
        loadedVocabFromAsset = false
        try {
            val inputStream = context.assets.open("vocab.txt")
            inputStream.bufferedReader().useLines { lines ->
                lines.forEachIndexed { index, word ->
                    val trimmed = word.trim()
                    if (trimmed.isNotEmpty()) vocabulary[trimmed] = index
                }
            }
            if (vocabulary.size > 100) {
                loadedVocabFromAsset = true
                return
            }
        } catch (_: Exception) {
            // vocab.txt absent or truncated — build lightweight token table
        }
        
        // Build comprehensive vocabulary for tokenization
        // Special tokens
        val specialTokens = listOf("[PAD]", "[UNK]", "[CLS]", "[SEP]", "[MASK]")
        specialTokens.forEachIndexed { index, token -> vocabulary[token] = index }
        
        var nextId = specialTokens.size
        
        // Common English words (top 200+) to provide reasonable token coverage
        val commonWords = listOf(
            "the", "be", "to", "of", "and", "a", "in", "that", "have", "i",
            "it", "for", "not", "on", "with", "he", "as", "you", "do", "at",
            "this", "but", "his", "by", "from", "they", "we", "say", "her", "she",
            "or", "an", "will", "my", "one", "all", "would", "there", "their", "what",
            "so", "up", "out", "if", "about", "who", "get", "which", "go", "me",
            "when", "make", "can", "like", "time", "no", "just", "him", "know", "take",
            "people", "into", "year", "your", "good", "some", "could", "them", "see",
            "other", "than", "then", "now", "look", "only", "come", "its", "over",
            "also", "after", "use", "how", "our", "well", "way", "want", "because",
            "any", "give", "most", "us", "is", "are", "was", "were", "been", "has",
            // Scam/security domain words
            "urgent", "account", "verify", "suspended", "click", "winner", "prize",
            "claim", "congratulations", "tax", "refund", "payment", "confirm", "security",
            "alert", "bank", "password", "username", "social", "number", "card",
            "credit", "debit", "transfer", "wire", "bitcoin", "crypto", "investment",
            "profit", "earning", "money", "cash", "dollar", "free", "reward", "bonus",
            "lottery", "jackpot", "irs", "fbi", "police", "government", "federal",
            "court", "warrant", "arrest", "lawsuit", "legal", "penalty", "fine",
            "investigation", "fraud", "suspicious", "unauthorized", "blocked", "locked",
            "frozen", "terminated", "cancelled", "deactivated", "restricted",
            "immediately", "asap", "today", "expire", "deadline", "limited", "hurry",
            "download", "install", "update", "reset", "submit", "enter", "provide",
            "send", "reply", "respond", "act", "redeem", "call", "phone", "email",
            "link", "url", "website", "login", "signin", "otp", "pin", "cvv",
            "verification", "code", "identity", "personal", "information", "details",
            "microsoft", "apple", "google", "amazon", "paypal", "netflix", "facebook"
        )
        
        commonWords.forEach { word ->
            if (word !in vocabulary) {
                vocabulary[word] = nextId++
            }
        }
    }
    
    /**
     * MAIN ANALYSIS FUNCTION - Government-grade text scam detection
     */
    @Suppress("UNUSED_PARAMETER")
    suspend fun analyzeText(
        text: String,
        _senderInfo: String? = null,
        _context: Map<String, Any> = emptyMap()
    ): GovernmentGradeTextAnalysis {
        ensureInitialized()

        val tokens = tokenizeText(text)

        val activeModelScores = linkedMapOf<String, Float>()
        val heuristicSignals = linkedMapOf<String, Float>()

        val heuristicScamScore = runHeuristicScamDetection(text)
        heuristicSignals["HeuristicScam"] = heuristicScamScore
        if (distilBertInterpreter != null) {
            runDistilBertAnalysis(tokens)?.let { activeModelScores["DistilBERT"] = it }
        }

        val heuristicPhishScore = runHeuristicPhishingDetection(text)
        heuristicSignals["HeuristicPhishing"] = heuristicPhishScore
        if (robertaInterpreter != null) {
            runRobertaAnalysis(tokens)?.let { activeModelScores["RoBERTa"] = it }
        }

        val heuristicMultiLangScore = runHeuristicMultiLanguageDetection(text)
        heuristicSignals["HeuristicMultiLingual"] = heuristicMultiLangScore
        if (xlmRobertaInterpreter != null) {
            runXLMRobertaAnalysis(tokens)?.let { activeModelScores["XLM-RoBERTa"] = it }
        }

        val heuristicAiStyleScore = detectAIGeneratedText(text)
        heuristicSignals["HeuristicStylometry"] = heuristicAiStyleScore
        // Keep GPT-Detector (AI-authorship probe) out of scam activeModelScores so it never
        // sets mlActive/calibratedConfidence or biases scam probability when 2-class scam models are inactive.
        if (gptDetectorInterpreter != null) {
            runGPTDetectionAnalysis(tokens)
        }

        val linguisticFeatures = extractLinguisticFeatures(text)
        val manipulationTechniques = detectManipulationTechniques(text, linguisticFeatures)
        val urgencyScore = calculateUrgencyScore(text)
        val emotionalScore = calculateEmotionalManipulation(text, linguisticFeatures)
        val threatIndicators = identifyThreatIndicators(text, activeModelScores)

        val signalScore = calculateEnsembleScore(
            modelScores = activeModelScores,
            heuristicSignals = heuristicSignals,
            urgencyScore = urgencyScore,
            emotionalScore = emotionalScore,
            manipulationCount = manipulationTechniques.size
        )

        val isScam = signalScore > 0.6f
        val scamCategory = determineScamCategory(text, activeModelScores, threatIndicators)
        val forensicEvidence = generateForensicEvidence(activeModelScores, heuristicSignals, threatIndicators)
        val responseStrategy = generateResponseStrategy(scamCategory, signalScore)

        val mlActive = activeModelScores.isNotEmpty()
        val activeModels = activeModelScores.keys.toList()
        val methods = buildList {
            add("Deterministic Heuristic Text Analysis (keyword, regex, urgency & linguistic rules)")
            if (mlActive) {
                add("Validated On-Device TFLite NLP Models: ${activeModels.joinToString()}")
            }
        }
        val limitations = buildList {
            validationReports.filterNot { it.isValid }.forEach { rep ->
                add("${rep.displayName} (${rep.filename}) inactive: ${rep.reason}")
            }
            if (!mlActive) {
                add("No active TFLite NLP model ran; classification is purely rule/heuristic-based with no calibrated ML probability.")
            }
        }

        return GovernmentGradeTextAnalysis(
            isScam = isScam,
            confidence = signalScore,
            modelScores = activeModelScores,
            scamCategory = scamCategory,
            manipulationTechniques = manipulationTechniques,
            urgencyScore = urgencyScore,
            emotionalManipulationScore = emotionalScore,
            linguisticFeatures = linguisticFeatures,
            threatIndicators = threatIndicators,
            certificationLevel = if (mlActive) "VALIDATED_TFLITE_AND_HEURISTIC" else "HEURISTIC_PATTERN_ENGINE",
            forensicEvidence = forensicEvidence,
            recommendedResponse = responseStrategy,
            calibratedConfidence = if (mlActive) activeModelScores.values.average().toFloat() else null,
            heuristicSignals = heuristicSignals,
            mlModelsActive = mlActive,
            activeModels = activeModels,
            analysisMethods = methods,
            limitations = limitations
        )
    }

    // === MODEL INFERENCE METHODS (null on failure, never hallucinated) ===

    private fun runDistilBertAnalysis(tokens: IntArray): Float? {
        val interp = distilBertInterpreter ?: return null
        return try {
            val input = prepareInputBuffer(tokens)
            val output = Array(1) { FloatArray(2) }
            interp.run(input, output)
            output[0][1].takeIf { it.isFinite() }?.coerceIn(0f, 1f)
        } catch (_: Exception) {
            null
        }
    }

    private fun runRobertaAnalysis(tokens: IntArray): Float? {
        val interp = robertaInterpreter ?: return null
        return try {
            val input = prepareInputBuffer(tokens)
            val output = Array(1) { FloatArray(2) }
            interp.run(input, output)
            output[0][1].takeIf { it.isFinite() }?.coerceIn(0f, 1f)
        } catch (_: Exception) {
            null
        }
    }

    private fun runXLMRobertaAnalysis(tokens: IntArray): Float? {
        val interp = xlmRobertaInterpreter ?: return null
        return try {
            val input = prepareInputBuffer(tokens)
            val output = Array(1) { FloatArray(2) }
            interp.run(input, output)
            output[0][1].takeIf { it.isFinite() }?.coerceIn(0f, 1f)
        } catch (_: Exception) {
            null
        }
    }

    private fun runGPTDetectionAnalysis(tokens: IntArray): Float? {
        val interp = gptDetectorInterpreter ?: return null
        return try {
            val input = prepareInputBuffer(tokens)
            val output = Array(1) { FloatArray(1) }
            interp.run(input, output)
            output[0][0].takeIf { it.isFinite() }?.coerceIn(0f, 1f)
        } catch (_: Exception) {
            null
        }
    }

    // === TOKENIZATION ===

    private fun tokenizeText(text: String): IntArray {
        val words = text.lowercase()
            .replace(Regex("[^a-z0-9\\s]"), " ")
            .split(Regex("\\s+"))
            .filter { it.isNotEmpty() }

        val tokens = mutableListOf<Int>()
        tokens.add(vocabulary["[CLS]"] ?: 2)

        for (word in words) {
            if (tokens.size >= maxSequenceLength - 1) break
            val direct = vocabulary[word]
            if (direct != null) {
                tokens.add(direct)
            } else if (loadedVocabFromAsset) {
                var start = 0
                var matchedAll = true
                val subTokens = mutableListOf<Int>()
                while (start < word.length) {
                    var end = word.length
                    var foundId: Int? = null
                    while (start < end) {
                        val sub = if (start == 0) word.substring(start, end) else "##${word.substring(start, end)}"
                        val id = vocabulary[sub]
                        if (id != null) {
                            foundId = id
                            break
                        }
                        end--
                    }
                    if (foundId == null) {
                        matchedAll = false
                        break
                    }
                    subTokens.add(foundId)
                    start = end
                }
                if (matchedAll) {
                    for (t in subTokens) {
                        if (tokens.size >= maxSequenceLength - 1) break
                        tokens.add(t)
                    }
                } else {
                    tokens.add(vocabulary["[UNK]"] ?: 1)
                }
            } else {
                tokens.add(vocabulary["[UNK]"] ?: 1)
            }
        }

        tokens.add(vocabulary["[SEP]"] ?: 3)
        while (tokens.size < maxSequenceLength) {
            tokens.add(vocabulary["[PAD]"] ?: 0)
        }
        return tokens.take(maxSequenceLength).toIntArray()
    }
    
    private fun prepareInputBuffer(tokens: IntArray): ByteBuffer {
        val buffer = ByteBuffer.allocateDirect(4 * maxSequenceLength)
        buffer.order(ByteOrder.nativeOrder())
        
        tokens.forEach { token ->
            buffer.putInt(token)
        }
        
        buffer.rewind()
        return buffer
    }
    
    // === FEATURE EXTRACTION ===
    
    private fun extractLinguisticFeatures(text: String): LinguisticFeatures {
        val words = text.split(Regex("\\s+"))
        val sentences = text.split(Regex("[.!?]"))
        
        // Calculate reading level (Flesch-Kincaid)
        val readingLevel = calculateReadingLevel(text)
        
        // Sentence complexity
        val avgWordsPerSentence = words.size.toFloat() / sentences.size
        val sentenceComplexity = (avgWordsPerSentence / 20f).coerceIn(0f, 1f)
        
        // Vocabulary richness (unique words / total words)
        val uniqueWords = words.toSet().size
        val vocabularyRichness = uniqueWords.toFloat() / words.size
        
        // Grammar errors (simplified)
        val grammarErrors = detectGrammarErrors(text)
        
        // Emotional and action words
        val emotionalWords = extractEmotionalWords(text)
        val actionWords = extractActionWords(text)
        
        return LinguisticFeatures(
            language = detectLanguage(text),
            readingLevel = readingLevel,
            sentenceComplexity = sentenceComplexity,
            vocabularyRichness = vocabularyRichness,
            grammarErrors = grammarErrors,
            typingSpeed = null,
            emotionalWords = emotionalWords,
            actionWords = actionWords
        )
    }
    
    private fun calculateReadingLevel(text: String): Int {
        // Simplified Flesch-Kincaid Grade Level
        val words = text.split(Regex("\\s+")).size
        val sentences = text.split(Regex("[.!?]")).size
        val syllables = countSyllables(text)
        
        if (sentences == 0 || words == 0) return 0
        
        val grade = 0.39 * (words.toFloat() / sentences) + 11.8 * (syllables.toFloat() / words) - 15.59
        return grade.toInt().coerceIn(0, 18)
    }
    
    private fun countSyllables(text: String): Int {
        // Simplified syllable counting
        val vowels = "aeiouy"
        var count = 0
        var lastWasVowel = false
        
        text.lowercase().forEach { char ->
            val isVowel = vowels.contains(char)
            if (isVowel && !lastWasVowel) {
                count++
            }
            lastWasVowel = isVowel
        }
        
        return count
    }
    
    private fun detectGrammarErrors(text: String): Int {
        // Simplified grammar error detection
        var errors = 0
        
        // Check for common errors
        if (text.contains("your welcome")) errors++
        if (text.contains("could of")) errors++
        if (text.contains("should of")) errors++
        
        return errors
    }
    
    private fun extractEmotionalWords(text: String): List<String> {
        val emotionalKeywords = setOf(
            "urgent", "emergency", "critical", "important", "alert",
            "warning", "danger", "risk", "threat", "fear",
            "exciting", "amazing", "incredible", "guaranteed",
            "limited", "exclusive", "special", "opportunity"
        )
        
        return text.lowercase().split(Regex("\\s+"))
            .filter { it in emotionalKeywords }
            .distinct()
    }
    
    private fun extractActionWords(text: String): List<String> {
        val actionKeywords = setOf(
            "click", "verify", "confirm", "update", "reset",
            "download", "install", "call", "reply", "respond",
            "act", "claim", "redeem", "enter", "submit"
        )
        
        return text.lowercase().split(Regex("\\s+"))
            .filter { it in actionKeywords }
            .distinct()
    }
    
    private fun detectLanguage(text: String): String {
        // Simplified language detection
        return when {
            text.any { it in '\u4E00'..'\u9FFF' } -> "Chinese"
            text.any { it in '\u0400'..'\u04FF' } -> "Russian"
            text.any { it in '\u0600'..'\u06FF' } -> "Arabic"
            else -> "English"
        }
    }
    
    // === MANIPULATION DETECTION ===
    
    private fun detectManipulationTechniques(
        text: String,
        features: LinguisticFeatures
    ): List<ManipulationTechnique> {
        val techniques = mutableListOf<ManipulationTechnique>()
        val textLower = text.lowercase()
        
        // 1. Urgency/Time pressure
        if (features.actionWords.isNotEmpty() && features.emotionalWords.contains("urgent")) {
            techniques.add(
                ManipulationTechnique(
                    technique = "Urgency & Time Pressure",
                    severity = 0.9f,
                    examples = listOf("Must act immediately", "Limited time offer")
                )
            )
        }
        
        // 2. Authority impersonation
        val authorityWords = listOf("irs", "bank", "police", "government", "fbi", "microsoft")
        if (authorityWords.any { textLower.contains(it) }) {
            techniques.add(
                ManipulationTechnique(
                    technique = "Authority Impersonation",
                    severity = 0.95f,
                    examples = listOf("Claims to be from government/bank")
                )
            )
        }
        
        // 3. Fear tactics
        val fearWords = listOf("suspended", "locked", "frozen", "blocked", "terminated")
        if (fearWords.any { textLower.contains(it) }) {
            techniques.add(
                ManipulationTechnique(
                    technique = "Fear & Intimidation",
                    severity = 0.85f,
                    examples = listOf("Account will be suspended")
                )
            )
        }
        
        // 4. Greed appeal
        val greedWords = listOf("winner", "prize", "jackpot", "free", "reward")
        if (greedWords.any { textLower.contains(it) }) {
            techniques.add(
                ManipulationTechnique(
                    technique = "Greed Appeal",
                    severity = 0.75f,
                    examples = listOf("You've won a prize")
                )
            )
        }
        
        return techniques
    }
    
    private fun calculateUrgencyScore(text: String): Float {
        val urgencyWords = listOf(
            "urgent", "immediately", "now", "asap", "today",
            "expire", "deadline", "limited", "hurry", "quick"
        )
        
        val textLower = text.lowercase()
        val urgencyCount = urgencyWords.count { textLower.contains(it) }
        
        return (urgencyCount / 3f).coerceIn(0f, 1f)
    }
    
    @Suppress("UNUSED_PARAMETER")
    private fun calculateEmotionalManipulation(
        _text: String,
        features: LinguisticFeatures
    ): Float {
        val emotionalIntensity = features.emotionalWords.size / 10f
        val actionPressure = features.actionWords.size / 5f
        
        return ((emotionalIntensity + actionPressure) / 2f).coerceIn(0f, 1f)
    }
    
    // === THREAT IDENTIFICATION ===
    
    @Suppress("UNUSED_PARAMETER")
    private fun identifyThreatIndicators(
        text: String,
        _modelScores: Map<String, Float>
    ): List<ThreatIndicator> {
        val indicators = mutableListOf<ThreatIndicator>()
        val textLower = text.lowercase()
        
        // URL/link indicators
        if (textLower.contains("http") || textLower.contains("click here") || textLower.contains("bit.ly")) {
            indicators.add(
                ThreatIndicator(
                    type = "SUSPICIOUS_LINK",
                    description = "Contains potentially malicious links",
                    riskLevel = "HIGH",
                    evidence = listOf("URLs detected in message")
                )
            )
        }
        
        // Credential harvesting
        if (textLower.contains("password") || textLower.contains("username") || textLower.contains("otp")) {
            indicators.add(
                ThreatIndicator(
                    type = "CREDENTIAL_THEFT",
                    description = "Requests sensitive authentication information",
                    riskLevel = "CRITICAL",
                    evidence = listOf("Asks for passwords/OTP")
                )
            )
        }
        
        // Financial threat
        if (textLower.contains("payment") || textLower.contains("credit card") || textLower.contains("bank account")) {
            indicators.add(
                ThreatIndicator(
                    type = "FINANCIAL_FRAUD",
                    description = "Requests financial information",
                    riskLevel = "CRITICAL",
                    evidence = listOf("Asks for payment details")
                )
            )
        }
        
        return indicators
    }
    
    // === SCORING ===
    
    private fun calculateEnsembleScore(
        modelScores: Map<String, Float>,
        heuristicSignals: Map<String, Float>,
        urgencyScore: Float,
        emotionalScore: Float,
        manipulationCount: Int
    ): Float {
        val avgHeuristic = if (heuristicSignals.isEmpty()) 0f else heuristicSignals.values.average().toFloat()
        val avgModel = if (modelScores.isEmpty()) avgHeuristic else modelScores.values.average().toFloat()
        val combinedBase = if (modelScores.isEmpty()) avgHeuristic else maxOf(avgHeuristic, avgModel)
        val manipulationPenalty = (manipulationCount / 5f).coerceIn(0f, 0.3f)

        val finalScore = (combinedBase * 0.6f +
                         urgencyScore * 0.2f +
                         emotionalScore * 0.2f +
                         manipulationPenalty)

        return finalScore.coerceIn(0f, 1f)
    }

    @Suppress("UNUSED_PARAMETER")
    private fun determineScamCategory(
        text: String,
        _modelScores: Map<String, Float>,
        threatIndicators: List<ThreatIndicator>
    ): ScamCategory {
        val textLower = text.lowercase()

        return when {
            textLower.contains("irs") || textLower.contains("tax") -> ScamCategory.TAX_IRS_SCAM
            textLower.contains("bank") || textLower.contains("account") -> ScamCategory.PHISHING
            textLower.contains("prize") || textLower.contains("winner") -> ScamCategory.LOTTERY_PRIZE_SCAM
            textLower.contains("investment") || textLower.contains("crypto") -> ScamCategory.INVESTMENT_FRAUD
            threatIndicators.any { it.type == "CREDENTIAL_THEFT" } -> ScamCategory.CREDENTIAL_HARVESTING
            else -> ScamCategory.NONE
        }
    }

    private fun generateForensicEvidence(
        modelScores: Map<String, Float>,
        heuristicSignals: Map<String, Float>,
        threatIndicators: List<ThreatIndicator>
    ): List<String> {
        val evidence = mutableListOf<String>()

        modelScores.forEach { (model, score) ->
            evidence.add("TFLite $model: ${(score * 100).toInt()}% probability")
        }
        heuristicSignals.forEach { (signal, score) ->
            evidence.add("$signal intensity: ${(score * 100).toInt()}%")
        }
        threatIndicators.forEach { indicator ->
            evidence.add("${indicator.type}: ${indicator.description}")
        }

        return evidence
    }
    
    @Suppress("UNUSED_PARAMETER")
    private fun generateResponseStrategy(
        _category: ScamCategory,
        confidence: Float
    ): ResponseStrategy {
        return when {
            confidence > 0.8f -> ResponseStrategy(
                action = "BLOCK_AND_REPORT",
                reasoning = "High confidence scam detection",
                reportingAgencies = listOf("FBI IC3", "FTC", "Local Police"),
                safetySteps = listOf(
                    "Do not respond",
                    "Block sender",
                    "Report to authorities",
                    "Monitor your accounts"
                )
            )
            confidence > 0.6f -> ResponseStrategy(
                action = "VERIFY_THROUGH_OFFICIAL_CHANNELS",
                reasoning = "Moderate risk - verify before taking action",
                reportingAgencies = listOf("FTC"),
                safetySteps = listOf(
                    "Do not click links",
                    "Contact organization directly using official number",
                    "Verify request authenticity"
                )
            )
            else -> ResponseStrategy(
                action = "PROCEED_WITH_CAUTION",
                reasoning = "Low risk but stay vigilant",
                reportingAgencies = emptyList(),
                safetySteps = listOf(
                    "Verify sender identity",
                    "Don't share sensitive information"
                )
            )
        }
    }
    
    // === FALLBACK HEURISTICS ===
    
    private val productionHeuristics by lazy {
        com.deepfakeshield.ml.heuristics.ProductionHeuristicTextAnalyzer()
    }
    
    private fun runHeuristicScamDetection(text: String): Float {
        val result = productionHeuristics.analyzeText(text)
        return result.confidence
    }
    
    private fun runHeuristicPhishingDetection(text: String): Float {
        val result = productionHeuristics.analyzeText(text)
        return if (result.scamCategory.contains("PHISHING") || 
                   result.scamCategory.contains("CREDENTIAL")) {
            result.confidence
        } else {
            result.confidence * 0.7f
        }
    }
    
    /**
     * Detect AI-generated text using heuristic signals:
     * - Perplexity proxy via vocabulary richness
     * - Sentence length uniformity (AI tends toward consistent sentence lengths)
     * - Lack of typos/colloquialisms
     */
    private fun detectAIGeneratedText(text: String): Float {
        if (text.length < 50) return 0.1f // Too short to analyze
        
        val words = text.split(Regex("\\s+"))
        val sentences = text.split(Regex("[.!?]+")).filter { it.isNotBlank() }
        
        var aiScore = 0f
        
        // 1. Vocabulary richness - AI text tends to have higher unique-word ratio
        val uniqueRatio = words.toSet().size.toFloat() / words.size
        if (uniqueRatio > 0.75f && words.size > 20) {
            aiScore += 0.15f
        }
        
        // 2. Sentence length uniformity - AI produces more consistent sentence lengths
        if (sentences.size >= 3) {
            val lengths = sentences.map { it.trim().split(Regex("\\s+")).size }
            val mean = lengths.average()
            val variance = lengths.map { (it - mean) * (it - mean) }.average()
            val cv = if (mean > 0) kotlin.math.sqrt(variance) / mean else 1.0
            
            if (cv < 0.2) { // Very uniform sentence lengths
                aiScore += 0.2f
            }
        }
        
        // 3. Lack of colloquialisms, contractions, typos
        val colloquialisms = listOf("gonna", "wanna", "gotta", "kinda", "sorta", "ya", "ur", "u", "r", "lol", "omg", "btw")
        val hasColloquialisms = colloquialisms.any { text.lowercase().contains(it) }
        if (!hasColloquialisms && words.size > 30) {
            aiScore += 0.1f
        }
        
        // 4. Perfect punctuation with no typos is slightly suspicious in informal contexts
        val hasTypos = text.contains("  ") || text.contains("teh ") || text.contains("adn ")
        if (!hasTypos && text.length > 200) {
            aiScore += 0.05f
        }
        
        return aiScore.coerceIn(0f, 1f)
    }
    
    /**
     * Heuristic multi-language scam detection using the production text analyzer's
     * multi-language keyword databases.
     */
    private fun runHeuristicMultiLanguageDetection(text: String): Float {
        val result = productionHeuristics.analyzeTextMultiLanguage(text)
        return result.confidence
    }
    
    fun cleanup() {
        distilBertInterpreter?.close()
        robertaInterpreter?.close()
        xlmRobertaInterpreter?.close()
        gptDetectorInterpreter?.close()
        gpuDelegate?.close()
    }
}
