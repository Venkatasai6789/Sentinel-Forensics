package com.deepfakeshield.ml.engine

import android.content.Context
import android.graphics.Bitmap
import android.graphics.Rect
import android.net.Uri
import com.deepfakeshield.core.model.FindingSeverity
import com.deepfakeshield.core.model.SecurityFinding
import dagger.hilt.android.qualifiers.ApplicationContext
import java.nio.charset.StandardCharsets
import javax.inject.Inject
import javax.inject.Singleton
import kotlin.math.PI
import kotlin.math.abs
import kotlin.math.cos
import kotlin.math.max
import kotlin.math.min
import kotlin.math.pow
import kotlin.math.sqrt

/**
 * Decoded video frame paired with its exact presentation timestamp in milliseconds.
 */
data class TimestampedFrame(
    val index: Int,
    val timeMs: Long,
    val bitmap: Bitmap,
    val isBurstFrame: Boolean = false
)

/**
 * Per-frame ML Kit face tracking metadata aligned with [TimestampedFrame].
 */
data class FrameFaceObservation(
    val frameIndex: Int,
    val timeMs: Long,
    val faceBox: Rect?,
    val mouthApertureRatio: Float = -1f
)

data class DeepfakeForensicSignals(
    val noiseDisparityScore: Float,       // 0..1 SRM high-pass noise residual mismatch (face vs background)
    val dctSpectralScore: Float,          // 0..1 2D 8x8 DCT upsampling / spectral cutoff divergence
    val boundaryBlendingScore: Float,     // 0..1 YCbCr chrominance & gradient seam around face perimeter
    val temporalFlickerScore: Float,      // 0..1 inter-frame face micro-flicker / shimmer vs background
    val rppgIncoherenceScore: Float,      // 0..1 physiological green-channel pulse incoherence across facial ROIs
    val avSyncAnomalyScore: Float,        // 0..1 audio-visual mouth motion vs speech energy mismatch
    val voiceCloneScore: Float,           // 0..1 acoustic voice-clone likelihood when speech audio present
    val containerSignatureScore: Float,   // 0..1 AI generator / C2PA / non-standard encoding metadata score
    val findings: List<SecurityFinding>,
    val detectedGeneratorTag: String? = null
)

/**
 * Multi-Domain On-Device Deepfake Video Forensic Analyzer.
 *
 * Implements research-backed classical signal processing & computer vision forensics
 * on decoded RGB frames and PCM audio without fabricating ML confidence:
 *  1. SRM-inspired high-pass noise residual disparity (face skin vs background sensor noise)
 *  2. Separable 2D 8x8 Block DCT spectral rolloff & checkerboard/upsampling analysis
 *  3. YCbCr face-perimeter blending seam & chrominance temperature mismatch
 *  4. Dense-burst temporal micro-flicker & chrominance shimmer (face vs background)
 *  5. Physiological rPPG green-channel spatial coherence across cheeks & forehead
 *  6. Audio-visual lip-sync correlation & VoiceCloneDetectionEngine acoustic check
 *  7. MP4/WebM container atom & header/trailer AI generator signature inspection
 */
@Singleton
class VideoDeepfakeForensicAnalyzer @Inject constructor(
    @ApplicationContext private val context: Context,
    private val voiceCloneEngine: VoiceCloneDetectionEngine
) {

    companion object {
        private const val DCT_N = 8

        // Precomputed 8x8 1D DCT-II basis matrix: C[u][x] = alpha(u) * cos((2x+1)*u*pi/(2N))
        private val DCT_COS: Array<DoubleArray> = Array(DCT_N) { u ->
            val alpha = if (u == 0) sqrt(1.0 / DCT_N) else sqrt(2.0 / DCT_N)
            DoubleArray(DCT_N) { x ->
                alpha * cos(((2 * x + 1) * u * PI) / (2.0 * DCT_N))
            }
        }

        private val AI_VIDEO_TOOL_SIGNATURES = listOf(
            "trainedalgorithmicmedia", "c2pa", "sora", "runway", "gen-2", "gen-3",
            "kling", "heygen", "synthesia", "d-id", "pika", "luma", "dream machine",
            "deepfacelab", "faceswap", "roop", "simswap", "wav2lip", "reface",
            "hailuo", "minimax", "veo", "wan2", "cogvideo", "hunyuan", "seedance",
            "comfyui", "animatediff", "stable video", "midjourney", "faceapp"
        )

        private val AI_TYPICAL_DIMENSIONS = setOf(
            512 to 512, 768 to 768, 1024 to 1024,
            1024 to 576, 576 to 1024,
            768 to 512, 512 to 768,
            896 to 512, 512 to 896,
            1280 to 768, 768 to 1280
        )
    }

    /**
     * Inspect container header & trailer bytes for AI video generator tags or C2PA provenance.
     */
    fun scanContainerSignatures(uri: Uri): Pair<String?, Float> {
        val findingsText = StringBuilder()
        runCatching {
            context.contentResolver.openInputStream(uri)?.use { stream ->
                val headBuf = ByteArray(131072) // 128 KB head
                val headRead = readUpTo(stream, headBuf)
                if (headRead > 0) {
                    findingsText.append(String(headBuf, 0, headRead, StandardCharsets.ISO_8859_1))
                }
                // Check if stream exposes remaining bytes to read MP4 moov/udta/meta trailer atoms
                val avail = runCatching { stream.available().toLong() }.getOrDefault(0L)
                if (avail > 65536L && avail < 150_000_000L) {
                    val toSkip = avail - 65536L
                    var skipped = 0L
                    while (skipped < toSkip) {
                        val s = stream.skip(toSkip - skipped)
                        if (s <= 0L) break
                        skipped += s
                    }
                    val tailBuf = ByteArray(65536)
                    val tailRead = readUpTo(stream, tailBuf)
                    if (tailRead > 0) {
                        findingsText.append('\n')
                        findingsText.append(String(tailBuf, 0, tailRead, StandardCharsets.ISO_8859_1))
                    }
                }
            }
        }
        val lower = findingsText.toString().lowercase()
        val matched = AI_VIDEO_TOOL_SIGNATURES.firstOrNull { sig -> lower.contains(sig) }
        val score = if (matched != null) 0.95f else 0f
        return matched to score
    }

    /**
     * Execute full multi-domain forensic analysis on decoded frames, face ROIs, and optional PCM audio.
     */
    fun analyze(
        frames: List<TimestampedFrame>,
        faceObservations: List<FrameFaceObservation>,
        videoMeta: VideoMediaMetadata,
        audioPcm16k: FloatArray? = null,
        containerTag: String? = null
    ): DeepfakeForensicSignals {
        val findings = mutableListOf<SecurityFinding>()

        // 1. Container & encoding metadata checks
        var containerScore = 0f
        if (containerTag != null) {
            containerScore = 0.95f
            findings += SecurityFinding(
                title = "AI video generator / provenance tag detected ('$containerTag')",
                description = "Container metadata/atoms reference '$containerTag'.",
                severity = FindingSeverity.CRITICAL,
                evidenceSource = "Container Atom Scanner",
                detectionMethod = "MP4/WebM Header & Trailer Signature Match",
                inputLocation = "Container metadata",
                explanation = "Embedded container metadata explicitly names a synthetic video or face-swap tool/provenance standard.",
                recommendedAction = "Treat video as AI-generated or synthetically manipulated unless proven otherwise."
            )
        }

        val dimPair = videoMeta.width to videoMeta.height
        val unusualAiRes = dimPair in AI_TYPICAL_DIMENSIONS
        val fps = videoMeta.frameRate
        val unusualFps = fps != null && fps > 0f && listOf(23.976f, 24f, 25f, 29.97f, 30f, 50f, 59.94f, 60f)
            .none { abs(fps - it) < 0.6f }
        if (unusualAiRes) {
            containerScore = maxOf(containerScore, 0.35f)
            findings += SecurityFinding(
                title = "Non-camera generative video resolution (${videoMeta.width}x${videoMeta.height})",
                description = "Dimensions match common diffusion/AI video latent output grids rather than standard camera aspect presets.",
                severity = FindingSeverity.LOW,
                evidenceSource = "Container Telemetry",
                detectionMethod = "Resolution Grid Check",
                inputLocation = "${videoMeta.width}x${videoMeta.height}",
                explanation = "Text-to-video and image-to-video models frequently output 64-aligned latent grids (e.g., 512x512, 1024x576).",
                recommendedAction = "Corroborate with pixel-domain spectral and temporal findings."
            )
        }
        if (unusualFps) {
            containerScore = maxOf(containerScore, if (unusualAiRes) 0.55f else 0.30f)
            findings += SecurityFinding(
                title = "Non-standard frame rate (${"%.2f".format(fps)} fps)",
                description = "Frame rate deviates from standard camera/broadcast rates (24/25/30/50/60 fps).",
                severity = FindingSeverity.MEDIUM,
                evidenceSource = "Container Telemetry",
                detectionMethod = "Frame Rate Regularity Check",
                inputLocation = "Video track",
                explanation = "AI generators and frame-interpolated deepfakes often export at non-broadcast rates (e.g., 8, 12, 16, or variable fps).",
                recommendedAction = "Inspect motion cadence for synthetic interpolation."
            )
        }

        if (frames.isEmpty()) {
            return DeepfakeForensicSignals(
                noiseDisparityScore = 0f,
                dctSpectralScore = 0f,
                boundaryBlendingScore = 0f,
                temporalFlickerScore = 0f,
                rppgIncoherenceScore = 0f,
                avSyncAnomalyScore = 0f,
                voiceCloneScore = 0f,
                containerSignatureScore = containerScore,
                findings = findings,
                detectedGeneratorTag = containerTag
            )
        }

        // Pre-extract pixel buffers once per frame to avoid slow JNI getPixel() loops
        val faceObsByIndex = faceObservations.associateBy { it.frameIndex }
        val frameBuffers = frames.map { tf ->
            val w = tf.bitmap.width
            val h = tf.bitmap.height
            val pixels = IntArray(w * h)
            tf.bitmap.getPixels(pixels, 0, w, 0, 0, w, h)
            val luma = FloatArray(w * h)
            val cb = FloatArray(w * h)
            val cr = FloatArray(w * h)
            val gMinusRb = FloatArray(w * h)
            for (i in pixels.indices) {
                val p = pixels[i]
                val r = (p shr 16) and 0xFF
                val g = (p shr 8) and 0xFF
                val b = p and 0xFF
                luma[i] = 0.299f * r + 0.587f * g + 0.114f * b
                cb[i] = 128f - 0.168736f * r - 0.331264f * g + 0.5f * b
                cr[i] = 128f + 0.5f * r - 0.418688f * g - 0.081312f * b
                gMinusRb[i] = g - 0.5f * (r + b)
            }
            FrameBuffer(tf.index, tf.timeMs, w, h, luma, cb, cr, gMinusRb, tf.isBurstFrame, faceObsByIndex[tf.index]?.faceBox)
        }

        // 2. Spatial analyses on frames with detected faces (sample up to 8 diverse frames for speed)
        val faceBuffers = frameBuffers.filter { it.faceBox != null && it.faceBox.width() >= 24 && it.faceBox.height() >= 24 }
        val spatialSample = sampleEvenly(faceBuffers, 8)

        val noiseScores = mutableListOf<Float>()
        val noiseRatios = mutableListOf<Float>()
        val dctScores = mutableListOf<Float>()
        val boundaryScores = mutableListOf<Float>()

        for (fb in spatialSample) {
            val box = fb.faceBox!!
            val (nScore, ratio) = computeSrmNoiseDisparity(fb, box)
            noiseScores += nScore
            if (ratio > 0f) noiseRatios += ratio

            dctScores += computeDctSpectralScore(fb, box)
            boundaryScores += computeBoundaryBlendingScore(fb, box)
        }

        // Also run global DCT upsampling check across frames even when face box is small or partial
        val globalDctScore = if (dctScores.isNotEmpty()) {
            dctScores.average().toFloat()
        } else {
            sampleEvenly(frameBuffers, 6).map { computeGlobalDctUpsamplingScore(it) }.average().toFloat()
        }.coerceIn(0f, 1f)

        val avgNoiseScore = if (noiseScores.isEmpty()) 0f else topKMean(noiseScores, 3)
        val avgBoundaryScore = if (boundaryScores.isEmpty()) 0f else topKMean(boundaryScores, 3)

        if (avgNoiseScore >= 0.45f) {
            val meanRatio = if (noiseRatios.isNotEmpty()) noiseRatios.average().toFloat() else 0f
            val desc = when {
                meanRatio in 0.01f..0.60f ->
                    "Inner face skin noise residual is ${"%.2f".format(meanRatio)}x background sensor noise (over-smoothed neural synthesis)."
                meanRatio > 1.75f ->
                    "Inner face noise residual is ${"%.2f".format(meanRatio)}x background noise (synthetic texture/upsampling mismatch)."
                else ->
                    "High-pass SRM noise floor inside facial mask diverges from surrounding frame."
            }
            findings += SecurityFinding(
                title = "Face-vs-background sensor noise residual mismatch",
                description = desc,
                severity = if (avgNoiseScore >= 0.68f) FindingSeverity.HIGH else FindingSeverity.MEDIUM,
                evidenceSource = "SRM Noise Residual Analyzer",
                detectionMethod = "3x3 High-Pass Residual Disparity",
                inputLocation = "${spatialSample.size} face-cropped frames",
                explanation = "Authentic camera footage shares consistent sensor noise between face skin and background; face swaps replace or over-smooth facial sensor noise.",
                recommendedAction = "Inspect cheek and forehead skin texture against surrounding hair/neck."
            )
        }

        if (globalDctScore >= 0.45f) {
            findings += SecurityFinding(
                title = "Frequency-domain DCT spectral / upsampling anomaly",
                description = "2D 8x8 DCT spectrum shows high-frequency attenuation mismatch or periodic grid energy (score ${(globalDctScore * 100).toInt()}%).",
                severity = if (globalDctScore >= 0.68f) FindingSeverity.HIGH else FindingSeverity.MEDIUM,
                evidenceSource = "2D DCT Spectral Analyzer",
                detectionMethod = "8x8 Block Discrete Cosine Transform",
                inputLocation = "Face & background frequency bands",
                explanation = "Neural decoders and face-swap warping alter high-frequency DCT energy distribution relative to native camera compression.",
                recommendedAction = "Compare facial sharpness and fine detail against background textures."
            )
        }

        if (avgBoundaryScore >= 0.45f) {
            findings += SecurityFinding(
                title = "Face-perimeter YCbCr chrominance & blending seam",
                description = "Measured chrominance/gradient discontinuity along cheek & jawline face mask boundary (${(avgBoundaryScore * 100).toInt()}%).",
                severity = if (avgBoundaryScore >= 0.68f) FindingSeverity.HIGH else FindingSeverity.MEDIUM,
                evidenceSource = "YCbCr Boundary Seam Analyzer",
                detectionMethod = "Radial Chroma & Laplacian Seam Gradient",
                inputLocation = "Face oval perimeter",
                explanation = "Alpha/Poisson blending of a swapped face introduces subtle chrominance shifts and edge-softening halos along the jawline and cheeks.",
                recommendedAction = "Examine jawline, ears, and hairline transitions during head turns."
            )
        }

        // 3. Temporal face micro-flicker / shimmer across consecutive close frames
        val temporalFlickerScore = computeTemporalFaceFlicker(frameBuffers, findings)

        // 4. Physiological rPPG coherence across cheeks & forehead during burst window
        val rppgIncoherenceScore = computeRppgIncoherence(frameBuffers, findings)

        // 5. Audio-visual lip-sync & synthetic voice forensics
        val (avSyncScore, voiceCloneScore) = analyzeAudioAndLipSync(
            frames = frames,
            frameBuffers = frameBuffers,
            faceObservations = faceObservations,
            audioPcm16k = audioPcm16k,
            videoDurationMs = videoMeta.durationMs,
            findings = findings
        )

        return DeepfakeForensicSignals(
            noiseDisparityScore = avgNoiseScore,
            dctSpectralScore = globalDctScore,
            boundaryBlendingScore = avgBoundaryScore,
            temporalFlickerScore = temporalFlickerScore,
            rppgIncoherenceScore = rppgIncoherenceScore,
            avSyncAnomalyScore = avSyncScore,
            voiceCloneScore = voiceCloneScore,
            containerSignatureScore = containerScore,
            findings = findings,
            detectedGeneratorTag = containerTag
        )
    }

    /**
     * Compare trimmed SRM 3x3 high-pass noise residual inside the inner face (cheeks/forehead)
     * against background tiles outside the face bounding box.
     */
    private fun computeSrmNoiseDisparity(fb: FrameBuffer, box: Rect): Pair<Float, Float> {
        val w = fb.w
        val h = fb.h
        // Shrink face box slightly to stay inside skin/face region and avoid background bleed
        val insetX = (box.width() * 0.16f).toInt()
        val insetY = (box.height() * 0.15f).toInt()
        val fx1 = (box.left + insetX).coerceIn(2, w - 3)
        val fx2 = (box.right - insetX).coerceIn(fx1 + 4, w - 2)
        val fy1 = (box.top + insetY).coerceIn(2, h - 3)
        val fy2 = (box.bottom - insetY).coerceIn(fy1 + 4, h - 2)

        val faceResiduals = ArrayList<Float>(512)
        val bgResiduals = ArrayList<Float>(512)
        val step = max(1, min(w, h) / 140)

        for (y in 2 until h - 2 step step) {
            val rowOffset = y * w
            for (x in 2 until w - 2 step step) {
                val idx = rowOffset + x
                // 3x3 SRM-style Laplacian-cross noise residual
                val res = abs(
                    4f * fb.luma[idx] -
                        fb.luma[idx - 1] - fb.luma[idx + 1] -
                        fb.luma[idx - w] - fb.luma[idx + w]
                ) / 4f
                val inInnerFace = x in fx1..fx2 && y in fy1..fy2
                val outsideFaceBox = x < box.left - 8 || x > box.right + 8 || y < box.top - 8 || y > box.bottom + 8
                if (inInnerFace) {
                    faceResiduals += res
                } else if (outsideFaceBox) {
                    bgResiduals += res
                }
            }
        }

        if (faceResiduals.size < 30 || bgResiduals.size < 30) return 0f to 0f

        // Use 20th..75th percentile trimmed mean to ignore strong structural edges (eyes, eyebrows, text)
        // and isolate true smooth-surface sensor noise floor.
        val faceNoise = trimmedPercentileMean(faceResiduals, 0.20f, 0.75f)
        val bgNoise = trimmedPercentileMean(bgResiduals, 0.20f, 0.75f)

        val denom = max(bgNoise, 0.35f)
        val ratio = faceNoise / denom

        // Over-smoothed synthetic face (ratio < 0.62) OR overly noisy synthetic patch (ratio > 1.75)
        var score = when {
            ratio < 0.62f -> ((0.62f - ratio) / 0.42f).coerceIn(0f, 1f)
            ratio > 1.75f -> ((ratio - 1.75f) / 1.50f).coerceIn(0f, 1f)
            else -> 0f
        }

        // Also check face skin flatness directly (extreme AI plastic smoothing)
        if (faceNoise < 0.85f && bgNoise > 1.4f) {
            score = max(score, ((1.4f - faceNoise) / 1.0f).coerceIn(0f, 0.85f))
        }

        return score.coerceIn(0f, 1f) to ratio
    }

    /**
     * 2D 8x8 DCT-II comparison between face blocks and background blocks + checkerboard energy check.
     */
    private fun computeDctSpectralScore(fb: FrameBuffer, box: Rect): Float {
        val faceBands = collectDctBandStats(fb, box.left, box.top, box.right, box.bottom)
        val bgBandsLeft = if (box.left > 24) collectDctBandStats(fb, 0, 0, box.left - 8, fb.h) else null
        val bgBandsRight = if (fb.w - box.right > 24) collectDctBandStats(fb, box.right + 8, 0, fb.w, fb.h) else null
        val bgBandsTop = if (box.top > 24) collectDctBandStats(fb, 0, 0, fb.w, box.top - 8) else null

        val bgList = listOfNotNull(bgBandsLeft, bgBandsRight, bgBandsTop).filter { it.blockCount >= 4 }
        if (faceBands.blockCount < 4) return 0f

        var score = 0f
        if (bgList.isNotEmpty()) {
            val bgHighRatio = bgList.map { it.highToMidRatio }.average().toFloat()
            val faceHighRatio = faceBands.highToMidRatio
            val ratioDivergence = abs(faceHighRatio - bgHighRatio) / max(bgHighRatio, 0.08f)

            // Face-swaps often have sharp spectral high-freq rolloff mismatch vs background
            if (ratioDivergence > 0.35f) {
                score += ((ratioDivergence - 0.35f) / 0.75f).coerceIn(0f, 0.65f)
            }
        }

        // Checkerboard / upsampling periodic peak energy (high u=4/v=4/Nyquist concentration)
        if (faceBands.checkerboardIndex > 0.24f) {
            score += ((faceBands.checkerboardIndex - 0.24f) / 0.25f).coerceIn(0f, 0.55f)
        }

        return score.coerceIn(0f, 1f)
    }

    private fun computeGlobalDctUpsamplingScore(fb: FrameBuffer): Float {
        val stats = collectDctBandStats(fb, 0, 0, fb.w, fb.h)
        if (stats.blockCount < 6) return 0f
        val checker = ((stats.checkerboardIndex - 0.26f) / 0.24f).coerceIn(0f, 0.7f)
        val extremeDropoff = if (stats.highToMidRatio < 0.14f) ((0.14f - stats.highToMidRatio) / 0.10f).coerceIn(0f, 0.5f) else 0f
        return max(checker, extremeDropoff).coerceIn(0f, 1f)
    }

    private data class DctBandStats(
        val blockCount: Int,
        val highToMidRatio: Float,
        val checkerboardIndex: Float
    )

    private fun collectDctBandStats(fb: FrameBuffer, x1: Int, y1: Int, x2: Int, y2: Int): DctBandStats {
        val sx = x1.coerceIn(0, max(0, fb.w - 8))
        val sy = y1.coerceIn(0, max(0, fb.h - 8))
        val ex = x2.coerceIn(sx, fb.w) - 8
        val ey = y2.coerceIn(sy, fb.h) - 8
        if (ex <= sx || ey <= sy) return DctBandStats(0, 0f, 0f)

        val stepX = max(8, (ex - sx) / 8)
        val stepY = max(8, (ey - sy) / 8)
        val block = DoubleArray(64)
        val tmp = DoubleArray(64)
        val coeff = DoubleArray(64)

        var totalMid = 0.0
        var totalHigh = 0.0
        var totalChecker = 0.0
        var blocks = 0

        for (by in sy..ey step stepY) {
            for (bx in sx..ex step stepX) {
                // Extract 8x8 luma patch
                for (r in 0 until DCT_N) {
                    val rowIdx = (by + r) * fb.w + bx
                    for (c in 0 until DCT_N) {
                        block[r * DCT_N + c] = fb.luma[rowIdx + c].toDouble()
                    }
                }
                // Separable 2D DCT: rows then columns
                for (r in 0 until DCT_N) {
                    val rOff = r * DCT_N
                    for (v in 0 until DCT_N) {
                        var sum = 0.0
                        val cosV = DCT_COS[v]
                        for (c in 0 until DCT_N) {
                            sum += block[rOff + c] * cosV[c]
                        }
                        tmp[rOff + v] = sum
                    }
                }
                var midE = 0.0
                var highE = 0.0
                var checkerE = 0.0
                for (u in 0 until DCT_N) {
                    val cosU = DCT_COS[u]
                    for (v in 0 until DCT_N) {
                        var sum = 0.0
                        for (r in 0 until DCT_N) {
                            sum += tmp[r * DCT_N + v] * cosU[r]
                        }
                        val valAbs = abs(sum)
                        coeff[u * DCT_N + v] = valAbs
                        val freq = u + v
                        if (freq in 3..6) midE += valAbs
                        if (freq >= 7) highE += valAbs
                        if ((u == 4 || u == 7) && (v == 4 || v == 7)) checkerE += valAbs
                    }
                }
                if (midE > 1.0) {
                    totalMid += midE
                    totalHigh += highE
                    totalChecker += checkerE
                    blocks++
                }
            }
        }

        if (blocks == 0 || totalMid <= 1e-6) return DctBandStats(0, 0f, 0f)
        val highToMid = (totalHigh / totalMid).toFloat()
        val checkerIdx = (totalChecker / (totalHigh + 1e-6)).toFloat()
        return DctBandStats(blocks, highToMid, checkerIdx)
    }

    /**
     * Detect YCbCr chrominance step & blending-halo sharpness drops along the cheek/jawline face perimeter.
     */
    private fun computeBoundaryBlendingScore(fb: FrameBuffer, box: Rect): Float {
        val cx = box.centerX().toFloat()
        val cy = box.centerY().toFloat()
        val rx = (box.width() * 0.46f).coerceAtLeast(8f)
        val ry = (box.height() * 0.46f).coerceAtLeast(8f)
        val band = max(4, min(box.width(), box.height()) / 18)

        val chromaSteps = ArrayList<Float>(60)
        val lumaGradRing = ArrayList<Float>(60)
        val lumaGradInner = ArrayList<Float>(60)

        // Focus on cheeks, temples, and jawline (-45 deg .. +225 deg, skipping top hairline)
        for (deg in -35..215 step 6) {
            val rad = Math.toRadians(deg.toDouble())
            val cosA = cos(rad).toFloat()
            val sinA = kotlin.math.sin(rad).toFloat()

            val inX = (cx + (rx - band) * cosA).toInt()
            val inY = (cy + (ry - band) * sinA).toInt()
            val midX = (cx + rx * cosA).toInt()
            val midY = (cy + ry * sinA).toInt()
            val outX = (cx + (rx + band) * cosA).toInt()
            val outY = (cy + (ry + band) * sinA).toInt()

            if (inX in 2 until fb.w - 2 && inY in 2 until fb.h - 2 &&
                midX in 2 until fb.w - 2 && midY in 2 until fb.h - 2 &&
                outX in 2 until fb.w - 2 && outY in 2 until fb.h - 2
            ) {
                val inIdx = inY * fb.w + inX
                val midIdx = midY * fb.w + midX
                val outIdx = outY * fb.w + outX

                val dCb = abs(fb.cb[inIdx] - fb.cb[outIdx])
                val dCr = abs(fb.cr[inIdx] - fb.cr[outIdx])
                chromaSteps += (dCb + dCr) * 0.5f

                val ringGrad = abs(fb.luma[midIdx + 1] - fb.luma[midIdx - 1]) +
                    abs(fb.luma[midIdx + fb.w] - fb.luma[midIdx - fb.w])
                val innerGrad = abs(fb.luma[inIdx + 1] - fb.luma[inIdx - 1]) +
                    abs(fb.luma[inIdx + fb.w] - fb.luma[inIdx - fb.w])
                lumaGradRing += ringGrad
                lumaGradInner += innerGrad
            }
        }

        if (chromaSteps.size < 10) return 0f
        val highChromaRatio = chromaSteps.count { it > 9.5f }.toFloat() / chromaSteps.size
        val meanChromaStep = chromaSteps.average().toFloat()

        // Blending halo: smoothed boundary ring compared to inner facial gradient or sharp seam
        val ringMean = lumaGradRing.average().toFloat()
        val innerMean = lumaGradInner.average().toFloat().coerceAtLeast(1f)
        val haloRatio = ringMean / innerMean

        var score = 0f
        if (meanChromaStep > 7.5f && highChromaRatio > 0.30f) {
            score += ((meanChromaStep - 7.5f) / 14f).coerceIn(0f, 0.65f)
        }
        if (haloRatio < 0.55f || haloRatio > 2.2f) {
            score += 0.35f
        }
        return score.coerceIn(0f, 1f)
    }

    /**
     * Measure face-region temporal micro-flicker ("shimmer" / per-frame synthesis instability)
     * normalized against background motion across closely spaced consecutive frames.
     */
    private fun computeTemporalFaceFlicker(
        buffers: List<FrameBuffer>,
        findings: MutableList<SecurityFinding>
    ): Float {
        if (buffers.size < 3) return 0f

        val flickerRatios = mutableListOf<Float>()
        val chromaFlickers = mutableListOf<Float>()
        var duplicateCount = 0
        var closePairs = 0

        for (i in 1 until buffers.size) {
            val prev = buffers[i - 1]
            val curr = buffers[i]
            val dt = curr.timeMs - prev.timeMs
            if (dt <= 0L || dt > 450L) continue
            if (prev.w != curr.w || prev.h != curr.h) continue

            closePairs++
            val box = curr.faceBox ?: prev.faceBox
            var faceLumaDiff = 0.0
            var faceChromaDiff = 0.0
            var faceCount = 0
            var bgLumaDiff = 0.0
            var bgCount = 0
            var globalDiff = 0.0
            var globalCount = 0

            val step = max(2, min(curr.w, curr.h) / 90)
            for (y in 2 until curr.h - 2 step step) {
                val off = y * curr.w
                for (x in 2 until curr.w - 2 step step) {
                    val idx = off + x
                    // Compare local high-pass residual difference to ignore smooth global lighting shifts
                    val hpCurr = curr.luma[idx] - 0.25f * (curr.luma[idx - 1] + curr.luma[idx + 1] + curr.luma[idx - curr.w] + curr.luma[idx + curr.w])
                    val hpPrev = prev.luma[idx] - 0.25f * (prev.luma[idx - 1] + prev.luma[idx + 1] + prev.luma[idx - prev.w] + prev.luma[idx + prev.w])
                    val hpDelta = abs(hpCurr - hpPrev)
                    val cDelta = abs(curr.cb[idx] - prev.cb[idx]) + abs(curr.cr[idx] - prev.cr[idx])

                    globalDiff += abs(curr.luma[idx] - prev.luma[idx])
                    globalCount++

                    if (box != null && x in box.left..box.right && y in box.top..box.bottom) {
                        faceLumaDiff += hpDelta
                        faceChromaDiff += cDelta
                        faceCount++
                    } else {
                        bgLumaDiff += hpDelta
                        bgCount++
                    }
                }
            }

            if (globalCount > 0 && globalDiff / globalCount < 0.35) {
                duplicateCount++
                continue
            }

            if (faceCount >= 20 && bgCount >= 20) {
                val faceHp = (faceLumaDiff / faceCount).toFloat()
                val bgHp = (bgLumaDiff / bgCount).toFloat().coerceAtLeast(0.4f)
                flickerRatios += faceHp / bgHp
                chromaFlickers += (faceChromaDiff / faceCount).toFloat()
            }
        }

        if (flickerRatios.isEmpty()) return 0f

        val meanFlickerRatio = flickerRatios.average().toFloat()
        val meanChromaFlicker = chromaFlickers.average().toFloat()
        val ratioVar = if (flickerRatios.size >= 3) {
            val m = flickerRatios.average()
            sqrt(flickerRatios.map { (it - m).pow(2) }.average()).toFloat()
        } else 0f

        var score = 0f
        // When face high-pass temporal shimmer is >1.9x background shimmer on close frames
        if (meanFlickerRatio > 1.9f) {
            score += ((meanFlickerRatio - 1.9f) / 1.8f).coerceIn(0f, 0.65f)
        }
        if (meanChromaFlicker > 5.5f) {
            score += ((meanChromaFlicker - 5.5f) / 8.0f).coerceIn(0f, 0.45f)
        }
        if (ratioVar > 0.65f) {
            score += 0.2f
        }
        if (closePairs >= 4 && duplicateCount >= closePairs / 2) {
            // Repeated frozen frames during a burst can indicate synthetic frame-duplication / low-fps AI export
            score = max(score, 0.35f)
        }

        val finalScore = score.coerceIn(0f, 1f)
        if (finalScore >= 0.45f) {
            findings += SecurityFinding(
                title = "Temporal face-region micro-flicker / shimmer",
                description = "High-frequency facial texture shimmer averaged ${"%.2f".format(meanFlickerRatio)}x background across consecutive burst frames (chroma drift ${"%.1f".format(meanChromaFlicker)}).",
                severity = if (finalScore >= 0.68f) FindingSeverity.HIGH else FindingSeverity.MEDIUM,
                evidenceSource = "Temporal Shimmer Analyzer",
                detectionMethod = "Burst High-Pass & YCbCr Temporal Residual",
                inputLocation = "${flickerRatios.size} consecutive frame pairs",
                explanation = "Per-frame neural synthesis causes fine skin/edge texture and chrominance to shimmer independently of camera background motion.",
                recommendedAction = "Watch cheeks, teeth, and hairline closely during slow playback."
            )
        }
        return finalScore
    }

    /**
     * Evaluate physiological rPPG pulse coherence across Left Cheek, Right Cheek, and Forehead.
     * Requires >= 6 distinct sequential burst frames with a detected face.
     */
    private fun computeRppgIncoherence(
        buffers: List<FrameBuffer>,
        findings: MutableList<SecurityFinding>
    ): Float {
        val burstFaceFrames = buffers.filter { it.isBurstFrame && it.faceBox != null && it.faceBox.width() >= 30 }
            .sortedBy { it.timeMs }
        if (burstFaceFrames.size < 6) return 0f

        val leftCheekSignal = mutableListOf<Float>()
        val rightCheekSignal = mutableListOf<Float>()
        val foreheadSignal = mutableListOf<Float>()

        for (fb in burstFaceFrames) {
            val b = fb.faceBox!!
            val lc = meanPatchSignal(fb, b.left + b.width() * 0.22f, b.top + b.height() * 0.55f, b.width() * 0.16f, b.height() * 0.14f)
            val rc = meanPatchSignal(fb, b.left + b.width() * 0.62f, b.top + b.height() * 0.55f, b.width() * 0.16f, b.height() * 0.14f)
            val fh = meanPatchSignal(fb, b.left + b.width() * 0.35f, b.top + b.height() * 0.16f, b.width() * 0.30f, b.height() * 0.12f)
            if (lc != null && rc != null && fh != null) {
                leftCheekSignal += lc
                rightCheekSignal += rc
                foreheadSignal += fh
            }
        }

        if (leftCheekSignal.size < 6) return 0f

        val corrLR = pearson(leftCheekSignal, rightCheekSignal)
        val corrLF = pearson(leftCheekSignal, foreheadSignal)
        val corrRF = pearson(rightCheekSignal, foreheadSignal)
        val avgCorr = (corrLR + corrLF + corrRF) / 3f

        // Real illuminated faces usually show positive spatial pulse coherence (> 0.20).
        // Negative or near-zero coherence across all 3 facial ROIs indicates uncorrelated synthetic skin drift.
        val score = if (avgCorr < 0.12f) {
            ((0.12f - avgCorr) / 0.50f).coerceIn(0f, 0.85f)
        } else 0f

        if (score >= 0.45f) {
            findings += SecurityFinding(
                title = "Incoherent facial rPPG pulse color-channel trend",
                description = "Green-channel chrominance pulse correlation across cheeks and forehead was ${"%.2f".format(avgCorr)} across ${leftCheekSignal.size} burst frames.",
                severity = FindingSeverity.MEDIUM,
                evidenceSource = "rPPG Physiological Analyzer",
                detectionMethod = "Multi-ROI Chrominance Pulse Coherence",
                inputLocation = "Cheeks & Forehead ROIs",
                explanation = "Natural skin exhibits spatially coherent blood-flow color micro-oscillations; neural face swaps frequently break spatial pulse coherence.",
                recommendedAction = "Treat as supporting physiological evidence alongside visual and temporal cues."
            )
        }
        return score
    }

    private fun analyzeAudioAndLipSync(
        frames: List<TimestampedFrame>,
        frameBuffers: List<FrameBuffer>,
        faceObservations: List<FrameFaceObservation>,
        audioPcm16k: FloatArray?,
        videoDurationMs: Long,
        findings: MutableList<SecurityFinding>
    ): Pair<Float, Float> {
        if (audioPcm16k == null || audioPcm16k.size < 3200) {
            return 0f to 0f
        }

        // A. Voice-clone acoustic check on extracted speech PCM
        val voiceResult = voiceCloneEngine.analyzeVoice(audioPcm16k, 16000)
        var voiceScore = 0f
        if (voiceResult.isCloned) {
            voiceScore = (1f - voiceResult.naturalness).coerceIn(0.4f, 1f)
            findings += SecurityFinding(
                title = "Synthetic / cloned voice acoustic indicators",
                description = voiceResult.findings.take(2).joinToString("; ").ifBlank {
                    "Audio track shows abnormal pitch jitter/shimmer or spectral uniformity."
                },
                severity = if (voiceScore >= 0.70f) FindingSeverity.HIGH else FindingSeverity.MEDIUM,
                evidenceSource = "VoiceCloneDetectionEngine",
                detectionMethod = "Jitter / Shimmer / Micro-Prosody & Spectral Flux",
                inputLocation = "Audio PCM track (16 kHz)",
                explanation = "AI TTS and voice-cloning models often exhibit overly uniform pitch perturbation, missing breath cycles, or smooth formant transitions.",
                recommendedAction = "Verify the speaker's voice through an independent trusted channel."
            )
        }

        // B. Audio-Visual Lip-Sync correlation on burst/close frames
        var avSyncScore = 0f
        val obsMap = faceObservations.associateBy { it.frameIndex }
        val sortedBuffers = frameBuffers.filter { it.faceBox != null }.sortedBy { it.timeMs }
        if (sortedBuffers.size >= 4 && videoDurationMs > 0L) {
            val audioWindowEnergies = mutableListOf<Float>()
            val mouthDeltas = mutableListOf<Float>()
            var speechFrames = 0

            for (i in 1 until sortedBuffers.size) {
                val prev = sortedBuffers[i - 1]
                val curr = sortedBuffers[i]
                val dt = curr.timeMs - prev.timeMs
                if (dt <= 0L || dt > 600L) continue

                val sampleCenter = ((curr.timeMs / 1000.0) * 16000.0).toInt()
                val halfWin = 1200 // +/- 75ms
                val sStart = (sampleCenter - halfWin).coerceIn(0, audioPcm16k.size)
                val sEnd = (sampleCenter + halfWin).coerceIn(sStart, audioPcm16k.size)
                if (sEnd - sStart < 160) continue

                var energySum = 0.0
                for (k in sStart until sEnd) {
                    val v = audioPcm16k[k]
                    energySum += v * v
                }
                val rms = sqrt(energySum / (sEnd - sStart)).toFloat()
                if (rms > 0.02f) speechFrames++
                audioWindowEnergies += rms

                // Prefer ML Kit mouth aperture delta; fallback to lower-third face pixel motion
                val apPrev = obsMap[prev.index]?.mouthApertureRatio ?: -1f
                val apCurr = obsMap[curr.index]?.mouthApertureRatio ?: -1f
                val mouthDelta = if (apPrev >= 0f && apCurr >= 0f) {
                    abs(apCurr - apPrev) * 100f
                } else {
                    computeLowerFaceDelta(prev, curr, curr.faceBox!!)
                }
                mouthDeltas += mouthDelta
            }

            if (audioWindowEnergies.size >= 4 && speechFrames >= 2) {
                val corr = pearson(audioWindowEnergies, mouthDeltas)
                val meanMouth = mouthDeltas.average().toFloat()
                val meanRms = audioWindowEnergies.average().toFloat()

                // Strong speech audio but virtually frozen mouth OR strongly negative AV correlation
                if (meanRms > 0.04f && meanMouth < 0.25f) {
                    avSyncScore = 0.65f
                } else if (corr < -0.25f) {
                    avSyncScore = ((-corr - 0.15f) / 0.65f).coerceIn(0.35f, 0.85f)
                }

                if (avSyncScore >= 0.45f) {
                    findings += SecurityFinding(
                        title = "Audio-visual lip-sync mismatch",
                        description = "Speech audio energy does not align with observed lip/mouth kinematics (correlation=${"%.2f".format(corr)}).",
                        severity = FindingSeverity.MEDIUM,
                        evidenceSource = "AV Lip-Sync Correlator",
                        detectionMethod = "Mouth Aperture vs Audio RMS Envelope",
                        inputLocation = "${audioWindowEnergies.size} synchronized frames",
                        explanation = "Lip-sync manipulation (e.g., Wav2Lip/dubbing) or mismatched audio swaps often decouple mouth motion from speech RMS peaks.",
                        recommendedAction = "Listen for consonant-lip mismatches on plosive sounds (/p/, /b/, /m/)."
                    )
                }
            }
        }

        // Also suppress unused warning if frames only used for metadata
        if (frames.isEmpty()) return 0f to 0f
        return avSyncScore.coerceIn(0f, 1f) to voiceScore.coerceIn(0f, 1f)
    }

    private fun computeLowerFaceDelta(prev: FrameBuffer, curr: FrameBuffer, box: Rect): Float {
        if (prev.w != curr.w || prev.h != curr.h) return 0f
        val x1 = (box.left + box.width() / 4).coerceIn(0, curr.w - 1)
        val x2 = (box.right - box.width() / 4).coerceIn(x1 + 1, curr.w)
        val y1 = (box.top + (box.height() * 0.58f).toInt()).coerceIn(0, curr.h - 1)
        val y2 = (box.bottom - (box.height() * 0.08f).toInt()).coerceIn(y1 + 1, curr.h)
        var sum = 0.0
        var count = 0
        for (y in y1 until y2 step 2) {
            val row = y * curr.w
            for (x in x1 until x2 step 2) {
                sum += abs(curr.luma[row + x] - prev.luma[row + x])
                count++
            }
        }
        return if (count > 0) (sum / count).toFloat() else 0f
    }

    private fun meanPatchSignal(fb: FrameBuffer, x: Float, y: Float, w: Float, h: Float): Float? {
        val x1 = x.toInt().coerceIn(0, fb.w - 1)
        val y1 = y.toInt().coerceIn(0, fb.h - 1)
        val x2 = (x + w).toInt().coerceIn(x1, fb.w)
        val y2 = (y + h).toInt().coerceIn(y1, fb.h)
        if (x2 <= x1 || y2 <= y1) return null
        var sum = 0.0
        var count = 0
        for (py in y1 until y2 step 2) {
            val row = py * fb.w
            for (px in x1 until x2 step 2) {
                sum += fb.gMinusRb[row + px]
                count++
            }
        }
        return if (count > 0) (sum / count).toFloat() else null
    }

    private fun pearson(xs: List<Float>, ys: List<Float>): Float {
        if (xs.size != ys.size || xs.size < 3) return 0f
        val mx = xs.average()
        val my = ys.average()
        var num = 0.0
        var dx2 = 0.0
        var dy2 = 0.0
        for (i in xs.indices) {
            val a = xs[i] - mx
            val b = ys[i] - my
            num += a * b
            dx2 += a * a
            dy2 += b * b
        }
        val denom = sqrt(dx2 * dy2)
        return if (denom > 1e-8) (num / denom).toFloat().coerceIn(-1f, 1f) else 0f
    }

    private fun trimmedPercentileMean(values: List<Float>, lowFrac: Float, highFrac: Float): Float {
        if (values.isEmpty()) return 0f
        val sorted = values.sorted()
        val start = (sorted.size * lowFrac).toInt().coerceIn(0, sorted.lastIndex)
        val end = (sorted.size * highFrac).toInt().coerceIn(start + 1, sorted.size)
        var sum = 0.0
        for (i in start until end) sum += sorted[i]
        return (sum / (end - start)).toFloat()
    }

    private fun topKMean(values: List<Float>, k: Int): Float {
        if (values.isEmpty()) return 0f
        val top = values.sortedDescending().take(k.coerceAtLeast(1))
        return top.average().toFloat()
    }

    private fun <T> sampleEvenly(items: List<T>, maxCount: Int): List<T> {
        if (items.size <= maxCount || maxCount <= 0) return items
        return List(maxCount) { i ->
            val idx = ((i.toFloat() / (maxCount - 1).coerceAtLeast(1)) * (items.size - 1)).toInt()
            items[idx.coerceIn(0, items.lastIndex)]
        }.distinct()
    }

    private fun readUpTo(stream: java.io.InputStream, buf: ByteArray): Int {
        var total = 0
        while (total < buf.size) {
            val n = stream.read(buf, total, buf.size - total)
            if (n <= 0) break
            total += n
        }
        return total
    }

    private class FrameBuffer(
        val index: Int,
        val timeMs: Long,
        val w: Int,
        val h: Int,
        val luma: FloatArray,
        val cb: FloatArray,
        val cr: FloatArray,
        val gMinusRb: FloatArray,
        val isBurstFrame: Boolean,
        val faceBox: Rect?
    )
}
