package com.deepfakeshield.ml.engine

import android.content.Context
import android.graphics.Bitmap
import android.graphics.Color
import android.media.MediaCodec
import android.media.MediaExtractor
import android.media.MediaFormat
import android.media.MediaMetadataRetriever
import android.net.Uri
import android.util.Log
import com.deepfakeshield.core.model.AnalysisStatus
import com.deepfakeshield.core.model.FindingSeverity
import com.deepfakeshield.core.model.SecurityAnalysisResult
import com.deepfakeshield.core.model.SecurityFinding
import com.deepfakeshield.core.model.SecurityModule
import com.deepfakeshield.core.model.SecurityVerdict
import com.deepfakeshield.ml.deepfake.GovernmentGradeDeepfakeDetector
import com.deepfakeshield.ml.face.FaceMeshDeepfakeAnalyzer
import com.deepfakeshield.ml.face.MLKitFaceAnalyzer
import com.deepfakeshield.ml.face.TemporalFaceTracker
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.withContext
import java.nio.ByteOrder
import java.util.UUID
import javax.inject.Inject
import javax.inject.Singleton
import kotlin.math.abs
import kotlin.math.max
import kotlin.math.min

data class VideoMediaMetadata(
    val displayName: String,
    val durationMs: Long,
    val width: Int,
    val height: Int,
    val mimeType: String?,
    val bitrateBps: Long?,
    val frameRate: Float?,
    val hasAudioTrack: Boolean,
    val audioSampleRateHz: Int? = null
)

data class VideoForensicReport(
    val analysisResult: SecurityAnalysisResult,
    val mediaMetadata: VideoMediaMetadata?,
    val framesExtracted: Int,
    val framesWithFaces: Int,
    val faceConsistencyScore: Float?,
    val temporalLuminanceAnomalies: Int,
    val flaggedFrameIndices: List<Int>
)

/**
 * Multi-Domain Video & Deepfake Forensics Pipeline:
 * 1. Inspects container/track metadata & binary header/trailer AI generator/C2PA signatures
 * 2. Extracts uniform keyframes PLUS a dense temporal burst (~110ms spacing) for micro-flicker,
 *    blink-rate, and rPPG pulse analysis
 * 3. Runs Google ML Kit Face Detection & 468-pt Face Mesh with real video presentation timestamps
 * 4. Runs multi-domain signal forensics via [VideoDeepfakeForensicAnalyzer]:
 *    - SRM high-pass sensor noise residual disparity (face vs background)
 *    - 2D 8x8 Block DCT spectral rolloff & checkerboard upsampling detection
 *    - YCbCr face-perimeter blending seam & chrominance mismatch
 *    - Dense-burst face micro-flicker / shimmer & rPPG pulse coherence
 *    - Audio track 16kHz PCM extraction for AV lip-sync & voice-clone forensics
 * 5. Reports TFLite validation state transparently and returns `FAILED` on unreadable/0-frame videos
 *    and `INCONCLUSIVE` when zero faces are visible and no explicit AI container tag is present.
 */
@Singleton
class VideoForensicsPipeline @Inject constructor(
    @ApplicationContext private val context: Context,
    private val mlKitFaceAnalyzer: MLKitFaceAnalyzer,
    private val faceMeshAnalyzer: FaceMeshDeepfakeAnalyzer,
    private val temporalTracker: TemporalFaceTracker,
    private val deepfakeDetector: GovernmentGradeDeepfakeDetector,
    private val deepfakeForensicAnalyzer: VideoDeepfakeForensicAnalyzer
) {

    companion object {
        private const val TAG = "VideoForensicsPipeline"
        private const val MAX_DIM = 540
        private const val UNIFORM_SAMPLE_COUNT = 10
        private const val BURST_SAMPLE_COUNT = 8
        private const val BURST_INTERVAL_MS = 115L
        private const val TARGET_AUDIO_RATE = 16000
        private const val MAX_AUDIO_SECONDS = 8
    }

    suspend fun analyzeVideoUri(
        uri: Uri,
        displayName: String? = null,
        onProgress: (Float, String) -> Unit = { _, _ -> }
    ): VideoForensicReport = withContext(Dispatchers.IO) {
        val startedAt = System.currentTimeMillis()
        val label = displayName ?: uri.lastPathSegment ?: "selected_video"
        val retriever = MediaMetadataRetriever()
        val timestampedFrames = mutableListOf<TimestampedFrame>()

        try {
            onProgress(0.05f, "Inspecting video container & provenance atoms...")
            currentCoroutineContext().ensureActive()

            val (containerTag, _) = runCatching {
                deepfakeForensicAnalyzer.scanContainerSignatures(uri)
            }.getOrDefault(null to 0f)

            try {
                retriever.setDataSource(context, uri)
            } catch (e: Exception) {
                return@withContext failedReport(
                    label = label,
                    startedAt = startedAt,
                    error = "Unable to open video source ($label): ${e.message ?: e::class.java.simpleName}"
                )
            }

            val hasVideo = retriever.extractMetadata(MediaMetadataRetriever.METADATA_KEY_HAS_VIDEO) == "yes"
            val durationMs = retriever.extractMetadata(MediaMetadataRetriever.METADATA_KEY_DURATION)?.toLongOrNull() ?: 0L
            val width = retriever.extractMetadata(MediaMetadataRetriever.METADATA_KEY_VIDEO_WIDTH)?.toIntOrNull() ?: 0
            val height = retriever.extractMetadata(MediaMetadataRetriever.METADATA_KEY_VIDEO_HEIGHT)?.toIntOrNull() ?: 0
            val bitrate = retriever.extractMetadata(MediaMetadataRetriever.METADATA_KEY_BITRATE)?.toLongOrNull()
            val frameRate = retriever.extractMetadata(MediaMetadataRetriever.METADATA_KEY_CAPTURE_FRAMERATE)?.toFloatOrNull()
            val mimeType = retriever.extractMetadata(MediaMetadataRetriever.METADATA_KEY_MIMETYPE)
            val hasAudio = retriever.extractMetadata(MediaMetadataRetriever.METADATA_KEY_HAS_AUDIO) == "yes"

            val extractorInfo = readTrackMetadataWithExtractor(uri)
            val effectiveMime = mimeType ?: extractorInfo.videoMime
            val audioSampleRate = extractorInfo.audioSampleRate
            val effectiveFps = frameRate ?: extractorInfo.frameRate

            if (!hasVideo && width == 0 && height == 0) {
                return@withContext failedReport(
                    label = label,
                    startedAt = startedAt,
                    error = "Media source does not contain a readable video track."
                )
            }

            val mediaMeta = VideoMediaMetadata(
                displayName = label,
                durationMs = durationMs,
                width = width,
                height = height,
                mimeType = effectiveMime,
                bitrateBps = bitrate,
                frameRate = effectiveFps,
                hasAudioTrack = hasAudio,
                audioSampleRateHz = audioSampleRate
            )

            // Build sampling schedule: uniform coverage across video + dense temporal burst
            val effectiveDuration = durationMs.coerceAtLeast(1000L)
            val uniformCount = if (durationMs <= 0L) 5 else UNIFORM_SAMPLE_COUNT.coerceAtMost((durationMs / 250L).toInt().coerceAtLeast(5))
            val schedule = mutableListOf<Pair<Long, Boolean>>()

            val uniformStep = effectiveDuration / uniformCount.coerceAtLeast(1)
            for (i in 0 until uniformCount) {
                schedule += (i.toLong() * uniformStep) to false
            }

            if (durationMs >= 900L) {
                val burstStart = ((durationMs * 0.30f).toLong())
                    .coerceAtMost((durationMs - BURST_SAMPLE_COUNT * BURST_INTERVAL_MS).coerceAtLeast(0L))
                for (b in 0 until BURST_SAMPLE_COUNT) {
                    val t = (burstStart + b * BURST_INTERVAL_MS).coerceAtMost(durationMs - 10L)
                    schedule += t to true
                }
            }

            // Sort chronologically and merge near-duplicate timestamps
            val orderedSchedule = schedule
                .sortedBy { it.first }
                .fold(mutableListOf<Pair<Long, Boolean>>()) { acc, item ->
                    val prev = acc.lastOrNull()
                    if (prev == null || abs(item.first - prev.first) >= 40L) {
                        acc += item
                    } else if (item.second && !prev.second) {
                        acc[acc.lastIndex] = prev.first to true
                    }
                    acc
                }

            val useClosestOption = durationMs in 1L..180_000L
            for ((idx, entry) in orderedSchedule.withIndex()) {
                currentCoroutineContext().ensureActive()
                val (timeMs, isBurst) = entry
                val timeUs = timeMs * 1000L
                val rawFrame = runCatching {
                    val primaryOpt = if (isBurst || useClosestOption) {
                        MediaMetadataRetriever.OPTION_CLOSEST
                    } else {
                        MediaMetadataRetriever.OPTION_CLOSEST_SYNC
                    }
                    retriever.getFrameAtTime(timeUs, primaryOpt)
                        ?: retriever.getFrameAtTime(timeUs, MediaMetadataRetriever.OPTION_CLOSEST_SYNC)
                        ?: if (idx == 0) retriever.getFrameAtTime(0L) else null
                }.getOrNull()

                if (rawFrame != null) {
                    val downscaled = downscaleBitmap(rawFrame, MAX_DIM)
                    timestampedFrames += TimestampedFrame(
                        index = timestampedFrames.size,
                        timeMs = timeMs,
                        bitmap = downscaled,
                        isBurstFrame = isBurst
                    )
                }
                onProgress(
                    0.08f + (0.38f * (idx + 1) / orderedSchedule.size.coerceAtLeast(1)),
                    "Extracted frame ${idx + 1}/${orderedSchedule.size}..."
                )
            }

            if (timestampedFrames.isEmpty()) {
                return@withContext failedReport(
                    label = label,
                    startedAt = startedAt,
                    error = "Decoded 0 video frames from '$label'. File may be corrupted or uses an unsupported codec."
                )
            }

            val audioPcm16k = if (hasAudio) {
                onProgress(0.48f, "Decoding audio track for lip-sync & voice forensics...")
                runCatching { extractMono16kAudio(uri) }.getOrNull()
            } else null

            analyzeTimestampedFrames(
                frames = timestampedFrames,
                videoMeta = mediaMeta,
                audioPcm16k = audioPcm16k,
                containerTag = containerTag,
                startedAtOverride = startedAt,
                onProgress = onProgress
            )
        } finally {
            timestampedFrames.forEach { tf ->
                runCatching { if (!tf.bitmap.isRecycled) tf.bitmap.recycle() }
            }
            runCatching { retriever.release() }
        }
    }

    suspend fun analyzeFramesList(
        frames: List<Bitmap>,
        videoMeta: VideoMediaMetadata,
        startedAtOverride: Long = System.currentTimeMillis(),
        onProgress: (Float, String) -> Unit = { _, _ -> }
    ): VideoForensicReport {
        val duration = videoMeta.durationMs.coerceAtLeast((frames.size * 120L).coerceAtLeast(1000L))
        val step = if (frames.size > 1) duration / frames.size else 100L
        val timestamped = frames.mapIndexed { idx, bmp ->
            TimestampedFrame(
                index = idx,
                timeMs = idx * step,
                bitmap = bmp,
                isBurstFrame = step <= 350L
            )
        }
        return analyzeTimestampedFrames(
            frames = timestamped,
            videoMeta = videoMeta,
            audioPcm16k = null,
            containerTag = null,
            startedAtOverride = startedAtOverride,
            onProgress = onProgress
        )
    }

    private suspend fun analyzeTimestampedFrames(
        frames: List<TimestampedFrame>,
        videoMeta: VideoMediaMetadata,
        audioPcm16k: FloatArray?,
        containerTag: String?,
        startedAtOverride: Long,
        onProgress: (Float, String) -> Unit
    ): VideoForensicReport = withContext(Dispatchers.Default) {
        val analysisId = UUID.randomUUID().toString()
        if (frames.isEmpty()) {
            return@withContext failedReport(
                label = videoMeta.displayName,
                startedAt = startedAtOverride,
                error = "No video frames supplied for forensic inspection."
            )
        }

        val modelReports = runCatching { deepfakeDetector.getValidationReports() }.getOrDefault(emptyList())
        val activeTfliteModels = modelReports.filter { it.isValid }.map { it.displayName }
        val findings = mutableListOf<SecurityFinding>()

        onProgress(0.55f, "Running facial landmark & 3D mesh extraction...")
        currentCoroutineContext().ensureActive()

        var framesWithFaces = 0
        var framesWithMeshes = 0
        val mlKitFaceScores = mutableListOf<Float>()
        val faceMeshScores = mutableListOf<Float>()
        val flaggedFrames = mutableListOf<Int>()
        val centerHistograms = mutableListOf<IntArray>()
        val luminances = mutableListOf<Float>()
        val faceObservations = mutableListOf<FrameFaceObservation>()
        var mlKitUnavailable = false
        var meshProcessed = 0

        val callerContext = currentCoroutineContext()
        synchronized(temporalTracker) {
            temporalTracker.reset()
            frames.forEachIndexed { idx, tf ->
                callerContext.ensureActive()
                val frame = tf.bitmap
                if (frame.isRecycled || frame.width < 12 || frame.height < 12) return@forEachIndexed

                luminances += computeAverageLuminance(frame)
                centerHistograms += computeCenterHistogram(frame)

                var detectedBox: android.graphics.Rect? = null
                try {
                    val faceRes = mlKitFaceAnalyzer.analyzeForDeepfake(frame)
                    if (faceRes.facesDetected > 0) {
                        framesWithFaces++
                        mlKitFaceScores += faceRes.deepfakeScore
                        val primaryFace = faceRes.faces.firstOrNull()
                        if (primaryFace != null) {
                            detectedBox = primaryFace.boundingBox
                            temporalTracker.recordFrame(primaryFace, tf.timeMs)
                        }
                        if (faceRes.deepfakeScore >= 0.45f) {
                            flaggedFrames += tf.index
                        }
                    }
                } catch (e: Exception) {
                    mlKitUnavailable = true
                    Log.w(TAG, "ML Kit face analyzer unavailable/error on frame $idx: ${e.message}")
                }

                // Run 468-pt face mesh on up to 6 frames for geometric depth checks
                if (idx % 3 == 0 && meshProcessed < 6) {
                    meshProcessed++
                    try {
                        val meshRes = faceMeshAnalyzer.analyze(frame)
                        if (meshRes.meshDetected) {
                            framesWithMeshes++
                            faceMeshScores += meshRes.deepfakeScore
                        }
                    } catch (e: Exception) {
                        Log.w(TAG, "Face mesh error on frame $idx: ${e.message}")
                    }
                }

                faceObservations += FrameFaceObservation(
                    frameIndex = tf.index,
                    timeMs = tf.timeMs,
                    faceBox = detectedBox,
                    mouthApertureRatio = -1f
                )
            }

            // Populate mouth aperture ratios computed by TemporalFaceTracker
            val snapshotsByTime = temporalTracker.getSnapshots().associateBy { it.timestamp }
            for (i in faceObservations.indices) {
                val obs = faceObservations[i]
                val snap = snapshotsByTime[obs.timeMs]
                if (snap != null && snap.mouthApertureRatio >= 0f) {
                    faceObservations[i] = obs.copy(mouthApertureRatio = snap.mouthApertureRatio)
                }
            }
        }

        onProgress(0.75f, "Running SRM noise, 2D DCT, YCbCr boundary & temporal shimmer forensics...")
        currentCoroutineContext().ensureActive()

        val forensicSignals = deepfakeForensicAnalyzer.analyze(
            frames = frames,
            faceObservations = faceObservations,
            videoMeta = videoMeta,
            audioPcm16k = audioPcm16k,
            containerTag = containerTag
        )
        findings += forensicSignals.findings

        onProgress(0.90f, "Evaluating multi-domain temporal & biometric coherence...")
        currentCoroutineContext().ensureActive()

        var temporalJumps = 0
        for (i in 1 until luminances.size) {
            if (abs(luminances[i] - luminances[i - 1]) > 18f) {
                temporalJumps++
                if (i !in flaggedFrames) flaggedFrames += i
            }
        }

        val histSimilarities = mutableListOf<Float>()
        for (i in 1 until centerHistograms.size) {
            histSimilarities += computeHistogramSimilarity(centerHistograms[i - 1], centerHistograms[i])
        }
        val avgHistSim = if (histSimilarities.isEmpty()) 1f else histSimilarities.average().toFloat()

        // Metadata / re-encoding signals
        var metadataRisk = 0
        if (videoMeta.bitrateBps != null && videoMeta.bitrateBps in 1 until 400_000L) {
            metadataRisk += 10
            findings += SecurityFinding(
                title = "Low video bitrate (${videoMeta.bitrateBps / 1000} kbps)",
                description = "Heavy compression can obscure blending seams and high-frequency skin texture.",
                severity = FindingSeverity.LOW,
                evidenceSource = "MediaMetadataRetriever",
                detectionMethod = "Container Bitrate Check",
                inputLocation = "Container stream",
                explanation = "Re-encoding at low bitrate degrades forensic evidence quality.",
                recommendedAction = "Obtain the original unmodified video file when available."
            )
        }
        if (temporalJumps >= 2) {
            metadataRisk += (temporalJumps * 8).coerceAtMost(30)
            findings += SecurityFinding(
                title = "Abrupt frame luminance transitions ($temporalJumps jumps)",
                description = "Sudden brightness discontinuities observed at sampled frame indices ${flaggedFrames.distinct().sorted().joinToString()}.",
                severity = if (temporalJumps >= 4) FindingSeverity.HIGH else FindingSeverity.MEDIUM,
                evidenceSource = "Temporal Frame Analyzer",
                detectionMethod = "Inter-Frame Luminance Delta",
                inputLocation = "Frames ${flaggedFrames.distinct().sorted().joinToString()}",
                explanation = "Can indicate harsh splices, scene cuts, or frame insertion artifacts.",
                recommendedAction = "Inspect the flagged timestamps closely for lighting jumps or scene edits."
            )
        }

        val metadataMap = linkedMapOf(
            "Resolution" to "${videoMeta.width}x${videoMeta.height}",
            "Duration" to "${videoMeta.durationMs} ms",
            "Frames Sampled" to frames.size.toString(),
            "Frames With Faces" to "$framesWithFaces/${frames.size}",
            "Frames With 3D Mesh" to "$framesWithMeshes",
            "Audio Track" to if (videoMeta.hasAudioTrack) {
                "Present${videoMeta.audioSampleRateHz?.let { " ($it Hz)" }.orEmpty()}"
            } else {
                "None"
            },
            "SRM Noise Disparity" to "${(forensicSignals.noiseDisparityScore * 100).toInt()}%",
            "2D DCT Spectral Anomaly" to "${(forensicSignals.dctSpectralScore * 100).toInt()}%",
            "YCbCr Boundary Seam" to "${(forensicSignals.boundaryBlendingScore * 100).toInt()}%",
            "Temporal Shimmer" to "${(forensicSignals.temporalFlickerScore * 100).toInt()}%"
        )
        videoMeta.mimeType?.let { metadataMap["Container MIME"] = it }
        videoMeta.bitrateBps?.let { metadataMap["Bitrate"] = "${it / 1000} kbps" }
        videoMeta.frameRate?.let { metadataMap["Frame Rate"] = "%.1f fps".format(it) }
        forensicSignals.detectedGeneratorTag?.let { metadataMap["Generator Tag"] = it }

        val limitations = buildList {
            add("Google ML Kit provides face bounding boxes, landmarks, and 3D mesh geometry ONLY — it does not independently classify deepfakes.")
            modelReports.filterNot { it.isValid }.forEach { rep ->
                add("${rep.displayName} (${rep.filename}) inactive: ${rep.reason}")
            }
            if (activeTfliteModels.isEmpty()) {
                add("No calibrated TFLite deepfake vision/audio model is active; verdict reflects multi-domain deterministic signal forensics (SRM noise, 2D DCT, YCbCr boundary, temporal shimmer, rPPG, AV-sync, and container inspection) without ML probability.")
            }
            if (!videoMeta.hasAudioTrack) {
                add("No audio track present; voice-clone & audio-visual lip-sync checks could not be performed.")
            }
        }

        val methods = buildList {
            add("MediaMetadataRetriever, MediaExtractor & MP4/WebM AI Signature Inspection")
            add("Uniform + Dense-Burst Frame Extraction (${frames.size} timestamped frames)")
            add("Google ML Kit Face Landmark, Blink & 468-pt 3D Mesh Geometry")
            add("SRM High-Pass Noise Residual Disparity (Face Skin vs Background)")
            add("2D 8x8 Block DCT Spectral Rolloff & Upsampling Grid Analysis")
            add("YCbCr Face-Perimeter Chrominance Seam & Blending Halo Detection")
            add("Burst Temporal Micro-Flicker & Multi-ROI rPPG Pulse Coherence")
            if (audioPcm16k != null) {
                add("16kHz PCM Audio-Visual Lip-Sync & Voice-Clone Acoustic Forensics")
            }
        }

        // Case A: Zero faces found across all sampled frames AND no explicit AI container tag -> INCONCLUSIVE!
        if (framesWithFaces == 0 && forensicSignals.detectedGeneratorTag == null) {
            findings += SecurityFinding(
                title = if (mlKitUnavailable) "Face detector unavailable offline/emulator" else "No faces detected across ${frames.size} frames",
                description = "Facial manipulation checks require clearly visible human faces in sampled frames.",
                severity = FindingSeverity.INFO,
                evidenceSource = "MLKitFaceAnalyzer",
                detectionMethod = "Frame Face Coverage Check",
                inputLocation = "Sampled frames 0..${frames.size - 1}",
                explanation = "Without visible facial landmarks across frames, facial deepfake verification is inconclusive.",
                recommendedAction = "Submit a clip with clear front-facing subjects if testing for face manipulation."
            )
            onProgress(1.0f, "Analysis inconclusive (no faces detected)")
            val result = SecurityAnalysisResult(
                analysisId = analysisId,
                module = SecurityModule.DEEPFAKE_VIDEO,
                inputName = videoMeta.displayName,
                inputType = videoMeta.mimeType ?: "video/*",
                status = AnalysisStatus.COMPLETED,
                verdict = SecurityVerdict.INCONCLUSIVE,
                riskScore = metadataRisk.takeIf { it > 0 },
                confidence = null,
                findings = findings,
                analysisMethods = methods,
                limitations = limitations,
                processingDurationMs = System.currentTimeMillis() - startedAtOverride,
                analyzedAt = System.currentTimeMillis(),
                modelVersion = null,
                errorMessage = null,
                metadata = metadataMap
            )
            return@withContext VideoForensicReport(
                analysisResult = result,
                mediaMetadata = videoMeta,
                framesExtracted = frames.size,
                framesWithFaces = 0,
                faceConsistencyScore = null,
                temporalLuminanceAnomalies = temporalJumps,
                flaggedFrameIndices = flaggedFrames.distinct().sorted()
            )
        }

        // Case B: Faces detected (or explicit AI container tag found) -> convergent multi-domain scoring
        val avgFaceAnomaly = if (mlKitFaceScores.isEmpty()) 0f else mlKitFaceScores.average().toFloat()
        val avgMeshAnomaly = if (faceMeshScores.isEmpty()) 0f else faceMeshScores.average().toFloat()
        val temporalResult = synchronized(temporalTracker) {
            if (framesWithFaces >= 2) runCatching { temporalTracker.analyze() }.getOrNull() else null
        }
        val temporalAnomaly = temporalResult?.temporalDeepfakeScore ?: 0f

        temporalResult?.findings?.forEach { findingText ->
            findings += SecurityFinding(
                title = "Temporal facial signal anomaly",
                description = findingText,
                severity = if (temporalAnomaly > 0.50f) FindingSeverity.HIGH else FindingSeverity.MEDIUM,
                evidenceSource = "TemporalFaceTracker",
                detectionMethod = "ML Kit Multi-Frame Landmark Tracking",
                inputLocation = "$framesWithFaces face frames",
                explanation = findingText,
                recommendedAction = "Verify speaker authenticity via a second channel."
            )
        }
        if (avgMeshAnomaly > 0.45f) {
            findings += SecurityFinding(
                title = "Face mesh geometry asymmetry/irregularity",
                description = "Mean 468-pt facial mesh anomaly score: ${(avgMeshAnomaly * 100).toInt()}%.",
                severity = if (avgMeshAnomaly > 0.65f) FindingSeverity.HIGH else FindingSeverity.MEDIUM,
                evidenceSource = "FaceMeshDeepfakeAnalyzer",
                detectionMethod = "3D Mesh Symmetry & Depth Heuristic",
                inputLocation = "$framesWithMeshes mesh-analyzed frames",
                explanation = "Mesh point depth or symmetry showed elevated variance across sampled frames (heuristic indicator, not proof).",
                recommendedAction = "Inspect mouth, eye borders, and jawline under motion."
            )
        }
        if (avgHistSim < 0.72f) {
            findings += SecurityFinding(
                title = "Center-frame color distribution shift",
                description = "Adjacent center histograms averaged ${(avgHistSim * 100).toInt()}% correlation across cuts/motion.",
                severity = FindingSeverity.LOW,
                evidenceSource = "Center Histogram Tracker",
                detectionMethod = "Inter-Frame Correlation",
                inputLocation = "Center 50% crop",
                explanation = "Low frame-to-frame correlation reflects fast camera cuts, heavy motion, or video edits.",
                recommendedAction = "Check whether the clip contains scene edits."
            )
        }

        // Convergent multi-cue aggregation (prevents weak signals from diluting strong forensic artifacts)
        val geometryCue = max(avgFaceAnomaly, avgMeshAnomaly)
        val lumJumpCue = (temporalJumps / 4f).coerceIn(0f, 1f) * 0.65f
        val histShiftCue = ((1f - avgHistSim).coerceIn(0f, 1f)) * 0.5f

        val domainCues = listOf(
            forensicSignals.noiseDisparityScore,
            forensicSignals.dctSpectralScore,
            forensicSignals.boundaryBlendingScore,
            forensicSignals.temporalFlickerScore,
            forensicSignals.rppgIncoherenceScore * 0.78f,
            forensicSignals.avSyncAnomalyScore * 0.92f,
            forensicSignals.voiceCloneScore * 0.92f,
            forensicSignals.containerSignatureScore,
            geometryCue,
            temporalAnomaly,
            max(lumJumpCue, histShiftCue)
        )

        val sortedCues = domainCues.sortedDescending()
        val maxCue = sortedCues.firstOrNull() ?: 0f
        val top3Mean = sortedCues.take(3).average().toFloat()
        val noisyOr = 1f - domainCues.fold(1f) { acc, s ->
            acc * (1f - (s * 0.62f).coerceIn(0f, 0.90f))
        }
        val strongCueCount = domainCues.count { it >= 0.50f }
        val moderateCueCount = domainCues.count { it >= 0.35f }
        val corroborationBonus = when {
            strongCueCount >= 3 -> 10
            strongCueCount >= 2 -> 6
            moderateCueCount >= 3 -> 4
            else -> 0
        }

        val combinedSignal = (top3Mean * 0.45f + noisyOr * 0.35f + maxCue * 0.20f).coerceIn(0f, 1f)
        val rawRisk = (combinedSignal * 90f) + corroborationBonus + (metadataRisk * 0.25f)
        val totalRiskScore = max(
            rawRisk.toInt(),
            if (forensicSignals.detectedGeneratorTag != null) 88 else 0
        ).coerceIn(0, 100)

        val faceConsistency = (1f - max(
            avgFaceAnomaly * 0.4f + temporalAnomaly * 0.4f,
            forensicSignals.temporalFlickerScore * 0.65f + forensicSignals.boundaryBlendingScore * 0.35f
        )).coerceIn(0f, 1f)

        val verdict = when {
            forensicSignals.detectedGeneratorTag != null || totalRiskScore >= 80 -> SecurityVerdict.LIKELY_AI_GENERATED
            totalRiskScore >= 60 -> SecurityVerdict.HIGH_RISK
            totalRiskScore >= 35 -> SecurityVerdict.SUSPICIOUS
            totalRiskScore >= 18 -> SecurityVerdict.LOW_RISK
            else -> SecurityVerdict.SAFE
        }

        onProgress(1.0f, "Video forensics complete")

        val result = SecurityAnalysisResult(
            analysisId = analysisId,
            module = SecurityModule.DEEPFAKE_VIDEO,
            inputName = videoMeta.displayName,
            inputType = videoMeta.mimeType ?: "video/*",
            status = AnalysisStatus.COMPLETED,
            verdict = verdict,
            riskScore = totalRiskScore,
            confidence = null, // No calibrated TFLite deepfake classifier active
            findings = findings,
            analysisMethods = methods,
            limitations = limitations,
            processingDurationMs = System.currentTimeMillis() - startedAtOverride,
            analyzedAt = System.currentTimeMillis(),
            modelVersion = if (activeTfliteModels.isEmpty()) null else activeTfliteModels.joinToString(),
            errorMessage = null,
            metadata = metadataMap
        )

        VideoForensicReport(
            analysisResult = result,
            mediaMetadata = videoMeta,
            framesExtracted = frames.size,
            framesWithFaces = framesWithFaces,
            faceConsistencyScore = faceConsistency,
            temporalLuminanceAnomalies = temporalJumps,
            flaggedFrameIndices = flaggedFrames.distinct().sorted()
        )
    }

    private data class ExtractorTrackInfo(
        val videoMime: String?,
        val audioSampleRate: Int?,
        val frameRate: Float?
    )

    private fun readTrackMetadataWithExtractor(uri: Uri): ExtractorTrackInfo {
        val extractor = MediaExtractor()
        return try {
            extractor.setDataSource(context, uri, null)
            var videoMime: String? = null
            var audioSampleRate: Int? = null
            var frameRate: Float? = null
            for (i in 0 until extractor.trackCount) {
                val format = extractor.getTrackFormat(i)
                val mime = format.getString(MediaFormat.KEY_MIME)
                if (mime != null) {
                    if (mime.startsWith("video/") && videoMime == null) {
                        videoMime = mime
                        if (format.containsKey(MediaFormat.KEY_FRAME_RATE)) {
                            frameRate = runCatching { format.getInteger(MediaFormat.KEY_FRAME_RATE).toFloat() }
                                .getOrElse { runCatching { format.getFloat(MediaFormat.KEY_FRAME_RATE) }.getOrNull() }
                        }
                    } else if (mime.startsWith("audio/") && audioSampleRate == null && format.containsKey(MediaFormat.KEY_SAMPLE_RATE)) {
                        audioSampleRate = format.getInteger(MediaFormat.KEY_SAMPLE_RATE)
                    }
                }
            }
            ExtractorTrackInfo(videoMime, audioSampleRate, frameRate)
        } catch (_: Exception) {
            ExtractorTrackInfo(null, null, null)
        } finally {
            runCatching { extractor.release() }
        }
    }

    /**
     * Decode up to [MAX_AUDIO_SECONDS] of mono 16kHz PCM audio from the video's audio track
     * using Android [MediaExtractor] + [MediaCodec], downmixing channels & resampling to 16kHz.
     */
    private fun extractMono16kAudio(uri: Uri): FloatArray? {
        val extractor = MediaExtractor()
        var decoder: MediaCodec? = null
        return try {
            extractor.setDataSource(context, uri, null)
            var audioTrackIdx = -1
            var format: MediaFormat? = null
            for (i in 0 until extractor.trackCount) {
                val f = extractor.getTrackFormat(i)
                val mime = f.getString(MediaFormat.KEY_MIME) ?: continue
                if (mime.startsWith("audio/")) {
                    audioTrackIdx = i
                    format = f
                    break
                }
            }
            if (audioTrackIdx < 0 || format == null) return null

            extractor.selectTrack(audioTrackIdx)
            val mime = format.getString(MediaFormat.KEY_MIME) ?: return null
            val srcRate = if (format.containsKey(MediaFormat.KEY_SAMPLE_RATE)) {
                format.getInteger(MediaFormat.KEY_SAMPLE_RATE).coerceAtLeast(8000)
            } else TARGET_AUDIO_RATE
            val channels = if (format.containsKey(MediaFormat.KEY_CHANNEL_COUNT)) {
                format.getInteger(MediaFormat.KEY_CHANNEL_COUNT).coerceIn(1, 8)
            } else 1

            decoder = MediaCodec.createDecoderByType(mime)
            decoder.configure(format, null, null, 0)
            decoder.start()

            val maxSrcSamples = srcRate * MAX_AUDIO_SECONDS
            val monoRaw = ArrayList<Float>(min(maxSrcSamples, srcRate * 4))
            val info = MediaCodec.BufferInfo()
            var inputDone = false
            var outputDone = false
            var iterations = 0

            while (!outputDone && monoRaw.size < maxSrcSamples && iterations < 800) {
                iterations++
                if (!inputDone) {
                    val inIdx = decoder.dequeueInputBuffer(5_000L)
                    if (inIdx >= 0) {
                        val buf = decoder.getInputBuffer(inIdx)
                        if (buf != null) {
                            val sz = extractor.readSampleData(buf, 0)
                            if (sz < 0) {
                                decoder.queueInputBuffer(inIdx, 0, 0, 0L, MediaCodec.BUFFER_FLAG_END_OF_STREAM)
                                inputDone = true
                            } else {
                                decoder.queueInputBuffer(inIdx, 0, sz, extractor.sampleTime, 0)
                                extractor.advance()
                            }
                        }
                    }
                }

                val outIdx = decoder.dequeueOutputBuffer(info, 5_000L)
                if (outIdx >= 0) {
                    val outBuf = decoder.getOutputBuffer(outIdx)
                    if (outBuf != null && info.size > 0) {
                        outBuf.order(ByteOrder.LITTLE_ENDIAN)
                        outBuf.position(info.offset)
                        outBuf.limit(info.offset + info.size)
                        val shortBuf = outBuf.asShortBuffer()
                        while (shortBuf.remaining() >= channels && monoRaw.size < maxSrcSamples) {
                            var chSum = 0f
                            for (c in 0 until channels) {
                                chSum += shortBuf.get() / 32768f
                            }
                            monoRaw += chSum / channels
                        }
                    }
                    decoder.releaseOutputBuffer(outIdx, false)
                    if ((info.flags and MediaCodec.BUFFER_FLAG_END_OF_STREAM) != 0) {
                        outputDone = true
                    }
                }
            }

            if (monoRaw.isEmpty()) return null
            if (srcRate == TARGET_AUDIO_RATE) {
                monoRaw.toFloatArray()
            } else {
                val targetCount = ((monoRaw.size.toDouble() * TARGET_AUDIO_RATE) / srcRate).toInt().coerceAtLeast(1)
                val ratio = monoRaw.size.toDouble() / targetCount
                FloatArray(targetCount) { i ->
                    val pos = i * ratio
                    val idx0 = pos.toInt().coerceIn(0, monoRaw.lastIndex)
                    val idx1 = (idx0 + 1).coerceIn(0, monoRaw.lastIndex)
                    val frac = (pos - idx0).toFloat()
                    monoRaw[idx0] * (1f - frac) + monoRaw[idx1] * frac
                }
            }
        } catch (_: Exception) {
            null
        } finally {
            runCatching { decoder?.stop() }
            runCatching { decoder?.release() }
            runCatching { extractor.release() }
        }
    }

    private fun downscaleBitmap(bitmap: Bitmap, maxDimension: Int): Bitmap {
        val w = bitmap.width
        val h = bitmap.height
        if (w <= maxDimension && h <= maxDimension) return bitmap
        val scale = maxDimension.toFloat() / maxOf(w, h)
        val newW = (w * scale).toInt().coerceAtLeast(1)
        val newH = (h * scale).toInt().coerceAtLeast(1)
        val scaled = Bitmap.createScaledBitmap(bitmap, newW, newH, true)
        if (scaled !== bitmap) bitmap.recycle()
        return scaled
    }

    private fun computeAverageLuminance(bitmap: Bitmap): Float {
        var sum = 0L
        var count = 0
        for (y in 0 until bitmap.height step 6) {
            for (x in 0 until bitmap.width step 6) {
                val p = bitmap.getPixel(x, y)
                sum += (0.299 * Color.red(p) + 0.587 * Color.green(p) + 0.114 * Color.blue(p)).toLong()
                count++
            }
        }
        return if (count > 0) sum.toFloat() / count else 0f
    }

    private fun computeCenterHistogram(bitmap: Bitmap): IntArray {
        val hist = IntArray(64)
        val sx = bitmap.width / 4
        val ex = (sx + bitmap.width / 2).coerceAtMost(bitmap.width)
        val sy = bitmap.height / 4
        val ey = (sy + bitmap.height / 2).coerceAtMost(bitmap.height)
        for (y in sy until ey step 4) {
            for (x in sx until ex step 4) {
                val p = bitmap.getPixel(x, y)
                val lum = (0.299 * Color.red(p) + 0.587 * Color.green(p) + 0.114 * Color.blue(p)).toInt().coerceIn(0, 255)
                hist[lum / 4]++
            }
        }
        return hist
    }

    private fun computeHistogramSimilarity(a: IntArray, b: IntArray): Float {
        val m1 = a.average()
        val m2 = b.average()
        var num = 0.0
        var d1 = 0.0
        var d2 = 0.0
        for (i in a.indices) {
            val da = a[i] - m1
            val db = b[i] - m2
            num += da * db
            d1 += da * da
            d2 += db * db
        }
        val denom = kotlin.math.sqrt(d1 * d2)
        return if (denom > 0.0) (num / denom).toFloat().coerceIn(0f, 1f) else 1f
    }

    private fun failedReport(label: String, startedAt: Long, error: String): VideoForensicReport {
        val result = SecurityAnalysisResult(
            analysisId = UUID.randomUUID().toString(),
            module = SecurityModule.DEEPFAKE_VIDEO,
            inputName = label,
            inputType = "video",
            status = AnalysisStatus.FAILED,
            verdict = SecurityVerdict.NOT_ANALYZED,
            riskScore = null,
            confidence = null,
            findings = emptyList(),
            analysisMethods = listOf("Video Container & Frame Extraction"),
            limitations = listOf(error),
            processingDurationMs = System.currentTimeMillis() - startedAt,
            analyzedAt = System.currentTimeMillis(),
            modelVersion = null,
            errorMessage = error
        )
        return VideoForensicReport(
            analysisResult = result,
            mediaMetadata = null,
            framesExtracted = 0,
            framesWithFaces = 0,
            faceConsistencyScore = null,
            temporalLuminanceAnomalies = 0,
            flaggedFrameIndices = emptyList()
        )
    }
}
