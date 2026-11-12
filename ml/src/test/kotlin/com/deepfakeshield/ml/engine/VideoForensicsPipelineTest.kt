package com.deepfakeshield.ml.engine

import android.content.Context
import android.graphics.Bitmap
import android.graphics.Color
import android.graphics.PointF
import android.graphics.Rect
import android.net.Uri
import androidx.test.core.app.ApplicationProvider
import com.deepfakeshield.core.model.AnalysisStatus
import com.deepfakeshield.core.model.SecurityVerdict
import com.deepfakeshield.ml.deepfake.GovernmentGradeDeepfakeDetector
import com.deepfakeshield.ml.face.FaceMeshDeepfakeAnalyzer
import com.deepfakeshield.ml.face.MLKitFaceAnalyzer
import com.deepfakeshield.ml.face.TemporalFaceTracker
import io.mockk.every
import io.mockk.mockk
import kotlinx.coroutines.test.runTest
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.util.Random

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [28])
class VideoForensicsPipelineTest {

    private lateinit var context: Context
    private lateinit var deepfakeDetector: GovernmentGradeDeepfakeDetector
    private lateinit var mlKitFaceAnalyzer: MLKitFaceAnalyzer
    private lateinit var faceMeshAnalyzer: FaceMeshDeepfakeAnalyzer
    private lateinit var temporalTracker: TemporalFaceTracker
    private lateinit var forensicAnalyzer: VideoDeepfakeForensicAnalyzer
    private lateinit var pipeline: VideoForensicsPipeline

    @Before
    fun setup() {
        context = ApplicationProvider.getApplicationContext()
        deepfakeDetector = mockk(relaxed = true)
        mlKitFaceAnalyzer = mockk(relaxed = true)
        faceMeshAnalyzer = mockk(relaxed = true)
        temporalTracker = TemporalFaceTracker()
        forensicAnalyzer = VideoDeepfakeForensicAnalyzer(
            context = context,
            voiceCloneEngine = VoiceCloneDetectionEngine()
        )
        every { deepfakeDetector.getValidationReports() } returns emptyList()
        pipeline = VideoForensicsPipeline(
            context = context,
            mlKitFaceAnalyzer = mlKitFaceAnalyzer,
            faceMeshAnalyzer = faceMeshAnalyzer,
            temporalTracker = temporalTracker,
            deepfakeDetector = deepfakeDetector,
            deepfakeForensicAnalyzer = forensicAnalyzer
        )
    }

    @Test
    fun `corrupt or missing video uri returns FAILED never SAFE`() = runTest {
        val report = pipeline.analyzeVideoUri(Uri.parse("file:///nonexistent/corrupt_video.mp4"))
        assertEquals(AnalysisStatus.FAILED, report.analysisResult.status)
        assertNotEquals(SecurityVerdict.SAFE, report.analysisResult.verdict)
        assertNull(report.analysisResult.confidence)
    }

    @Test
    fun `empty frame list returns FAILED with NOT_ANALYZED verdict`() = runTest {
        val report = pipeline.analyzeFramesList(
            frames = emptyList(),
            videoMeta = VideoMediaMetadata(
                displayName = "empty.mp4",
                durationMs = 0L,
                width = 0,
                height = 0,
                mimeType = "video/mp4",
                bitrateBps = null,
                frameRate = null,
                hasAudioTrack = false
            )
        )
        assertEquals(AnalysisStatus.FAILED, report.analysisResult.status)
        assertEquals(SecurityVerdict.NOT_ANALYZED, report.analysisResult.verdict)
        assertNull(report.analysisResult.riskScore)
        assertNull(report.analysisResult.confidence)
    }

    @Test
    fun `frames with zero detected faces return INCONCLUSIVE and disclose ML Kit scope`() = runTest {
        every { mlKitFaceAnalyzer.analyzeForDeepfake(any()) } returns MLKitFaceAnalyzer.FaceAnalysisResult(
            facesDetected = 0,
            faces = emptyList(),
            deepfakeScore = 0f,
            findings = emptyList(),
            processingTimeMs = 1L
        )
        every { faceMeshAnalyzer.analyze(any()) } returns FaceMeshDeepfakeAnalyzer.FaceMeshResult(
            meshDetected = false,
            meshPointCount = 0,
            meshRegularityScore = 0f,
            depthConsistencyScore = 0f,
            meshSymmetryScore = 0f,
            faceOvalSmoothnessScore = 0f,
            lipMeshScore = 0f,
            eyeMeshScore = 0f,
            deepfakeScore = 0f,
            findings = emptyList(),
            processingTimeMs = 1L
        )
        val frames = List(4) { Bitmap.createBitmap(64, 64, Bitmap.Config.ARGB_8888) }
        val report = pipeline.analyzeFramesList(
            frames = frames,
            videoMeta = VideoMediaMetadata(
                displayName = "no_faces.mp4",
                durationMs = 2000L,
                width = 64,
                height = 64,
                mimeType = "video/mp4",
                bitrateBps = 900_000L,
                frameRate = 30f,
                hasAudioTrack = false
            )
        )

        assertEquals(AnalysisStatus.COMPLETED, report.analysisResult.status)
        assertEquals(SecurityVerdict.INCONCLUSIVE, report.analysisResult.verdict)
        assertNull("Heuristic/ML Kit geometry check must NOT report ML confidence", report.analysisResult.confidence)
        assertTrue(report.analysisResult.limitations.any { it.contains("ML Kit") && it.contains("does not independently classify deepfakes") })
    }

    @Test
    fun `synthetic face-swap artifacts trigger HIGH_RISK or LIKELY_AI_GENERATED`() = runTest {
        val w = 240
        val h = 240
        val faceBox = Rect(70, 50, 170, 190)

        every { mlKitFaceAnalyzer.analyzeForDeepfake(any()) } returns MLKitFaceAnalyzer.FaceAnalysisResult(
            facesDetected = 1,
            faces = listOf(
                MLKitFaceAnalyzer.DetectedFaceInfo(
                    boundingBox = faceBox,
                    leftEyeOpenProb = 0.92f,
                    rightEyeOpenProb = 0.91f,
                    smileProb = 0.2f,
                    headEulerX = 0f,
                    headEulerY = 0f,
                    headEulerZ = 0f,
                    trackingId = 1,
                    landmarks = mapOf(
                        1 to PointF(100f, 100f),
                        4 to PointF(120f, 125f)
                    ),
                    contourPoints = emptyMap(),
                    landmarkScore = 0.1f,
                    eyeAsymmetryScore = 0.01f,
                    mouthNaturalness = 0.1f
                )
            ),
            deepfakeScore = 0.1f,
            findings = emptyList(),
            processingTimeMs = 5L
        )
        every { faceMeshAnalyzer.analyze(any()) } returns FaceMeshDeepfakeAnalyzer.FaceMeshResult(
            meshDetected = true,
            meshPointCount = 468,
            meshRegularityScore = 0.1f,
            depthConsistencyScore = 0.1f,
            meshSymmetryScore = 0.1f,
            faceOvalSmoothnessScore = 0.1f,
            lipMeshScore = 0.1f,
            eyeMeshScore = 0.1f,
            deepfakeScore = 0.1f,
            findings = emptyList(),
            processingTimeMs = 5L
        )

        // Build 10 frames simulating a face-swap deepfake:
        // - Natural noisy camera background
        // - Over-smoothed plastic inner face with shifted Cb/Cr chrominance + checkerboard shimmer
        val rng = Random(42L)
        val frames = List(10) { frameIdx ->
            val bmp = Bitmap.createBitmap(w, h, Bitmap.Config.ARGB_8888)
            val pixels = IntArray(w * h)
            val shimmer = if (frameIdx % 2 == 0) 12 else -12
            for (y in 0 until h) {
                for (x in 0 until w) {
                    val inFace = x in faceBox.left..faceBox.right && y in faceBox.top..faceBox.bottom
                    if (inFace) {
                        // Smooth plastic face with alternating checkerboard & chrominance tint shift
                        val checker = if ((x + y) % 2 == 0) shimmer else -shimmer
                        val r = (205 + checker).coerceIn(0, 255)
                        val g = (165 + checker / 2).coerceIn(0, 255)
                        val b = (135 - checker).coerceIn(0, 255)
                        pixels[y * w + x] = Color.rgb(r, g, b)
                    } else {
                        // Textured/noisy natural background
                        val noise = rng.nextInt(45) - 22
                        val r = (90 + noise).coerceIn(0, 255)
                        val g = (115 + noise).coerceIn(0, 255)
                        val b = (140 + noise).coerceIn(0, 255)
                        pixels[y * w + x] = Color.rgb(r, g, b)
                    }
                }
            }
            bmp.setPixels(pixels, 0, w, 0, 0, w, h)
            bmp
        }

        val report = pipeline.analyzeFramesList(
            frames = frames,
            videoMeta = VideoMediaMetadata(
                displayName = "faceswap_clip.mp4",
                durationMs = 6000L, // > 4.5s with zero blinks + 10 frames
                width = 512,
                height = 512,
                mimeType = "video/avc",
                bitrateBps = 1_200_000L,
                frameRate = 12f,
                hasAudioTrack = false
            )
        )

        assertEquals(AnalysisStatus.COMPLETED, report.analysisResult.status)
        val score = report.analysisResult.riskScore ?: 0
        assertTrue(
            "Expected elevated riskScore >= 60 for multi-cue deepfake artifacts, got $score (${report.analysisResult.verdict})",
            score >= 60
        )
        assertTrue(
            "Expected HIGH_RISK or LIKELY_AI_GENERATED verdict, got ${report.analysisResult.verdict}",
            report.analysisResult.verdict == SecurityVerdict.HIGH_RISK ||
                report.analysisResult.verdict == SecurityVerdict.LIKELY_AI_GENERATED
        )
        assertNull("Without calibrated TFLite model, confidence must remain null", report.analysisResult.confidence)
        assertTrue(report.analysisResult.findings.isNotEmpty())
    }

    @Test
    fun `consistent natural sensor noise across face and background stays SAFE or LOW_RISK`() = runTest {
        val w = 200
        val h = 200
        val faceBox = Rect(60, 40, 140, 160)

        every { mlKitFaceAnalyzer.analyzeForDeepfake(any()) } returns MLKitFaceAnalyzer.FaceAnalysisResult(
            facesDetected = 1,
            faces = listOf(
                MLKitFaceAnalyzer.DetectedFaceInfo(
                    boundingBox = faceBox,
                    leftEyeOpenProb = 0.9f,
                    rightEyeOpenProb = 0.9f,
                    smileProb = 0.2f,
                    headEulerX = 0f,
                    headEulerY = 0f,
                    headEulerZ = 0f,
                    trackingId = 1,
                    landmarks = mapOf(
                        1 to PointF(85f, 80f),
                        4 to PointF(100f, 105f)
                    ),
                    contourPoints = emptyMap(),
                    landmarkScore = 0.05f,
                    eyeAsymmetryScore = 0.01f,
                    mouthNaturalness = 0.05f
                )
            ),
            deepfakeScore = 0.05f,
            findings = emptyList(),
            processingTimeMs = 5L
        )
        every { faceMeshAnalyzer.analyze(any()) } returns FaceMeshDeepfakeAnalyzer.FaceMeshResult(
            meshDetected = true,
            meshPointCount = 468,
            meshRegularityScore = 0.05f,
            depthConsistencyScore = 0.05f,
            meshSymmetryScore = 0.05f,
            faceOvalSmoothnessScore = 0.05f,
            lipMeshScore = 0.05f,
            eyeMeshScore = 0.05f,
            deepfakeScore = 0.05f,
            findings = emptyList(),
            processingTimeMs = 5L
        )

        // Authentic-like consistent camera noise across the whole frame and natural blink on frame 3
        val rng = Random(99L)
        val frames = List(6) { _ ->
            val bmp = Bitmap.createBitmap(w, h, Bitmap.Config.ARGB_8888)
            val pixels = IntArray(w * h)
            for (y in 0 until h) {
                for (x in 0 until w) {
                    val noise = rng.nextInt(16) - 8
                    val v = (140 + noise).coerceIn(0, 255)
                    pixels[y * w + x] = Color.rgb(v, v - 5, v - 10)
                }
            }
            bmp.setPixels(pixels, 0, w, 0, 0, w, h)
            bmp
        }

        // Simulate a natural blink in frame 2 so blink check passes cleanly
        every { mlKitFaceAnalyzer.analyzeForDeepfake(frames[2]) } returns MLKitFaceAnalyzer.FaceAnalysisResult(
            facesDetected = 1,
            faces = listOf(
                MLKitFaceAnalyzer.DetectedFaceInfo(
                    boundingBox = faceBox,
                    leftEyeOpenProb = 0.1f,
                    rightEyeOpenProb = 0.1f,
                    smileProb = 0.2f,
                    headEulerX = 0f,
                    headEulerY = 0f,
                    headEulerZ = 0f,
                    trackingId = 1,
                    landmarks = mapOf(
                        1 to PointF(85f, 80f),
                        4 to PointF(100f, 105f)
                    ),
                    contourPoints = emptyMap(),
                    landmarkScore = 0.05f,
                    eyeAsymmetryScore = 0.01f,
                    mouthNaturalness = 0.05f
                )
            ),
            deepfakeScore = 0.05f,
            findings = emptyList(),
            processingTimeMs = 5L
        )

        val report = pipeline.analyzeFramesList(
            frames = frames,
            videoMeta = VideoMediaMetadata(
                displayName = "authentic_clip.mp4",
                durationMs = 2000L,
                width = 1920,
                height = 1080,
                mimeType = "video/avc",
                bitrateBps = 4_500_000L,
                frameRate = 30f,
                hasAudioTrack = true,
                audioSampleRateHz = 48000
            )
        )

        assertEquals(AnalysisStatus.COMPLETED, report.analysisResult.status)
        val score = report.analysisResult.riskScore ?: 0
        assertTrue(
            "Expected low riskScore < 35 for consistent authentic-like frames, got $score",
            score < 35
        )
        assertTrue(
            "Expected SAFE or LOW_RISK, got ${report.analysisResult.verdict}",
            report.analysisResult.verdict == SecurityVerdict.SAFE ||
                report.analysisResult.verdict == SecurityVerdict.LOW_RISK
        )
    }

    @Test
    fun `temporal face tracker uses video presentation timestamps for blink suppression`() {
        val tracker = TemporalFaceTracker()
        val face = MLKitFaceAnalyzer.DetectedFaceInfo(
            boundingBox = Rect(50, 50, 150, 180),
            leftEyeOpenProb = 0.95f,
            rightEyeOpenProb = 0.95f,
            smileProb = 0.1f,
            headEulerX = 0f,
            headEulerY = 0f,
            headEulerZ = 0f,
            trackingId = 1,
            landmarks = emptyMap(),
            contourPoints = emptyMap(),
            landmarkScore = 0f,
            eyeAsymmetryScore = 0f,
            mouthNaturalness = 0f
        )

        // Record 8 frames spanning 6 seconds of video time within milliseconds of CPU time
        for (i in 0 until 8) {
            tracker.recordFrame(face, videoTimestampMs = i * 850L)
        }
        val result = tracker.analyze()
        assertTrue("Expected non-zero blinkRateScore when no blinks occur over 5.95s", result.blinkRateScore > 0.3f)
        assertTrue(result.findings.any { it.contains("No blinks detected", ignoreCase = true) })
    }
}
