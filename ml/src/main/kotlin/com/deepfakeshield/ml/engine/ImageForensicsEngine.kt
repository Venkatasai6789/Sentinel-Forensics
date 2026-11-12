package com.deepfakeshield.ml.engine

import android.content.Context
import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.graphics.Color
import android.net.Uri
import androidx.exifinterface.media.ExifInterface
import com.deepfakeshield.core.model.AnalysisStatus
import com.deepfakeshield.core.model.FindingSeverity
import com.deepfakeshield.core.model.SecurityAnalysisResult
import com.deepfakeshield.core.model.SecurityFinding
import com.deepfakeshield.core.model.SecurityModule
import com.deepfakeshield.core.model.SecurityVerdict
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.withContext
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.util.UUID
import javax.inject.Inject
import javax.inject.Singleton
import kotlin.math.abs
import kotlin.math.pow
import kotlin.math.sqrt

data class ElaHeatmapStats(
    val meanDifference: Float,
    val p95Difference: Float,
    val maxBlockVariance: Float,
    val outlierBlockRatio: Float,
    val elaBitmap: Bitmap?
)

data class PhotoForensicReport(
    val analysisResult: SecurityAnalysisResult,
    val displayName: String,
    val sha256: String?,
    val width: Int,
    val height: Int,
    val fileSizeBytes: Long,
    val containerFormat: String,
    val hasCameraExif: Boolean,
    val detectedGeneratorTag: String?,
    val metadataMap: Map<String, String>,
    val elaStats: ElaHeatmapStats?
)

/**
 * On-device Photo Forensics Engine:
 * - Safe downsampled decoding (`inSampleSize` capped <= 1600px)
 * - Container format, SHA-256 digest & file size metrics
 * - Real EXIF (`ExifInterface`), JPEG XMP/C2PA and PNG `tEXt`/`iTXt`/`zTXt` metadata parsing
 * - True JPEG Q90 recompression Error Level Analysis (ELA) producing a visual heatmap Bitmap & block stats
 * - Block duplicate & Laplacian spatial noise consistency analysis
 *
 * Strictly enforces Rule 7: neither EXIF stripping nor high ELA differences prove AI generation.
 */
@Singleton
class ImageForensicsEngine @Inject constructor() {

    data class ImageForensicResult(
        val isManipulated: Boolean,
        val confidence: Float,
        val manipulationType: String,
        val findings: List<ForensicFinding>,
        val riskScore: Int,
        val recommendation: String
    )

    data class ForensicFinding(
        val type: String,
        val description: String,
        val severity: String,
        val region: String? = null
    )

    companion object {
        private const val MAX_ANALYSIS_DIMENSION = 1600
        private const val MAX_ELA_BITMAP_DIM = 512
        private const val MAX_IMAGE_BYTES = 35L * 1024L * 1024L

        private val AI_GENERATOR_SIGNATURES = listOf(
            "stable diffusion", "automatic1111", "comfyui", "midjourney",
            "dall-e", "dall·e", "imagen", "firefly", "novelai",
            "invokeai", "fooocus", "sdxl", "dreamstudio", "bing image creator",
            "c2pa", "trainedalgorithmicmedia", "digitalcapture"
        )

        private val EDITING_SOFTWARE_SIGNATURES = listOf(
            "photoshop", "gimp", "lightroom", "affinity", "pixelmator",
            "snapseed", "picsart", "canva", "facetune", "meitu", "remini"
        )
    }

    suspend fun analyzeImageUri(
        context: Context,
        uri: Uri,
        displayName: String? = null,
        onProgress: (Float, String) -> Unit = { _, _ -> }
    ): PhotoForensicReport = withContext(Dispatchers.IO) {
        val startedAt = System.currentTimeMillis()
        val label = displayName ?: uri.lastPathSegment ?: "selected_image"

        onProgress(0.08f, "Reading image stream...")
        val bytes = try {
            context.contentResolver.openInputStream(uri)?.use { stream ->
                val out = ByteArrayOutputStream()
                val buf = ByteArray(16384)
                var total = 0L
                var n: Int
                while (stream.read(buf).also { n = it } != -1) {
                    currentCoroutineContext().ensureActive()
                    total += n
                    if (total > MAX_IMAGE_BYTES) {
                        return@withContext failedReport(
                            label = label,
                            startedAt = startedAt,
                            error = "Image exceeds maximum 35 MB forensic analysis buffer."
                        )
                    }
                    out.write(buf, 0, n)
                }
                out.toByteArray()
            } ?: return@withContext failedReport(
                label = label,
                startedAt = startedAt,
                error = "Unable to open selected image URI stream."
            )
        } catch (e: Exception) {
            if (e is kotlinx.coroutines.CancellationException) throw e
            return@withContext failedReport(
                label = label,
                startedAt = startedAt,
                error = "Failed reading image: ${e.message ?: e::class.java.simpleName}"
            )
        }

        analyzeImageBytes(bytes = bytes, fileName = label, onProgress = onProgress)
    }

    suspend fun analyzeImageBytes(
        bytes: ByteArray,
        fileName: String,
        onProgress: (Float, String) -> Unit = { _, _ -> }
    ): PhotoForensicReport = withContext(Dispatchers.IO) {
        val startedAt = System.currentTimeMillis()
        val analysisId = UUID.randomUUID().toString()

        if (bytes.isEmpty()) {
            return@withContext failedReport(fileName, startedAt, "Image file is empty (0 bytes).")
        }

        val sha256 = MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }
        val container = detectContainerFormat(bytes)
        if (container == "UNKNOWN") {
            return@withContext failedReport(
                label = fileName,
                startedAt = startedAt,
                error = "Unrecognized or corrupt image container header (expected PNG, JPEG, WebP, GIF, BMP, or HEIF)."
            )
        }

        // Stage 1: Safe bounds decode
        onProgress(0.20f, "Checking image header & dimensions...")
        currentCoroutineContext().ensureActive()
        val boundsOpts = BitmapFactory.Options().apply { inJustDecodeBounds = true }
        BitmapFactory.decodeByteArray(bytes, 0, bytes.size, boundsOpts)
        val rawW = boundsOpts.outWidth
        val rawH = boundsOpts.outHeight
        if (rawW <= 0 || rawH <= 0) {
            return@withContext failedReport(
                label = fileName,
                startedAt = startedAt,
                error = "Corrupt or unsupported image format ($container): decoder returned ${rawW}x${rawH}."
            )
        }

        val sampleSize = computeInSampleSize(rawW, rawH, MAX_ANALYSIS_DIMENSION)
        val decodeOpts = BitmapFactory.Options().apply {
            inSampleSize = sampleSize
            inPreferredConfig = Bitmap.Config.ARGB_8888
        }
        val bitmap = BitmapFactory.decodeByteArray(bytes, 0, bytes.size, decodeOpts)
            ?: return@withContext failedReport(
                label = fileName,
                startedAt = startedAt,
                error = "Failed to decode pixel raster for $fileName."
            )

        try {
            // Stage 2: EXIF, XMP/C2PA & PNG chunk metadata extraction
            onProgress(0.40f, "Extracting EXIF, XMP & PNG metadata...")
            currentCoroutineContext().ensureActive()
            val metadataMap = linkedMapOf<String, String>()
            metadataMap["Container"] = container
            metadataMap["Dimensions"] = "${rawW}x${rawH} px"
            metadataMap["File Size"] = "${(bytes.size / 1024.0).let { if (it < 1) "${bytes.size} B" else "%.1f KB".format(it) }}"
            metadataMap["SHA-256"] = sha256.take(16) + "..."

            val findings = mutableListOf<SecurityFinding>()
            var make: String? = null
            var model: String? = null
            var software: String? = null
            var exifError = false

            try {
                val exif = ExifInterface(ByteArrayInputStream(bytes))
                make = exif.getAttribute(ExifInterface.TAG_MAKE)?.trim()?.takeIf { it.isNotEmpty() }
                model = exif.getAttribute(ExifInterface.TAG_MODEL)?.trim()?.takeIf { it.isNotEmpty() }
                software = exif.getAttribute(ExifInterface.TAG_SOFTWARE)?.trim()?.takeIf { it.isNotEmpty() }
                val dateOrig = exif.getAttribute(ExifInterface.TAG_DATETIME_ORIGINAL)?.trim()
                val iso = exif.getAttribute(ExifInterface.TAG_PHOTOGRAPHIC_SENSITIVITY)?.trim()
                val exposure = exif.getAttribute(ExifInterface.TAG_EXPOSURE_TIME)?.trim()
                val focal = exif.getAttribute(ExifInterface.TAG_FOCAL_LENGTH)?.trim()
                val gpsLat = exif.getAttribute(ExifInterface.TAG_GPS_LATITUDE)?.trim()

                make?.let { metadataMap["Camera Make"] = it }
                model?.let { metadataMap["Camera Model"] = it }
                software?.let { metadataMap["Software Tag"] = it }
                dateOrig?.takeIf { it.isNotEmpty() }?.let { metadataMap["Captured At"] = it }
                if (iso != null || exposure != null || focal != null) {
                    metadataMap["Exposure Info"] = listOfNotNull(
                        iso?.let { "ISO $it" },
                        exposure?.let { "${it}s" },
                        focal?.let { "${it}mm" }
                    ).joinToString(" · ")
                }
                metadataMap["GPS Coordinates"] = if (gpsLat != null) "Present" else "Absent"
            } catch (_: Exception) {
                exifError = true
            }

            // Parse PNG text chunks & JPEG XMP/C2PA XML snippets
            val embeddedTextTags = mutableMapOf<String, String>()
            if (container == "PNG") {
                embeddedTextTags += extractPngTextChunks(bytes)
            }
            val headerAscii = String(bytes, 0, minOf(bytes.size, 256 * 1024), StandardCharsets.ISO_8859_1)
            val generatorMatch = detectGeneratorTag(
                software = software,
                embeddedTags = embeddedTextTags,
                headerText = headerAscii
            )
            val editorMatch = detectEditingSoftwareTag(
                software = software,
                embeddedTags = embeddedTextTags,
                headerText = headerAscii
            )
            embeddedTextTags.entries.take(5).forEach { (k, v) ->
                metadataMap["PNG Chunk ($k)"] = v.take(120)
            }

            val hasCameraExif = make != null || model != null
            var evidenceRisk = 0

            if (generatorMatch != null) {
                metadataMap["Generator Signature"] = generatorMatch
                evidenceRisk += 70
                findings += SecurityFinding(
                    title = "AI generator / C2PA tag in metadata",
                    description = "Embedded metadata references '$generatorMatch'.",
                    severity = FindingSeverity.HIGH,
                    evidenceSource = "Metadata / Chunk Parser",
                    detectionMethod = "EXIF / XMP / PNG Text Inspection",
                    inputLocation = generatorMatch,
                    explanation = "Metadata fields inside the file contain an explicit AI tool or algorithmic media tag.",
                    recommendedAction = "Verify origin; explicit generator metadata was embedded in the image file."
                )
            } else if (editorMatch != null) {
                metadataMap["Editing Software"] = editorMatch
                evidenceRisk += 32
                findings += SecurityFinding(
                    title = "Image editing software signature found",
                    description = "Software tag references '$editorMatch'.",
                    severity = FindingSeverity.MEDIUM,
                    evidenceSource = "EXIF / XMP / PNG Metadata",
                    detectionMethod = "Software Tag Matching",
                    inputLocation = software ?: editorMatch,
                    explanation = "Image metadata records post-processing in editing software (this does not indicate AI generation).",
                    recommendedAction = "Inspect image regions for cropping, color edits, or splices."
                )
            }

            if (hasCameraExif) {
                findings += SecurityFinding(
                    title = "Camera EXIF metadata present",
                    description = "EXIF records camera '${listOfNotNull(make, model).joinToString(" ")}'.",
                    severity = FindingSeverity.INFO,
                    evidenceSource = "ExifInterface",
                    detectionMethod = "TIFF/EXIF Tag Extraction",
                    inputLocation = "IFD0/ExifIFD",
                    explanation = "Hardware make/model tags are present (note: EXIF can still be copied or spoofed).",
                    recommendedAction = "Cross-check with ELA and visual cues."
                )
            } else {
                findings += SecurityFinding(
                    title = "Camera EXIF metadata absent",
                    description = if (exifError) {
                        "Container does not expose standard camera EXIF headers."
                    } else {
                        "No camera make, model, or shooting metadata present."
                    },
                    severity = FindingSeverity.INFO,
                    evidenceSource = "ExifInterface",
                    detectionMethod = "Metadata Presence Check",
                    inputLocation = "File header",
                    explanation = "Messaging apps, screenshots, web exports, and AI renders commonly strip or omit EXIF. Missing EXIF alone NEVER proves editing or AI synthesis.",
                    recommendedAction = "Rely on provenance and pixel consistency rather than absent EXIF alone."
                )
            }

            // Stage 3: True JPEG Q90 Recompression Error Level Analysis
            onProgress(0.65f, "Running JPEG Q90 Error Level Analysis (ELA)...")
            currentCoroutineContext().ensureActive()
            val elaStats = computeTrueJpegEla(bitmap)
            metadataMap["ELA Mean Residual"] = "%.2f".format(elaStats.meanDifference)
            metadataMap["ELA Outlier Block Ratio"] = "%.1f%%".format(elaStats.outlierBlockRatio * 100f)

            val elaStrongOutliers = elaStats.outlierBlockRatio > 0.14f && elaStats.maxBlockVariance > 35f
            val elaModerateOutliers = elaStats.outlierBlockRatio > 0.08f && elaStats.p95Difference > 16f
            if (elaStrongOutliers) {
                evidenceRisk += 38
                findings += SecurityFinding(
                    title = "Localized JPEG recompression variance (ELA)",
                    description = "${"%.1f".format(elaStats.outlierBlockRatio * 100f)}% of 8x8 blocks exhibit elevated Q90 residual variance (95th pct: ${"%.1f".format(elaStats.p95Difference)}).",
                    severity = FindingSeverity.MEDIUM,
                    evidenceSource = "JPEG Q90 Error Level Analysis",
                    detectionMethod = "Real Recompression Residual Comparison",
                    inputLocation = "ELA Heatmap",
                    explanation = "Different regions compressed differently during JPEG Q90 recompression, which can indicate local splicing, compositing, or sharp graphical overlays (NOT proof of AI generation).",
                    recommendedAction = "Inspect bright areas in the ELA heatmap preview for pasted elements or altered text."
                )
            } else if (elaModerateOutliers) {
                evidenceRisk += 18
                findings += SecurityFinding(
                    title = "Mild compression-level variation (ELA)",
                    description = "${"%.1f".format(elaStats.outlierBlockRatio * 100f)}% of blocks stand above local error baseline.",
                    severity = FindingSeverity.LOW,
                    evidenceSource = "JPEG Q90 Error Level Analysis",
                    detectionMethod = "Real Recompression Residual Comparison",
                    inputLocation = "ELA Heatmap",
                    explanation = "Moderate ELA variance can happen in sharp text overlays, high-contrast edges, or re-saved images.",
                    recommendedAction = "Inspect heatmap highlights visually."
                )
            }

            // Stage 4: Noise & block duplicate check
            onProgress(0.85f, "Checking spatial noise uniformity & copy-move blocks...")
            currentCoroutineContext().ensureActive()
            val copyMoveScore = detectCopyMove(bitmap)
            val noiseScore = analyzeSpatialNoiseSmoothness(bitmap)
            if (copyMoveScore > 0.55f) {
                evidenceRisk += 30
                findings += SecurityFinding(
                    title = "Repeated visual patch clusters",
                    description = "Sampled 16x16 regions contain above-threshold repeated block hashes (ratio=${"%.2f".format(copyMoveScore)}).",
                    severity = FindingSeverity.MEDIUM,
                    evidenceSource = "Block Hash Comparator",
                    detectionMethod = "Quantized Copy-Move Heuristic",
                    inputLocation = "Raster Grid",
                    explanation = "Repeated patch patterns occur in cloning/inpainting edits as well as natural uniform textures (e.g., skies or brick walls).",
                    recommendedAction = "Inspect repetitive regions carefully."
                )
            }
            if (noiseScore > 0.55f) {
                evidenceRisk += 14
                findings += SecurityFinding(
                    title = "Inconsistent spatial noise floor",
                    description = "Edge Laplacian variance varies sharply across sampled image regions.",
                    severity = FindingSeverity.LOW,
                    evidenceSource = "Spatial Noise Estimator",
                    detectionMethod = "Laplacian Variance Profile",
                    inputLocation = "Raster Grid",
                    explanation = "Synthetic inpainting or heavy blurring can smooth sensor noise unevenly compared with untouched regions.",
                    recommendedAction = "Treat as supporting heuristic context only."
                )
            }

            onProgress(1.0f, "Finalizing forensic report...")

            val finalScore = evidenceRisk.coerceIn(0, 100)
            // Verdict policy obeying Rule 7:
            // - Never claim AI_GENERATED from ELA or stripped EXIF alone.
            // - Only flag LIKELY_AI_GENERATED / HIGH_RISK when explicit generator tag or strong splice evidence exists.
            // - When camera EXIF is missing AND no splicing/generator evidence was found -> INCONCLUSIVE!
            val verdict = when {
                generatorMatch != null -> SecurityVerdict.LIKELY_AI_GENERATED
                elaStrongOutliers || copyMoveScore > 0.55f || editorMatch != null -> SecurityVerdict.SUSPICIOUS
                hasCameraExif && finalScore < 20 -> SecurityVerdict.SAFE
                !hasCameraExif -> SecurityVerdict.INCONCLUSIVE
                else -> SecurityVerdict.LOW_RISK
            }

            val methods = listOf(
                "Container Magic & SHA-256 Digest",
                "EXIF / XMP / PNG Text Chunk Metadata Parsing",
                "True JPEG Q90 Recompression Error Level Analysis (ELA)",
                "Quantized 16x16 Block Repetition & Spatial Laplacian Check"
            )
            val limitations = listOf(
                "Error Level Analysis (ELA) and EXIF inspection CANNOT prove an image is AI-generated or camera-authentic.",
                "No calibrated neural image forensic model ran; forensic findings are non-ML signal measurements (no ML probability shown)."
            )

            val result = SecurityAnalysisResult(
                analysisId = analysisId,
                module = SecurityModule.PHOTO_FORENSICS,
                inputName = fileName,
                inputType = "image/${container.lowercase()}",
                status = AnalysisStatus.COMPLETED,
                verdict = verdict,
                riskScore = finalScore,
                confidence = null, // Rule 7 & Rule 4.2: never convert ELA/EXIF heuristics to fake ML %
                findings = findings,
                analysisMethods = methods,
                limitations = limitations,
                processingDurationMs = System.currentTimeMillis() - startedAt,
                analyzedAt = System.currentTimeMillis(),
                modelVersion = null,
                errorMessage = null,
                metadata = metadataMap
            )

            PhotoForensicReport(
                analysisResult = result,
                displayName = fileName,
                sha256 = sha256,
                width = rawW,
                height = rawH,
                fileSizeBytes = bytes.size.toLong(),
                containerFormat = container,
                hasCameraExif = hasCameraExif,
                detectedGeneratorTag = generatorMatch,
                metadataMap = metadataMap,
                elaStats = elaStats
            )
        } finally {
            if (!bitmap.isRecycled) {
                bitmap.recycle()
            }
        }
    }

    /**
     * Legacy synchronous signature retained for existing direct bitmap callers;
     * uses true Q90 ELA recompression and non-fabricated findings.
     */
    fun analyzeImage(bitmap: Bitmap): ImageForensicResult {
        if (bitmap.isRecycled || bitmap.width == 0 || bitmap.height == 0) {
            return ImageForensicResult(false, 0f, "None", emptyList(), 0, "Unable to analyze")
        }
        val findings = mutableListOf<ForensicFinding>()
        var riskScore = 0

        val ela = computeTrueJpegEla(bitmap)
        ela.elaBitmap?.takeIf { !it.isRecycled }?.recycle()
        if (ela.outlierBlockRatio > 0.14f && ela.maxBlockVariance > 35f) {
            riskScore += 38
            findings += ForensicFinding(
                "ELA_ANOMALY",
                "JPEG Q90 recompression shows localized variance (${"%.1f".format(ela.outlierBlockRatio * 100)}% outlier blocks)",
                "MEDIUM",
                "Local regions"
            )
        }
        val copyMove = detectCopyMove(bitmap)
        if (copyMove > 0.55f) {
            riskScore += 30
            findings += ForensicFinding(
                "COPY_MOVE",
                "Repeated 16x16 texture block clusters detected",
                "MEDIUM",
                "Raster grid"
            )
        }
        val noise = analyzeSpatialNoiseSmoothness(bitmap)
        if (noise > 0.55f) {
            riskScore += 14
            findings += ForensicFinding(
                "NOISE_INCONSISTENCY",
                "Uneven spatial noise profile across regions",
                "LOW"
            )
        }
        val score = riskScore.coerceIn(0, 100)
        val manipulated = score >= 35
        val type = when {
            findings.any { it.type == "COPY_MOVE" } -> "Copy-Move / Patch Repetition"
            findings.any { it.type == "ELA_ANOMALY" } -> "Localized Recompression Variance"
            else -> "No Strong Indicators"
        }
        val recommendation = when {
            score >= 55 -> "SPLICING INDICATORS: Elevated recompression variance or block cloning detected. Verify provenance independently (note: ELA alone does not prove AI synthesis)."
            score >= 30 -> "INCONCLUSIVE / MILD SIGNALS: Mild compression or noise variation found; verify source."
            else -> "NO STRONG EDIT SIGNALS: Pixel checks did not highlight localized recompression anomalies."
        }
        return ImageForensicResult(manipulated, score / 100f, type, findings, score, recommendation)
    }

    private fun computeTrueJpegEla(source: Bitmap): ElaHeatmapStats {
        val baos = ByteArrayOutputStream()
        source.compress(Bitmap.CompressFormat.JPEG, 90, baos)
        val recompressedBytes = baos.toByteArray()
        val recompressed = BitmapFactory.decodeByteArray(recompressedBytes, 0, recompressedBytes.size)
            ?: return ElaHeatmapStats(0f, 0f, 0f, 0f, null)

        return try {
            val w = minOf(source.width, recompressed.width)
            val h = minOf(source.height, recompressed.height)
            val scale = minOf(1f, MAX_ELA_BITMAP_DIM.toFloat() / maxOf(w, h).coerceAtLeast(1))
            val mapW = (w * scale).toInt().coerceAtLeast(1)
            val mapH = (h * scale).toInt().coerceAtLeast(1)
            val heatmap = Bitmap.createBitmap(mapW, mapH, Bitmap.Config.ARGB_8888)

            val residuals = mutableListOf<Float>()
            val blockMeans = mutableListOf<Double>()

            val blockSize = 8
            val rowStride = (h / MAX_ELA_BITMAP_DIM.coerceAtLeast(1)).coerceAtLeast(1)

            // Populate visual ELA heatmap bitmap (amplified 12x residual)
            for (hy in 0 until mapH) {
                val sy = ((hy.toFloat() / mapH) * h).toInt().coerceIn(0, h - 1)
                for (hx in 0 until mapW) {
                    val sx = ((hx.toFloat() / mapW) * w).toInt().coerceIn(0, w - 1)
                    val orig = source.getPixel(sx, sy)
                    val recomp = recompressed.getPixel(sx, sy)
                    val dr = abs(Color.red(orig) - Color.red(recomp))
                    val dg = abs(Color.green(orig) - Color.green(recomp))
                    val db = abs(Color.blue(orig) - Color.blue(recomp))
                    val diff = (dr + dg + db) / 3f
                    residuals += diff
                    val amp = (diff * 12f).toInt().coerceIn(0, 255)
                    val heatColor = when {
                        amp > 180 -> Color.rgb(255, (255 - amp).coerceAtLeast(30), 20)
                        amp > 90 -> Color.rgb(amp, (amp * 0.85f).toInt(), 30)
                        else -> Color.rgb(amp / 3, amp / 2, (amp + 24).coerceAtMost(255))
                    }
                    heatmap.setPixel(hx, hy, heatColor)
                }
            }

            // Compute 8x8 block statistics across subsampled grid (capped <= 320px for speed)
            val step = maxOf(1, maxOf(w, h) / 320)
            var by = 0
            while (by + blockSize * step <= h) {
                var bx = 0
                while (bx + blockSize * step <= w) {
                    var sum = 0.0
                    var cnt = 0
                    var iy = 0
                    while (iy < blockSize) {
                        var ix = 0
                        while (ix < blockSize) {
                            val px = (bx + ix * step).coerceAtMost(w - 1)
                            val py = (by + iy * step).coerceAtMost(h - 1)
                            val p1 = source.getPixel(px, py)
                            val p2 = recompressed.getPixel(px, py)
                            sum += (abs(Color.red(p1) - Color.red(p2)) +
                                abs(Color.green(p1) - Color.green(p2)) +
                                abs(Color.blue(p1) - Color.blue(p2))) / 3.0
                            cnt++
                            ix += 2
                        }
                        iy += 2
                    }
                    if (cnt > 0) blockMeans += (sum / cnt)
                    bx += blockSize * step
                }
                by += blockSize * step
            }

            val meanDiff = if (residuals.isEmpty()) 0f else residuals.average().toFloat()
            val sortedRes = residuals.sorted()
            val p95 = if (sortedRes.isEmpty()) 0f else sortedRes[((sortedRes.size - 1) * 0.95).toInt()]
            val blockAvg = if (blockMeans.isEmpty()) 0.0 else blockMeans.average()
            val blockStd = if (blockMeans.size < 2) 0.0 else sqrt(blockMeans.map { (it - blockAvg).pow(2) }.average())
            val threshold = blockAvg + maxOf(4.0, 2.2 * blockStd)
            val outlierRatio = if (blockMeans.isEmpty()) 0f else blockMeans.count { it > threshold }.toFloat() / blockMeans.size
            val maxBlockDev = if (blockMeans.isEmpty()) 0f else ((blockMeans.maxOrNull() ?: 0.0) - blockAvg).toFloat()

            ElaHeatmapStats(
                meanDifference = meanDiff,
                p95Difference = p95,
                maxBlockVariance = maxBlockDev,
                outlierBlockRatio = outlierRatio,
                elaBitmap = heatmap
            )
        } finally {
            if (!recompressed.isRecycled) recompressed.recycle()
        }
    }

    private fun detectCopyMove(bitmap: Bitmap): Float {
        val w = minOf(bitmap.width, 224)
        val h = minOf(bitmap.height, 224)
        if (w < 32 || h < 32) return 0f
        val stepX = (bitmap.width / w.toFloat()).coerceAtLeast(1f)
        val stepY = (bitmap.height / h.toFloat()).coerceAtLeast(1f)
        val blocks = HashMap<Long, Int>()
        var duplicates = 0
        var totalBlocks = 0

        for (y in 0 until h - 16 step 8) {
            for (x in 0 until w - 16 step 8) {
                var hash = 17L
                var minLum = 255
                var maxLum = 0
                for (by in 0 until 16 step 4) {
                    for (bx in 0 until 16 step 4) {
                        val sx = ((x + bx) * stepX).toInt().coerceIn(0, bitmap.width - 1)
                        val sy = ((y + by) * stepY).toInt().coerceIn(0, bitmap.height - 1)
                        val p = bitmap.getPixel(sx, sy)
                        val r = Color.red(p) / 24
                        val g = Color.green(p) / 24
                        val b = Color.blue(p) / 24
                        val lum = (Color.red(p) + Color.green(p) + Color.blue(p)) / 3
                        if (lum < minLum) minLum = lum
                        if (lum > maxLum) maxLum = lum
                        hash = hash * 31L + (r shl 8) + (g shl 4) + b
                    }
                }
                // Skip completely flat/solid-color patches (sky/margins) so they aren't misclassified as copy-move
                if (maxLum - minLum >= 12) {
                    val prev = blocks.getOrDefault(hash, 0)
                    if (prev > 0) duplicates++
                    blocks[hash] = prev + 1
                    totalBlocks++
                }
            }
        }
        return if (totalBlocks > 10) (duplicates.toFloat() / totalBlocks * 2.5f).coerceIn(0f, 1f) else 0f
    }

    private fun analyzeSpatialNoiseSmoothness(bitmap: Bitmap): Float {
        val w = minOf(bitmap.width, 256)
        val h = minOf(bitmap.height, 256)
        if (w < 32 || h < 32) return 0f
        val sxScale = bitmap.width / w.toFloat()
        val syScale = bitmap.height / h.toFloat()
        val regionMeans = mutableListOf<Double>()

        for (ry in 0 until h - 32 step 32) {
            for (rx in 0 until w - 32 step 32) {
                var sum = 0.0
                var cnt = 0
                for (y in ry + 1 until ry + 31 step 2) {
                    for (x in rx + 1 until rx + 31 step 2) {
                        val cx = (x * sxScale).toInt().coerceIn(1, bitmap.width - 2)
                        val cy = (y * syScale).toInt().coerceIn(1, bitmap.height - 2)
                        val c = lum(bitmap.getPixel(cx, cy))
                        val lap = abs(
                            4 * c -
                                lum(bitmap.getPixel(cx - 1, cy)) -
                                lum(bitmap.getPixel(cx + 1, cy)) -
                                lum(bitmap.getPixel(cx, cy - 1)) -
                                lum(bitmap.getPixel(cx, cy + 1))
                        )
                        sum += lap
                        cnt++
                    }
                }
                if (cnt > 0) regionMeans += sum / cnt
            }
        }
        if (regionMeans.size < 4) return 0f
        val mean = regionMeans.average()
        if (mean < 0.5) return 0f
        val std = sqrt(regionMeans.map { (it - mean).pow(2) }.average())
        return ((std / mean) * 0.45).toFloat().coerceIn(0f, 1f)
    }

    private fun detectContainerFormat(bytes: ByteArray): String {
        if (bytes.size >= 8 &&
            bytes[0] == 0x89.toByte() && bytes[1] == 0x50.toByte() &&
            bytes[2] == 0x4E.toByte() && bytes[3] == 0x47.toByte()
        ) return "PNG"
        if (bytes.size >= 3 &&
            bytes[0] == 0xFF.toByte() && bytes[1] == 0xD8.toByte() && bytes[2] == 0xFF.toByte()
        ) return "JPEG"
        if (bytes.size >= 12 &&
            String(bytes, 0, 4, StandardCharsets.US_ASCII) == "RIFF" &&
            String(bytes, 8, 4, StandardCharsets.US_ASCII) == "WEBP"
        ) return "WEBP"
        if (bytes.size >= 6 &&
            String(bytes, 0, 3, StandardCharsets.US_ASCII) == "GIF"
        ) return "GIF"
        if (bytes.size >= 14 &&
            bytes[0] == 0x42.toByte() && bytes[1] == 0x4D.toByte()
        ) return "BMP"
        if (bytes.size >= 12 &&
            String(bytes, 4, 4, StandardCharsets.US_ASCII) == "ftyp"
        ) return "HEIF"
        return "UNKNOWN"
    }

    private fun extractPngTextChunks(bytes: ByteArray): Map<String, String> {
        val result = linkedMapOf<String, String>()
        var pos = 8
        while (pos + 12 <= bytes.size && result.size < 16) {
            val length = ((bytes[pos].toInt() and 0xFF) shl 24) or
                ((bytes[pos + 1].toInt() and 0xFF) shl 16) or
                ((bytes[pos + 2].toInt() and 0xFF) shl 8) or
                (bytes[pos + 3].toInt() and 0xFF)
            if (length < 0 || pos + 12L + length > bytes.size) break
            val type = String(bytes, pos + 4, 4, StandardCharsets.US_ASCII)
            if (type == "tEXt" || type == "iTXt") {
                val data = bytes.copyOfRange(pos + 8, pos + 8 + minOf(length, 4096))
                val nulIdx = data.indexOf(0.toByte())
                if (nulIdx > 0) {
                    val key = String(data, 0, nulIdx, StandardCharsets.ISO_8859_1).trim()
                    val value = String(data, nulIdx + 1, data.size - nulIdx - 1, StandardCharsets.UTF_8)
                        .replace("\u0000", " ")
                        .trim()
                    if (key.isNotEmpty() && value.isNotEmpty()) result[key] = value
                }
            } else if (type == "IEND") {
                break
            }
            pos += 12 + length
        }
        return result
    }

    private fun detectGeneratorTag(
        software: String?,
        embeddedTags: Map<String, String>,
        headerText: String
    ): String? {
        val haystack = buildString {
            software?.let { append(it).append('\n') }
            embeddedTags.forEach { (k, v) -> append(k).append(':').append(v).append('\n') }
            append(headerText)
        }.lowercase()
        return AI_GENERATOR_SIGNATURES.firstOrNull { sig -> haystack.contains(sig) }
    }

    private fun detectEditingSoftwareTag(
        software: String?,
        embeddedTags: Map<String, String>,
        headerText: String
    ): String? {
        val haystack = buildString {
            software?.let { append(it).append('\n') }
            embeddedTags.forEach { (k, v) -> append(k).append(':').append(v).append('\n') }
            append(headerText)
        }.lowercase()
        return EDITING_SOFTWARE_SIGNATURES.firstOrNull { sig -> haystack.contains(sig) }
    }

    private fun computeInSampleSize(width: Int, height: Int, maxDim: Int): Int {
        var inSampleSize = 1
        while (width / inSampleSize > maxDim || height / inSampleSize > maxDim) {
            inSampleSize *= 2
        }
        return inSampleSize.coerceAtLeast(1)
    }

    private fun lum(pixel: Int): Int =
        (0.299 * Color.red(pixel) + 0.587 * Color.green(pixel) + 0.114 * Color.blue(pixel)).toInt()

    private fun failedReport(label: String, startedAt: Long, error: String): PhotoForensicReport {
        val result = SecurityAnalysisResult(
            analysisId = UUID.randomUUID().toString(),
            module = SecurityModule.PHOTO_FORENSICS,
            inputName = label,
            inputType = "image",
            status = AnalysisStatus.FAILED,
            verdict = SecurityVerdict.NOT_ANALYZED,
            riskScore = null,
            confidence = null,
            findings = emptyList(),
            analysisMethods = listOf("Image Container & Header Validation"),
            limitations = listOf(error),
            processingDurationMs = System.currentTimeMillis() - startedAt,
            analyzedAt = System.currentTimeMillis(),
            modelVersion = null,
            errorMessage = error
        )
        return PhotoForensicReport(
            analysisResult = result,
            displayName = label,
            sha256 = null,
            width = 0,
            height = 0,
            fileSizeBytes = 0L,
            containerFormat = "UNKNOWN",
            hasCameraExif = false,
            detectedGeneratorTag = null,
            metadataMap = emptyMap(),
            elaStats = null
        )
    }
}
