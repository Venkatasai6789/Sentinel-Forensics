package com.deepfakeshield.ml.engine

import android.graphics.Bitmap
import android.graphics.Color
import com.deepfakeshield.core.model.AnalysisStatus
import com.deepfakeshield.core.model.SecurityVerdict
import kotlinx.coroutines.test.runTest
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import java.util.zip.CRC32

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [28])
class ImageForensicsEngineTest {

    private val engine = ImageForensicsEngine()

    private fun createSamplePngBytes(width: Int = 48, height: Int = 48): ByteArray {
        val bmp = Bitmap.createBitmap(width, height, Bitmap.Config.ARGB_8888)
        for (y in 0 until height) {
            for (x in 0 until width) {
                val c = Color.rgb((x * 5) % 255, (y * 5) % 255, ((x + y) * 3) % 255)
                bmp.setPixel(x, y, c)
            }
        }
        val baos = ByteArrayOutputStream()
        bmp.compress(Bitmap.CompressFormat.PNG, 100, baos)
        return baos.toByteArray()
    }

    private fun injectPngTextChunk(pngBytes: ByteArray, key: String, value: String): ByteArray {
        val iendOffset = pngBytes.size - 12 // Standard 12-byte IEND chunk at end of PNG
        val payload = (key + "\u0000" + value).toByteArray(Charsets.ISO_8859_1)
        val type = "tEXt".toByteArray(Charsets.US_ASCII)
        val crc = CRC32().apply {
            update(type)
            update(payload)
        }.value.toInt()

        val out = ByteArrayOutputStream()
        out.write(pngBytes, 0, iendOffset)
        out.write(ByteBuffer.allocate(4).putInt(payload.size).array())
        out.write(type)
        out.write(payload)
        out.write(ByteBuffer.allocate(4).putInt(crc).array())
        out.write(pngBytes, iendOffset, 12)
        return out.toByteArray()
    }

    @Test
    fun `empty or corrupt bytes fail cleanly and never return SAFE`() = runTest {
        val empty = engine.analyzeImageBytes(ByteArray(0), "empty.jpg")
        assertEquals(AnalysisStatus.FAILED, empty.analysisResult.status)
        assertNotEquals(SecurityVerdict.SAFE, empty.analysisResult.verdict)
        assertNull(empty.analysisResult.confidence)

        val corrupt = engine.analyzeImageBytes("NOT_AN_IMAGE_12345".toByteArray(), "corrupt.png")
        assertEquals(AnalysisStatus.FAILED, corrupt.analysisResult.status)
        assertNotEquals(SecurityVerdict.SAFE, corrupt.analysisResult.verdict)
    }

    @Test
    fun `stripped png without camera EXIF returns INCONCLUSIVE with Rule 7 disclosure`() = runTest {
        val pngBytes = createSamplePngBytes()
        val report = engine.analyzeImageBytes(pngBytes, "stripped.png")

        assertEquals(AnalysisStatus.COMPLETED, report.analysisResult.status)
        assertEquals(SecurityVerdict.INCONCLUSIVE, report.analysisResult.verdict)
        assertNull("Non-ML forensics must not emit ML confidence", report.analysisResult.confidence)
        assertEquals(64, report.sha256?.length)
        assertTrue(report.analysisResult.limitations.any {
            it.contains("EXIF", ignoreCase = true) && it.contains("AI-generated", ignoreCase = true)
        })
    }

    @Test
    fun `png containing generator metadata triggers LIKELY_AI_GENERATED without fabricated confidence`() = runTest {
        val basePng = createSamplePngBytes()
        val taggedPng = injectPngTextChunk(basePng, "parameters", "Generated with Stable Diffusion XL\nSteps: 30")
        val report = engine.analyzeImageBytes(taggedPng, "ai_tagged.png")

        assertEquals(AnalysisStatus.COMPLETED, report.analysisResult.status)
        assertEquals(SecurityVerdict.LIKELY_AI_GENERATED, report.analysisResult.verdict)
        assertNull(report.analysisResult.confidence)
        assertTrue(report.metadataMap.containsKey("Generator Signature"))
        assertTrue(report.analysisResult.findings.any { it.title.contains("AI generator", ignoreCase = true) })
    }
}
