package com.deepfakeshield.ml.engine

import android.content.Context
import android.util.Log
import org.tensorflow.lite.DataType
import org.tensorflow.lite.Interpreter
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.channels.FileChannel
import javax.inject.Inject
import javax.inject.Singleton
import kotlin.math.abs

/**
 * Specification used to verify that a bundled `.tflite` asset is structurally
 * compatible with the TFLite runtime, matches expected input/output shapes,
 * and produces non-degenerate (input-responsive) finite inference outputs.
 */
data class TfliteModelSpec(
    val filename: String,
    val displayName: String,
    val expectedInputShape: IntArray,
    val expectedOutputMinLength: Int,
    val expectedInputDataType: DataType = DataType.FLOAT32
)

data class ModelValidationReport(
    val filename: String,
    val displayName: String,
    val isValid: Boolean,
    val actualInputShape: List<Int> = emptyList(),
    val actualOutputShape: List<Int> = emptyList(),
    val reason: String
)

data class ValidatedTfliteModel(
    val interpreter: Interpreter?,
    val report: ModelValidationReport
)

@Singleton
class TfliteModelValidator @Inject constructor() {

    fun loadAndValidateAsset(
        context: Context,
        spec: TfliteModelSpec,
        options: Interpreter.Options = Interpreter.Options().apply { setNumThreads(2) }
    ): ValidatedTfliteModel {
        val modelBuffer = try {
            loadAssetBuffer(context, spec.filename)
        } catch (e: Exception) {
            return ValidatedTfliteModel(
                interpreter = null,
                report = ModelValidationReport(
                    filename = spec.filename,
                    displayName = spec.displayName,
                    isValid = false,
                    reason = "Model asset missing or unreadable: ${e.message ?: e::class.java.simpleName}"
                )
            )
        }

        val interpreter = try {
            Interpreter(modelBuffer, options)
        } catch (t: Throwable) {
            return ValidatedTfliteModel(
                interpreter = null,
                report = ModelValidationReport(
                    filename = spec.filename,
                    displayName = spec.displayName,
                    isValid = false,
                    reason = "TFLite runtime rejected model (incompatible ops or schema): ${t.message ?: t::class.java.simpleName}"
                )
            )
        }

        return try {
            interpreter.allocateTensors()
            val inputTensor = interpreter.getInputTensor(0)
            val outputTensor = interpreter.getOutputTensor(0)
            val actualInShape = inputTensor.shape().toList()
            val actualOutShape = outputTensor.shape().toList()

            if (!shapesMatch(spec.expectedInputShape, inputTensor.shape())) {
                interpreter.close()
                return ValidatedTfliteModel(
                    interpreter = null,
                    report = ModelValidationReport(
                        filename = spec.filename,
                        displayName = spec.displayName,
                        isValid = false,
                        actualInputShape = actualInShape,
                        actualOutputShape = actualOutShape,
                        reason = "Input shape $actualInShape does not match required ${spec.expectedInputShape.toList()}"
                    )
                )
            }

            val outputElementCount = outputTensor.shape().fold(1) { acc, dim -> acc * dim.coerceAtLeast(1) }
            if (outputElementCount < spec.expectedOutputMinLength) {
                interpreter.close()
                return ValidatedTfliteModel(
                    interpreter = null,
                    report = ModelValidationReport(
                        filename = spec.filename,
                        displayName = spec.displayName,
                        isValid = false,
                        actualInputShape = actualInShape,
                        actualOutputShape = actualOutShape,
                        reason = "Output shape $actualOutShape has $outputElementCount elements; requires >= ${spec.expectedOutputMinLength}"
                    )
                )
            }

            if (inputTensor.dataType() != spec.expectedInputDataType &&
                !(spec.expectedInputDataType == DataType.FLOAT32 && inputTensor.dataType() == DataType.UINT8)
            ) {
                interpreter.close()
                return ValidatedTfliteModel(
                    interpreter = null,
                    report = ModelValidationReport(
                        filename = spec.filename,
                        displayName = spec.displayName,
                        isValid = false,
                        actualInputShape = actualInShape,
                        actualOutputShape = actualOutShape,
                        reason = "Input dtype ${inputTensor.dataType()} mismatches expected ${spec.expectedInputDataType}"
                    )
                )
            }

            // Probe with two sharply contrasting inputs to confirm non-constant weights.
            val probeA = runProbe(interpreter, inputTensor.dataType(), inputTensor.shape(), outputTensor.shape(), highSignal = false)
            val probeB = runProbe(interpreter, inputTensor.dataType(), inputTensor.shape(), outputTensor.shape(), highSignal = true)

            if (probeA.any { it.isNaN() || it.isInfinite() } || probeB.any { it.isNaN() || it.isInfinite() }) {
                interpreter.close()
                return ValidatedTfliteModel(
                    interpreter = null,
                    report = ModelValidationReport(
                        filename = spec.filename,
                        displayName = spec.displayName,
                        isValid = false,
                        actualInputShape = actualInShape,
                        actualOutputShape = actualOutShape,
                        reason = "Model produced NaN or Inf during validation probe"
                    )
                )
            }

            val maxDelta = probeA.zip(probeB).maxOfOrNull { (a, b) -> abs(a - b) } ?: 0f
            if (maxDelta < 1e-6f) {
                interpreter.close()
                return ValidatedTfliteModel(
                    interpreter = null,
                    report = ModelValidationReport(
                        filename = spec.filename,
                        displayName = spec.displayName,
                        isValid = false,
                        actualInputShape = actualInShape,
                        actualOutputShape = actualOutShape,
                        reason = "Model output is invariant/constant across distinct inputs (max delta=$maxDelta)"
                    )
                )
            }

            Log.i("TfliteValidator", "Validated ${spec.filename}: in=$actualInShape out=$actualOutShape delta=$maxDelta")
            ValidatedTfliteModel(
                interpreter = interpreter,
                report = ModelValidationReport(
                    filename = spec.filename,
                    displayName = spec.displayName,
                    isValid = true,
                    actualInputShape = actualInShape,
                    actualOutputShape = actualOutShape,
                    reason = "Validated active TFLite model"
                )
            )
        } catch (t: Throwable) {
            try {
                interpreter.close()
            } catch (_: Throwable) {
            }
            ValidatedTfliteModel(
                interpreter = null,
                report = ModelValidationReport(
                    filename = spec.filename,
                    displayName = spec.displayName,
                    isValid = false,
                    reason = "Validation probe failed: ${t.message ?: t::class.java.simpleName}"
                )
            )
        }
    }

    private fun shapesMatch(expected: IntArray, actual: IntArray): Boolean {
        if (expected.size != actual.size) return false
        return expected.indices.all { idx ->
            expected[idx] <= 0 || expected[idx] == actual[idx]
        }
    }

    private fun runProbe(
        interpreter: Interpreter,
        inputType: DataType,
        inputShape: IntArray,
        outputShape: IntArray,
        highSignal: Boolean
    ): FloatArray {
        val elemCount = inputShape.fold(1) { acc, dim -> acc * dim.coerceAtLeast(1) }
        val bytesPerElem = when (inputType) {
            DataType.UINT8, DataType.INT8 -> 1
            else -> 4
        }
        val inputBuf = ByteBuffer.allocateDirect(elemCount * bytesPerElem).order(ByteOrder.nativeOrder())
        for (i in 0 until elemCount) {
            when (inputType) {
                DataType.INT32 -> inputBuf.putInt(if (highSignal) ((i % 97) + 1) else 0)
                DataType.FLOAT32 -> inputBuf.putFloat(if (highSignal) ((i % 29) / 29f) else 0f)
                DataType.UINT8 -> inputBuf.put(if (highSignal) ((i % 200) + 20).toByte() else 0.toByte())
                DataType.INT8 -> inputBuf.put(if (highSignal) ((i % 100) + 1).toByte() else 0.toByte())
                else -> inputBuf.putFloat(0f)
            }
        }
        inputBuf.rewind()

        val rows = outputShape.firstOrNull()?.coerceAtLeast(1) ?: 1
        val cols = outputShape.drop(1).fold(1) { acc, dim -> acc * dim.coerceAtLeast(1) }
        val output = Array(rows) { FloatArray(cols) }
        interpreter.run(inputBuf, output)
        return output.flatMap { it.toList() }.toFloatArray()
    }

    private fun loadAssetBuffer(context: Context, filename: String): ByteBuffer {
        val afd = context.assets.openFd(filename)
        return afd.use { descriptor ->
            descriptor.createInputStream().use { inputStream ->
                inputStream.channel.use { channel ->
                    channel.map(FileChannel.MapMode.READ_ONLY, descriptor.startOffset, descriptor.declaredLength)
                }
            }
        }
    }
}

