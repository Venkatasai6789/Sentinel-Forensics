package com.deepfakeshield.av.engine

import java.io.File
import java.io.InputStream

/**
 * Thread-safe, zero-allocation (during scanning) Aho-Corasick DFA byte matcher.
 *
 * Scans arbitrarily large files or byte buffers in a single O(n) pass across
 * 64 KB chunks without missing patterns split across chunk boundaries and
 * without converting binary payloads into heap-allocated hex strings.
 */
class BytePatternMatcher<T> private constructor(
    private val transitions: IntArray,
    private val stateOutputs: Array<IntArray?>,
    private val labels: List<T>,
    private val ignoreAsciiCase: Boolean
) {
    val patternCount: Int get() = labels.size

    fun createSession(): ScanSession<T> = ScanSession(transitions, stateOutputs, labels, ignoreAsciiCase)

    fun scanBytes(bytes: ByteArray, offset: Int = 0, length: Int = bytes.size): List<T> {
        if (labels.isEmpty() || length <= 0) return emptyList()
        val session = createSession()
        session.update(bytes, offset, length)
        return session.matchedLabels()
    }

    fun scanStream(input: InputStream, maxBytes: Long = Long.MAX_VALUE): List<T> {
        if (labels.isEmpty() || maxBytes <= 0L) return emptyList()
        val session = createSession()
        val buffer = ByteArray(64 * 1024)
        var remaining = maxBytes
        while (remaining > 0L) {
            val toRead = minOf(buffer.size.toLong(), remaining).toInt()
            val read = input.read(buffer, 0, toRead)
            if (read <= 0) break
            session.update(buffer, 0, read)
            remaining -= read
            if (session.allMatched()) break
        }
        return session.matchedLabels()
    }

    fun scanFile(file: File, maxBytes: Long = Long.MAX_VALUE): List<T> {
        if (labels.isEmpty() || !file.exists() || !file.canRead()) return emptyList()
        return file.inputStream().buffered(64 * 1024).use { scanStream(it, maxBytes) }
    }

    class ScanSession<T> internal constructor(
        private val transitions: IntArray,
        private val stateOutputs: Array<IntArray?>,
        private val labels: List<T>,
        private val ignoreAsciiCase: Boolean
    ) {
        private var state: Int = 0
        private val matched = BooleanArray(labels.size)
        private var matchedCount: Int = 0

        fun allMatched(): Boolean = matchedCount >= labels.size

        fun update(buffer: ByteArray, offset: Int = 0, length: Int = buffer.size) {
            if (labels.isEmpty() || length <= 0 || offset >= buffer.size) return
            val end = minOf(buffer.size, offset + length)
            var current = state
            val foldCase = ignoreAsciiCase
            for (i in offset until end) {
                var b = buffer[i].toInt() and 0xFF
                if (foldCase && b in 65..90) {
                    b += 32
                }
                current = transitions[(current shl 8) or b]
                val out = stateOutputs[current]
                if (out != null) {
                    for (idx in out) {
                        if (!matched[idx]) {
                            matched[idx] = true
                            matchedCount++
                        }
                    }
                }
            }
            state = current
        }

        fun matchedLabels(): List<T> {
            if (matchedCount == 0) return emptyList()
            val result = ArrayList<T>(matchedCount)
            for (i in matched.indices) {
                if (matched[i]) result.add(labels[i])
            }
            return result
        }
    }

    class Builder<T>(private val ignoreAsciiCase: Boolean = false) {
        private val trie = ArrayList<IntArray>().apply { add(IntArray(256) { -1 }) }
        private val outputs = ArrayList<MutableSet<Int>>().apply { add(LinkedHashSet()) }
        private val labels = ArrayList<T>()

        fun addBytes(pattern: ByteArray, label: T): Builder<T> {
            if (pattern.isEmpty()) return this
            val labelIdx = labels.size
            labels.add(label)
            var node = 0
            for (raw in pattern) {
                var b = raw.toInt() and 0xFF
                if (ignoreAsciiCase && b in 65..90) b += 32
                var next = trie[node][b]
                if (next == -1) {
                    next = trie.size
                    trie[node][b] = next
                    trie.add(IntArray(256) { -1 })
                    outputs.add(LinkedHashSet())
                }
                node = next
            }
            outputs[node].add(labelIdx)
            return this
        }

        fun addHex(hex: String, label: T): Builder<T> {
            val bytes = decodeHexOrNull(hex) ?: return this
            return addBytes(bytes, label)
        }

        fun addAscii(text: String, label: T): Builder<T> {
            if (text.isEmpty()) return this
            return addBytes(text.toByteArray(Charsets.UTF_8), label)
        }

        fun build(): BytePatternMatcher<T> {
            val nodeCount = trie.size
            val fail = IntArray(nodeCount)
            val queue = ArrayDeque<Int>()

            for (c in 0 until 256) {
                val child = trie[0][c]
                if (child != -1) {
                    fail[child] = 0
                    queue.addLast(child)
                } else {
                    trie[0][c] = 0
                }
            }

            while (queue.isNotEmpty()) {
                val u = queue.removeFirst()
                val fRow = trie[fail[u]]
                val uRow = trie[u]
                for (c in 0 until 256) {
                    val v = uRow[c]
                    if (v != -1) {
                        val f = fRow[c]
                        fail[v] = f
                        if (outputs[f].isNotEmpty()) {
                            outputs[v].addAll(outputs[f])
                        }
                        queue.addLast(v)
                    } else {
                        uRow[c] = fRow[c]
                    }
                }
            }

            val flatTransitions = IntArray(nodeCount * 256)
            val flatOutputs = arrayOfNulls<IntArray>(nodeCount)
            for (i in 0 until nodeCount) {
                System.arraycopy(trie[i], 0, flatTransitions, i shl 8, 256)
                val out = outputs[i]
                if (out.isNotEmpty()) {
                    flatOutputs[i] = out.toIntArray()
                }
            }

            return BytePatternMatcher(
                transitions = flatTransitions,
                stateOutputs = flatOutputs,
                labels = labels.toList(),
                ignoreAsciiCase = ignoreAsciiCase
            )
        }
    }

    companion object {
        fun decodeHexOrNull(hex: String): ByteArray? {
            val clean = hex.trim()
            if (clean.length < 2 || clean.length % 2 != 0) return null
            val out = ByteArray(clean.length / 2)
            for (i in out.indices) {
                val hi = hexDigit(clean[i * 2])
                val lo = hexDigit(clean[i * 2 + 1])
                if (hi < 0 || lo < 0) return null
                out[i] = ((hi shl 4) or lo).toByte()
            }
            return out
        }

        private fun hexDigit(c: Char): Int = when (c) {
            in '0'..'9' -> c - '0'
            in 'a'..'f' -> c - 'a' + 10
            in 'A'..'F' -> c - 'A' + 10
            else -> -1
        }
    }
}

