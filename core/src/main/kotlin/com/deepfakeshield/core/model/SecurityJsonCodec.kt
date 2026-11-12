package com.deepfakeshield.core.model

/**
 * Dependency-free strict JSON encoder/decoder for SecurityAnalysisResult fields
 * so serialization works identically in Android runtime and pure-JVM unit tests.
 */
object SecurityJsonCodec {

    fun encodeStringList(items: List<String>): String =
        items.joinToString(prefix = "[", postfix = "]", separator = ",") { quote(it) }

    fun decodeStringList(json: String?): List<String> {
        if (json.isNullOrBlank()) return emptyList()
        val parser = JsonReader(json)
        return parser.readStringArrayOrEmpty()
    }

    fun encodeStringMap(map: Map<String, String>): String =
        map.entries.joinToString(prefix = "{", postfix = "}", separator = ",") { (k, v) ->
            "${quote(k)}:${quote(v)}"
        }

    fun decodeStringMap(json: String?): Map<String, String> {
        if (json.isNullOrBlank()) return emptyMap()
        val parser = JsonReader(json)
        return parser.readStringObjectOrEmpty()
    }

    fun encodeFindings(findings: List<SecurityFinding>): String =
        findings.joinToString(prefix = "[", postfix = "]", separator = ",") { f ->
            buildString {
                append('{')
                append("\"title\":${quote(f.title)},")
                append("\"description\":${quote(f.description)},")
                append("\"severity\":${quote(f.severity.name)},")
                append("\"evidenceSource\":${quote(f.evidenceSource)},")
                append("\"detectionMethod\":${quote(f.detectionMethod)},")
                append("\"inputLocation\":${f.inputLocation?.let(::quote) ?: "null"},")
                append("\"explanation\":${quote(f.explanation)},")
                append("\"recommendedAction\":${quote(f.recommendedAction)}")
                append('}')
            }
        }

    fun decodeFindings(json: String?): List<SecurityFinding> {
        if (json.isNullOrBlank()) return emptyList()
        val parser = JsonReader(json)
        return parser.readFindingsArrayOrEmpty()
    }

    private fun quote(value: String): String = buildString(value.length + 2) {
        append('"')
        for (ch in value) {
            when (ch) {
                '\\' -> append("\\\\")
                '"' -> append("\\\"")
                '\n' -> append("\\n")
                '\r' -> append("\\r")
                '\t' -> append("\\t")
                '\b' -> append("\\b")
                '\u000C' -> append("\\f")
                else -> {
                    if (ch.code < 0x20) {
                        append("\\u%04x".format(ch.code))
                    } else {
                        append(ch)
                    }
                }
            }
        }
        append('"')
    }

    private class JsonReader(private val input: String) {
        private var pos = 0

        fun readStringArrayOrEmpty(): List<String> {
            return try {
                skipWhitespace()
                if (!consume('[')) return emptyList()
                val list = mutableListOf<String>()
                skipWhitespace()
                if (peek() == ']') {
                    pos++
                    return list
                }
                while (pos < input.length) {
                    skipWhitespace()
                    readString()?.let { list += it }
                    skipWhitespace()
                    when (peek()) {
                        ',' -> pos++
                        ']' -> {
                            pos++
                            return list
                        }
                        else -> break
                    }
                }
                list
            } catch (_: Exception) {
                emptyList()
            }
        }

        fun readStringObjectOrEmpty(): Map<String, String> {
            return try {
                skipWhitespace()
                if (!consume('{')) return emptyMap()
                val map = linkedMapOf<String, String>()
                skipWhitespace()
                if (peek() == '}') {
                    pos++
                    return map
                }
                while (pos < input.length) {
                    skipWhitespace()
                    val key = readString() ?: break
                    skipWhitespace()
                    if (!consume(':')) break
                    skipWhitespace()
                    val value = readStringOrNull() ?: ""
                    map[key] = value
                    skipWhitespace()
                    when (peek()) {
                        ',' -> pos++
                        '}' -> {
                            pos++
                            return map
                        }
                        else -> break
                    }
                }
                map
            } catch (_: Exception) {
                emptyMap()
            }
        }

        fun readFindingsArrayOrEmpty(): List<SecurityFinding> {
            return try {
                skipWhitespace()
                if (!consume('[')) return emptyList()
                val list = mutableListOf<SecurityFinding>()
                skipWhitespace()
                if (peek() == ']') {
                    pos++
                    return list
                }
                while (pos < input.length) {
                    val obj = readStringObjectOrEmpty()
                    if (obj.containsKey("title")) {
                        val sev = runCatching { FindingSeverity.valueOf(obj["severity"] ?: "INFO") }
                            .getOrDefault(FindingSeverity.INFO)
                        list += SecurityFinding(
                            title = obj["title"].orEmpty(),
                            description = obj["description"].orEmpty(),
                            severity = sev,
                            evidenceSource = obj["evidenceSource"].orEmpty(),
                            detectionMethod = obj["detectionMethod"].orEmpty(),
                            inputLocation = obj["inputLocation"]?.takeIf { it.isNotEmpty() },
                            explanation = obj["explanation"].orEmpty(),
                            recommendedAction = obj["recommendedAction"].orEmpty()
                        )
                    }
                    skipWhitespace()
                    when (peek()) {
                        ',' -> pos++
                        ']' -> {
                            pos++
                            return list
                        }
                        else -> break
                    }
                }
                list
            } catch (_: Exception) {
                emptyList()
            }
        }

        private fun skipWhitespace() {
            while (pos < input.length && input[pos].isWhitespace()) pos++
        }

        private fun peek(): Char? = if (pos < input.length) input[pos] else null

        private fun consume(expected: Char): Boolean {
            if (peek() == expected) {
                pos++
                return true
            }
            return false
        }

        private fun readStringOrNull(): String? {
            skipWhitespace()
            if (pos + 4 <= input.length && input.substring(pos, pos + 4) == "null") {
                pos += 4
                return null
            }
            return readString()
        }

        private fun readString(): String? {
            skipWhitespace()
            if (!consume('"')) return null
            val sb = StringBuilder()
            while (pos < input.length) {
                val ch = input[pos++]
                when (ch) {
                    '"' -> return sb.toString()
                    '\\' -> {
                        if (pos >= input.length) break
                        when (val esc = input[pos++]) {
                            '"', '\\', '/' -> sb.append(esc)
                            'n' -> sb.append('\n')
                            'r' -> sb.append('\r')
                            't' -> sb.append('\t')
                            'b' -> sb.append('\b')
                            'f' -> sb.append('\u000C')
                            'u' -> {
                                if (pos + 4 <= input.length) {
                                    val hex = input.substring(pos, pos + 4)
                                    pos += 4
                                    hex.toIntOrNull(16)?.let { sb.append(it.toChar()) }
                                }
                            }
                            else -> sb.append(esc)
                        }
                    }
                    else -> sb.append(ch)
                }
            }
            return sb.toString()
        }
    }
}

