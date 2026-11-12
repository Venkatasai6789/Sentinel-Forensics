package com.deepfakeshield.core.security

import java.security.SecureRandom
import kotlin.math.log2
import kotlin.math.min
import kotlin.math.pow

enum class PasswordStrengthTier(val label: String) {
    VERY_WEAK("Very Weak"),
    WEAK("Weak"),
    FAIR("Fair"),
    STRONG("Strong"),
    VERY_STRONG("Very Strong")
}

data class PasswordAuditReport(
    val length: Int,
    val score: Int,
    val tier: PasswordStrengthTier,
    val shannonEntropyBits: Double,
    val poolEntropyBits: Double,
    val uppercaseCount: Int,
    val lowercaseCount: Int,
    val digitCount: Int,
    val symbolCount: Int,
    val warnings: List<String>,
    val suggestions: List<String>,
    val crackTimeOnlineThrottled: String,
    val crackTimeGpuFastHash: String,
    val crackTimeArgon2id: String
)

data class PasswordGenerationConfig(
    val mode: GenerationMode = GenerationMode.RANDOM_CHARACTERS,
    val length: Int = 18,
    val includeUppercase: Boolean = true,
    val includeLowercase: Boolean = true,
    val includeDigits: Boolean = true,
    val includeSymbols: Boolean = true,
    val excludeAmbiguous: Boolean = false,
    val wordCount: Int = 5,
    val wordSeparator: String = "-"
)

enum class GenerationMode {
    RANDOM_CHARACTERS,
    DICEWARE_PASSPHRASE
}

/**
 * Pure deterministic mathematical password auditor and CSPRNG password/passphrase generator.
 */
object PasswordAuditor {

    private val random = SecureRandom()

    private val commonPasswords = setOf(
        "123456", "password", "12345678", "qwerty", "123456789", "12345", "1234",
        "111111", "1234567", "dragon", "123123", "baseball", "abc123", "football",
        "monkey", "letmein", "shadow", "master", "666666", "qwertyuiop", "123321",
        "mustang", "1234567890", "michael", "654321", "superman", "1qaz2wsx",
        "7777777", "fuckyou", "121212", "000000", "qazwsx", "123qwe", "killer",
        "trustno1", "jordan", "jennifer", "zxcvbnm", "asdfgh", "hunter", "buster",
        "soccer", "harley", "batman", "andrew", "tigger", "sunshine", "iloveyou",
        "2000", "charlie", "robert", "thomas", "hockey", "ranger", "daniel",
        "starwars", "klaster", "112233", "george", "computer", "michelle", "jessica",
        "pepper", "1111", "zxcvbn", "555555", "11111111", "131313", "freedom",
        "777777", "pass", "maggie", "159753", "aaaaaa", "ginger", "princess",
        "joshua", "cheese", "amanda", "summer", "love", "ashley", "nicole",
        "chelsea", "biteme", "matthew", "access", "yankees", "987654321", "dallas",
        "austin", "thunder", "taylor", "matrix", "admin", "root", "toor",
        "welcome", "password1", "password123", "passw0rd", "p@ssw0rd", "changeme",
        "qwerty123", "letmein123", "admin123", "test123", "guest", "oracle", "default",
        "1q2w3e4r", "1q2w3e4r5t", "zaq12wsx", "q1w2e3r4", "a1b2c3d4"
    )

    private val keyboardWalks = listOf(
        "qwerty", "qwertz", "azerty", "asdfgh", "zxcvbn", "1qaz2wsx", "qazwsx",
        "1q2w3e", "zaq1", "xsw2", "cde3", "vfr4", "90op", "89io", "78ui", "poiuyt",
        "lkjhgf", "mnbvcx"
    )

    // Authentic EFF short-style distinct high-memorability words for CSPRNG passphrases
    private val dicewareWords = listOf(
        "acorn", "anchor", "anthem", "apricot", "arch", "arrow", "aspen", "atlas",
        "aurora", "autumn", "badge", "badger", "bamboo", "banjo", "barley", "barrel",
        "basalt", "beacon", "beaver", "belfry", "berry", "bison", "blazer", "bloom",
        "bluff", "bobcat", "bonnet", "boulder", "bramble", "branch", "breeze", "briar",
        "bridge", "bristle", "bronze", "brook", "brush", "bucket", "buffalo", "bugle",
        "cabin", "cactus", "cairn", "canary", "candle", "canyon", "canvas", "caper",
        "carbon", "caribou", "carve", "cascade", "castle", "cedar", "cellar", "chalk",
        "chapel", "charger", "chasm", "cherry", "chime", "chimney", "chisel", "cinder",
        "cipher", "citadel", "citron", "clang", "clover", "cobalt", "cobble", "comet",
        "compass", "condor", "conifer", "copper", "coral", "cornet", "corral", "cotton",
        "cougar", "cove", "cradle", "crag", "crane", "crater", "creek", "crest",
        "cricket", "crimson", "crocus", "crown", "crystal", "cubby", "current", "cypress",
        "dagger", "dahlia", "daisy", "dancer", "dawn", "daybreak", "delta", "desert",
        "dewdrops", "diamond", "dinghy", "dolphin", "domino", "dove", "draft", "dragon",
        "drift", "drizzle", "drum", "dune", "dusk", "eagle", "earth", "ebony",
        "echo", "eclipse", "eddy", "elder", "elm", "ember", "emerald", "empire",
        "encore", "engine", "enigma", "epoch", "equinox", "ermine", "estuary", "ether",
        "fable", "falcon", "falls", "fathom", "feather", "fennel", "fern", "ferry",
        "fiddle", "field", "fig", "finch", "fjord", "flame", "flannel", "flash",
        "flint", "flora", "flute", "foliage", "forest", "forge", "fossil", "fountain",
        "fox", "frame", "frost", "fungus", "furrow", "gable", "galaxy", "galley",
        "garden", "garnet", "gavel", "gazelle", "gecko", "geyser", "ginger", "glacier",
        "glade", "glass", "glen", "glider", "globe", "gloom", "gloss", "glow",
        "granite", "grape", "gravel", "gravity", "griffin", "grove", "gull", "gusto",
        "harbor", "harvest", "haven", "hawk", "hazel", "hearth", "heather", "hedgerow",
        "helium", "helmet", "hemlock", "herald", "heron", "hickory", "highland", "hilltop",
        "holly", "honey", "horizon", "hornet", "hound", "huckle", "humble", "hurdle",
        "ibis", "iceberg", "icicle", "iguana", "indigo", "ingot", "inlet", "iris",
        "iron", "island", "ivory", "ivy", "jackal", "jade", "jaguar", "jasmine",
        "jasper", "javelin", "jay", "jester", "jetty", "jewel", "jigsaw", "juniper",
        "kayak", "kestrel", "kettle", "keystone", "kilo", "kinglet", "kiosk", "kite",
        "knoll", "koala", "lagoon", "larch", "lark", "laser", "lantern", "lapis",
        "lariat", "latch", "laurel", "lava", "lavender", "ledge", "lemon", "leopard",
        "lichen", "lilac", "linden", "linnet", "lion", "lizard", "llama", "locket",
        "locust", "lodge", "loft", "lotus", "lumber", "lunar", "lynx", "lyre",
        "magnet", "magpie", "mahogany", "mallet", "mammoth", "mango", "manor", "mantis",
        "maple", "marble", "marina", "marigold", "marmot", "marsh", "marten", "meadow",
        "melon", "mercury", "mesa", "meteor", "mica", "mildew", "millstone", "mimic",
        "minnow", "mirage", "mirror", "mistle", "mitten", "moat", "mocking", "monarch",
        "mongoose", "monolith", "monsoon", "moose", "moraine", "morning", "mortar", "mosaic",
        "moss", "moth", "mountain", "mulberry", "murmur", "musket", "mustang", "myrtle",
        "narwhal", "nebula", "nectar", "needle", "nestle", "nettle", "newt", "nimbus",
        "nomad", "north", "nostril", "nugget", "nutmeg", "oasis", "obelisk", "obsidian",
        "ocean", "ocelot", "ochre", "octave", "octopus", "odyssey", "olive", "omega",
        "onyx", "opal", "oracle", "orange", "orbit", "orchard", "orchid", "oriole",
        "osprey", "otter", "outpost", "oval", "oven", "owl", "oxford", "oyster",
        "paddle", "pagoda", "palace", "palm", "panther", "papaya", "paper", "parade",
        "parchment", "parrot", "parsley", "pasture", "patch", "pavilion", "pebble", "pecan",
        "pelican", "pendulum", "penguin", "peony", "pepper", "perch", "peregrine", "petal",
        "petrel", "pewter", "phantom", "pheasant", "phoenix", "picnic", "pigeon", "pillar",
        "pilot", "pine", "pinnacle", "pioneer", "pipit", "pistachio", "pitcher", "pixel",
        "planet", "plaza", "plover", "plum", "plume", "pocket", "pointer", "polar",
        "pollen", "ponder", "poplar", "poppy", "portal", "porch", "porcupine", "porpoise",
        "prairie", "prism", "prospector", "prowler", "prune", "puffin", "pulse", "puma",
        "pumpkin", "pyramid", "quail", "quarry", "quartz", "quasar", "quest", "quiver",
        "rabbit", "raccoon", "radar", "radish", "raft", "rainbow", "ramble", "ranch",
        "ranger", "rapids", "raptor", "rascal", "raven", "ravine", "reef", "reindeer",
        "relic", "rhino", "ribbon", "ridge", "ripple", "river", "robin", "rocket",
        "rooster", "rosewood", "rowboat", "ruby", "rudder", "runway", "russet", "saddle",
        "saffron", "sage", "sailor", "salmon", "salute", "sandbar", "sandstone", "sapphire",
        "sardine", "satchel", "saturn", "savanna", "sawmill", "scaffold", "scarlet", "scepter",
        "schooner", "scorpion", "scout", "scroll", "sculptor", "seabird", "seagull", "seahorse",
        "seal", "season", "sediment", "sequoia", "serpent", "shadow", "shallot", "shamrock",
        "shelter", "sheriff", "shingle", "shipyard", "shoal", "shrew", "shrimp", "shutter",
        "sierra", "signal", "silver", "siren", "sketch", "skylark", "slate", "sleigh",
        "slope", "sloth", "smelt", "snowfall", "snowshoe", "socket", "solar", "solstice",
        "sonnet", "sorrel", "sparrow", "spectrum", "sphere", "spindle", "spire", "spruce",
        "sputnik", "squirrel", "stadium", "stallion", "starfish", "starling", "steeple", "stellar",
        "steppe", "sterling", "stew", "stilt", "stone", "stork", "storm", "stratum",
        "stream", "stucco", "studio", "stump", "sturgeon", "summit", "sunbeam", "sundial",
        "sunrise", "sunset", "surf", "swallow", "swamp", "swan", "swift", "sycamore",
        "symbol", "table", "taiga", "talon", "tamarind", "tandem", "tangerine", "tapestry",
        "tarpon", "tartan", "tassel", "teacup", "teak", "teapot", "temple", "terrace",
        "terrier", "thicket", "thimble", "thistle", "thorn", "thrush", "thunder", "thyme",
        "ticket", "tidal", "tiger", "timber", "tinsel", "toast", "topaz", "torch",
        "tornado", "torpedo", "tortoise", "totem", "toucan", "tower", "tractor", "trail",
        "transit", "treasure", "trellis", "tremor", "trench", "trident", "trillium", "trinket",
        "tripod", "triton", "trolley", "trophy", "tropic", "trout", "trowel", "trumpet",
        "tulip", "tumble", "tundra", "tunnel", "turban", "turbine", "turf", "turnip",
        "turtle", "tusk", "twilight", "twine", "typhoon", "umbra", "umbrella", "unicorn",
        "updraft", "uplift", "urchin", "utopia", "valley", "valve", "vanguard", "vanilla",
        "vault", "vector", "velvet", "veranda", "verdict", "vertex", "vessel", "vestige",
        "vortex", "voyage", "vulture", "waffle", "wagon", "walnut", "walrus", "wand",
        "warbler", "warden", "watchtower", "water", "wattle", "weasel", "weather", "weaver",
        "wedge", "weir", "westward", "whale", "wheat", "wheel", "whippet", "whirlpool",
        "whisker", "whistle", "wildcat", "willow", "windmill", "window", "winter", "wisteria",
        "wizard", "wolf", "wombat", "woodland", "woodpecker", "wool", "wren", "yarrow",
        "yew", "yonder", "zenith", "zephyr", "zigzag", "zinc", "zinnia", "zircon"
    )

    fun audit(password: String): PasswordAuditReport {
        val len = password.length
        val upper = password.count { it.isUpperCase() }
        val lower = password.count { it.isLowerCase() }
        val digits = password.count { it.isDigit() }
        val symbols = password.count { !it.isLetterOrDigit() }

        val freq = mutableMapOf<Char, Int>()
        for (c in password) freq[c] = (freq[c] ?: 0) + 1
        val shannonPerChar = if (len == 0) 0.0 else freq.values.sumOf { count ->
            val p = count.toDouble() / len
            -p * log2(p)
        }
        val shannonBits = shannonPerChar * len

        var charsetPool = 0
        if (lower > 0) charsetPool += 26
        if (upper > 0) charsetPool += 26
        if (digits > 0) charsetPool += 10
        if (symbols > 0) charsetPool += 32
        val poolBits = if (len == 0 || charsetPool == 0) 0.0 else len * log2(charsetPool.toDouble())

        val warnings = mutableListOf<String>()
        val suggestions = mutableListOf<String>()
        val lowerPw = password.lowercase()

        var penalty = 0
        if (lowerPw in commonPasswords) {
            warnings += "Matches a widely exploited common password."
            penalty += 55
        }
        if (keyboardWalks.any { lowerPw.contains(it) }) {
            warnings += "Contains a predictable keyboard sequence."
            penalty += 20
        }
        if (hasSequentialChars(lowerPw)) {
            warnings += "Contains sequential alphanumeric characters (e.g., 1234 or abcd)."
            penalty += 15
        }
        if (hasRepeatedRun(password)) {
            warnings += "Contains 3 or more repeated consecutive characters."
            penalty += 15
        }
        if (Regex("(19\\d{2}|20[0-3]\\d)").containsMatchIn(password)) {
            warnings += "Contains a 4-digit year pattern that reduces search space."
            penalty += 10
        }
        if (len in 1..11) {
            warnings += "Short password length ($len chars); 14+ chars recommended."
            suggestions += "Increase length to at least 14 characters or use a 5-word passphrase."
        }
        if (upper == 0) suggestions += "Add uppercase letters to expand character set diversity."
        if (lower == 0) suggestions += "Add lowercase letters."
        if (digits == 0) suggestions += "Include numbers outside trailing year/date positions."
        if (symbols == 0 && len < 16) suggestions += "Include punctuation/symbols or lengthen passphrase."

        // Effective entropy accounts conservatively for repetition & predictability
        val effectiveBits = (min(poolBits, shannonBits * 1.45) - penalty * 0.5).coerceAtLeast(if (len > 0) 1.0 else 0.0)

        val rawScore = when {
            len == 0 -> 0
            lowerPw in commonPasswords -> 5
            else -> {
                val base = ((effectiveBits / 95.0) * 100.0).toInt().coerceIn(5, 100)
                (base - penalty).coerceIn(5, 100)
            }
        }

        val tier = when {
            rawScore >= 85 && len >= 14 -> PasswordStrengthTier.VERY_STRONG
            rawScore >= 65 && len >= 12 -> PasswordStrengthTier.STRONG
            rawScore >= 45 -> PasswordStrengthTier.FAIR
            rawScore >= 25 -> PasswordStrengthTier.WEAK
            else -> PasswordStrengthTier.VERY_WEAK
        }

        val guesses = if (lowerPw in commonPasswords) 1e3 else 2.0.pow(effectiveBits.coerceAtMost(200.0))

        return PasswordAuditReport(
            length = len,
            score = rawScore,
            tier = tier,
            shannonEntropyBits = shannonBits,
            poolEntropyBits = poolBits,
            uppercaseCount = upper,
            lowercaseCount = lower,
            digitCount = digits,
            symbolCount = symbols,
            warnings = warnings,
            suggestions = suggestions,
            crackTimeOnlineThrottled = formatDurationSeconds(guesses / 100.0),
            crackTimeGpuFastHash = formatDurationSeconds(guesses / 1e10),
            crackTimeArgon2id = formatDurationSeconds(guesses / 1e4)
        )
    }

    fun generate(config: PasswordGenerationConfig): String {
        return when (config.mode) {
            GenerationMode.DICEWARE_PASSPHRASE -> {
                val count = config.wordCount.coerceIn(3, 12)
                (0 until count).joinToString(config.wordSeparator) {
                    dicewareWords[random.nextInt(dicewareWords.size)]
                }
            }
            GenerationMode.RANDOM_CHARACTERS -> {
                val len = config.length.coerceIn(8, 64)
                val ambiguous = setOf('0', 'O', 'o', '1', 'l', 'I')
                fun filterSet(raw: String) = if (config.excludeAmbiguous) raw.filterNot { it in ambiguous } else raw

                val lower = if (config.includeLowercase) filterSet("abcdefghjkmnpqrstuvwxyzilov") else ""
                val upper = if (config.includeUppercase) filterSet("ABCDEFGHJKLMNPQRSTUVWXYZOI") else ""
                val digits = if (config.includeDigits) filterSet("0123456789") else ""
                val symbols = if (config.includeSymbols) "!@#$%^&*()-_=+[]{}|;:,.<>?" else ""

                val groups = listOf(lower, upper, digits, symbols).filter { it.isNotEmpty() }
                val effectiveGroups = if (groups.isEmpty()) listOf("abcdefghjkmnpqrstuvwxyz23456789") else groups
                val combined = effectiveGroups.joinToString("")

                val chars = mutableListOf<Char>()
                // Guarantee at least 1 character from every enabled group
                for (group in effectiveGroups) {
                    if (chars.size < len) {
                        chars += group[random.nextInt(group.length)]
                    }
                }
                while (chars.size < len) {
                    chars += combined[random.nextInt(combined.length)]
                }
                // Fisher-Yates shuffle via SecureRandom
                for (i in chars.lastIndex downTo 1) {
                    val j = random.nextInt(i + 1)
                    val tmp = chars[i]
                    chars[i] = chars[j]
                    chars[j] = tmp
                }
                chars.joinToString("")
            }
        }
    }

    private fun hasSequentialChars(s: String): Boolean {
        if (s.length < 4) return false
        var asc = 1
        var desc = 1
        for (i in 1 until s.length) {
            val diff = s[i].code - s[i - 1].code
            asc = if (diff == 1) asc + 1 else 1
            desc = if (diff == -1) desc + 1 else 1
            if (asc >= 4 || desc >= 4) return true
        }
        return false
    }

    private fun hasRepeatedRun(s: String): Boolean {
        if (s.length < 3) return false
        var run = 1
        for (i in 1 until s.length) {
            run = if (s[i] == s[i - 1]) run + 1 else 1
            if (run >= 3) return true
        }
        return false
    }

    private fun formatDurationSeconds(seconds: Double): String {
        if (seconds.isNaN() || seconds < 1.0) return "< 1 second"
        if (seconds < 60.0) return "${seconds.toInt()} seconds"
        val minutes = seconds / 60.0
        if (minutes < 60.0) return "${minutes.toInt()} minutes"
        val hours = minutes / 60.0
        if (hours < 24.0) return "${hours.toInt()} hours"
        val days = hours / 24.0
        if (days < 365.0) return "${days.toInt()} days"
        val years = days / 365.25
        return when {
            years < 1000.0 -> "${years.toInt()} years"
            years < 1_000_000.0 -> "${(years / 1000.0).toInt()}k years"
            years < 1_000_000_000.0 -> "${(years / 1_000_000.0).toInt()}M years"
            else -> "> 1B years"
        }
    }
}

