# Sentinel Forensics — Module Implementation Analysis

## Overview of Module Groups

This document provides an exhaustive, code-level analysis of all functional modules in Sentinel Forensics. Each module is evaluated according to twelve rigorous criteria, explicitly documenting actual algorithms, source files, asset dependencies, Android platform restrictions, and verified implementation limitations.

---

## Group A: Message and Phishing Protection

### A.1 Suspicious SMS & Message Analysis

1. **Implementation Status:** **Implemented** (for standard SMS; restricted for third-party messaging).
2. **Source Files & Classes:**
   - `app/.../receiver/SmsReceiver.kt` (`SmsReceiver`)
   - `core/.../engine/RiskIntelligenceEngine.kt` (`RiskIntelligenceEngine`)
   - `ml/.../text/GovernmentGradeTextDetector.kt` (`GovernmentGradeTextDetector`)
   - `feature/shield/.../MessageShieldScreen.kt` & `MessageShieldViewModel.kt`
3. **Input Type:** UTF-8 text strings extracted from incoming SMS PDUs (`Telephony.Sms.Intents.getMessagesFromIntent`), clipboard data, or manual user input.
4. **Processing Workflow:**
   - Broadcast received by `SmsReceiver.onReceive()` -> calls `goAsync()` to obtain asynchronous execution time.
   - Originating address and message body concatenated.
   - Text passed to `RiskIntelligenceEngine.analyzeText(text, ThreatSource.SMS)`.
   - Lexical pattern evaluation executes across multiple weighted heuristics.
   - If computed `score >= 30` (`shouldAlert == true`), an `AlertEntity` is inserted into `alertRepository`.
   - Notification posted to system notification drawer via `NotificationManager` (unless suppressed by `QuietHoursHelper`).
   - Threat status pushed to draggable `FloatingBubbleService`.
5. **Detection Technique / Algorithm:**
   - Heuristic pattern-matching engine using regular expressions and keyword weighting.
   - Red flag detectors:
     - OTP theft: `otp|one-time password|verification code|security code` (Weight: +35 to +50).
     - Financial coercion / payment pressure: `wire transfer|gift card|crypto|bitcoin|send money` (+30).
     - Remote access trojans (RAT): `anydesk|teamviewer|quicksupport|airdroid` (+50).
     - Artificial urgency: `urgent|immediately|act now|suspended|locked within 24 hours` (+20).
     - Impersonation heuristic: Mismatches between claimed sender organization (bank, IRS, postal service) and originating telephone number.
   - Total score normalized to $[0, 100]$. Severity mapped to `LOW` (<30), `MEDIUM` (30–59), `HIGH` (60–79), and `CRITICAL` ($\ge 80$).
6. **Rules, Signatures, or Model Assets:**
   - In-code compiled regexes in `RiskIntelligenceEngine.kt`.
   - Optional asset: `ml/src/main/assets/distilbert_scam_classifier.tflite` (20.3 MB) and `vocab.txt` (320 KB) in `GovernmentGradeTextDetector`. Heuristic scoring serves as the primary ground truth (`maxOf(heuristic, ml)`).
7. **Output Format:** `RiskResult` data class containing `threatType: ThreatType`, `severity: RiskSeverity`, `score: Int`, `confidence: Float`, `reasons: List<Reason>`, `recommendedActions: List<String>`, and `explainLikeImFive: String`.
8. **Error Handling:** Broadcast parsing wrapped in nested `try-catch` blocks. `pendingResult.finish()` is strictly called in a `finally` block to prevent ANR. If dependencies fail to inject, SMS processing aborts cleanly.
9. **Offline Operation:** **100% Offline.** All regex parsing, heuristic scoring, and Room database insertions occur locally on-device.
10. **Android Permissions & Platform Restrictions:**
    - Requires `android.permission.RECEIVE_SMS`.
    - **Platform Restriction:** Android does NOT permit non-default SMS apps to block or delete incoming SMS messages from the system SMS provider; Sentinel Forensics can only detect and notify, not silently drop SMS.
11. **Test Coverage:** Verified unit tests in `core/src/test/.../RiskIntelligenceEngineTest.kt` (clean text, OTP detection, urgency, impersonation, payment pressure, RAT keywords).
12. **Limitations:** Cannot inspect end-to-end encrypted messaging applications (WhatsApp, Signal, Telegram) at the protocol layer.

---

### A.2 Phishing URL Analysis

1. **Implementation Status:** **Implemented** (Offline heuristics + local caching of online threat feeds).
2. **Source Files & Classes:**
   - `core/.../engine/UrlSafetyEngine.kt` (`UrlSafetyEngine`)
   - `intelligence/.../UnifiedUrlThreatCache.kt` (`UnifiedUrlThreatCache`)
   - `intelligence/.../feed/PhishTankFeed.kt`, `OpenPhishFeed.kt`, `UrlHausFeed.kt`
   - `feature/shield/.../SafeBrowserScreen.kt` & `SafeBrowserViewModel.kt`
3. **Input Type:** Uniform Resource Identifier (URI) / URL string.
4. **Processing Workflow:**
   - Normalization: String trimmed, scheme extracted, domain parsed, lowercase conversion.
   - Cache Lookup: Query against `UnifiedUrlThreatCache` (in-memory `Set<String>` backed by local file storage).
   - Structural Analysis: Evaluated by `UrlSafetyEngine.analyzeUrl(url)`.
   - Risk aggregation: Point penalties assigned for high-risk attributes; total risk capped at 100.
5. **Detection Technique / Algorithm:**
   - **Lexical & Structural Heuristics:**
     - Punycode / Homoglyph detection: Flagging `xn--` internationalized domains mimicking standard brands (+25).
     - Known Brand Lookalikes: Detection of brand keywords (`paypal`, `netflix`, `amazon`, `google`, `apple`, `microsoft`) situated inside subdomains rather than registered root domains (+35).
     - Suspicious Top-Level Domains: Flagging high-abuse TLDs (`.tk`, `.ml`, `.ga`, `.cf`, `.gq`, `.top`, `.xyz`, `.buzz`, `.club`, `.work`) (+20).
     - IP Address Hostnames: URLs with numeric IPv4 addresses instead of domain names (+30).
     - URL Shortener Detection: Identifying redirectors (`bit.ly`, `tinyurl.com`, `t.co`, `is.gd`) (+15).
     - Subdomain Depth: Flagging excessive subdomain nesting (>3 subdomains) (+15).
     - Transport Security: HTTP protocol without TLS (+10).
6. **Rules, Signatures, or Model Assets:**
   - Domain pattern registries compiled into `UrlSafetyEngine.kt`.
   - Local feed cache file: `url_threat_cache.txt`.
   - Optional TFLite model: `ml/src/main/assets/roberta_phishing_detector.tflite` (33.5 MB).
7. **Output Format:** `UrlSafetyResult` object with `url`, `riskScore: Int`, `isSafe: Boolean`, `domain: String`, `isHttps: Boolean`, `threats: List<UrlThreatDetail>`, and `recommendation: String`.
8. **Error Handling:** URL parsing wrapped in `try-catch`; invalid or malformed URI formats default to high-risk parsing flags rather than throwing uncaught exceptions.
9. **Offline Operation:** **Fully Offline for Heuristic Scanning.** Feed refresh requires internet connectivity; cached feeds remain fully queryable offline.
10. **Android Permissions & Platform Restrictions:**
    - Requires `android.permission.INTERNET` only when refreshing threat feed lists.
    - **Platform Restriction:** The app cannot intercept browser navigation system-wide without running as an active VPN or custom accessibility service.
11. **Test Coverage:** Verified unit tests in `core/src/test/.../UrlSafetyEngineTest.kt` (HTTP vs HTTPS, lookalike domains, suspicious TLDs, IP hostnames, URL shorteners, excessive subdomains).
12. **Limitations:** Brand lookalike detection is dictionary-based; completely novel zero-day phishing domains lacking recognized brand keywords or suspicious TLDs may receive low risk scores unless matched against cached feeds.

---

### A.3 Scam Number Intelligence & Call Screening

1. **Implementation Status:** **Implemented**.
2. **Source Files & Classes:**
   - `app/.../service/CallScreeningService.kt` (`CallScreeningService`)
   - `core/.../engine/RiskIntelligenceEngine.kt` (`analyzeCall`)
   - `data/.../repository/PhoneReputationRepository.kt` (`PhoneReputationRepository`)
   - `feature/callprotection/.../CallProtectionViewModel.kt`
   - `feature/shield/.../ScamNumberLookupScreen.kt`
3. **Input Type:** Inbound telecom caller telephone numbers (E.164 strings) passed via `Call.Details.getHandle()`.
4. **Processing Workflow:**
   - Telecom subsystem invokes `CallScreeningService.onScreenCall(callDetails)`.
   - Checks `userPreferences.callShieldEnabled`.
   - Pre-Screening: Queries local `PhoneReputationRepository` database. If explicitly blocked, call is rejected immediately (`setRejectCall(true)`, `setDisallowCall(true)`).
   - If whitelisted, call is allowed immediately.
   - Analysis: Invokes `RiskIntelligenceEngine.analyzeCall(phoneNumber, isIncoming = true)` with a 4000ms coroutine timeout.
   - Policy Enforcement:
     - Score $\ge 65$: Call rejected and disallowed.
     - Score $45–64$: Call silenced (`setSilenceCall(true)` on API 29+).
     - Score $< 45$: Call permitted.
   - Alert Generation: Persists `AlertEntity` with status `BLOCKED`, `SILENCED`, or `WARNED`.
5. **Detection Technique / Algorithm:**
   - Country code risk profiling: High-risk originating international dial codes (+30).
   - Number entropy & structure: Premium rate prefixes, spoofed shortcodes, sequential repetitive digits.
   - Local database reputation lookup (`phone_reputation` table) scoring historical user reports.
6. **Rules, Signatures, or Model Assets:**
   - Country prefix map in `RiskIntelligenceEngine.kt`.
   - SQLite `phone_reputation` table.
7. **Output Format:** Android Telecom `CallResponse` alongside an `AlertEntity` record.
8. **Error Handling:** Analysis bounded by a strict `withTimeout(4000)` block. If analysis times out or throws an exception, the service falls back to allowing the call rather than causing call dropped exceptions.
9. **Offline Operation:** **100% Offline.** Evaluated entirely against local rules and SQLite reputation tables.
10. **Android Permissions & Platform Restrictions:**
    - Requires user to set Sentinel Forensics as the default **Caller ID & Spam App** (`RoleManager.ROLE_CALL_SCREENING`).
    - Requires `android.permission.READ_PHONE_STATE`.
    - Modern Android restricts background audio capture during calls; automated in-call voice analysis cannot be performed silently.
11. **Test Coverage:** Verified unit tests in `core/src/test/.../RiskIntelligenceEngineTest.kt` (domestic numbers, international prefixes).
12. **Limitations:** Cannot detect sophisticated caller ID spoofing if the spoofed number matches a legitimate domestic number not present in the local blacklist.

---

## Group B: Media Forensics

### B.1 Image Metadata Inspection & Stripper

1. **Implementation Status:** **Implemented** (Inspection & Risk Scoring); **UI Only** for File Scrubbing.
2. **Source Files & Classes:**
   - `feature/shield/.../PhotoForensicsScreen.kt` (`analyzePhoto`)
   - `feature/shield/.../MetadataStripperScreen.kt` (`extractMetadata`)
3. **Input Type:** `android.net.Uri` referencing local image storage (`image/*`).
4. **Processing Workflow:**
   - ContentResolver opens an `InputStream` to the target URI.
   - `androidx.exifinterface.media.ExifInterface` instantiates and parses standard EXIF tags.
   - Extracts camera hardware fields, temporal timestamps, GPS coordinates, and software tags.
   - Evaluates metadata consistency against known AI generation generator signatures.
   - Assigns severity rankings to exposed sensitive attributes (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`).
5. **Detection Technique / Algorithm:**
   - EXIF signature auditing: Searches `TAG_SOFTWARE` for strings matching AI synthesis engines (`dall-e`, `midjourney`, `stable diffusion`, `stablediffusion`, `comfyui`, `automatic1111`, `novelai`, `leonardo`, `firefly`, `copilot`, `chatgpt`, `bing image`) or desktop editing suites (`photoshop`, `gimp`, `lightroom`, `snapseed`, `picsart`, `canva`).
   - Hardware presence check: Verifies presence of physical camera parameters (`TAG_MAKE`, `TAG_MODEL`, `FOCAL_LENGTH`, `EXPOSURE_TIME`, `ISO_SPEED_RATINGS`, `F_NUMBER`). Absence in high-resolution photographs flags an AI-generation warning.
6. **Rules, Signatures, or Model Assets:** Hardcoded dictionary of AI synthesis software tags and image manipulation signatures.
7. **Output Format:** `List<MetadataField>` and `ForensicsResult` containing individual `ForensicsCheck` outcomes.
8. **Error Handling:** Stream reading wrapped in `try-catch`; corrupted EXIF headers fail gracefully with a descriptive warning card.
9. **Offline Operation:** **100% Offline.**
10. **Android Permissions & Platform Restrictions:** Requires Storage / `READ_MEDIA_IMAGES` permission.
11. **Test Coverage:** Manual UI verification; no dedicated unit test file.
12. **Limitations:** Metadata inspection is only effective if EXIF tags have not been stripped prior to ingestion; social media platforms (WhatsApp, Twitter) routinely strip EXIF upon upload.

---

### B.2 Image Manipulation Analysis (Pixel Forensics)

1. **Implementation Status:** **Implemented**.
2. **Source Files & Classes:**
   - `ml/.../engine/ImageForensicsEngine.kt` (`ImageForensicsEngine`)
3. **Input Type:** In-memory uncompressed `android.graphics.Bitmap`.
4. **Processing Workflow:**
   - Validates bitmap state (non-recycled, positive dimensions).
   - Executes six parallel pixel-level diagnostic algorithms.
   - Accumulates penalty points into a unified `riskScore` capped at 100.
   - Classifies primary manipulation type (`Copy-Paste Forgery`, `Image Splicing`, `Text Manipulation`, `Region Editing`).
5. **Detection Technique / Algorithm:**
   - **Error Level Analysis (ELA):** Divides image into $8 \times 8$ pixel blocks, computes intra-block pixel gradient variance (energy). Computes mean and standard deviation across blocks. Blocks deviating by $> 2.5\sigma$ are counted as high-frequency compression anomalies.
   - **Copy-Move Detection:** Evaluates $16 \times 16$ pixel blocks with a stride of 8 pixels. Computes a 64-bit spatial color hash for each block (`hash = hash * 31 + color`). Identical hash collisions across disparate spatial coordinates flag duplicate/cloned regions.
   - **Text Consistency Analysis:** Scans horizontal scanlines for rapid luminance transitions ($|L_x - L_{x+1}| > 50$). High variance in edge density across regions flags spliced or altered text overlays in screenshots.
   - **Edit Boundary Analysis:** Computes discrete 4-neighbor Laplacian differences across $2 \times 2$ pixel steps. Unnatural concentrations of razor-sharp boundaries flag digital lasso/cut-and-paste splices.
   - **Color Palette & Resolution Consistency:** Compares color histogram distributions between vertical image halves and evaluates local sharpness variance across $32 \times 32$ blocks.
6. **Rules, Signatures, or Model Assets:** Deterministic mathematical algorithms implemented in pure Kotlin.
7. **Output Format:** `ImageForensicResult` containing `isManipulated: Boolean`, `confidence: Float`, `manipulationType: String`, `findings: List<ForensicFinding>`, `riskScore: Int`, and `recommendation: String`.
8. **Error Handling:** Returns default clean result if bitmap is recycled or invalid; bounds all array indices.
9. **Offline Operation:** **100% Offline.**
10. **Android Permissions & Platform Restrictions:** Operates on in-memory bitmaps; zero platform restrictions.
11. **Test Coverage:** Not covered in automated unit test suite.
12. **Limitations:** Heavy computational operations on very large bitmaps can introduce UI lag if not dispatched to background coroutines. Block hashing is sensitive to geometric rotations.

---

### B.3 Deepfake Video Analysis

1. **Implementation Status:** **Implemented** (Hybrid ML Kit + Heuristic Temporal Tracker); **Partially Implemented** for Heavy TFLite Models.
2. **Source Files & Classes:**
   - `ml/.../engine/DeepfakeMLEngine.kt` (`DeepfakeMLEngine`)
   - `ml/.../face/MLKitFaceAnalyzer.kt` (`MLKitFaceAnalyzer`)
   - `ml/.../face/FaceMeshDeepfakeAnalyzer.kt` (`FaceMeshDeepfakeAnalyzer`)
   - `ml/.../face/TemporalFaceTracker.kt` (`TemporalFaceTracker`)
   - `ml/.../deepfake/GovernmentGradeDeepfakeDetector.kt`
   - `app/.../service/ScreenCaptureService.kt`
   - `feature/shield/.../VideoScanScreen.kt` & `VideoShieldViewModel.kt`
3. **Input Type:** Sequence of video frame bitmaps extracted via `MediaMetadataRetriever` or captured in real time via `MediaProjection`.
4. **Processing Workflow:**
   - **Stage 1 (ML Kit Face Detection):** Extracts face bounding boxes, 133 contour landmarks, eye open/close probabilities, smile probabilities, and 3D Euler head orientation angles (pitch, yaw, roll).
   - **Stage 2 (ML Kit 468-point 3D Face Mesh):** Maps fine-grained 3D mesh coordinates; computes triangle proportions and mesh symmetry.
   - **Stage 3 (Temporal Face Tracking):** Buffers landmark positions across sequential frames to compute blink rate regularities, landmark micro-jitter, and head pose velocity.
   - **Stage 4 (Pixel Heuristics):** Executes Error Level Analysis, FFT high-frequency noise inspection, and facial boundary blend transitions.
   - **Stage 5 (TFLite Inference):** In `GovernmentGradeDeepfakeDetector`, attempts to pass preprocessed face crops into bundled TFLite models (`efficientnet_b4_deepfake.tflite`, `xception_deepfake.tflite`, `cnn_detection.tflite`).
   - **Ensemble Scoring:** Merges model inference and heuristics using conservative bounding: $Score = \max(Score_{heuristic}, Score_{ML})$.
5. **Detection Technique / Algorithm:**
   - Blink rate anomaly detection: Detects unnaturally low or erratic eye-closure frequencies common in synthetic talking heads.
   - 3D Mesh Discontinuity: High geometric variance across facial triangle ratios.
   - Audio-Visual Asynchrony: Correlates per-frame audio root-mean-square (RMS) energy with spatial mouth-region pixel movement.
6. **Rules, Signatures, or Model Assets:**
   - Google ML Kit bundled models: `blazeface.tfl`, `face_mesh_graph.binarypb`, `fssd_25_8bit_v2.tflite`.
   - Bundled TFLite models in `ml/src/main/assets/`:
     - `efficientnet_b4_deepfake.tflite` (28.3 MB)
     - `xception_deepfake.tflite` (33.3 MB)
     - `cnn_detection.tflite` (21.8 MB)
     - `wav2vec2_audio_deepfake.tflite` (3.6 MB)
7. **Output Format:** `DeepfakeResult` with `isDeepfake: Boolean`, `confidence: Float`, `manipulationScore: Float`, `findings: List<String>`, and `technicalDetails: Map<String, String>`.
8. **Error Handling:** Bitmaps recycled explicitly in `finally` blocks to prevent OutOfMemory (OOM) crashes. TFLite loading catches `Throwable` (handling missing native GPU delegate libraries).
9. **Offline Operation:** **100% Offline.**
10. **Android Permissions & Platform Restrictions:**
    - Live monitoring requires `android.permission.FOREGROUND_SERVICE_MEDIA_PROJECTION` and user consent via system projection dialog.
    - Video file analysis requires media read permissions (`READ_MEDIA_VIDEO`).
11. **Test Coverage:** Verified unit tests in `core/src/test/.../RiskIntelligenceEngineTest.kt` (`analyzeVideo`).
12. **Limitations:** TFLite models are evaluated as binary classifiers without retraining on device; heuristic scoring provides the active fallback. Real-time screen capture is throttled to 1.8-second intervals to preserve battery and thermal performance.

---

### B.4 Evidence Integrity Checks

1. **Implementation Status:** **Implemented** (Hashing & Audit Trails); **Planned / Mocked** (Hardware Attestation).
2. **Source Files & Classes:**
   - `data/.../database/DeepfakeShieldDatabase.kt`
   - `data/.../entity/AuditLogEntity.kt`
   - `data/.../entity/ExportHistoryEntity.kt`
   - `feature/export/.../ExportManager.kt`
3. **Input Type:** Scanned binary files, APK files, and generated forensic findings.
4. **Processing Workflow:**
   - Computes standard SHA-256 digests over files and evidence payloads.
   - Records immutable event logs in `audit_log` Room table (`timestamp`, `action`, `entityType`, `entityId`, `hash`).
   - Exported reports include creation timestamps, item counts, and SHA-256 file hashes in `export_history`.
5. **Detection Technique / Algorithm:** Cryptographic hashing via `java.security.MessageDigest.getInstance("SHA-256")`.
6. **Rules, Signatures, or Model Assets:** Standard Java Security Cryptography Architecture.
7. **Output Format:** 64-character lowercase hexadecimal hash strings.
8. **Error Handling:** Catches standard security provider exceptions; returns `"unavailable"` if digest creation fails.
9. **Offline Operation:** **100% Offline.**
10. **Android Permissions & Platform Restrictions:** Standard file read access.
11. **Test Coverage:** Verified unit tests in `av/src/test/.../AntivirusEngineTest.kt` (`scanFile includes file hash`).
12. **Limitations:** Evidence records are stored in standard SQLite and are not backed by Android Keystore hardware-backed hardware keys or cryptographic asymmetric digital signatures.

---

## Group C: Device and Network Security

### C.1 Accessible-File Malware Scanning (Antivirus Engine)

1. **Implementation Status:** **Implemented**.
2. **Source Files & Classes:**
   - `av/.../engine/AntivirusEngine.kt` (`AntivirusEngine`)
   - `av/.../engine/MalwareSignatureDatabase.kt` (`MalwareSignatureDatabase`)
   - `av/.../engine/HeuristicMalwareAnalyzer.kt` (`HeuristicMalwareAnalyzer`)
   - `av/.../engine/YaraRuleEngine.kt` & `intelligence/.../YaraLikeRuleEngine.kt`
   - `av/.../engine/QuarantineManager.kt` (`QuarantineManager`)
3. **Input Type:** File paths, file URIs, or installed package names (`packageName`).
4. **Processing Workflow:**
   - Exclusion Filter: Skips internal application files and designated trusted publishers (`com.google.*`, `com.samsung.*`, etc.) to minimize false positives.
   - Hash Matching: Computes SHA-256 of target file; checks against memory hash set loaded from `malware_hashes.txt`.
   - Byte Pattern Matching: Scans binary streams for 38 high-specificity malware strings (`metasploit`, `c2`, `implant`, `ransomware_note`, `xhook`, `xmrig`, `root_shell`, etc.).
   - Heuristic APK Inspection: Evaluates file extension anomalies, double extensions, tiny APK droppers, and high Shannon entropy.
   - YARA Inspection: Executes in-process pattern rules against file content.
   - APK Internal Scanning: If target is an APK/ZIP, unzips archive in-memory to scan embedded `.dex` and `.so` binaries.
   - Aggregation: Generates `AvScanResult`; if infected, optionally moves file to quarantine sandbox using XOR obfuscation.
5. **Detection Technique / Algorithm:**
   - Exact SHA-256 cryptographic signature lookup.
   - Boyer-Moore-style in-memory byte matching for binary indicators.
   - Shannon entropy thresholding: $H(X) = -\sum P(x) \log_2 P(x)$ to detect encrypted payloads or packed executables.
   - Structural APK verification: Flags APKs with sizes $< 100$ KB containing executable bytecode.
6. **Rules, Signatures, or Model Assets:**
   - `av/src/main/assets/malware_hashes.txt` (3.58 MB containing ~54,000 SHA-256 hashes).
   - In-memory `HIGH_SPECIFICITY_PATTERNS` set.
7. **Output Format:** `AvScanResult` containing `threatLevel: ThreatLevel` (`CLEAN`, `LOW_RISK`, `SUSPICIOUS`, `PUA`, `INFECTED`), `threatName: String?`, `indicators: List<AvIndicator>`, `durationMs`, and `fileHash`.
8. **Error Handling:** File access wrapped in `try-catch`; unreadable files return `AvScanResult.ERROR` without crashing background workers.
9. **Offline Operation:** **100% Offline.** Cloud lookup explicitly disabled in `CloudHashChecker.kt`.
10. **Android Permissions & Platform Restrictions:**
    - Requires `MANAGE_EXTERNAL_STORAGE` on Android 11+ to scan external public directories.
    - **Platform Restriction:** Android sandbox rules prohibit scanning private data directories (`/data/data/<package>/`) of third-party applications. Only public shared storage and public APK files in `/data/app/` can be scanned.
11. **Test Coverage:** Verified unit tests in `av/src/test/.../` (`AntivirusEngineTest`, `HeuristicMalwareAnalyzerTest`, `MalwareSignatureDatabaseTest`).
12. **Limitations:** Cannot inspect memory execution or runtime heap of running processes; static file analysis only.

---

### C.2 Wi-Fi and Network Analysis

1. **Implementation Status:** **Implemented**.
2. **Source Files & Classes:**
   - `feature/diagnostics/.../WifiScannerScreen.kt`
   - `feature/diagnostics/.../NetworkMonitorScreen.kt`
3. **Input Type:** Wi-Fi connection info (`WifiManager.getConnectionInfo()`), network capabilities, `/proc/net/tcp`, and socket connections.
4. **Processing Workflow:**
   - Reads active network link properties, DNS servers, gateways, and transport types via `ConnectivityManager`.
   - Parses Linux `/proc/net/tcp` and `/proc/net/udp` tables to extract local/remote IP addresses, ports, connection states, and owning UIDs.
   - Maps remote IPs against server signature tables (Google, Meta, Cloudflare, etc.).
   - Computes per-app data usage via `TrafficStats.getUidTxBytes()` and `getUidRxBytes()`.
   - Conducts gateway port scanning against 14 common ports (21, 22, 23, 53, 80, 443, 445, 8080, etc.).
   - Evaluates Wi-Fi encryption protocol (`WPA3`, `WPA2`, `WEP`, `Open`).
5. **Detection Technique / Algorithm:**
   - Socket connection testing via `java.net.Socket.connect(InetSocketAddress, timeout = 800ms)`.
   - Data exfiltration heuristic: Flags apps sending 5x more data than receiving (`tx > rx * 5` with `tx > 1MB`).
   - Private DNS verification via `Settings.Global.getString(ctx.contentResolver, "private_dns_mode")`.
6. **Rules, Signatures, or Model Assets:** Known port maps and CIDR/IP prefix tables for cloud and advertising networks.
7. **Output Format:** Diagnostic dashboard UI states (`LiveConnection`, `AppNetworkInfo`, `NetSecCheck`, `PortScanResult`).
8. **Error Handling:** Socket timeouts handled gracefully; file reads on `/proc/net/tcp` catch security exceptions.
9. **Offline Operation:** **Mostly Offline.** Speed benchmarking and DNS reachability tests inherently require active network packets.
10. **Android Permissions & Platform Restrictions:**
    - Requires `ACCESS_WIFI_STATE`, `ACCESS_NETWORK_STATE`, and `ACCESS_FINE_LOCATION` (to read SSID/BSSID on Android 9+).
    - **Platform Restriction:** On Android 10+ (API 29+), SELinux policies restrict access to `/proc/net/tcp` for non-root apps. If restricted by OEM policies, live socket lists appear empty.
11. **Test Coverage:** Manual diagnostics verification; no automated unit tests.
12. **Limitations:** Network socket enumeration is subject to Android version-specific SELinux restrictions.

---

### C.3 Device Security Checks (App Auditor & Root Detection)

1. **Implementation Status:** **Implemented**.
2. **Source Files & Classes:**
   - `feature/diagnostics/.../AppAuditorScreen.kt` (`deepAudit`)
   - `av/.../engine/RootDetector.kt` (`RootDetector`)
   - `feature/analytics/.../DeviceSecurityScoreScreen.kt` & `PrivacyScoreScreen.kt`
3. **Input Type:** System package registry (`PackageManager.getInstalledPackages`) and OS environment properties.
4. **Processing Workflow:**
   - Queries `PackageManager` for installed packages, permissions, activities, services, receivers, and metadata.
   - Audits 24 critical permissions across 4 threat categories (`Surveillance`, `Data Access`, `Network`, `System`).
   - Matches manifest metadata keys against 21 commercial tracking SDK signatures.
   - Inspects application flags for cleartext HTTP traffic allowance (`FLAG_USES_CLEARTEXT_TRAFFIC`).
   - Inspects `nativeLibraryDir` for presence of native `.so` binaries.
   - Computes SHA-256 hash of the installed APK source directory.
   - Calculates a weighted composite security risk score ($0–100$) and letter grade ($A–F$).
5. **Detection Technique / Algorithm:**
   - Static manifest heuristic analysis.
   - Root detection heuristics: Checking existence of `su`, `busybox`, `magisk` across standard paths (`/system/bin/`, `/system/xbin/`, `/sbin/`, `/system/sd/xbin/`), checking `Build.TAGS.contains("test-keys")`, and executing `/system/bin/which su`.
6. **Rules, Signatures, or Model Assets:**
   - `PERM_DB` dictionary mapping permissions to risk weights.
   - `TRACKER_SIGS` list matching package prefixes (Facebook Ads, Firebase, Adjust, AppsFlyer, Mixpanel, Sentry, etc.).
7. **Output Format:** `AuditedApp` records and overall device security score percentage.
8. **Error Handling:** Unreadable package info or security exceptions caught cleanly during enumeration.
9. **Offline Operation:** **100% Offline.**
10. **Android Permissions & Platform Restrictions:**
    - Requires `android.permission.QUERY_ALL_PACKAGES` to view third-party apps on Android 11+ (API 30+).
11. **Test Coverage:** Manual UI audit; no dedicated unit test.
12. **Limitations:** Static analysis only; cannot determine whether an app actively exercises granted permissions at runtime.

---

### C.4 Background Monitoring & Automation

1. **Implementation Status:** **Implemented**.
2. **Source Files & Classes:**
   - `app/.../service/ProtectionForegroundService.kt`
   - `app/.../service/AntivirusForegroundService.kt`
   - `app/.../worker/ScheduledScanWorker.kt`, `DailyDigestWorker.kt`, `DailyCleanupWorker.kt`
   - `app/.../receiver/BootReceiver.kt`
3. **Input Type:** OS lifecycle triggers, WorkManager scheduled timers, and boot broadcasts.
4. **Processing Workflow:**
   - `BootReceiver` captures `ACTION_BOOT_COMPLETED` and restarts persistent protection services.
   - `WorkManager` schedules periodic background workers for daily cache cleanups, scheduled antivirus scans, and threat digest notifications.
   - Persistent foreground services run with sticky notifications to maintain memory residence.
5. **Detection Technique / Algorithm:** Scheduled WorkManager task triggers and persistent notification loops.
6. **Rules, Signatures, or Model Assets:** WorkManager periodic constraints (`NetworkType.CONNECTED`, `requiresBatteryNotLow`).
7. **Output Format:** Periodic system notifications and updated Room database counters.
8. **Error Handling:** WorkManager retry policies with exponential backoff.
9. **Offline Operation:** **100% Offline.**
10. **Android Permissions & Platform Restrictions:**
    - Requires `RECEIVE_BOOT_COMPLETED`, `FOREGROUND_SERVICE`, and `REQUEST_IGNORE_BATTERY_OPTIMIZATIONS`.
    - **Platform Restriction:** OEM background execution killers (e.g., Xiaomi MIUI, Samsung OneUI aggressive Doze) may kill foreground services if not manually exempted by the user.
11. **Test Coverage:** Not covered in unit tests.
12. **Limitations:** Subject to aggressive Android 14 foreground service policies and OEM battery optimization kills.

---

## Group D: Privacy and Security Utilities

### D.1 Password Generation & Breach Verification

1. **Implementation Status:** **Implemented**.
2. **Source Files & Classes:**
   - `feature/shield/.../PasswordCheckerScreen.kt`
3. **Input Type:** User-entered candidate password strings.
4. **Processing Workflow:**
   - Evaluates local password entropy, length, character diversity, and common pattern weaknesses.
   - Computes SHA-1 hash over password: `MessageDigest.getInstance("SHA-1")`.
   - Extracts the first 5 hexadecimal characters as a k-anonymity prefix.
   - Sends HTTPS GET request to HaveIBeenPwned API (`https://api.pwnedpasswords.com/range/{prefix}`).
   - Receives list of matching hash suffixes with breach frequency counts.
   - Compares the remaining 35 characters locally against the returned suffix list.
5. **Detection Technique / Algorithm:**
   - K-Anonymity mathematical model: Full password is never transmitted across the network; privacy is preserved because the 5-character prefix matches thousands of unrelated hashes.
   - Local Shannon password entropy calculation.
6. **Rules, Signatures, or Model Assets:** Remote HIBP k-anonymity API endpoint.
7. **Output Format:** Breach status indicator, occurrence count, and visual password strength meter.
8. **Error Handling:** Network timeouts or API errors display an *"Offline / Unable to verify breaches"* warning while continuing to show local entropy analysis.
9. **Offline Operation:** **Partially Offline.** Local strength evaluation is 100% offline; breach check requires internet connectivity.
10. **Android Permissions & Platform Restrictions:** Requires `android.permission.INTERNET`.
11. **Test Coverage:** Manual UI testing.
12. **Limitations:** Does not check organizational custom wordlists or localized dictionary variants.

---

### D.2 Forensic Vault, Findings History & Reporting

1. **Implementation Status:** **Implemented** (for Room-backed Incident Vault and CSV/JSON Export); **UI Only** (for Secure Notes and File Vault).
2. **Source Files & Classes:**
   - `data/.../dao/Daos.kt` (`VaultDao`, `AlertDao`)
   - `data/.../repository/VaultRepository.kt` & `AlertRepository.kt`
   - `feature/vault/.../VaultScreen.kt` & `VaultViewModel.kt`
   - `feature/export/.../ExportManager.kt`
   - `feature/vault/.../SecureNotesScreen.kt` (UI prototype)
   - `feature/vault/.../SecureFileVaultScreen.kt` (UI prototype)
3. **Input Type:** Generated threat alerts, user feedback notes, and incident records.
4. **Processing Workflow:**
   - Forensic incidents persisted in Room `vault_entries` table.
   - User triggers export in `VaultViewModel` or `ExportManager`.
   - Background coroutine serializes entities to structured CSV or UTC-timestamped JSON formats in `context.cacheDir`.
   - FileProvider generates secure `content://` URI with `FLAG_GRANT_READ_URI_PERMISSION`.
   - Launches Android system share sheet (`Intent.ACTION_SEND`).
5. **Detection Technique / Algorithm:** Relational querying, indexing, and deterministic structured formatting.
6. **Rules, Signatures, or Model Assets:** Room Database v3 schema.
7. **Output Format:**
   - CSV format (`Date,Time,Type,Severity,Score,Source,Summary`).
   - JSON format (`{"export_date": "...", "total_threats": N, "alerts": [...]}`).
8. **Error Handling:** File creation wrapped in `try-catch`; empty tables return explicit user-facing errors rather than creating empty files.
9. **Offline Operation:** **100% Offline.**
10. **Android Permissions & Platform Restrictions:** Utilizes internal app cache storage and `androidx.core.content.FileProvider`; requires zero external storage permissions.
11. **Test Coverage:** Verified unit tests in `data/src/test/.../AlertDaoTest.kt` (insert, retrieve, count unhandled, mark handled).
12. **Limitations:** Export files are unencrypted plain JSON/CSV; password protection or PGP encryption over exported reports is not implemented.
