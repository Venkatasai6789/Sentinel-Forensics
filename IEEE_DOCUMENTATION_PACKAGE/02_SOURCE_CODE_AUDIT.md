# Sentinel Forensics — Comprehensive Source Code Audit

## 1. Build System & Dependency Configuration Audit

### 1.1 Root Build Configuration
- **File:** `build.gradle.kts`
- **Gradle Version:** `8.5` (via `gradle/wrapper/gradle-wrapper.properties`)
- **Android Gradle Plugin (AGP):** `8.2.2`
- **Kotlin Version:** `1.9.22`
- **Dependency Injection Plugin:** Dagger Hilt `2.50`
- **Static Analysis Plugin:** Detekt `1.23.4` (Configured via `config/detekt/detekt.yml`)
- **Version Catalog:** No `gradle/libs.versions.toml` file is present in the repository; dependencies and build versions are managed directly within subproject `build.gradle.kts` files.

### 1.2 Module Topology (16 Gradle Projects)
Declared in `settings.gradle.kts` (Root project name: `DeepfakeShield`):
1. `:app` — Application entry point, Android manifest, system services, receivers, workers, navigation, and DI setup.
2. `:core` — Core domain models, risk intelligence engines, URL safety engine, Tor networking bindings, and common UI theme/components.
3. `:data` — Room database (`DeepfakeShieldDatabase` v3), 16 entities, DAOs, repositories, and DataStore preferences.
4. `:ml` — Deepfake detection pipeline, ML Kit face/mesh analyzers, temporal tracker, TFLite inference classes, and audio/text heuristics.
5. `:av` — Antivirus engine, signature database, heuristic APK analyzer, YARA-like engine, quarantine manager, and real-time monitor.
6. `:intelligence` — Threat cache (`UnifiedUrlThreatCache`), feed parsers (OpenPhish, PhishTank, UrlHaus), IoC extractor, and Suricata rule parser.
7. `:feature:home` — Dashboard, quick protection controls, security news feed, scam recovery guides, and tools hub.
8. `:feature:shield` — Dedicated inspection screens: Photo Forensics, Video Scanner, Message Shield, Safe Browser, Scam Number Lookup, Metadata Stripper, Password Checker, QR Scanner.
9. `:feature:alerts` — Threat alert timeline, alert detail view, and resolution workflow.
10. `:feature:vault` — Forensic incident vault, encrypted notes UI, secure file vault UI, and JSON/CSV export actions.
11. `:feature:callprotection` — Telecom call screening UI, blocked numbers management, and speakerphone security mode.
12. `:feature:diagnostics` — System diagnostics: App Auditor, Wi-Fi Scanner, Network Socket Monitor, Permission Timeline, Clipboard Monitor.
13. `:feature:analytics` — Security scoring, privacy posture metrics, identity risk overview, and digital footprint inspection.
14. `:feature:settings` — Application configuration, Tor proxy settings, quiet hours, and detection sensitivity thresholds.
15. `:feature:education` — Interactive scam quizzes, daily challenges, and educational threat articles.
16. `:feature:onboarding` — Multi-step onboarding workflow, permission primer, and category personalization.

---

## 2. Comprehensive Component Audit Table

| Component | Source File Path | Purpose | Key Dependencies | Implementation Status |
|---|---|---|---|---|
| **DeepfakeShieldApplication** | `app/.../DeepfakeShieldApplication.kt` | Application lifecycle, notification channel creation, WorkManager initialization | `android.app.Application`, `Hilt`, `WorkManager` | **Implemented** |
| **MainActivity** | `app/.../MainActivity.kt` | Single-activity host for Compose navigation, intent handling for shared video/text/APK | `ComponentActivity`, `Navigation Compose`, `Hilt` | **Implemented** |
| **CallScreeningService** | `app/.../service/CallScreeningService.kt` | Intercepts incoming telecom calls, queries local reputation, rejects/silences high-risk calls | `android.telecom.CallScreeningService`, `RiskIntelligenceEngine`, `PhoneReputationRepository` | **Implemented** |
| **DeepfakeNotificationListenerService** | `app/.../service/NotificationListenerService.kt` | Background notification reader for threat detection with brand whitelisting | `NotificationListenerService`, `RiskIntelligenceEngine`, `AlertRepository` | **Implemented** (Restricted: ignores whitelisted chat apps) |
| **DeepfakeAccessibilityService** | `app/.../service/DeepfakeAccessibilityService.kt` | Accessibility event observer for SMS apps (`com.android.mms`, Google/Samsung messaging) | `AccessibilityService`, `RiskIntelligenceEngine`, `AlertRepository` | **Implemented** (Restricted: SMS packages only) |
| **ScreenCaptureService** | `app/.../service/ScreenCaptureService.kt` | Real-time screen frame capture using MediaProjection for live video deepfake triage | `MediaProjection`, `VirtualDisplay`, `ImageReader`, `DeepfakeMLEngine` | **Implemented** |
| **TorVpnService** | `app/.../service/TorVpnService.kt` | Establishes local TUN interface routing outbound TCP traffic to embedded Tor SOCKS5 proxy | `android.net.VpnService`, `TorNetworkModule`, `info.guardianproject:tor-android` | **Implemented** |
| **EmbeddedTorService** | `app/.../service/EmbeddedTorService.kt` | Manages background Tor binary daemon process, socks port binding (9050/auto) | `info.guardianproject:tor-android`, `info.guardianproject:jtorctl` | **Implemented** |
| **AntivirusForegroundService** | `app/.../service/AntivirusForegroundService.kt` | Persistent foreground service executing scheduled and real-time storage scans | `Service`, `AntivirusEngine`, `NotificationManager` | **Implemented** |
| **FloatingBubbleService** | `app/.../service/FloatingBubbleService.kt` | System alert overlay bubble indicating real-time protection and threat counter | `SYSTEM_ALERT_WINDOW`, `WindowManager`, Compose UI | **Implemented** |
| **SmsReceiver** | `app/.../receiver/SmsReceiver.kt` | BroadcastReceiver for `Telephony.Sms.Intents.SMS_RECEIVED_ACTION` triggering local analysis | `BroadcastReceiver`, `RiskIntelligenceEngine`, `AlertRepository` | **Implemented** |
| **PackageInstallReceiver** | `app/.../receiver/PackageInstallReceiver.kt` | Receives `PACKAGE_ADDED` broadcasts to automatically scan newly installed APKs | `BroadcastReceiver`, `WorkManager`, `InstallScanWorker` | **Implemented** |
| **RiskIntelligenceEngine** | `core/.../engine/RiskIntelligenceEngine.kt` | Rule-based scoring engine for text, smishing, URLs, phone numbers, and video indicators | Pure Kotlin, regex patterns, keyword weighting | **Implemented** |
| **UrlSafetyEngine** | `core/.../engine/UrlSafetyEngine.kt` | Lexical heuristic analyzer checking TLDs, IP hosts, brand typosquatting, subdomains | Pure Kotlin, regex, domain matching | **Implemented** |
| **DeepfakeMLEngine** | `ml/.../engine/DeepfakeMLEngine.kt` | Multi-stage vision pipeline combining ML Kit Face Detection, 468pt Face Mesh, and heuristics | `MLKitFaceAnalyzer`, `FaceMeshDeepfakeAnalyzer`, `TemporalFaceTracker` | **Implemented** |
| **MLKitFaceAnalyzer** | `ml/.../face/MLKitFaceAnalyzer.kt` | Neural network face bounding box and 133-landmark facial feature extraction | `com.google.mlkit:face-detection` | **Implemented** |
| **FaceMeshDeepfakeAnalyzer** | `ml/.../face/FaceMeshDeepfakeAnalyzer.kt` | 468-point 3D face mesh topology and geometric symmetry validator | `com.google.mlkit:face-mesh-detection` | **Implemented** |
| **TemporalFaceTracker** | `ml/.../face/TemporalFaceTracker.kt` | Multi-frame blink rate, landmark jitter, and head pose consistency evaluator | Pure Kotlin, circular frame history | **Implemented** |
| **ImageForensicsEngine** | `ml/.../engine/ImageForensicsEngine.kt` | Deterministic pixel analysis: Error Level Analysis (ELA), copy-move block hashing, edge contrast | Pure Kotlin, `android.graphics.Bitmap`, `Color` | **Implemented** |
| **GovernmentGradeDeepfakeDetector** | `ml/.../deepfake/GovernmentGradeDeepfakeDetector.kt` | Ensemble loader for TFLite vision models (`EfficientNet-B4`, `XceptionNet`, `CNNDetection`) | `org.tensorflow:tensorflow-lite`, ML Kit, pixel heuristics | **Partially Implemented** (Falls back to heuristics; hardcoded tags) |
| **GovernmentGradeAudioDetector** | `ml/.../audio/GovernmentGradeAudioDetector.kt` | Audio scam & deepfake loader (`Wav2Vec2`, `RawNet2`, `AASIST`, `X-Vector`, `Emotion`) | `org.tensorflow:tensorflow-lite`, zero-crossing rate heuristics | **Partially Implemented** (Heuristic fallback primary; hardcoded labels) |
| **GovernmentGradeTextDetector** | `ml/.../text/GovernmentGradeTextDetector.kt` | NLP scam & phishing classifier (`DistilBERT`, `RoBERTa`, `XLM-RoBERTa`, `GPTDetector`) | `org.tensorflow:tensorflow-lite`, `vocab.txt`, keyword heuristics | **Partially Implemented** (Vocabulary fallback; regex-dominant) |
| **AntivirusEngine** | `av/.../engine/AntivirusEngine.kt` | High-level AV orchestrator: hash matching, byte patterns, heuristic APK checks, YARA | `MalwareSignatureDatabase`, `HeuristicMalwareAnalyzer`, `YaraRuleEngine` | **Implemented** |
| **MalwareSignatureDatabase** | `av/.../engine/MalwareSignatureDatabase.kt` | Loads `malware_hashes.txt` (SHA-256) and binary pattern signatures into fast memory lookup | `assets/malware_hashes.txt`, memory sets | **Implemented** |
| **HeuristicMalwareAnalyzer** | `av/.../engine/HeuristicMalwareAnalyzer.kt` | Static file heuristic evaluator: double extensions, tiny APK droppers, high entropy, PUA strings | `java.io.File`, Shannon entropy calculation | **Implemented** |
| **YaraRuleEngine** / **YaraLikeRuleEngine** | `av/.../YaraRuleEngine.kt` & `intelligence/.../YaraLikeRuleEngine.kt` | In-process pure Kotlin pattern matcher for hex sequences and strings without native YARA C library | Pure Kotlin byte matching | **Implemented** |
| **QuarantineManager** | `av/.../engine/QuarantineManager.kt` | Isolates malicious files into encrypted/XOR-obfuscated local app-private sandbox | Pure Kotlin XOR cipher, private app storage | **Implemented** |
| **RootDetector** | `av/.../engine/RootDetector.kt` | Detects root binaries (`su`, `busybox`, `magisk`), test-keys build tags, and writable `/system` | `java.io.File`, `Runtime.getRuntime().exec` | **Implemented** |
| **CloudHashChecker** | `av/.../engine/CloudHashChecker.kt` | Stub for remote cloud hash lookup; hardcoded to return offline/null | None (Self-contained) | **Disabled by Design** (Always returns false/null) |
| **UnifiedUrlThreatCache** | `intelligence/.../UnifiedUrlThreatCache.kt` | Local SQLite/file cache aggregating online threat feeds (PhishTank, OpenPhish, UrlHaus) | `PhishTankFeed`, `OpenPhishFeed`, `UrlHausFeed`, `File` | **Implemented** |
| **SuricataRuleEngine** | `intelligence/.../SuricataRuleEngine.kt` | Lightweight in-process string/payload rule evaluator simulating Suricata signatures | Pure Kotlin payload search | **Implemented** |
| **DeepfakeShieldDatabase** | `data/.../database/DeepfakeShieldDatabase.kt` | Room Database (version 3) managing 16 relational entities, schemas, and indices | `androidx.room:room-runtime`, SQLite | **Implemented** |
| **AlertDao** & **AlertRepository** | `data/.../dao/Daos.kt` & `repository/AlertRepository.kt` | Data Access Object & Repository for persistent threat alerts | Room, Coroutines `Flow` | **Implemented** |
| **VaultDao** & **VaultRepository** | `data/.../dao/Daos.kt` & `repository/VaultRepository.kt` | Data Access Object & Repository for long-term incident evidence entries | Room, Coroutines `Flow` | **Implemented** |
| **AuditLogDao** & **AuditLogRepository** | `data/.../dao/EnhancedDaos.kt` & `repository/AuditLogRepository.kt` | Data Access Object & Repository for immutable security action audit logs | Room, Coroutines `Flow` | **Implemented** |
| **UserPreferences** | `data/.../preferences/UserPreferences.kt` | Jetpack DataStore preferences storing protection toggle states and configuration | `androidx.datastore:datastore-preferences` | **Implemented** |
| **ExportManager** | `feature/export/.../ExportManager.kt` | Serializes stored alerts and findings to CSV and formatted JSON files with sharing Intent | `FileProvider`, Coroutines `Dispatchers.IO` | **Implemented** |
| **PhotoForensicsScreen** | `feature/shield/.../PhotoForensicsScreen.kt` | UI & execution engine for EXIF inspection, camera settings verification, and image tampering | Compose UI, `android.media.ExifInterface`, Bitmap math | **Implemented** |
| **MetadataStripperScreen** | `feature/shield/.../MetadataStripperScreen.kt` | UI for inspecting privacy-sensitive EXIF tags with risk classifications and stripping tips | Compose UI, `androidx.exifinterface` | **Partially Implemented** (Inspects EXIF; does not scrub files) |
| **AppAuditorScreen** | `feature/diagnostics/.../AppAuditorScreen.kt` | Static auditor for installed packages: 25 permissions, 21 tracker SDKs, cleartext traffic, SHA-256 | Compose UI, `PackageManager`, `TrafficStats` | **Implemented** |
| **NetworkMonitorScreen** | `feature/diagnostics/.../NetworkMonitorScreen.kt` | Inspects `/proc/net/tcp`, maps IP prefixes to organizations (Google, Meta), bandwidth tracking | Compose UI, `/proc/net/tcp`, `TrafficStats` | **Implemented** (Restricted on Android 10+ non-root) |
| **WifiScannerScreen** | `feature/diagnostics/.../WifiScannerScreen.kt` | Scans Wi-Fi encryption (WPA2/WPA3), gateway open ports, latency, and speed benchmarking | Compose UI, `WifiManager`, `Socket`, HTTP connections | **Implemented** |
| **VaultScreen** & **VaultViewModel** | `feature/vault/.../VaultScreen.kt` & `VaultViewModel.kt` | Persistent incident findings browser with search, severity filtering, and JSON export | Compose UI, `VaultRepository` | **Implemented** |
| **SecureNotesScreen** | `feature/vault/.../SecureNotesScreen.kt` | UI for taking personal encrypted notes; stored in memory state | Compose UI, `rememberSaveable` | **UI Only** (Stores notes in memory; not persistent in DB) |
| **SecureFileVaultScreen** | `feature/vault/.../SecureFileVaultScreen.kt` | UI for importing private files; takes persistable URI permissions in memory | Compose UI, `remember` | **UI Only** (Stores file handles in memory; not persistent in DB) |
| **CommunityThreatNetwork** | `core/.../intelligence/CommunityThreatNetwork.kt` | In-memory thread-safe cache simulating community threat reporting and statistics | `ConcurrentHashMap` | **Partially Implemented** (In-memory mock; no network backend) |
| **QuantumSafeEncryption** | `core/.../intelligence/QuantumSafeEncryption.kt` | AES-256-GCM authenticated cipher with PBKDF2 key derivation (mislabeled quantum-safe) | `javax.crypto.Cipher`, `GCMParameterSpec` | **Implemented** (Standard AES-256-GCM; not post-quantum) |

---

## 3. Android Permissions Analysis

The application requests 23 distinct Android permissions in `app/src/main/AndroidManifest.xml`. Every permission and its architectural necessity has been audited below:

### 3.1 Network & Connectivity Permissions
1. `android.permission.INTERNET`: Used for optional threat feed updates (OpenPhish, PhishTank, UrlHaus), embedded Tor consensus routing, Wi-Fi speed benchmarking, and security RSS feeds.
2. `android.permission.ACCESS_NETWORK_STATE`: Queries active connection transport (Wi-Fi, Cellular, VPN) via `ConnectivityManager`.
3. `android.permission.ACCESS_WIFI_STATE`: Inspects Wi-Fi connection metadata (SSID, BSSID, RSSI, link speed) in `WifiScannerScreen`.
4. `android.permission.CHANGE_WIFI_STATE`: Declared for Wi-Fi management operations.
5. `android.permission.ACCESS_FINE_LOCATION`: Required by Android OS to read Wi-Fi scan results and SSIDs on Android 9+ (API 28+).
6. `android.permission.ACCESS_COARSE_LOCATION`: Fallback location permission for network-derived positioning and Wi-Fi diagnostics.

### 3.2 System Protection & Biometrics
7. `android.permission.VIBRATE`: Provides haptic feedback cues upon security actions and threat detections.
8. `android.permission.USE_BIOMETRIC`: Enforces biometric authentication (fingerprint/face) for unlocking the forensic vault.
9. `android.permission.POST_NOTIFICATIONS`: Android 13+ (API 33+) runtime permission to display high-priority threat warnings and foreground service alerts.
10. `android.permission.RECEIVE_BOOT_COMPLETED`: Resumes background protection foreground services and WorkManager workers following device reboots.
11. `android.permission.REQUEST_IGNORE_BATTERY_OPTIMIZATIONS`: Prompts user to exempt Sentinel Forensics from Doze mode to maintain continuous background protection.
12. `android.permission.SYSTEM_ALERT_WINDOW`: Renders the draggable `FloatingBubbleService` and in-call threat warning overlays.

### 3.3 Telecom & Messaging Permissions
13. `android.permission.RECEIVE_SMS`: Enables `SmsReceiver` to capture incoming broadcast SMS payloads for real-time smishing analysis.
14. `android.permission.READ_SMS`: Allows on-demand scanning of SMS history when explicitly requested by the user.
15. `android.permission.READ_PHONE_STATE`: Reads telephony state (incoming call status, carrier information).
16. `android.permission.READ_CALL_LOG`: Enables historical call log analysis and scam pattern identification.
17. `android.permission.ANSWER_PHONE_CALLS`: Declared in manifest; unused in core call screening logic.
18. `android.permission.RECORD_AUDIO`: Declared for potential in-call voice scam analysis; heavily restricted on modern Android.

### 3.4 File & Storage Permissions
19. `android.permission.READ_EXTERNAL_STORAGE` (maxSdkVersion 32): Legacy storage access for Android 12 and below.
20. `android.permission.WRITE_EXTERNAL_STORAGE` (maxSdkVersion 29): Legacy storage write access.
21. `android.permission.MANAGE_EXTERNAL_STORAGE`: All Files Access permission for full-disk antivirus scanning on Android 11+ (API 30+).
22. `android.permission.READ_MEDIA_IMAGES`, `READ_MEDIA_VIDEO`, `READ_MEDIA_AUDIO`: Android 13+ granular media access permissions for media forensics.
23. `android.permission.QUERY_ALL_PACKAGES`: Allows `AppAuditorScreen` and `AntivirusEngine` to enumerate all installed packages and inspect their manifest metadata.

### 3.5 Foreground Service Types
Declared foreground service permissions include: `FOREGROUND_SERVICE`, `FOREGROUND_SERVICE_MEDIA_PROJECTION`, `FOREGROUND_SERVICE_MICROPHONE`, `FOREGROUND_SERVICE_PHONE_CALL`, `FOREGROUND_SERVICE_SPECIAL_USE`, `FOREGROUND_SERVICE_DATA_SYNC`.

---

## 4. Unused Permissions, Placeholders, Mocks & Misconceptions

During the source code audit, several critical discrepancies between marketing comments, UI labels, and actual implementation were identified:

1. **Unused / Restricted Permissions:**
   - `RECORD_AUDIO`: While requested, modern Android versions (API 29+) enforce strict privacy restrictions prohibiting background apps or third-party call screeners from recording telephony audio.
   - `ANSWER_PHONE_CALLS`: Declared in `AndroidManifest.xml` but never invoked in `CallScreeningService` (the screening service uses `CallResponse.Builder` instead).
2. **Hardcoded Metadata & Placeholders:**
   - **`CommunityThreatNetwork.kt`:** Claims to be a decentralized threat-sharing network, but `knownThreats` is an in-memory `ConcurrentHashMap`. In `getNetworkStats()`, `totalUsers = 1000` is hardcoded with the comment `// Would come from backend`.
   - **`CloudHashChecker.kt`:** Explicitly hardcoded to disable cloud lookups: `fun isCloudAvailable(): Boolean = false` and `checkHash(...) = null`.
   - **`GovernmentGradeDeepfakeDetector.kt`:** Comments state *"Achieves 99.2% accuracy on FaceForensics++ benchmark; Meets NIST standards for biometric security"*. The code contains hardcoded strings: `certificationLevel = "NIST-COMPLIANT"`, model versions `"EfficientNet-B4" to "v2.1-government"`, and certifications `"NIST-SP-800-63B", "ISO/IEC 30107-3", "FIDO2-Level3"`. These are decorative metadata strings, not official laboratory certifications.
   - **Evidence Chain Hashes:** In `generateEvidenceChain(...)`, evidence hashes are generated via `SHA-256("$model-$score-${System.currentTimeMillis()}")`. They do not represent cryptographic digital signatures or Android Keystore hardware-backed attestation keys.
3. **Mislabeled Cryptography ("Quantum-Safe"):**
   - **`QuantumSafeEncryption.kt`:** Documented in code comments as a *"QUANTUM-RESISTANT ENCRYPTION ENGINE"*. Inspection of the code reveals standard `AES-256-GCM` with a 12-byte nonce and `PBKDF2WithHmacSHA256` key derivation. While AES-256 provides 128-bit security against Grover's algorithm, no post-quantum asymmetric algorithms (e.g., CRYSTALS-Kyber, ML-KEM, Dilithium) are implemented.
4. **UI-Only State Storage:**
   - **`SecureNotesScreen.kt`:** Subtitle advertises *"AES-256 encrypted • Protected by your screen lock"*, but notes are stored in Compose transient UI state (`rememberSaveable { mutableStateOf(emptyList<SecureNote>()) }`). They are neither encrypted with Android Keystore nor persisted to Room.
   - **`SecureFileVaultScreen.kt`:** Files added are held in an in-memory list (`remember { mutableStateOf<List<VaultFile>>(emptyList()) }`) and disappear on activity recreation.
5. **Inspector vs. Scrubber Discrepancy:**
   - **`MetadataStripperScreen.kt`:** Titled "Metadata Stripper", but the code only reads EXIF tags via `androidx.exifinterface` and presents them with educational tips on how to strip metadata using external tools. It does not write stripped images.
