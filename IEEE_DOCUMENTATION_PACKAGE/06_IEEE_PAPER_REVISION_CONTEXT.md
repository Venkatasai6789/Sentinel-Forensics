# Sentinel Forensics — IEEE Paper Revision Context & Authoritative Guide

## Purpose of this Document

This document provides the verified technical baseline, structural mapping, and scientific boundary constraints required for an AI language model (such as Claude) to revise the existing IEEE conference paper (*"Corroboration-Weighted Correlation of Forensic Engines, Threat Intelligence, and Local Models for Anti-Forensic Detection"*).

The existing draft manuscript describes a **server-oriented, distributed architecture** featuring Redis job queues, multi-lane worker pools, external threat intelligence SaaS microservices, and a 50,000-sample Monte Carlo mathematical simulation. **None of these exist in the actual Android codebase.**

This guide realigns the manuscript with the **real Android software artifact**—an offline-first, on-device mobile cyber-forensic analysis and threat triage suite.

---

## A. Verified Research Scope

### Core Research Contribution Actually Supported by the Codebase:
> **An autonomous, privacy-preserving, edge-native Android framework that coordinates hybrid neural-network inference (TensorFlow Lite, Google ML Kit Face Mesh) and deterministic heuristics to conduct multi-modal cyber-forensic analysis and threat triage on-device, operating fully within Android platform sandboxing constraints without cloud telemetry.**

### Key Real Contributions to Emphasize:
1. **Edge Multi-Modality:** Demonstrating that mobile devices can execute parallel triage across text (smishing), URLs (phishing), telephony (vishing), binary files (malware signatures/PUAs), and multimedia (face mesh deepfake analysis & ELA) locally.
2. **Hybrid ML-Heuristic Defense:** Implementing a defensive architecture where deterministic heuristics provide robust baselines while on-device neural networks provide granular feature representations.
3. **Android Platform Navigation:** Navigating modern Android permissions, foreground services, Telecom call screening, notification listeners, and MediaProjection screen capture to provide proactive defense without breaking the Android sandbox.
4. **Privacy-Preserving Forensics:** Zero external exfiltration of user communications, local SQLite evidence indexing, and embedded Tor network traffic anonymization.

---

## B. Recommended Paper Title

### Suggested Academic Title:
> **Sentinel Forensics: An Offline-First Android Framework for Mobile Threat Detection and Digital Evidence Analysis**

*Alternative Academic Variants:*
- *On-Device Multi-Modal Threat Detection and Forensic Triage for Android: An Offline-First Architecture*
- *Privacy-Preserving Mobile Cyber-Forensics: On-Device Threat Detection via Hybrid Neural-Heuristic Pipelines on Android*

---

## C. Section-by-Section Content Mapping

### Section I: Introduction
- **Verified Implementation Facts:** Mobile devices are targeted by multi-modal vectors (smishing, vishing, deepfake media, malicious APKs). Commercial tools offload user data to cloud servers. Sentinel Forensics is implemented as an on-device Android suite with 16 modules, running fully offline by default.
- **Available Experimental Evidence:** 37 passing unit tests verifying text scam parsing, URL lexical scoring, and onboarding rules. Tested on Android 14 (API 34) compilation target.
- **Proposed Research Framing:** Position the work as addressing the tension between mobile cyber-threat proliferation and user privacy. Frame on-device local triage as an urgent alternative to privacy-invasive cloud security solutions.
- **Unverified Claims to EXCLUDE:** Do not claim that Sentinel Forensics is a distributed cloud-assisted investigation workspace or that it correlates enterprise forensic server logs.

---

### Section II: Background and Related Work
- **Verified Implementation Facts:** Traditional mobile forensics relies on physical acquisition (FTK, Autopsy, Cellebrite) post-incident. Real-time mobile antivirus apps rely on cloud hash registries.
- **Available Experimental Evidence:** Literature-based positioning of on-device ML runtimes (TFLite, ML Kit).
- **Proposed Research Framing:** Review three domains: (1) Mobile malware and smishing detection, (2) Deepfake and synthetic media detection on edge devices, and (3) Android security architecture (sandboxing, permission models, scoped storage).
- **Unverified Claims to EXCLUDE:** Do not cite server SIEM platforms or cloud-hosted sandboxes (Cuckoo, Any.Run) as part of the tool's execution pipeline.

---

### Section III: System Architecture
- **Verified Implementation Facts:** Multi-module Android architecture (Clean Architecture, MVVM, Jetpack Compose, Room SQLite, Hilt DI). Ingestion channels: user document picker, `SmsReceiver`, `CallScreeningService`, `ScreenCaptureService`, and `NotificationListenerService`.
- **Available Experimental Evidence:** Codebase modular topology in `settings.gradle.kts`; Room Database schema version 3 with 16 entities.
- **Proposed Research Framing:** Describe the on-device component hierarchy, asynchronous Coroutine dispatching, and local data persistence pipeline.
- **Unverified Claims to EXCLUDE:** **Delete all references to Redis queues, worker clusters, API gateways, external threat intelligence microservices, and server-side relational databases.**

---

### Section IV: Threat Detection & Forensic Analysis Methods
- **Verified Implementation Facts:**
  - *Text & SMS:* Heuristic regex weights detecting OTP theft, payment pressure, RAT apps, and impersonation.
  - *Phishing URLs:* Lexical domain parsing (punycode, brand lookalikes, suspicious TLDs, IP hosts, subdomain depth).
  - *Media Forensics:* Google ML Kit 468-point 3D Face Mesh, 133 contour landmarks, temporal blink/jitter tracking, and Error Level Analysis (ELA).
  - *Antivirus:* 54k SHA-256 hash matching (`malware_hashes.txt`), 38 high-specificity byte patterns, Shannon entropy, and in-process YARA-like rule matching.
- **Available Experimental Evidence:** Code implementation in `RiskIntelligenceEngine.kt`, `UrlSafetyEngine.kt`, `DeepfakeMLEngine.kt`, `ImageForensicsEngine.kt`, and `AntivirusEngine.kt`.
- **Proposed Research Framing:** Present the formal mathematical rules behind the heuristics (e.g., Shannon entropy formula, ELA gradient variance, spatial block hashing).
- **Unverified Claims to EXCLUDE:** **Do not state that models achieve 99.2% accuracy on FaceForensics++ or 99.5% on ASVspoof as measured application results.** Clarify that TFLite models are integrated with heuristic fallbacks.

---

### Section V: Evidence Management & Risk Assessment
- **Verified Implementation Facts:** Findings stored in Room `alerts` and `vault_entries` tables. Immutable event logging in `audit_log` with SHA-256 hashes. Export to CSV and formatted JSON via Android `FileProvider`. Biometric vault locking via `BiometricPrompt`.
- **Available Experimental Evidence:** Room schema JSONs (v1, v2, v3); `ExportManager.kt` serialization implementation.
- **Proposed Research Framing:** Describe the local chain of custody and data handling safeguards ensuring forensic integrity within an offline device environment.
- **Unverified Claims to EXCLUDE:** **The 5-family corroboration-weighted noisy-OR correlation model ($m^+_f, m^-_f, S, R, C, \gamma$) is NOT implemented in the Android code.** If discussed, it must be framed strictly as a **"Proposed Theoretical Correlation Model for Future Multi-Source Integration"**, while clearly stating that the current Android client employs deterministic additive scoring and heuristic-dominant ensemble bounding.

---

### Section VI: Android Implementation & Platform Navigation
- **Verified Implementation Facts:** Developed in Kotlin 1.9.22, targeting API 34, minSdk 26. Uses `CallScreeningService` for robocall rejection, `NotificationListenerService` for notification triage, `MediaProjection` for screen capture deepfake analysis, and embedded Guardian Project `libtor.so` with `VpnService` for network anonymization.
- **Available Experimental Evidence:** Complete Android manifest, foreground service declarations, and Gradle dependency tree.
- **Proposed Research Framing:** A major technical contribution: documenting the exact engineering solutions required to navigate Android sandboxing, background execution limits, and scoped storage policies.
- **Unverified Claims to EXCLUDE:** Do not claim that Sentinel Forensics monitors all third-party encrypted messaging apps (WhatsApp, Telegram) internally; explain the specific whitelist exclusions and Android accessibility boundaries.

---

### Section VII: Experimental Evaluation
- **Verified Implementation Facts:** 37 passing unit tests across core risk rules, URL heuristics, and personalization state engines. Fast JVM execution times ($\le 1$ ms for URL checks; ~8 ms mean for text risk scoring). Debug APK compiles at 423 MB.
- **Available Experimental Evidence:** Unit test XML reports in `core/build/test-results/` and `feature/onboarding/build/test-results/`.
- **Proposed Research Framing:** Frame this section as a **Functional Validation and Computational Latency Feasibility Study** on Android runtime primitives.
- **Unverified Claims to EXCLUDE:** **Completely delete the 50,000-sample Monte Carlo ablation table and synthetic F1=0.91 claim.** Explicitly state that extensive benchmark evaluation on labeled public corpora (FaceForensics++, PhishTank test splits) remains future work.

---

### Section VIII: Limitations & Future Work
- **Verified Implementation Facts:**
  1. Sandboxed isolation prevents reading third-party app databases directly.
  2. Background execution is constrained by Android OEM battery optimization.
  3. Static APK analysis cannot observe runtime polymorphic behavior.
  4. Large bundled assets (TFLite models + hash database) result in a substantial APK footprint (~423 MB).
  5. Standalone `:data` unit testing requires migrating Room annotation processing from KAPT to KSP.
- **Proposed Research Framing:** Outline an empirical validation protocol on public benchmark corpora, automated model quantization (INT8 pruning) to reduce APK footprint, and formal hardware keystore digital signature binding.

---

### Section IX: Conclusion
- **Verified Implementation Facts:** Sentinel Forensics proves the viability of a zero-cloud, privacy-preserving mobile forensic triage and threat detection framework on modern Android devices.
- **Proposed Research Framing:** Summarize the architectural feasibility and call for standardized mobile on-device forensic evaluation benchmarks.

---

## D. Figures and Tables Replacement Strategy

| Manuscript Item | Original Paper Representation (Server/Simulated) | Mandatory Replacement Strategy for Revised Paper |
|---|---|---|
| **Fig. 1** | Server pipeline: Web Gateway $\to$ Redis Queue $\to$ 3 Worker Lanes $\to$ Relational Store | Replace with **On-Device Android Clean Architecture Diagram**: OS Ingestion (CallScreening, SMS, MediaProjection) $\to$ Parallel Local Engines (Heuristics, ML Kit, TFLite, Signatures) $\to$ Room SQLite Database $\to$ Compose UI. |
| **Table I** | Positioning against enterprise SIEMs (VarnAI, Open SIEM) | Position against **Mobile Antivirus & Forensics Tools** (e.g., Lookout, Avast, AndroPyTool, Mobile Verification Toolkit / MVT), contrasting on-device execution, cloud reliance, and privacy impact. |
| **Table II** | Catalogue of anti-forensic behaviors and observation mappings | Retain or refine to map **Mobile Threat Vectors** (Smishing, Lookalike URLs, Deepfake Video, Dropper APKs) to implemented Android detection components and heuristic rules. |
| **Table III & Fig. 2** | Six deterministic scenarios (S1–S6) with synthetic scores and coverage $\gamma$ | Replace with **Functional Verification Matrix**: Real test case descriptions, inputs, expected outcomes, and actual pass/fail results from verified unit tests. |
| **Table IV & Table V** | Monte Carlo error rate assumptions & 50,000-item ablation results | **DELETE ENTIRELY.** Replace with **On-Device Execution Latency & Asset Profile Table** (Asset sizes: 13 TFLite models, 54k malware hashes, unit test execution latencies). |
| **Fig. 3 & Table VI** | Monte Carlo F1 outage curves & $q_{clean}$ sensitivity sweep | **DELETE ENTIRELY.** Replace with a **Comparative Architectural Boundary Table** detailing Android permission access vs. platform security restrictions. |

---

## E. Topic Areas Requiring Legitimate Scientific References

When revising the manuscript, cite foundational peer-reviewed literature in the following areas (without fabricating citations or DOIs):

1. **Android Security Architecture & Sandboxing:** Android security model, permission evolution (runtime permissions, scoped storage), and inter-process communication (IPC) isolation.
2. **Mobile Smishing & Social Engineering:** Phishing detection via lexical URL analysis, brand impersonation, and NLP heuristics on mobile devices.
3. **Deepfake & Synthetic Media Detection on Edge Devices:** Facial landmark tracking, 3D face mesh topologies, Error Level Analysis (ELA), and temporal inconsistency detection.
4. **Mobile Malware & Static Analysis:** APK static auditing, manifest inspection, byte pattern scanning, and permission combination risk scoring.
5. **Privacy-Preserving Cyber-Forensics:** K-anonymity protocols, on-device machine learning inference, and network anonymization via Tor.

---

## F. Unverified Information & Missing Evaluation Checklist

Before submitting a finalized revision to an IEEE conference, the authors must address the following missing items:

- [ ] **Empirical Benchmark Corpus:** Evaluate the app against a public labeled dataset (e.g., FaceForensics++ video subset, PhishTank URL sample set, Drebin/CIC-MalAnal malware sample set).
- [ ] **Physical Hardware Benchmarking:** Measure real CPU utilization, memory footprint (RAM), battery discharge rate (mAh), and inference latency (ms) on physical Android devices (e.g., Google Pixel, Samsung Galaxy).
- [ ] **KSP Migration:** Migrate Room compiler dependencies in `data/build.gradle.kts` from legacy KAPT to KSP to enable complete automated test suite execution across all modules.
- [ ] **Hardware Attestation:** Implement Android Keystore hardware-backed cryptographic signing for forensic export reports to establish true legal chain-of-custody admissibility.
