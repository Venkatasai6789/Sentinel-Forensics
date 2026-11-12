# Sentinel Forensics — Verified Test & Evaluation Results

## 1. Test Environment Specification

The test results, build configurations, and test logs documented in this report were verified directly from the project build artifacts, XML test reports, and execution logs in `C:\Users\pvenk\Downloads\Sentinal Forensic`.

- **Device / Host Machine:** Windows Host (Hostname from test reports: `HEMANTH` / Current Build Host)
- **Host OS:** Windows 11 (Version 10.0, amd64)
- **Target Android Version:** Android 14 (UpsideDownCake)
- **Target API Level:** `34` (Compile SDK: `34`, Min SDK: `26`, Target SDK: `34`)
- **Java Runtime Environment (JVM):** OpenJDK 17.0.20.1 (Eclipse Adoptium `17.0.20.1+1`)
- **Android Gradle Plugin (AGP):** `8.2.2`
- **Gradle Build Tool:** `8.5`
- **App Version:** `1.0.0` (Version Code: `1`)
- **Build Variant Tested:** `debug` (`assembleDebug`, `testDebugUnitTest`)
- **Verified Test Execution Dates:** October 27, 2026 & October 28, 2026
- **Test Frameworks:** JUnit 4 (`junit:4.13.2`), Kotlinx Coroutines Test (`1.7.3`), Robolectric (`org.robolectric:robolectric`, SDK target 28)

---

## 2. Dataset Information

A thorough recursive search of the repository for benchmark corpora (`.csv`, `.json`, `.parquet`, `.tsv`, `.txt`) confirms that **no external empirical evaluation datasets or ground-truth testing corpora are bundled in the repository**.

| Module | Dataset Name | Total Samples | Positive Samples | Negative Samples | Source | Status / Description |
|---|---|---:|---:|---:|---|---|
| **Malware Scanner** | Bundled Malware Hash Asset | ~54,000 | 54,000 | 0 | `scripts/fetch_malware_hashes.py` (OSINT DigitalSide Threat-Intel) | Signature asset (`malware_hashes.txt`, 3.58 MB); not a balanced benchmark |
| **Phishing URL** | Local URL Threat Cache | Variable | Variable | 0 | Public Feeds (OpenPhish, PhishTank, URLhaus) | Ephemeral runtime threat feed cache; no static evaluation test set present |
| **Deepfake Video** | FaceForensics++ Benchmark | 0 | 0 | 0 | Cited in code comments | **NOT PRESENT** in repository (No video dataset bundled) |
| **Audio Deepfake** | ASVspoof / In-the-Wild Audio | 0 | 0 | 0 | Cited in code comments | **NOT PRESENT** in repository (No audio dataset bundled) |
| **Scam Call** | Telephony Scam Call Log | 0 | 0 | 0 | Local SQLite (`phone_reputation`) | User-generated local database; no public benchmark corpus |
| **Synthetic Simulation** | Monte Carlo Synthetic Dataset | 50,000 | 15,000 | 35,000 | Manuscript simulation script | **NOT PRESENT** in Android repo (Simulated mathematical scenario) |

> [!IMPORTANT]
> **Clarification Regarding Paper Claims vs. Codebase Reality:**
> The original draft paper reports a Monte Carlo ablation over 50,000 simulated evidence items achieving an F1-score of 0.91. This was a purely synthetic mathematical simulation modeling source error rates in an abstract queueing model; **no such 50,000-sample dataset, simulation script, or empirical test run exists in this Android repository**. Furthermore, marketing comments in the code claiming "99.2% accuracy on FaceForensics++" or "99.1% on DistilBERT" are theoretical figures from external research literature and must not be presented as measured performance of this Android application.

---

## 3. Detection Performance (Confusion Matrix)

In accordance with strict scientific auditing standards, precision, recall, and F1-scores are calculated **only** when empirical, verified ground-truth confusion matrix data is available.

| Module | True Positives (TP) | False Positives (FP) | True Negatives (TN) | False Negatives (FN) | Precision | Recall | F1-Score |
|---|---:|---:|---:|---:|---|---|---|
| **SMS Scam Detection** | **NOT MEASURED** | **NOT MEASURED** | **NOT MEASURED** | **NOT MEASURED** | **NOT MEASURED** | **NOT MEASURED** | **NOT MEASURED** |
| **Phishing URL Detection** | **NOT MEASURED** | **NOT MEASURED** | **NOT MEASURED** | **NOT MEASURED** | **NOT MEASURED** | **NOT MEASURED** | **NOT MEASURED** |
| **Call Screening** | **NOT MEASURED** | **NOT MEASURED** | **NOT MEASURED** | **NOT MEASURED** | **NOT MEASURED** | **NOT MEASURED** | **NOT MEASURED** |
| **Image Forensics (ELA/Copy-Move)** | **NOT MEASURED** | **NOT MEASURED** | **NOT MEASURED** | **NOT MEASURED** | **NOT MEASURED** | **NOT MEASURED** | **NOT MEASURED** |
| **Video Deepfake Detection** | **NOT MEASURED** | **NOT MEASURED** | **NOT MEASURED** | **NOT MEASURED** | **NOT MEASURED** | **NOT MEASURED** | **NOT MEASURED** |
| **Malware File Scanner** | **NOT MEASURED** | **NOT MEASURED** | **NOT MEASURED** | **NOT MEASURED** | **NOT MEASURED** | **NOT MEASURED** | **NOT MEASURED** |

*Status Rationale:* No labeled testing corpus is present in the repository to compute true/false positive/negative rates. To invent figures would constitute scientific fabrication.

---

## 4. Runtime & Latency Performance

Verified execution times extracted from unit test XML logs and test suites:

| Module / Test Suite | Samples Tested | Mean Processing Time | Median | P95 | Peak Memory | Measurement Method |
|---|---:|---:|---:|---:|---|---|
| **Risk Intelligence Engine (Text/Call/Video)** | 21 test cases | 8.38 ms / case | 1.00 ms | 40.00 ms | **NOT MEASURED** | JUnit 4 test runner (`core/.../RiskIntelligenceEngineTest.xml`) |
| **URL Safety Lexical Analysis** | 10 test cases | 1.40 ms / case | 1.00 ms | 5.00 ms | **NOT MEASURED** | JUnit 4 test runner (`core/.../UrlSafetyEngineTest.xml`) |
| **Personalization State Engine** | 6 test cases | 13.83 ms / case | 2.50 ms | 70.00 ms | **NOT MEASURED** | JUnit 4 test runner (`feature/onboarding/.../PersonalizationStateTest.xml`) |
| **Deepfake Frame Pipeline (ML Kit + Mesh)** | 0 (Live) | **NOT MEASURED** | **NOT MEASURED** | **NOT MEASURED** | **NOT MEASURED** | No automated benchmark instrumentation in repo |
| **Full Disk Antivirus Scan** | 0 (Live) | **NOT MEASURED** | **NOT MEASURED** | **NOT MEASURED** | **NOT MEASURED** | No automated benchmark instrumentation in repo |

*Note on Unit Test Timing:* In `RiskIntelligenceEngineTest`, the longest recorded individual test was `confidence increases with more indicators` (103 ms, which included engine initialization overhead), followed by `OTP request detected as high risk` (40 ms). Subsequent text and URL evaluations executed in $\le 1$ ms on JVM.

---

## 5. Functional Testing (Verified Unit Test Cases)

A total of 37 unit test cases have verified PASS results documented in the build output XML reports.

### 5.1 RiskIntelligenceEngineTest (`com.deepfakeshield.core.engine`)
*Execution Time: 0.176s across 21 test cases. Failures: 0, Errors: 0.*

| Test ID | Module | Test Description | Expected Result | Actual Result | Status |
|---|---|---|---|---|---|
| **TC-CORE-01** | Text Analysis | `clean text returns low risk` | Risk severity LOW, score < 25 | Severity LOW, score < 25 | **PASS** |
| **TC-CORE-02** | Text Analysis | `OTP request detected as high risk` | Score >= 40, reason contains "OTP" | Flagged OTP reason, score >= 40 | **PASS** |
| **TC-CORE-03** | Text Analysis | `urgency language increases risk score` | Score >= 25, reason contains "Urgent" | Urgency reason added, score >= 25 | **PASS** |
| **TC-CORE-04** | Text Analysis | `impersonation detected when org mentioned from unknown sender` | Reason contains "Impersonation" | Impersonation flag generated | **PASS** |
| **TC-CORE-05** | Text Analysis | `payment pressure detected` | Score >= 40, reason contains "Payment" | Payment coercion flagged | **PASS** |
| **TC-CORE-06** | Text Analysis | `remote access request detected` | Score >= 50, reason contains "Remote" | RAT keyword flagged (AnyDesk) | **PASS** |
| **TC-CORE-07** | Text Analysis | `suspicious link in text detected` | Reason contains URL risk | URL reason generated | **PASS** |
| **TC-CORE-08** | Text Analysis | `multiple red flags produce critical severity` | Severity >= HIGH, >= 3 reasons | Severity HIGH/CRITICAL, >= 3 reasons | **PASS** |
| **TC-CORE-09** | URL Analysis | `safe URL returns low risk` | Risk severity LOW | Severity LOW | **PASS** |
| **TC-CORE-10** | URL Analysis | `lookalike domain detected` | Score >= 30 | Lookalike brand flagged, score >= 30 | **PASS** |
| **TC-CORE-11** | URL Analysis | `suspicious TLD detected` | Reason contains "Domain Extension"/"TLD" | `.tk` extension flagged | **PASS** |
| **TC-CORE-12** | URL Analysis | `punycode URL detected` | Score >= 25 | Punycode `xn--` flagged | **PASS** |
| **TC-CORE-13** | Call Analysis | `domestic number returns low risk` | Score < 50 | Score < 50 | **PASS** |
| **TC-CORE-14** | Call Analysis | `international number flagged` | Reason contains "International" | Flagged international prefix | **PASS** |
| **TC-CORE-15** | Video Analysis | `normal video returns low risk` | Score < 30 | Score < 30 | **PASS** |
| **TC-CORE-16** | Video Analysis | `deepfake indicators produce high risk` | Severity >= HIGH, >= 2 reasons | Severity HIGH, >= 2 reasons | **PASS** |
| **TC-CORE-17** | Video Analysis | `confidence increases with more indicators` | High indicators yield higher confidence | Confidence monotonically higher | **PASS** |
| **TC-CORE-18** | Engine General | `score never exceeds 100` | Score bounded by 100 on multi-threat text | Score <= 100 | **PASS** |
| **TC-CORE-19** | Engine General | `confidence between 0 and 1` | Confidence in range [0.0, 1.0] | Valid float in range | **PASS** |
| **TC-CORE-20** | Engine General | `recommended actions provided for threats` | Recommended actions list non-empty | Actionable steps populated | **PASS** |
| **TC-CORE-21** | Engine General | `explain like im five is not empty` | Plain-language explanation generated | String populated | **PASS** |

### 5.2 UrlSafetyEngineTest (`com.deepfakeshield.core.engine`)
*Execution Time: 0.014s across 10 test cases. Failures: 0, Errors: 0.*

| Test ID | Module | Test Description | Expected Result | Actual Result | Status |
|---|---|---|---|---|---|
| **TC-URL-01** | URL Safety | `HTTPS URL gets lower score than HTTP` | HTTP score >= HTTPS score | Condition verified | **PASS** |
| **TC-URL-02** | URL Safety | `known brand lookalike detected` | Threat type LOOKALIKE flagged | Threat flagged | **PASS** |
| **TC-URL-03** | URL Safety | `suspicious TLD flagged` | Threat type SUSPICIOUS_TLD flagged | Flagged `.tk` | **PASS** |
| **TC-URL-04** | URL Safety | `IP address domain flagged` | Threat type IP_DOMAIN flagged | Flagged `192.168.1.1` host | **PASS** |
| **TC-URL-05** | URL Safety | `URL shortener detected` | Threat type URL_SHORTENER flagged | Flagged `bit.ly` | **PASS** |
| **TC-URL-06** | URL Safety | `safe URL has low risk score` | Risk score < 20 | Score < 20 | **PASS** |
| **TC-URL-07** | URL Safety | `excessive subdomains flagged` | Threat type EXCESSIVE_SUBDOMAINS | Subdomain count flagged | **PASS** |
| **TC-URL-08** | URL Safety | `risk score capped at 100` | Risk score <= 100 | Score bounded | **PASS** |
| **TC-URL-09** | URL Safety | `analysis returns domain info` | Extracted domain matches expected | Domain parsed correctly | **PASS** |
| **TC-URL-10** | URL Safety | `recommendation provided for all results` | Recommendations non-empty | Recommendations present | **PASS** |

### 5.3 PersonalizationStateTest (`com.deepfakeshield.feature.onboarding`)
*Execution Time: 0.083s across 6 test cases. Failures: 0, Errors: 0.*

| Test ID | Module | Test Description | Expected Result | Actual Result | Status |
|---|---|---|---|---|---|
| **TC-ONB-01** | Onboarding UI | `verify exactly eight categories in required order` | 8 distinct security categories | Verified exact ordering | **PASS** |
| **TC-ONB-02** | Onboarding UI | `default UI state has 0 selected, country is IN, cannot continue` | Initial state valid | State matches defaults | **PASS** |
| **TC-ONB-03** | Onboarding UI | `toggle category adds and removes properly` | State updates set properly | Set toggled | **PASS** |
| **TC-ONB-04** | Onboarding UI | `selecting fewer than 3 categories cannot continue` | `canContinue == false` | Continue disabled | **PASS** |
| **TC-ONB-05** | Onboarding UI | `selecting 3 or more categories enables continue` | `canContinue == true` | Continue enabled | **PASS** |
| **TC-ONB-06** | Onboarding UI | `isSaving flag disables continue even with 3 categories` | `canContinue == false` when saving | Continue blocked during save | **PASS** |

---

## 6. Unexecuted Tests & Compilation Diagnostics

During the audit, execution of unit tests in the `:av` and `:data` subprojects was attempted via Gradle:
```powershell
cmd /c "cd /d C:\Users\pvenk\Downloads\Sentinal Forensic && gradlew.bat :av:testDebugUnitTest"
```

### Status: NOT EXECUTED (Compilation Failure in Dependency Module)

#### Root Cause Analysis:
The task `:data:compileDebugJavaWithJavac` failed with 100 compilation errors. When Kotlin Symbol Processing / KAPT generated Java stubs from Room DAO interfaces (`AlertDao_Impl.java`, `ScamPatternDao_Impl.java`, `ThreatPredictionDao_Impl.java`), javac attempted to compile these stubs without having the compiled Kotlin entity classes (`com.deepfakeshield.data.entity.*`) and type converters (`com.deepfakeshield.data.database.Converters`) resolved on javac's compile classpath.

Example compiler errors:
```text
AlertDao_Impl.java:19: error: cannot find symbol: class Converters
AlertDao_Impl.java:20: error: package com.deepfakeshield.data.entity does not exist
AlertDao_Impl.java:40: error: cannot find symbol: class AlertDao
```

#### Remediation Steps Required to Execute:
1. In `data/build.gradle.kts`, ensure Kotlin compilation runs strictly before Java compilation and that KAPT is configured with `kapt { correctErrorTypes = true }`.
2. Migrate Room annotation processing from legacy `kapt` to modern **KSP (Kotlin Symbol Processing)**:
   ```kotlin
   plugins {
       id("com.google.devtools.ksp") version "1.9.22-1.0.17"
   }
   dependencies {
       ksp("androidx.room:room-compiler:2.6.1")
   }
   ```
3. Re-run `./gradlew :data:testDebugUnitTest :av:testDebugUnitTest` once Room annotations are processed via KSP.
