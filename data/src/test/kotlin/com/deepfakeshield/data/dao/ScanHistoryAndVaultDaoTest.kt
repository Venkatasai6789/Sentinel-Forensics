package com.deepfakeshield.data.dao

import android.content.Context
import android.database.sqlite.SQLiteDatabase
import androidx.room.Room
import androidx.test.core.app.ApplicationProvider
import com.deepfakeshield.core.model.*
import com.deepfakeshield.core.security.SoftwareAesGcmVaultCipher
import com.deepfakeshield.data.database.DeepfakeShieldDatabase
import com.deepfakeshield.data.di.DatabaseModule
import com.deepfakeshield.data.repository.PasswordVaultRepository
import com.deepfakeshield.data.repository.ScanHistoryRepository
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.test.runTest
import org.junit.After
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.io.File
import java.util.UUID

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [28])
class ScanHistoryAndVaultDaoTest {

    private lateinit var context: Context
    private lateinit var database: DeepfakeShieldDatabase
    private lateinit var scanHistoryRepo: ScanHistoryRepository
    private lateinit var vaultRepo: PasswordVaultRepository

    @Before
    fun setup() {
        context = ApplicationProvider.getApplicationContext()
        database = Room.inMemoryDatabaseBuilder(context, DeepfakeShieldDatabase::class.java)
            .allowMainThreadQueries()
            .build()
        scanHistoryRepo = ScanHistoryRepository(database.scanHistoryDao())
        vaultRepo = PasswordVaultRepository(database.vaultCredentialDao(), SoftwareAesGcmVaultCipher())
    }

    @After
    fun teardown() {
        database.close()
    }

    @Test
    fun `scanHistoryRepository persists and retrieves full forensic evidence without loss`() = runTest {
        val id = UUID.randomUUID().toString()
        val result = SecurityAnalysisResult(
            analysisId = id,
            module = SecurityModule.PHOTO_FORENSICS,
            inputName = "sample.jpg",
            inputType = "image/jpeg",
            status = AnalysisStatus.COMPLETED,
            verdict = SecurityVerdict.INCONCLUSIVE,
            riskScore = 24,
            confidence = null,
            findings = listOf(
                SecurityFinding(
                    title = "EXIF camera tags stripped",
                    description = "No Make/Model EXIF present",
                    severity = FindingSeverity.INFO,
                    evidenceSource = "ExifInterface",
                    detectionMethod = "EXIF Parse",
                    inputLocation = "IFD0",
                    explanation = "Social apps strip EXIF; this never proves editing or AI synthesis.",
                    recommendedAction = "Inspect original image provenance."
                )
            ),
            analysisMethods = listOf("SHA-256 Digest", "JPEG Q90 ELA"),
            limitations = listOf("ELA does not distinguish authentic cameras from AI generators."),
            processingDurationMs = 88L,
            analyzedAt = 1_700_000_000_000L,
            modelVersion = null,
            errorMessage = null,
            metadata = mapOf("sha256" to "deadbeef")
        )

        scanHistoryRepo.saveResult(result)
        val loaded = scanHistoryRepo.getById(id)
        assertNotNull(loaded)
        assertEquals(result, loaded)

        val historyList = scanHistoryRepo.observeHistory(SecurityModule.PHOTO_FORENSICS).first()
        assertEquals(1, historyList.size)
        assertEquals("deadbeef", historyList.first().metadata["sha256"])
    }

    @Test
    fun `passwordVaultRepository never stores plaintext secrets and tracks reuse and breaches`() = runTest {
        val secretOne = "S3cur3#Alpha!9921"
        val id1 = vaultRepo.saveCredential(
            title = "Bank Portal",
            username = "alice@example.org",
            password = secretOne,
            url = "https://bank.example.org",
            notes = "PIN hint none"
        )
        val id2 = vaultRepo.saveCredential(
            title = "Email Backup",
            username = "alice.b@example.org",
            password = secretOne,
            url = null,
            notes = "Reused intentionally to test health tracker"
        )

        // Verify raw SQLite table has ZERO plaintext username/password/notes
        val cursor = database.openHelper.writableDatabase.query("SELECT usernameEncrypted, passwordEncrypted, notesEncrypted FROM vault_credentials")
        cursor.use { c ->
            assertEquals(2, c.count)
            while (c.moveToNext()) {
                val encUser = c.getString(0)
                val encPass = c.getString(1)
                val encNotes = c.getString(2)
                assertFalse(encUser.contains("alice"))
                assertFalse(encPass.contains(secretOne))
                assertFalse(encNotes.contains("PIN hint"))
            }
        }

        // Verify decrypt recovers exact plaintext
        val decrypted1 = vaultRepo.decryptCredential(id1)
        assertNotNull(decrypted1)
        assertEquals("alice@example.org", decrypted1!!.username)
        assertEquals(secretOne, decrypted1.password)
        assertEquals("PIN hint none", decrypted1.notes)

        // Verify reuse & breach tracking
        vaultRepo.recordBreachCount(id1, 42)
        val summary = vaultRepo.observeVaultHealth().first()
        assertEquals(2, summary.totalCredentials)
        assertEquals(2, summary.reusedCount)
        assertEquals(1, summary.breachedCount)
        assertEquals(0, summary.weakCount)
        assertTrue(id2 > id1)
    }

    @Test
    fun `migration 3 to 4 preserves existing v3 alerts and validates v4 schema`() = runTest {
        val dbFile = File(context.cacheDir, "migration_v3_v4_test_${System.nanoTime()}.db")
        if (dbFile.exists()) dbFile.delete()

        val sqliteDb = SQLiteDatabase.openOrCreateDatabase(dbFile, null)
        sqliteDb.version = 3
        val v3Ddl = listOf(
            "CREATE TABLE IF NOT EXISTS `alerts` (`id` INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, `threatType` TEXT NOT NULL, `source` TEXT NOT NULL, `severity` TEXT NOT NULL, `score` INTEGER NOT NULL, `confidence` REAL NOT NULL, `title` TEXT NOT NULL, `summary` TEXT NOT NULL, `content` TEXT, `senderInfo` TEXT, `timestamp` INTEGER NOT NULL, `isHandled` INTEGER NOT NULL, `handledAt` INTEGER, `userMarkedAs` TEXT, `isExported` INTEGER NOT NULL, `metadata` TEXT)",
            "CREATE INDEX IF NOT EXISTS `index_alerts_timestamp` ON `alerts` (`timestamp`)",
            "CREATE INDEX IF NOT EXISTS `index_alerts_isHandled_timestamp` ON `alerts` (`isHandled`, `timestamp`)",
            "CREATE INDEX IF NOT EXISTS `index_alerts_severity` ON `alerts` (`severity`)",
            "CREATE INDEX IF NOT EXISTS `index_alerts_source` ON `alerts` (`source`)",
            "CREATE INDEX IF NOT EXISTS `index_alerts_threatType` ON `alerts` (`threatType`)",
            "CREATE TABLE IF NOT EXISTS `phone_reputation` (`phoneNumber` TEXT NOT NULL, `trustScore` INTEGER NOT NULL, `reportCount` INTEGER NOT NULL, `scamReports` INTEGER NOT NULL, `safeReports` INTEGER NOT NULL, `lastReportedAt` INTEGER NOT NULL, `isBlocked` INTEGER NOT NULL, `notes` TEXT, PRIMARY KEY(`phoneNumber`))",
            "CREATE INDEX IF NOT EXISTS `index_phone_reputation_isBlocked` ON `phone_reputation` (`isBlocked`)",
            "CREATE TABLE IF NOT EXISTS `domain_reputation` (`domain` TEXT NOT NULL, `trustScore` INTEGER NOT NULL, `reportCount` INTEGER NOT NULL, `scamReports` INTEGER NOT NULL, `safeReports` INTEGER NOT NULL, `lastReportedAt` INTEGER NOT NULL, `isBlocked` INTEGER NOT NULL, `category` TEXT, PRIMARY KEY(`domain`))",
            "CREATE INDEX IF NOT EXISTS `index_domain_reputation_isBlocked` ON `domain_reputation` (`isBlocked`)",
            "CREATE TABLE IF NOT EXISTS `user_feedback` (`id` INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, `alertId` INTEGER NOT NULL, `feedbackType` TEXT NOT NULL, `userMarkedAs` TEXT, `notes` TEXT, `timestamp` INTEGER NOT NULL)",
            "CREATE INDEX IF NOT EXISTS `index_user_feedback_alertId` ON `user_feedback` (`alertId`)",
            "CREATE TABLE IF NOT EXISTS `vault_entries` (`id` INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, `alertId` INTEGER, `entryType` TEXT NOT NULL, `title` TEXT NOT NULL, `description` TEXT NOT NULL, `severity` TEXT NOT NULL, `evidenceData` TEXT NOT NULL, `metadata` TEXT, `tags` TEXT, `createdAt` INTEGER NOT NULL, `isArchived` INTEGER NOT NULL)",
            "CREATE INDEX IF NOT EXISTS `index_vault_entries_entryType` ON `vault_entries` (`entryType`)",
            "CREATE TABLE IF NOT EXISTS `scam_patterns` (`id` INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, `patternType` TEXT NOT NULL, `pattern` TEXT NOT NULL, `threatType` TEXT NOT NULL, `weight` REAL NOT NULL, `confidence` REAL NOT NULL, `hitCount` INTEGER NOT NULL, `createdAt` INTEGER NOT NULL, `lastUsedAt` INTEGER)",
            "CREATE INDEX IF NOT EXISTS `index_scam_patterns_patternType` ON `scam_patterns` (`patternType`)",
            "CREATE TABLE IF NOT EXISTS `export_history` (`id` INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, `exportType` TEXT NOT NULL, `itemCount` INTEGER NOT NULL, `fileHash` TEXT, `exportedAt` INTEGER NOT NULL, `filePath` TEXT)",
            "CREATE TABLE IF NOT EXISTS `community_threats` (`threatHash` TEXT NOT NULL, `threatType` TEXT NOT NULL, `severity` INTEGER NOT NULL, `reportCount` INTEGER NOT NULL, `firstSeen` INTEGER NOT NULL, `lastSeen` INTEGER NOT NULL, `geographicRegion` TEXT, `metadata` TEXT, PRIMARY KEY(`threatHash`))",
            "CREATE TABLE IF NOT EXISTS `behavior_profiles` (`senderId` TEXT NOT NULL, `messageCount` INTEGER NOT NULL, `callCount` INTEGER NOT NULL, `avgResponseTime` INTEGER NOT NULL, `avgMessageLength` INTEGER NOT NULL, `activeHours` TEXT NOT NULL, `typingSpeed` REAL, `suspiciousPatterns` TEXT, `trustScore` INTEGER NOT NULL, `firstContact` INTEGER NOT NULL, `lastContact` INTEGER NOT NULL, PRIMARY KEY(`senderId`))",
            "CREATE TABLE IF NOT EXISTS `scammer_fingerprints` (`fingerprintId` TEXT NOT NULL, `phoneNumbers` TEXT NOT NULL, `deviceSignatures` TEXT, `writingStyleHash` TEXT NOT NULL, `activeHours` TEXT NOT NULL, `targetedVictims` INTEGER NOT NULL, `campaignIds` TEXT, `confidence` REAL NOT NULL, `firstSeen` INTEGER NOT NULL, `lastSeen` INTEGER NOT NULL, PRIMARY KEY(`fingerprintId`))",
            "CREATE TABLE IF NOT EXISTS `pattern_weights` (`patternId` TEXT NOT NULL, `pattern` TEXT NOT NULL, `weight` REAL NOT NULL, `accuracy` REAL NOT NULL, `falsePositiveRate` REAL NOT NULL, `truePositiveCount` INTEGER NOT NULL, `falsePositiveCount` INTEGER NOT NULL, `lastUpdated` INTEGER NOT NULL, PRIMARY KEY(`patternId`))",
            "CREATE TABLE IF NOT EXISTS `learned_patterns` (`id` INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, `pattern` TEXT NOT NULL, `confidence` REAL NOT NULL, `occurrences` INTEGER NOT NULL, `threatType` TEXT NOT NULL, `discoveredAt` INTEGER NOT NULL, `language` TEXT)",
            "CREATE TABLE IF NOT EXISTS `scam_campaigns` (`campaignId` TEXT NOT NULL, `campaignType` TEXT NOT NULL, `affectedUsers` INTEGER NOT NULL, `scammerCount` INTEGER NOT NULL, `commonPatterns` TEXT NOT NULL, `startDate` INTEGER NOT NULL, `endDate` INTEGER, `isActive` INTEGER NOT NULL, PRIMARY KEY(`campaignId`))",
            "CREATE TABLE IF NOT EXISTS `threat_predictions` (`id` INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, `threatType` TEXT NOT NULL, `probability` REAL NOT NULL, `expectedTimeframe` TEXT NOT NULL, `targetAudience` TEXT NOT NULL, `reasoning` TEXT NOT NULL, `createdAt` INTEGER NOT NULL, `isActive` INTEGER NOT NULL)",
            "CREATE TABLE IF NOT EXISTS `user_risk_profile` (`id` INTEGER NOT NULL, `overallRiskScore` INTEGER NOT NULL, `age` INTEGER, `occupation` TEXT, `techSavviness` TEXT, `hasSharedPersonalInfo` INTEGER NOT NULL, `clickedSuspiciousLinks` INTEGER NOT NULL, `lastUpdated` INTEGER NOT NULL, PRIMARY KEY(`id`))",
            "CREATE TABLE IF NOT EXISTS `audit_log` (`id` INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, `action` TEXT NOT NULL, `entityType` TEXT NOT NULL, `entityId` TEXT, `userId` TEXT NOT NULL, `timestamp` INTEGER NOT NULL, `metadata` TEXT, `hash` TEXT)"
        )
        v3Ddl.forEach { sqliteDb.execSQL(it) }
        sqliteDb.execSQL(
            "INSERT INTO `alerts` (threatType, source, severity, score, confidence, title, summary, timestamp, isHandled, isExported) VALUES ('SCAM_MESSAGE', 'SMS', 'HIGH', 85, 0.9, 'Legacy Alert', 'Saved in v3', 1234567, 0, 0)"
        )
        sqliteDb.close()

        val migratedDb = Room.databaseBuilder(context, DeepfakeShieldDatabase::class.java, dbFile.absolutePath)
            .addMigrations(DatabaseModule.MIGRATION_3_4)
            .allowMainThreadQueries()
            .build()
        try {
            val existingAlert = migratedDb.alertDao().getAlertById(1L)
            assertNotNull(existingAlert)
            assertEquals("Legacy Alert", existingAlert!!.title)

            val historyRepo = ScanHistoryRepository(migratedDb.scanHistoryDao())
            assertEquals(0, historyRepo.observeTotalScanCount().first())
        } finally {
            migratedDb.close()
            dbFile.delete()
        }
    }
}

