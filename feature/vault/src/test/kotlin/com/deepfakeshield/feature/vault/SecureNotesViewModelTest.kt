package com.deepfakeshield.feature.vault

import android.content.Context
import androidx.room.Room
import androidx.test.core.app.ApplicationProvider
import com.deepfakeshield.core.security.DeviceAuthHelper
import com.deepfakeshield.core.security.SoftwareAesGcmVaultCipher
import com.deepfakeshield.data.database.DeepfakeShieldDatabase
import com.deepfakeshield.data.repository.VaultRepository
import io.mockk.every
import io.mockk.mockk
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.test.setMain
import org.junit.After
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@OptIn(ExperimentalCoroutinesApi::class)
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [28])
class SecureNotesViewModelTest {

    private val testDispatcher = StandardTestDispatcher()
    private lateinit var context: Context
    private lateinit var db: DeepfakeShieldDatabase
    private lateinit var repo: VaultRepository

    @Before
    fun setup() {
        Dispatchers.setMain(testDispatcher)
        context = ApplicationProvider.getApplicationContext()
        db = Room.inMemoryDatabaseBuilder(context, DeepfakeShieldDatabase::class.java)
            .allowMainThreadQueries()
            .build()
        repo = VaultRepository(db.vaultDao())
    }

    @After
    fun teardown() {
        db.close()
        Dispatchers.resetMain()
    }

    @Test
    fun `SecureNotesViewModel starts empty with no hardcoded sample notes and encrypts saved notes`() = runTest(testDispatcher) {
        val cipher = SoftwareAesGcmVaultCipher()
        val authHelper = mockk<DeviceAuthHelper>(relaxed = true)
        every { authHelper.checkAvailability(any()) } returns DeviceAuthHelper.BiometricStatus.NOT_AVAILABLE
        every { authHelper.authenticate(any(), any(), any(), any()) } answers {
            lastArg<(DeviceAuthHelper.AuthOutcome) -> Unit>().invoke(DeviceAuthHelper.AuthOutcome.Authenticated)
        }

        val vm = SecureNotesViewModel(
            vaultRepository = repo,
            vaultCipher = cipher,
            deviceAuthHelper = authHelper,
            context = context
        )
        advanceUntilIdle()

        // Must never populate sample notes
        assertTrue(vm.uiState.value.noteMetadata.isEmpty())
        assertTrue(vm.uiState.value.notes.isEmpty())

        // Saving while locked must be blocked
        vm.saveNote(title = "Blocked", content = "SHOULD_NOT_SAVE", category = "Recovery")
        advanceUntilIdle()
        assertFalse(vm.uiState.value.isUnlocked)

        // Authenticate and verify unlock + encrypted save
        vm.authenticate(context)
        advanceUntilIdle()
        assertTrue(vm.uiState.value.isUnlocked)

        vm.saveNote(title = "Incident Token", content = "TOP_SECRET_RECOVERY_PHRASE_42", category = "Recovery")
        advanceUntilIdle()

        var rowCount = 0
        repeat(40) {
            advanceUntilIdle()
            db.openHelper.writableDatabase.query("SELECT title, evidenceData FROM vault_entries").use { c ->
                rowCount = c.count
            }
            if (rowCount >= 1) return@repeat
            Thread.sleep(25)
        }

        val cursor = db.openHelper.writableDatabase.query("SELECT title, evidenceData FROM vault_entries")
        cursor.use { c ->
            assertEquals(1, c.count)
            assertTrue(c.moveToFirst())
            val rawEvidence = c.getString(1)
            assertFalse("Raw SQLite vault row must NOT store plaintext note content", rawEvidence.contains("TOP_SECRET_RECOVERY_PHRASE_42"))
        }
        vm.lockNotes()
    }
}
