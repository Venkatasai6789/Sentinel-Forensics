package com.deepfakeshield.feature.shield

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import com.deepfakeshield.core.security.DeviceAuthHelper
import com.deepfakeshield.data.repository.PasswordVaultRepository
import com.deepfakeshield.data.repository.ScanHistoryRepository
import io.mockk.coVerify
import io.mockk.every
import io.mockk.mockk
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.flow.flowOf
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
import java.io.BufferedReader
import java.io.InputStreamReader
import java.net.InetAddress
import java.net.ServerSocket
import java.security.MessageDigest
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.concurrent.thread

@OptIn(ExperimentalCoroutinesApi::class)
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [28])
class PasswordVaultViewModelTest {

    private val testDispatcher = StandardTestDispatcher()
    private lateinit var context: Context
    private lateinit var vaultRepo: PasswordVaultRepository
    private lateinit var historyRepo: ScanHistoryRepository
    private lateinit var authHelper: DeviceAuthHelper

    @Before
    fun setup() {
        Dispatchers.setMain(testDispatcher)
        context = ApplicationProvider.getApplicationContext()
        vaultRepo = mockk(relaxed = true)
        historyRepo = mockk(relaxed = true)
        authHelper = mockk(relaxed = true)
        every { vaultRepo.observeCredentialMetadata() } returns flowOf(emptyList())
        every { historyRepo.observeHistory(any(), any()) } returns flowOf(emptyList())
        every { authHelper.checkAvailability(any()) } returns DeviceAuthHelper.BiometricStatus.NOT_AVAILABLE
    }

    @After
    fun teardown() {
        Dispatchers.resetMain()
    }

    @Test
    fun `k-anonymity breach check sends ONLY 5-char SHA1 prefix and parses Compromised vs Clean vs Failed`() = runTest(testDispatcher) {
        val vm = PasswordVaultViewModel(vaultRepo, historyRepo, authHelper, context)
        val compromisedPw = "CorrectHorseBatteryStapleTest1!"
        val sha1Hex = MessageDigest.getInstance("SHA-1")
            .digest(compromisedPw.toByteArray())
            .joinToString("") { "%02X".format(it) }
        val expectedPrefix = sha1Hex.substring(0, 5)
        val expectedSuffix = sha1Hex.substring(5)

        val seenRequestLines = mutableListOf<String>()
        val serverSocket = ServerSocket(0, 10, InetAddress.getByName("127.0.0.1"))
        val port = serverSocket.localPort
        val running = AtomicBoolean(true)
        val worker = thread(isDaemon = true) {
            while (running.get()) {
                try {
                    val client = serverSocket.accept()
                    client.use { sock ->
                        val reader = BufferedReader(InputStreamReader(sock.getInputStream()))
                        val requestLine = reader.readLine() ?: ""
                        seenRequestLines += requestLine
                        var line: String?
                        do {
                            line = reader.readLine()
                        } while (!line.isNullOrEmpty())

                        val response = when {
                            requestLine.contains("/fail/") ->
                                "HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                            requestLine.contains("/range/$expectedPrefix") -> {
                                val body = "00000000000000000000000000000000000:2\r\n$expectedSuffix:1337\r\n"
                                "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: ${body.length}\r\nConnection: close\r\n\r\n$body"
                            }
                            else -> {
                                val body = "11111111111111111111111111111111111:5\r\n"
                                "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: ${body.length}\r\nConnection: close\r\n\r\n$body"
                            }
                        }
                        sock.getOutputStream().write(response.toByteArray())
                        sock.getOutputStream().flush()
                    }
                } catch (_: Exception) {
                }
            }
        }

        try {
            suspend fun kotlinx.coroutines.test.TestScope.awaitTerminalBreachState() {
                advanceUntilIdle()
                val deadline = System.currentTimeMillis() + 5_000L
                while (vm.uiState.value.breachState is BreachCheckState.Checking && System.currentTimeMillis() < deadline) {
                    advanceUntilIdle()
                    if (vm.uiState.value.breachState !is BreachCheckState.Checking) break
                    Thread.sleep(20)
                }
                advanceUntilIdle()
            }

            // 1. Compromised match against local HTTP server
            vm.checkPasswordBreach(passwordOverride = compromisedPw, credentialId = 7L, baseUrl = "http://127.0.0.1:$port/range/")
            awaitTerminalBreachState()
            val breachedState = vm.uiState.value.breachState
            assertTrue("Expected Compromised state, got $breachedState", breachedState is BreachCheckState.Compromised)
            assertEquals(1337, (breachedState as BreachCheckState.Compromised).occurrences)
            assertTrue("HIBP request must contain ONLY the 5-char prefix", seenRequestLines.single().contains("/range/$expectedPrefix "))
            assertFalse("Full SHA-1 hash must never cross network", seenRequestLines.single().contains(expectedSuffix))
            coVerify { vaultRepo.recordBreachCount(7L, 1337) }

            // 2. Clean non-matching password
            vm.checkPasswordBreach(passwordOverride = "UnseenStrongPassword#2026!Qx", credentialId = null, baseUrl = "http://127.0.0.1:$port/range/")
            awaitTerminalBreachState()
            assertEquals(BreachCheckState.Clean, vm.uiState.value.breachState)

            // 3. Server error must NEVER emit Clean — must report Failed
            vm.checkPasswordBreach(passwordOverride = compromisedPw, credentialId = null, baseUrl = "http://127.0.0.1:$port/fail/")
            awaitTerminalBreachState()
            assertTrue("HTTP 500 must report Failed state", vm.uiState.value.breachState is BreachCheckState.Failed)
        } finally {
            running.set(false)
            runCatching { serverSocket.close() }
            worker.join(500)
        }
    }
}
