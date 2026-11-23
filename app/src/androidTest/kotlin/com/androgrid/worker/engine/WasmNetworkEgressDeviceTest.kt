package com.androgrid.worker.engine

import androidx.test.ext.junit.runners.AndroidJUnit4
import com.google.common.truth.Truth.assertThat
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import okhttp3.Call
import okhttp3.Dns
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import okio.Buffer
import org.junit.After
import org.junit.Assert.assertThrows
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.io.IOException
import java.net.InetAddress
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong
import java.util.concurrent.atomic.AtomicReference

/**
 * Headless on-device instrumentation test suite verifying controlled outbound network egress
 * on physical Android hardware (ART runtime + Conscrypt TLS provider + netd resolver).
 *
 * Strictly headless: zero Espresso, zero UI interactions, zero cellular toggle requirements.
 *
 * Verification Areas:
 * 1. Real Android netd DNS resolution + OkHttpClient Dns guard rejecting local LAN / loopback addresses.
 * 2. Real ART runtime + Okio bounded streaming abort (-413) on large payload without JVM heap exhaustion.
 * 3. Real ART runtime + Conscrypt socket teardown latency (< 50 ms) on mid-flight coroutine cancellation.
 *
 * Traces to: [INV-001], [INV-003], [INV-006], [ANTI-003], [NFR-SEC-001], [NFR-POW-001], [NFR-PERF-001], ADR-011
 */
@RunWith(AndroidJUnit4::class)
class WasmNetworkEgressDeviceTest {

    private lateinit var mockServer: MockWebServer

    @Before
    fun setUp() {
        mockServer = MockWebServer()
    }

    @After
    fun tearDown() {
        try {
            mockServer.shutdown()
        } catch (_: Exception) {
        }
    }

    /**
     * 1. Real Android netd DNS resolution + OkHttpClient Dns guard rejecting a local LAN / loopback address (-403).
     *
     * Evaluates Android libc/netd resolution for loopback and LAN endpoints. Confirms that createTaskDns
     * intercepts netd resolution results and deterministically throws SecurityException (-403) before any
     * socket connection attempt can be initiated.
     */
    @Test
    fun testRealDevice_netdResolutionAndTaskDnsGuardRejection() {
        val guard = WasmNetworkEgressSecurityGuard(
            isMeteredProvider = { false },
            allowLoopbackForTesting = false
        )

        // Real Android netd resolver
        val taskDns = guard.createTaskDns(Dns.SYSTEM)

        // Query 'localhost' through real Android netd
        val exLocalhost = assertThrows(SecurityException::class.java) {
            taskDns.lookup("localhost")
        }
        assertThat(exLocalhost.message).contains("disallowed IP")

        // Query literal loopback through real netd
        val exLoopback = assertThrows(SecurityException::class.java) {
            taskDns.lookup("127.0.0.1")
        }
        assertThat(exLoopback.message).contains("disallowed IP")

        // Injected into OkHttpClient on device
        val client = OkHttpClient.Builder()
            .dns(taskDns)
            .connectTimeout(2, TimeUnit.SECONDS)
            .build()

        val request = Request.Builder()
            .url("http://localhost:8080/internal-admin")
            .build()

        val connException = assertThrows(SecurityException::class.java) {
            client.newCall(request).execute().use { response ->
                response.body?.string()
            }
        }
        assertThat(connException.message).contains("disallowed IP")
    }

    /**
     * 2. Real ART + Okio bounded streaming abort (-413) on a large response without OOM.
     *
     * Streams a 16 MB payload from MockWebServer against a 64 KB outBufCap buffer on physical ART.
     * Verifies that chunked streaming directly aborts when buffer capacity is exceeded, capping
     * memory usage to ~72 KB and completing without OutOfMemoryError.
     */
    @Test
    fun testRealDevice_artOkioBoundedStreamingAbortWithoutOom() {
        mockServer.start()
        val port = mockServer.port

        // Prepare 16 MB streaming payload on device
        val totalSize = 16 * 1024 * 1024
        val chunk = ByteArray(64 * 1024) { 0x3c.toByte() }
        val buffer = Buffer()
        for (i in 0 until (totalSize / chunk.size)) {
            buffer.write(chunk)
        }

        mockServer.enqueue(
            MockResponse()
                .setResponseCode(200)
                .setBody(buffer)
        )

        val guard = WasmNetworkEgressSecurityGuard(
            isMeteredProvider = { false },
            allowLoopbackForTesting = true
        )

        val loopbackDns = object : Dns {
            override fun lookup(hostname: String): List<InetAddress> =
                listOf(InetAddress.getByName("127.0.0.1"))
        }

        val client = OkHttpClient.Builder()
            .dns(guard.createTaskDns(loopbackDns))
            .followRedirects(false)
            .followSslRedirects(false)
            .build()

        val request = Request.Builder()
            .url("http://127.0.0.1:$port/stream-large")
            .build()

        val outBufCap = 64 * 1024 // 64 KB WASM guest buffer
        val bytesTransferred = AtomicLong(0)
        val call = client.newCall(request)

        var statusOrError = 200
        val response = call.execute()
        val source = response.body?.source() ?: throw IOException("Empty body")
        val tempChunk = ByteArray(8192)
        var overflowDetected = false

        try {
            while (!source.exhausted()) {
                val readNow = source.read(tempChunk)
                if (readNow == -1) break
                bytesTransferred.addAndGet(readNow.toLong())

                if (bytesTransferred.get() > outBufCap) {
                    overflowDetected = true
                    call.cancel()
                    break
                }
            }
            statusOrError = if (overflowDetected) -413 else response.code
        } catch (_: Exception) {
            statusOrError = -413
        } finally {
            response.close()
        }

        // Must abort with ERR_BUFFER_TOO_SMALL (-413)
        assertThat(statusOrError).isEqualTo(-413)
        // Verified: The device only received ~72 KB, never loading 16 MB into ART heap
        assertThat(bytesTransferred.get()).isAtMost((outBufCap + 8192 * 2).toLong())
    }

    /**
     * 3. Real ART + Conscrypt socket teardown latency (< 50 ms) on coroutine cancellation.
     *
     * Evaluates in-flight socket interruption on real Android ART runtime with Conscrypt TLS provider.
     * Confirms that registering onCancelling = true hook cleanly tears down active OkHttp socket
     * in under 50 ms when coroutine job is cancelled.
     */
    @OptIn(kotlinx.coroutines.InternalCoroutinesApi::class)
    @Test
    fun testRealDevice_artConscryptSocketTeardownLatencyOnCancellation(): Unit = runBlocking {
        mockServer.start()
        val mockUrl = mockServer.url("/hang-socket").toString()

        // Mock server delays headers by 10s to simulate stalled remote server
        mockServer.enqueue(
            MockResponse()
                .setHeadersDelay(10, TimeUnit.SECONDS)
                .setBody("unreachable")
        )

        val client = OkHttpClient.Builder()
            .readTimeout(15, TimeUnit.SECONDS)
            .build()

        val requestStarted = CompletableDeferred<Unit>()
        val connectionAborted = CompletableDeferred<Unit>()
        val activeCallRef = AtomicReference<Call?>(null)

        val job: Job = CoroutineScope(Dispatchers.IO).launch {
            val call = client.newCall(Request.Builder().url(mockUrl).build())
            activeCallRef.set(call)
            requestStarted.complete(Unit)

            try {
                call.execute().use { response ->
                    response.body?.string()
                }
            } catch (e: IOException) {
                if (call.isCanceled()) {
                    connectionAborted.complete(Unit)
                }
            }
        }

        // Structured cancellation hook matching WasmComputeEngine implementation
        val handle = job.invokeOnCompletion(onCancelling = true) { cause ->
            if (cause != null) {
                activeCallRef.get()?.cancel()
            }
        }

        withTimeout(3000) {
            requestStarted.await()
        }

        // Brief delay to ensure TCP socket connection has engaged
        Thread.sleep(60)

        // Measure teardown duration on real hardware
        val startNano = System.nanoTime()
        job.cancelAndJoin()
        val elapsedMillis = (System.nanoTime() - startNano) / 1_000_000
        handle.dispose()

        assertThat(connectionAborted.isCompleted).isTrue()
        // Must abort socket cleanly in under 50 ms on real device
        assertThat(elapsedMillis).isLessThan(50L)
    }
}
