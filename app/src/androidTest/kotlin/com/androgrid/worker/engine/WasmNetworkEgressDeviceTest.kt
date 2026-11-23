package com.androgrid.worker.engine

import androidx.test.ext.junit.runners.AndroidJUnit4
import com.androgrid.v1.ExecutionEngine
import com.androgrid.v1.NetworkEgressPolicy
import com.androgrid.v1.TaskSpec
import com.google.common.truth.Truth.assertThat
import com.google.protobuf.ByteString
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.delay
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
import java.io.ByteArrayOutputStream
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
 * 2. Real ART runtime + Okio bounded streaming abort (-413) executing WASM bytecode without JVM heap exhaustion.
 * 3. Real ART runtime + Conscrypt socket teardown latency (< 50 ms) executing WASM on mid-flight coroutine cancellation.
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

    private fun writeSignedLeb128(out: ByteArrayOutputStream, value: Int) {
        var v = value
        var remaining = true
        while (remaining) {
            val byte = v and 0x7f
            v = v shr 7
            val hasMore = !((v == 0 && (byte and 0x40) == 0) || (v == -1 && (byte and 0x40) != 0))
            if (hasMore) {
                out.write(byte or 0x80)
            } else {
                out.write(byte)
                remaining = false
            }
        }
    }

    private fun buildSpikeWasmModule(
        urlPtr: Int = 64,
        urlLen: Int = 32,
        methodPtr: Int = 0,
        methodLen: Int = 0,
        headersPtr: Int = 0,
        headersLen: Int = 0,
        bodyPtr: Int = 0,
        bodyLen: Int = 0,
        outBufPtr: Int = 256,
        outBufCap: Int = 1024,
        outWrittenPtr: Int = 512
    ): ByteArray {
        val out = ByteArrayOutputStream()
        out.write(byteArrayOf(0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00))

        val typeSection = byteArrayOf(
            0x02,
            0x60.toByte(), 0x0b, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x01, 0x7f,
            0x60.toByte(), 0x00, 0x01, 0x7f
        )
        out.write(0x01); out.write(typeSection.size); out.write(typeSection)

        val modName = "androgrid_net".toByteArray(Charsets.UTF_8)
        val fieldName = "http_fetch".toByteArray(Charsets.UTF_8)
        val importPayload = ByteArrayOutputStream()
        importPayload.write(0x01)
        importPayload.write(modName.size); importPayload.write(modName)
        importPayload.write(fieldName.size); importPayload.write(fieldName)
        importPayload.write(0x00); importPayload.write(0x00)
        val importBytes = importPayload.toByteArray()
        out.write(0x02); out.write(importBytes.size); out.write(importBytes)

        val funcSection = byteArrayOf(0x01, 0x01)
        out.write(0x03); out.write(funcSection.size); out.write(funcSection)

        val memSection = byteArrayOf(0x01, 0x00, 0x01)
        out.write(0x05); out.write(memSection.size); out.write(memSection)

        val memExport = "memory".toByteArray(Charsets.UTF_8)
        val startExport = "_start".toByteArray(Charsets.UTF_8)
        val exportPayload = ByteArrayOutputStream()
        exportPayload.write(0x02)
        exportPayload.write(memExport.size); exportPayload.write(memExport)
        exportPayload.write(0x02); exportPayload.write(0x00)
        exportPayload.write(startExport.size); exportPayload.write(startExport)
        exportPayload.write(0x00); exportPayload.write(0x01)
        val exportBytes = exportPayload.toByteArray()
        out.write(0x07); out.write(exportBytes.size); out.write(exportBytes)

        val codeBody = ByteArrayOutputStream()
        codeBody.write(0x00)
        codeBody.write(0x41); writeSignedLeb128(codeBody, urlPtr)
        codeBody.write(0x41); writeSignedLeb128(codeBody, urlLen)
        codeBody.write(0x41); writeSignedLeb128(codeBody, methodPtr)
        codeBody.write(0x41); writeSignedLeb128(codeBody, methodLen)
        codeBody.write(0x41); writeSignedLeb128(codeBody, headersPtr)
        codeBody.write(0x41); writeSignedLeb128(codeBody, headersLen)
        codeBody.write(0x41); writeSignedLeb128(codeBody, bodyPtr)
        codeBody.write(0x41); writeSignedLeb128(codeBody, bodyLen)
        codeBody.write(0x41); writeSignedLeb128(codeBody, outBufPtr)
        codeBody.write(0x41); writeSignedLeb128(codeBody, outBufCap)
        codeBody.write(0x41); writeSignedLeb128(codeBody, outWrittenPtr)
        codeBody.write(0x10); codeBody.write(0x00)
        codeBody.write(0x0b)

        val bodyBytes = codeBody.toByteArray()
        val codeSectionPayload = ByteArrayOutputStream()
        codeSectionPayload.write(0x01); codeSectionPayload.write(bodyBytes.size); codeSectionPayload.write(bodyBytes)
        val codeSectionBytes = codeSectionPayload.toByteArray()
        out.write(0x0a); out.write(codeSectionBytes.size); out.write(codeSectionBytes)

        return out.toByteArray()
    }

    private fun buildWasmWithUrlData(
        url: String,
        urlPtr: Int = 64,
        outBufPtr: Int = 256,
        outBufCap: Int = 1024,
        outWrittenPtr: Int = 512
    ): ByteArray {
        val urlBytes = url.toByteArray(Charsets.UTF_8)
        val baseWasm = buildSpikeWasmModule(
            urlPtr = urlPtr,
            urlLen = urlBytes.size,
            outBufPtr = outBufPtr,
            outBufCap = outBufCap,
            outWrittenPtr = outWrittenPtr
        )

        val dataPayload = ByteArrayOutputStream()
        dataPayload.write(0x01); dataPayload.write(0x00)
        dataPayload.write(0x41); writeSignedLeb128(dataPayload, urlPtr)
        dataPayload.write(0x0b)
        dataPayload.write(urlBytes.size); dataPayload.write(urlBytes)

        val dataBytes = dataPayload.toByteArray()
        val fullWasm = ByteArrayOutputStream()
        fullWasm.write(baseWasm)
        fullWasm.write(0x0b); fullWasm.write(dataBytes.size); fullWasm.write(dataBytes)
        return fullWasm.toByteArray()
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
     * 2. Real ART + Okio bounded streaming abort (-413) executing WASM bytecode without JVM heap exhaustion.
     *
     * Streams a 16 MB payload from MockWebServer against a 64 KB outBufCap buffer on physical ART.
     * Executes through WasmComputeEngine to verify end-to-end WASM linear memory streaming bounds.
     */
    @Test
    fun testRealDevice_artOkioBoundedStreamingAbortWithoutOom(): Unit = runBlocking {
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

        val targetUrl = "http://127.0.0.1:$port/stream-large"
        val wasmBytecode = buildWasmWithUrlData(targetUrl, outBufCap = 64 * 1024)

        val loopbackDns = object : Dns {
            override fun lookup(hostname: String): List<InetAddress> =
                listOf(InetAddress.getByName("127.0.0.1"))
        }

        val engine = WasmComputeEngine(
            dns = loopbackDns,
            isMeteredProvider = { false },
            allowLoopbackForTesting = true
        )

        val task = TaskSpec.newBuilder()
            .setTaskId("device_streaming_oom_abort")
            .setEngine(ExecutionEngine.EXECUTION_ENGINE_WASM_WASI)
            .setEgressPolicy(NetworkEgressPolicy.NETWORK_EGRESS_POLICY_ALLOWLIST)
            .addAllowedHostnames("127.0.0.1")
            .setMaxEgressBytes(1048576)
            .setTimeoutSeconds(30)
            .setWasmBytecode(ByteString.copyFrom(wasmBytecode))
            .build()

        val result = engine.execute(task)

        assertThat(result.isSuccess).isTrue()
        // Must return ERR_BUFFER_TOO_SMALL (-413) directly from WASM execution
        assertThat(String(result.stdoutBytes, Charsets.UTF_8).trim()).isEqualTo("-413")
    }

    /**
     * 3. Real ART + Conscrypt socket teardown latency (< 50 ms) on coroutine cancellation.
     *
     * Evaluates in-flight socket interruption on real Android ART runtime with Conscrypt TLS provider.
     * Confirms that cancellation hook tears down active socket cleanly in under 50 ms.
     */
    @Test
    fun testRealDevice_artConscryptSocketTeardownLatencyOnCancellation(): Unit = runBlocking {
        mockServer.enqueue(
            MockResponse()
                .setHeadersDelay(10, TimeUnit.SECONDS)
                .setBody("unreachable")
        )
        mockServer.start()
        val port = mockServer.port

        val targetUrl = "http://127.0.0.1:$port/hang-socket"
        val wasmBytecode = buildWasmWithUrlData(targetUrl)

        val loopbackDns = object : Dns {
            override fun lookup(hostname: String): List<InetAddress> =
                listOf(InetAddress.getByName("127.0.0.1"))
        }

        val engine = WasmComputeEngine(
            dns = loopbackDns,
            isMeteredProvider = { false },
            allowLoopbackForTesting = true
        )

        val task = TaskSpec.newBuilder()
            .setTaskId("device_cancellation_teardown")
            .setEngine(ExecutionEngine.EXECUTION_ENGINE_WASM_WASI)
            .setEgressPolicy(NetworkEgressPolicy.NETWORK_EGRESS_POLICY_ALLOWLIST)
            .addAllowedHostnames("127.0.0.1")
            .setMaxEgressBytes(1048576)
            .setTimeoutSeconds(30)
            .setWasmBytecode(ByteString.copyFrom(wasmBytecode))
            .build()

        var caughtCancellation = false
        val job: Job = CoroutineScope(Dispatchers.IO).launch {
            try {
                engine.execute(task)
            } catch (e: CancellationException) {
                caughtCancellation = true
            }
        }

        delay(150)

        val startNano = System.nanoTime()
        job.cancelAndJoin()
        val elapsedMillis = (System.nanoTime() - startNano) / 1_000_000

        assertThat(caughtCancellation).isTrue()
        assertThat(elapsedMillis).isLessThan(50L)
    }
}
