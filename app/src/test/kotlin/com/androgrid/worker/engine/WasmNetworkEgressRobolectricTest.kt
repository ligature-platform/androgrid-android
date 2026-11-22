package com.androgrid.worker.engine

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
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import okhttp3.Dns
import okhttp3.OkHttpClient
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import org.junit.After
import org.junit.Assert.assertThrows
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.io.ByteArrayOutputStream
import java.io.File
import java.net.InetAddress
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Robolectric unit test suite verifying controlled outbound network egress for WASM workloads.
 *
 * Enforces:
 * 1. Successful HTTP/HTTPS requests to allowlisted external domains.
 * 2. Deterministic rejection of RFC 1918, loopback, and link-local IP addresses.
 * 3. Deterministic rejection of unlisted hostnames and blocked policies.
 * 4. Deterministic rejection when running on metered cellular interfaces ([ANTI-003], [INV-003], [NFR-POW-001]).
 * 5. Immediate cancellation and socket teardown when tasks are aborted mid-flight.
 * 6. Egress quota enforcement against max_egress_bytes.
 *
 * Traces to: [INV-001], [INV-003], [INV-006], [ANTI-003], [NFR-SEC-001], [NFR-POW-001], [NFR-PERF-001], ADR-011
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class WasmNetworkEgressRobolectricTest {

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
     * Writes a signed 32-bit integer as LEB128 bytes to output stream.
     */
    private fun writeSignedLeb128(out: ByteArrayOutputStream, value: Int) {
        var v = value
        var remaining = true
        while (remaining) {
            val byte = (v and 0x7F)
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

    /**
     * Builds a minimal valid WebAssembly binary module that:
     * - Imports "androgrid_net:http_fetch(url_ptr, url_len, method_ptr, method_len, body_ptr, body_len, out_buf_ptr, out_buf_cap, out_written_ptr) -> i32"
     * - Exports "memory" (1 page = 64KB)
     * - Exports "_start() -> i32" calling http_fetch
     */
    private fun buildHttpFetchWasmModule(
        urlPtr: Int,
        urlLen: Int,
        outBufPtr: Int = 256,
        outBufCap: Int = 1024,
        outWrittenPtr: Int = 512
    ): ByteArray {
        val out = ByteArrayOutputStream()
        // Magic & Version (8 bytes)
        out.write(byteArrayOf(0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00))

        // Type section (id 1):
        // Type 0: (i32, i32, i32, i32, i32, i32, i32, i32, i32) -> i32
        // Type 1: () -> i32
        val typeSection = byteArrayOf(
            0x02, // 2 types
            0x60.toByte(), 0x09, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x01, 0x7f,
            0x60.toByte(), 0x00, 0x01, 0x7f
        )
        out.write(0x01)
        out.write(typeSection.size)
        out.write(typeSection)

        // Import section (id 2):
        // 1 import: module "androgrid_net", field "http_fetch", kind 0 (func), type 0
        val modName = "androgrid_net".toByteArray(Charsets.UTF_8)
        val fieldName = "http_fetch".toByteArray(Charsets.UTF_8)
        val importPayload = ByteArrayOutputStream()
        importPayload.write(0x01) // 1 import
        importPayload.write(modName.size)
        importPayload.write(modName)
        importPayload.write(fieldName.size)
        importPayload.write(fieldName)
        importPayload.write(0x00) // kind = func
        importPayload.write(0x00) // type index 0
        val importBytes = importPayload.toByteArray()
        out.write(0x02)
        out.write(importBytes.size)
        out.write(importBytes)

        // Function section (id 3):
        // 1 function with type index 1
        val funcSection = byteArrayOf(0x01, 0x01)
        out.write(0x03)
        out.write(funcSection.size)
        out.write(funcSection)

        // Memory section (id 5):
        // 1 memory: min 1 page
        val memSection = byteArrayOf(0x01, 0x00, 0x01)
        out.write(0x05)
        out.write(memSection.size)
        out.write(memSection)

        // Export section (id 7):
        // 2 exports: "memory" (mem 0), "_start" (func 1)
        val memExport = "memory".toByteArray(Charsets.UTF_8)
        val startExport = "_start".toByteArray(Charsets.UTF_8)
        val exportPayload = ByteArrayOutputStream()
        exportPayload.write(0x02) // 2 exports
        exportPayload.write(memExport.size)
        exportPayload.write(memExport)
        exportPayload.write(0x02) // kind = memory
        exportPayload.write(0x00) // index 0
        exportPayload.write(startExport.size)
        exportPayload.write(startExport)
        exportPayload.write(0x00) // kind = func
        exportPayload.write(0x01) // func 1
        val exportBytes = exportPayload.toByteArray()
        out.write(0x07)
        out.write(exportBytes.size)
        out.write(exportBytes)

        // Code section (id 10):
        // 1 function body pushing 9 arguments and calling func 0
        val codeBody = ByteArrayOutputStream()
        codeBody.write(0x00) // 0 locals

        // arg 0: url_ptr
        codeBody.write(0x41); writeSignedLeb128(codeBody, urlPtr)
        // arg 1: url_len
        codeBody.write(0x41); writeSignedLeb128(codeBody, urlLen)
        // arg 2: method_ptr (0 = default GET)
        codeBody.write(0x41); writeSignedLeb128(codeBody, 0)
        // arg 3: method_len (0)
        codeBody.write(0x41); writeSignedLeb128(codeBody, 0)
        // arg 4: body_ptr (0)
        codeBody.write(0x41); writeSignedLeb128(codeBody, 0)
        // arg 5: body_len (0)
        codeBody.write(0x41); writeSignedLeb128(codeBody, 0)
        // arg 6: out_buf_ptr
        codeBody.write(0x41); writeSignedLeb128(codeBody, outBufPtr)
        // arg 7: out_buf_cap
        codeBody.write(0x41); writeSignedLeb128(codeBody, outBufCap)
        // arg 8: out_written_ptr
        codeBody.write(0x41); writeSignedLeb128(codeBody, outWrittenPtr)

        // call 0 (imported http_fetch)
        codeBody.write(0x10); codeBody.write(0x00)
        // end
        codeBody.write(0x0b)

        val bodyBytes = codeBody.toByteArray()
        val codeSectionPayload = ByteArrayOutputStream()
        codeSectionPayload.write(0x01) // 1 function body
        codeSectionPayload.write(bodyBytes.size)
        codeSectionPayload.write(bodyBytes)
        val codeSectionBytes = codeSectionPayload.toByteArray()
        out.write(0x0a)
        out.write(codeSectionBytes.size)
        out.write(codeSectionBytes)

        return out.toByteArray()
    }

    /**
     * Injects a URL string into the WASM module's data section at urlPtr.
     */
    private fun buildWasmWithUrlData(
        url: String,
        urlPtr: Int = 64
    ): ByteArray {
        val baseWasm = buildHttpFetchWasmModule(urlPtr = urlPtr, urlLen = url.toByteArray(Charsets.UTF_8).size)
        // Add data section (id 11) to initialize memory at urlPtr
        val urlBytes = url.toByteArray(Charsets.UTF_8)
        val dataPayload = ByteArrayOutputStream()
        dataPayload.write(0x01) // 1 data segment
        dataPayload.write(0x00) // memory index 0, active segment
        dataPayload.write(0x41) // i32.const
        writeSignedLeb128(dataPayload, urlPtr)
        dataPayload.write(0x0b) // end
        dataPayload.write(urlBytes.size)
        dataPayload.write(urlBytes)

        val dataBytes = dataPayload.toByteArray()
        val fullWasm = ByteArrayOutputStream()
        fullWasm.write(baseWasm)
        fullWasm.write(0x0b) // Section ID 11 (Data)
        fullWasm.write(dataBytes.size)
        fullWasm.write(dataBytes)
        return fullWasm.toByteArray()
    }

    @Test
    fun testSuccessfulOutboundCall_allowlistedExternalDestination(): Unit = runBlocking {
        mockServer.start()
        val port = mockServer.port
        mockServer.enqueue(
            MockResponse()
                .setResponseCode(200)
                .setBody("edge-data-payload-ok")
        )

        val targetUrl = "http://api.edge-compute.org:$port/data"
        val wasmBytecode = buildWasmWithUrlData(targetUrl)

        // Mock DNS mapping api.edge-compute.org to loopback for hermetic test execution
        val mockDns = object : Dns {
            override fun lookup(hostname: String): List<InetAddress> {
                return if (hostname == "api.edge-compute.org") {
                    listOf(InetAddress.getByName("127.0.0.1"))
                } else {
                    listOf(InetAddress.getByName("93.184.216.34"))
                }
            }
        }

        val engine = WasmComputeEngine(
            dns = mockDns,
            allowLoopbackForTesting = true
        )

        val task = TaskSpec.newBuilder()
            .setTaskId("task_egress_success")
            .setEngine(ExecutionEngine.EXECUTION_ENGINE_WASM_WASI)
            .setEgressPolicy(NetworkEgressPolicy.NETWORK_EGRESS_POLICY_ALLOWLIST)
            .addAllowedHostnames("api.edge-compute.org")
            .setMaxEgressBytes(1048576)
            .setTimeoutSeconds(10)
            .setWasmBytecode(ByteString.copyFrom(wasmBytecode))
            .build()

        val result = engine.execute(task)

        assertThat(result.isSuccess).isTrue()
        assertThat(result.exitCode).isEqualTo(0)
        // Function returned HTTP status 200 formatted into stdout
        assertThat(String(result.stdoutBytes, Charsets.UTF_8).trim()).isEqualTo("200")
    }

    @Test
    fun testDeterministicRejection_privateIpSpaces() {
        val guard = WasmNetworkEgressSecurityGuard()

        val privateUrls = listOf(
            "http://10.0.0.1/admin",
            "http://172.16.0.1/internal",
            "http://192.168.1.1/config",
            "http://127.0.0.1:8080/metrics",
            "http://localhost:8080/debug",
            "http://169.254.169.254/latest/meta-data/",
            "http://100.64.0.1/carrier-nat"
        )

        for (url in privateUrls) {
            val exception = assertThrows(SecurityException::class.java) {
                guard.validateOutboundUrl(
                    urlString = url,
                    policy = NetworkEgressPolicy.NETWORK_EGRESS_POLICY_ALLOWLIST,
                    allowedHostnames = listOf("*")
                )
            }
            assertThat(exception.message).contains("disallowed IP")
        }
    }

    @Test
    fun testDeterministicRejection_unlistedHost(): Unit = runBlocking {
        val targetUrl = "https://untrusted-exfiltration.com/leak"
        val wasmBytecode = buildWasmWithUrlData(targetUrl)

        val engine = WasmComputeEngine()

        val task = TaskSpec.newBuilder()
            .setTaskId("task_egress_unlisted")
            .setEngine(ExecutionEngine.EXECUTION_ENGINE_WASM_WASI)
            .setEgressPolicy(NetworkEgressPolicy.NETWORK_EGRESS_POLICY_ALLOWLIST)
            .addAllowedHostnames("api.mycompany.com") // Target host is NOT allowed
            .setTimeoutSeconds(10)
            .setWasmBytecode(ByteString.copyFrom(wasmBytecode))
            .build()

        val result = engine.execute(task)

        assertThat(result.isSuccess).isFalse()
        assertThat(result.errorCode).isEqualTo("SECURITY_VIOLATION")
        assertThat(result.errorMessage).contains("not in allowed_hostnames allowlist")
    }

    @Test
    fun testDeterministicRejection_blockedPolicy(): Unit = runBlocking {
        val targetUrl = "https://api.example.com/data"
        val wasmBytecode = buildWasmWithUrlData(targetUrl)

        val engine = WasmComputeEngine()

        val task = TaskSpec.newBuilder()
            .setTaskId("task_egress_blocked")
            .setEngine(ExecutionEngine.EXECUTION_ENGINE_WASM_WASI)
            .setEgressPolicy(NetworkEgressPolicy.NETWORK_EGRESS_POLICY_BLOCKED) // Policy is blocked
            .addAllowedHostnames("api.example.com")
            .setTimeoutSeconds(10)
            .setWasmBytecode(ByteString.copyFrom(wasmBytecode))
            .build()

        val result = engine.execute(task)

        assertThat(result.isSuccess).isFalse()
        assertThat(result.errorCode).isEqualTo("SECURITY_VIOLATION")
        assertThat(result.errorMessage).contains("disabled by task policy")
    }

    @Test
    fun testRejectionOnMeteredCellularInterface(): Unit = runBlocking {
        val targetUrl = "https://api.example.com/data"
        val wasmBytecode = buildWasmWithUrlData(targetUrl)

        // Engine configured with isMeteredProvider returning true (simulating cellular WAN)
        val engine = WasmComputeEngine(
            isMeteredProvider = { true }
        )

        val task = TaskSpec.newBuilder()
            .setTaskId("task_egress_metered")
            .setEngine(ExecutionEngine.EXECUTION_ENGINE_WASM_WASI)
            .setEgressPolicy(NetworkEgressPolicy.NETWORK_EGRESS_POLICY_ALLOWLIST)
            .addAllowedHostnames("api.example.com")
            .setTimeoutSeconds(10)
            .setWasmBytecode(ByteString.copyFrom(wasmBytecode))
            .build()

        val result = engine.execute(task)

        assertThat(result.isSuccess).isFalse()
        assertThat(result.errorCode).isEqualTo("METERED_NETWORK_REJECTED")
        assertThat(result.errorMessage).contains("metered connection is forbidden")
    }

    @Test
    fun testImmediateCancellationAndSocketTeardownOnMidFlightAbort(): Unit = runBlocking {
        mockServer.start()
        val port = mockServer.port
        mockServer.enqueue(
            MockResponse()
                .setHeadersDelay(10, TimeUnit.SECONDS)
                .setBody("delayed payload")
        )

        val targetUrl = "http://api.edge-compute.org:$port/hang"
        val wasmBytecode = buildWasmWithUrlData(targetUrl)

        val mockDns = object : Dns {
            override fun lookup(hostname: String): List<InetAddress> {
                return listOf(InetAddress.getByName("127.0.0.1"))
            }
        }

        val engine = WasmComputeEngine(
            dns = mockDns,
            allowLoopbackForTesting = true
        )

        val task = TaskSpec.newBuilder()
            .setTaskId("task_egress_abort")
            .setEngine(ExecutionEngine.EXECUTION_ENGINE_WASM_WASI)
            .setEgressPolicy(NetworkEgressPolicy.NETWORK_EGRESS_POLICY_ALLOWLIST)
            .addAllowedHostnames("api.edge-compute.org")
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

        // Allow execution to initiate the HTTP socket connection
        delayMs(150)

        // Cancel job mid-flight (simulating orchestrator cancel_task_ids or FGS timeout)
        val startMs = System.currentTimeMillis()
        job.cancelAndJoin()
        val elapsedMs = System.currentTimeMillis() - startMs

        assertThat(caughtCancellation).isTrue()
        assertThat(elapsedMs).isLessThan(500L)
    }

    @Test
    fun testEgressQuotaExceeded_terminatesConnection(): Unit = runBlocking {
        mockServer.start()
        val port = mockServer.port
        mockServer.enqueue(
            MockResponse()
                .setResponseCode(200)
                .setBody("this-payload-is-far-longer-than-ten-bytes")
        )

        val targetUrl = "http://api.edge-compute.org:$port/large"
        val wasmBytecode = buildWasmWithUrlData(targetUrl)

        val mockDns = object : Dns {
            override fun lookup(hostname: String): List<InetAddress> {
                return listOf(InetAddress.getByName("127.0.0.1"))
            }
        }

        val engine = WasmComputeEngine(
            dns = mockDns,
            allowLoopbackForTesting = true
        )

        val task = TaskSpec.newBuilder()
            .setTaskId("task_egress_quota")
            .setEngine(ExecutionEngine.EXECUTION_ENGINE_WASM_WASI)
            .setEgressPolicy(NetworkEgressPolicy.NETWORK_EGRESS_POLICY_ALLOWLIST)
            .addAllowedHostnames("api.edge-compute.org")
            .setMaxEgressBytes(10) // Strictly limit quota to 10 bytes
            .setTimeoutSeconds(10)
            .setWasmBytecode(ByteString.copyFrom(wasmBytecode))
            .build()

        val result = engine.execute(task)

        assertThat(result.isSuccess).isFalse()
        assertThat(result.errorCode).isEqualTo("SECURITY_VIOLATION")
        assertThat(result.errorMessage).contains("Egress quota exceeded")
    }

    private fun delayMs(ms: Long) {
        try {
            Thread.sleep(ms)
        } catch (_: InterruptedException) {
            Thread.currentThread().interrupt()
        }
    }
}
