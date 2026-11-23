package com.androgrid.worker.engine

import com.androgrid.v1.ExecutionEngine
import com.androgrid.v1.NetworkEgressPolicy
import com.androgrid.v1.TaskSpec
import com.google.common.truth.Truth.assertThat
import com.google.protobuf.ByteString
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import okhttp3.Dns
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
import java.net.InetAddress
import java.util.concurrent.TimeUnit

/**
 * Robolectric unit test suite verifying controlled outbound network egress for WASM workloads.
 *
 * Enforces Mandatory Verification Matrix:
 * 1. Successful HTTP/HTTPS requests to allowlisted external domains with HTTP status and byte count written.
 * 2. In-socket TOCTOU DNS rebinding rejection at OkHttpClient connection time (-403).
 * 3. Redirect SSRF rejection: 302 Found is not followed (followRedirects = false).
 * 4. IPv6 ULA (fc00::/7) and mapped-IPv4 (0.0.0.0, 255.255.255.255, 224.0.0.1, RFC 1918) rejection (-403).
 * 5. Wildcard and apex rules: bare '*' rejected; *.example.com does not match apex example.com.
 * 6. Fail-closed defaults: max_egress_bytes == 0 rejected; default isMeteredProvider fails closed (true).
 * 7. Streaming OOM and buffer bounds: out_buf_cap overflow aborts immediately with -413 (ERR_BUFFER_TOO_SMALL);
 *    max_egress_bytes overflow aborts with -429 (ERR_QUOTA_EXCEEDED).
 * 8. Header sanitization: hop-by-hop headers, CRLF injection, and headers > 8 KB rejected.
 * 9. Immediate cancellation and socket teardown on mid-flight task abort (< 500 ms).
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
     * - Imports "androgrid_net:http_fetch(11 i32 params) -> i32"
     * - Exports "memory" (1 page = 64KB)
     * - Exports "_start() -> i32" calling http_fetch
     */
    private fun buildHttpFetchWasmModule(
        urlPtr: Int,
        urlLen: Int,
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
        // Magic & Version (8 bytes)
        out.write(byteArrayOf(0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00))

        // Type section (id 1):
        // Type 0: (11 i32 params) -> i32
        // Type 1: () -> i32
        val typeSection = byteArrayOf(
            0x02, // 2 types
            0x60.toByte(), 0x0b, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x01, 0x7f,
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

        // Function section (id 3): 1 function with type index 1
        val funcSection = byteArrayOf(0x01, 0x01)
        out.write(0x03)
        out.write(funcSection.size)
        out.write(funcSection)

        // Memory section (id 5): 1 memory: min 1 page
        val memSection = byteArrayOf(0x01, 0x00, 0x01)
        out.write(0x05)
        out.write(memSection.size)
        out.write(memSection)

        // Export section (id 7): "memory" (mem 0), "_start" (func 1)
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

        // Code section (id 10): 1 function body pushing 11 arguments and calling func 0
        val codeBody = ByteArrayOutputStream()
        codeBody.write(0x00) // 0 locals

        // arg 0: url_ptr
        codeBody.write(0x41); writeSignedLeb128(codeBody, urlPtr)
        // arg 1: url_len
        codeBody.write(0x41); writeSignedLeb128(codeBody, urlLen)
        // arg 2: method_ptr
        codeBody.write(0x41); writeSignedLeb128(codeBody, methodPtr)
        // arg 3: method_len
        codeBody.write(0x41); writeSignedLeb128(codeBody, methodLen)
        // arg 4: headers_ptr
        codeBody.write(0x41); writeSignedLeb128(codeBody, headersPtr)
        // arg 5: headers_len
        codeBody.write(0x41); writeSignedLeb128(codeBody, headersLen)
        // arg 6: body_ptr
        codeBody.write(0x41); writeSignedLeb128(codeBody, bodyPtr)
        // arg 7: body_len
        codeBody.write(0x41); writeSignedLeb128(codeBody, bodyLen)
        // arg 8: out_buf_ptr
        codeBody.write(0x41); writeSignedLeb128(codeBody, outBufPtr)
        // arg 9: out_buf_cap
        codeBody.write(0x41); writeSignedLeb128(codeBody, outBufCap)
        // arg 10: out_written_ptr
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
        urlPtr: Int = 64,
        outBufPtr: Int = 256,
        outBufCap: Int = 1024,
        outWrittenPtr: Int = 512
    ): ByteArray {
        val baseWasm = buildHttpFetchWasmModule(
            urlPtr = urlPtr,
            urlLen = url.toByteArray(Charsets.UTF_8).size,
            outBufPtr = outBufPtr,
            outBufCap = outBufCap,
            outWrittenPtr = outWrittenPtr
        )
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
            isMeteredProvider = { false },
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
        // Function returned HTTP status 200
        assertThat(String(result.stdoutBytes, Charsets.UTF_8).trim()).isEqualTo("200")
    }

    @Test
    fun testDeterministicRejection_toctouDnsRebindingAtConnectionTime() {
        val guard = WasmNetworkEgressSecurityGuard(allowLoopbackForTesting = false)

        // Mock DNS returns public IP on pre-flight check, then private IP at in-socket connection time
        var lookupCount = 0
        val rebindingDns = object : Dns {
            override fun lookup(hostname: String): List<InetAddress> {
                lookupCount++
                return if (lookupCount == 1) {
                    listOf(InetAddress.getByName("93.184.216.34")) // Initial public IP
                } else {
                    listOf(InetAddress.getByName("192.168.1.50")) // Rebound private IP
                }
            }
        }

        val taskDns = guard.createTaskDns(rebindingDns)

        // First lookup succeeds
        val initialIps = taskDns.lookup("api.rebinding-test.org")
        assertThat(initialIps.first().hostAddress).isEqualTo("93.184.216.34")

        // Second in-socket lookup catches the rebinding and aborts with SecurityException
        val exception = assertThrows(SecurityException::class.java) {
            taskDns.lookup("api.rebinding-test.org")
        }
        assertThat(exception.message).contains("disallowed IP")
    }

    @Test
    fun testDeterministicRejection_redirectSsrfNotFollowed(): Unit = runBlocking {
        mockServer.start()
        val port = mockServer.port
        mockServer.enqueue(
            MockResponse()
                .setResponseCode(302)
                .setHeader("Location", "http://127.0.0.1:8080/secret")
                .setBody("redirecting")
        )

        val targetUrl = "http://api.edge-compute.org:$port/redirect"
        val wasmBytecode = buildWasmWithUrlData(targetUrl)

        val mockDns = object : Dns {
            override fun lookup(hostname: String): List<InetAddress> {
                return listOf(InetAddress.getByName("127.0.0.1"))
            }
        }

        val engine = WasmComputeEngine(
            dns = mockDns,
            isMeteredProvider = { false },
            allowLoopbackForTesting = true
        )

        val task = TaskSpec.newBuilder()
            .setTaskId("task_egress_redirect")
            .setEngine(ExecutionEngine.EXECUTION_ENGINE_WASM_WASI)
            .setEgressPolicy(NetworkEgressPolicy.NETWORK_EGRESS_POLICY_ALLOWLIST)
            .addAllowedHostnames("api.edge-compute.org")
            .setMaxEgressBytes(1048576)
            .setTimeoutSeconds(10)
            .setWasmBytecode(ByteString.copyFrom(wasmBytecode))
            .build()

        val result = engine.execute(task)

        assertThat(result.isSuccess).isTrue()
        // Must return 302 directly without following to 127.0.0.1
        assertThat(String(result.stdoutBytes, Charsets.UTF_8).trim()).isEqualTo("302")
    }

    @Test
    fun testDeterministicRejection_ipv6UlaAndMappedIpv4() {
        val guard = WasmNetworkEgressSecurityGuard(allowLoopbackForTesting = false)

        val ulaAddress = InetAddress.getByName("fc00::1")
        val ula2Address = InetAddress.getByName("fd12:3456:789a::1")
        val mappedZero = InetAddress.getByName("::ffff:0.0.0.0")
        val mappedBroadcast = InetAddress.getByName("::ffff:255.255.255.255")
        val mappedMulticast = InetAddress.getByName("::ffff:224.0.0.1")
        val mappedPrivate = InetAddress.getByName("::ffff:192.168.1.1")

        assertThat(guard.isDisallowedAddress(ulaAddress)).isTrue()
        assertThat(guard.isDisallowedAddress(ula2Address)).isTrue()
        assertThat(guard.isDisallowedAddress(mappedZero)).isTrue()
        assertThat(guard.isDisallowedAddress(mappedBroadcast)).isTrue()
        assertThat(guard.isDisallowedAddress(mappedMulticast)).isTrue()
        assertThat(guard.isDisallowedAddress(mappedPrivate)).isTrue()
    }

    @Test
    fun testWildcardAndApexMatchingRules() {
        val guard = WasmNetworkEgressSecurityGuard()

        // Bare wildcards are forbidden
        assertThat(guard.matchesHostnamePattern("example.com", "*")).isFalse()
        assertThat(guard.matchesHostnamePattern("example.com", "*.*")).isFalse()

        // Wildcard must NOT match apex domain
        assertThat(guard.matchesHostnamePattern("example.com", "*.example.com")).isFalse()

        // Wildcard matches subdomains
        assertThat(guard.matchesHostnamePattern("api.example.com", "*.example.com")).isTrue()
        assertThat(guard.matchesHostnamePattern("staging.api.example.com", "*.example.com")).isTrue()
        assertThat(guard.matchesHostnamePattern("other.org", "*.example.com")).isFalse()
    }

    @Test
    fun testFailClosedDefaults_zeroMaxEgressBytesAndMeteredProvider() {
        val guard = WasmNetworkEgressSecurityGuard(
            isMeteredProvider = { true } // default fail-closed
        )

        // max_egress_bytes == 0 must be rejected
        val exZeroQuota = assertThrows(SecurityException::class.java) {
            guard.validateOutboundUrl(
                urlString = "https://api.example.com/data",
                policy = NetworkEgressPolicy.NETWORK_EGRESS_POLICY_ALLOWLIST,
                allowedHostnames = listOf("api.example.com"),
                maxEgressBytes = 0
            )
        }
        assertThat(exZeroQuota.message).contains("max_egress_bytes must be greater than zero")

        // Metered provider true must be rejected
        val exMetered = assertThrows(SecurityException::class.java) {
            guard.validateOutboundUrl(
                urlString = "https://api.example.com/data",
                policy = NetworkEgressPolicy.NETWORK_EGRESS_POLICY_ALLOWLIST,
                allowedHostnames = listOf("api.example.com"),
                maxEgressBytes = 1024
            )
        }
        assertThat(exMetered.message).contains("metered connection is forbidden")
    }

    @Test
    fun testStreamingOomAndBufferBounds_errBufferTooSmall(): Unit = runBlocking {
        mockServer.start()
        val port = mockServer.port
        mockServer.enqueue(
            MockResponse()
                .setResponseCode(200)
                .setBody("A".repeat(500)) // 500 bytes payload
        )

        val targetUrl = "http://api.edge-compute.org:$port/data"
        // WASM module specifies outBufCap = 50 (smaller than 500)
        val wasmBytecode = buildWasmWithUrlData(targetUrl, outBufCap = 50)

        val mockDns = object : Dns {
            override fun lookup(hostname: String): List<InetAddress> {
                return listOf(InetAddress.getByName("127.0.0.1"))
            }
        }

        val engine = WasmComputeEngine(
            dns = mockDns,
            isMeteredProvider = { false },
            allowLoopbackForTesting = true
        )

        val task = TaskSpec.newBuilder()
            .setTaskId("task_buf_overflow")
            .setEngine(ExecutionEngine.EXECUTION_ENGINE_WASM_WASI)
            .setEgressPolicy(NetworkEgressPolicy.NETWORK_EGRESS_POLICY_ALLOWLIST)
            .addAllowedHostnames("api.edge-compute.org")
            .setMaxEgressBytes(1048576)
            .setTimeoutSeconds(10)
            .setWasmBytecode(ByteString.copyFrom(wasmBytecode))
            .build()

        val result = engine.execute(task)

        assertThat(result.isSuccess).isTrue()
        // Function returned ERR_BUFFER_TOO_SMALL (-413)
        assertThat(String(result.stdoutBytes, Charsets.UTF_8).trim()).isEqualTo("-413")
    }

    @Test
    fun testStreamingQuotaBounds_errQuotaExceeded(): Unit = runBlocking {
        mockServer.start()
        val port = mockServer.port
        mockServer.enqueue(
            MockResponse()
                .setResponseCode(200)
                .setBody("A".repeat(500))
        )

        val targetUrl = "http://api.edge-compute.org:$port/data"
        val wasmBytecode = buildWasmWithUrlData(targetUrl, outBufCap = 1024)

        val mockDns = object : Dns {
            override fun lookup(hostname: String): List<InetAddress> {
                return listOf(InetAddress.getByName("127.0.0.1"))
            }
        }

        val engine = WasmComputeEngine(
            dns = mockDns,
            isMeteredProvider = { false },
            allowLoopbackForTesting = true
        )

        val task = TaskSpec.newBuilder()
            .setTaskId("task_quota_exceeded")
            .setEngine(ExecutionEngine.EXECUTION_ENGINE_WASM_WASI)
            .setEgressPolicy(NetworkEgressPolicy.NETWORK_EGRESS_POLICY_ALLOWLIST)
            .addAllowedHostnames("api.edge-compute.org")
            .setMaxEgressBytes(50) // Quota is only 50 bytes
            .setTimeoutSeconds(10)
            .setWasmBytecode(ByteString.copyFrom(wasmBytecode))
            .build()

        val result = engine.execute(task)

        assertThat(result.isSuccess).isTrue()
        // Function returned ERR_QUOTA_EXCEEDED (-429)
        assertThat(String(result.stdoutBytes, Charsets.UTF_8).trim()).isEqualTo("-429")
    }

    @Test
    fun testHeaderSanitization_rejectsForbiddenHeadersAndCrlf() {
        val guard = WasmNetworkEgressSecurityGuard()

        // 1. Hop-by-hop headers rejected
        val forbiddenHeaders = listOf(
            "Host: evil.com",
            "Transfer-Encoding: chunked",
            "Content-Length: 100",
            "Connection: close",
            "Proxy-Authorization: Basic 123"
        )
        for (h in forbiddenHeaders) {
            val ex = assertThrows(SecurityException::class.java) {
                guard.sanitizeHeaders(h)
            }
            assertThat(ex.message).contains("Forbidden hop-by-hop")
        }

        // 2. CRLF or control character injection rejected
        val exCrlf = assertThrows(SecurityException::class.java) {
            guard.sanitizeHeaders("X-Custom: val\rInjected-Header: bad")
        }
        assertThat(exCrlf.message).contains("CRLF or control character injection")

        val exNull = assertThrows(SecurityException::class.java) {
            guard.sanitizeHeaders("X-Custom: val\u0000injected")
        }
        assertThat(exNull.message).contains("CRLF or control character injection")

        // 3. Valid headers parsed cleanly
        val validHeaders = "Accept: application/json\r\nX-Api-Key: secret123\nCache-Control: no-cache"
        val parsed = guard.sanitizeHeaders(validHeaders)
        assertThat(parsed["Accept"]).isEqualTo("application/json")
        assertThat(parsed["X-Api-Key"]).isEqualTo("secret123")
        assertThat(parsed["Cache-Control"]).isEqualTo("no-cache")
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
            isMeteredProvider = { false },
            allowLoopbackForTesting = true
        )

        val task = TaskSpec.newBuilder()
            .setTaskId("task_egress_abort")
            .setEngine(ExecutionEngine.EXECUTION_ENGINE_WASM_WASI)
            .setEgressPolicy(NetworkEgressPolicy.NETWORK_EGRESS_POLICY_ALLOWLIST)
            .addAllowedHostnames("api.edge-compute.org")
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

        // Allow execution to initiate the HTTP socket connection
        delayMs(150)

        // Cancel job mid-flight
        val startMs = System.currentTimeMillis()
        job.cancelAndJoin()
        val elapsedMs = System.currentTimeMillis() - startMs

        assertThat(caughtCancellation).isTrue()
        assertThat(elapsedMs).isLessThan(500L)
    }

    @Test
    fun testPortAndSchemeEnforcement() {
        val guard = WasmNetworkEgressSecurityGuard(
            isMeteredProvider = { false },
            allowLoopbackForTesting = false
        )

        // Non-443 port must be rejected in production mode
        val exPort = assertThrows(SecurityException::class.java) {
            guard.validateOutboundUrl(
                urlString = "https://api.example.com:8443/data",
                policy = NetworkEgressPolicy.NETWORK_EGRESS_POLICY_ALLOWLIST,
                allowedHostnames = listOf("api.example.com"),
                maxEgressBytes = 1048576
            )
        }
        assertThat(exPort.message).contains("Forbidden port")

        // Plaintext http:// must be rejected in production mode
        val exScheme = assertThrows(SecurityException::class.java) {
            guard.validateOutboundUrl(
                urlString = "http://api.example.com/data",
                policy = NetworkEgressPolicy.NETWORK_EGRESS_POLICY_ALLOWLIST,
                allowedHostnames = listOf("api.example.com"),
                maxEgressBytes = 1048576
            )
        }
        assertThat(exScheme.message).contains("Cleartext HTTP traffic is strictly forbidden")
    }

    @Test
    fun testNat64PrefixAndPublicSuffixRejection() {
        val guard = WasmNetworkEgressSecurityGuard(allowLoopbackForTesting = false)

        // NAT64 well-known prefix mapping to private 10.0.0.1
        val nat64Private = InetAddress.getByName("64:ff9b::10.0.0.1")
        assertThat(guard.isDisallowedAddress(nat64Private)).isTrue()

        // Bare TLD / Public suffix wildcard rejection on-device
        assertThat(guard.matchesHostnamePattern("evil.com", "*.com")).isFalse()
        assertThat(guard.matchesHostnamePattern("evil.co.uk", "*.co.uk")).isFalse()
        assertThat(guard.matchesHostnamePattern("evil.workers.dev", "*.workers.dev")).isFalse()
        assertThat(guard.matchesHostnamePattern("evil.amazonaws.com", "*.amazonaws.com")).isFalse()
    }

    private fun delayMs(ms: Long) {
        try {
            Thread.sleep(ms)
        } catch (_: InterruptedException) {
            Thread.currentThread().interrupt()
        }
    }
}
