package com.androgrid.worker.wasm

import com.dylibso.chicory.runtime.HostFunction
import com.dylibso.chicory.runtime.Instance
import com.dylibso.chicory.runtime.Store
import com.dylibso.chicory.wasm.Parser
import com.dylibso.chicory.wasm.types.FunctionType
import com.dylibso.chicory.wasm.types.ValType
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
import okhttp3.HttpUrl.Companion.toHttpUrlOrNull
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import org.junit.After
import org.junit.Assert.assertThrows
import org.junit.Before
import org.junit.Test
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.net.InetAddress
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger

/**
 * Empirical technical spike validating Chicory host function bridges for sandboxed outbound network access.
 *
 * Verifies two critical architectural behaviors:
 * 1. Security Guard: Deterministic rejection of private IP spaces (RFC 1918 10.0.0.0/8, 172.16.0.0/12,
 *    192.168.0.0/16), loopback (127.0.0.1, ::1), and link-local addresses (169.254.0.0/16) before any socket
 *    connection is attempted.
 * 2. Cancellation Integration: Immediate abort of in-flight network requests when the enclosing coroutine job
 *    is cancelled via structured hooks (executionJob?.invokeOnCompletion { call.cancel() }), preventing hangs.
 *
 * Traces to: [INV-006], [ANTI-003], [NFR-SEC-001], [NFR-POW-001]
 */
class WasmNetworkEgressSpikeTest {

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
     * Inspects target IP address to enforce SSRF and LAN isolation.
     * Rejects RFC 1918, loopback, link-local, carrier-grade NAT, and unspecified addresses.
     */
    private fun isDisallowedAddress(addr: InetAddress): Boolean {
        if (addr.isLoopbackAddress || addr.isSiteLocalAddress || addr.isLinkLocalAddress || addr.isAnyLocalAddress || addr.isMulticastAddress) {
            return true
        }
        val raw = addr.address
        if (raw.size == 4) {
            val b0 = raw[0].toInt() and 0xFF
            val b1 = raw[1].toInt() and 0xFF
            // RFC 6598 Carrier-Grade NAT (100.64.0.0/10: 100.64.0.0 to 100.127.255.255)
            if (b0 == 100 && b1 in 64..127) {
                return true
            }
        }
        return false
    }

    /**
     * Validates destination URL and resolved IPs before establishing any transport connection.
     *
     * @param urlString Destination HTTP/HTTPS URL.
     * @param dns Custom DNS resolver for hermetic validation.
     * @throws SecurityException If URL targets private, loopback, or link-local address.
     */
    private fun validateOutboundUrl(urlString: String, dns: Dns = Dns.SYSTEM) {
        val httpUrl = urlString.toHttpUrlOrNull()
            ?: throw IllegalArgumentException("Malformed URL: $urlString")

        val scheme = httpUrl.scheme.lowercase()
        if (scheme != "http" && scheme != "https") {
            throw SecurityException("Forbidden scheme '$scheme'. Only HTTP and HTTPS are permitted.")
        }

        val host = httpUrl.host
        val resolvedAddresses = dns.lookup(host)
        if (resolvedAddresses.isEmpty()) {
            throw SecurityException("Unable to resolve host '$host'")
        }

        for (addr in resolvedAddresses) {
            if (isDisallowedAddress(addr)) {
                throw SecurityException(
                    "Deterministic rejection: Host '$host' resolved to disallowed IP ${addr.hostAddress} (RFC 1918 / Loopback / Link-Local guard)"
                )
            }
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
     * - Imports "androgrid_net:http_fetch(url_ptr: i32, url_len: i32) -> i32"
     * - Exports "memory" (1 page)
     * - Exports "_start() -> i32" which calls http_fetch with provided urlPtr and urlLen
     */
    private fun buildSpikeWasmModule(urlPtr: Int, urlLen: Int): ByteArray {
        val out = ByteArrayOutputStream()
        // Magic & Version (8 bytes)
        out.write(byteArrayOf(0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00))

        // Type section (id 1):
        // Type 0: (i32, i32) -> i32
        // Type 1: () -> i32
        val typeSection = byteArrayOf(
            0x02, // count = 2
            0x60.toByte(), 0x02, 0x7f, 0x7f, 0x01, 0x7f,
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
        importPayload.write(0x01) // count = 1
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
        exportPayload.write(0x02) // count = 2
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
        // 1 function body: locals count 0, i32.const urlPtr, i32.const urlLen, call 0, end
        val codeBody = ByteArrayOutputStream()
        codeBody.write(0x00) // 0 locals
        codeBody.write(0x41) // i32.const
        writeSignedLeb128(codeBody, urlPtr)
        codeBody.write(0x41) // i32.const
        writeSignedLeb128(codeBody, urlLen)
        codeBody.write(0x10) // call
        codeBody.write(0x00) // func 0 (imported http_fetch)
        codeBody.write(0x0b) // end

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

    @Test
    fun testSecurityGuard_rejectsLoopbackAndPrivateIpSpaces() {
        val privateUrls = listOf(
            "http://127.0.0.1:8080/metrics",
            "http://localhost:8080/status",
            "http://10.0.0.1/admin",
            "http://172.16.0.5/api/v1/internal",
            "http://192.168.1.1:80/router",
            "http://169.254.169.254/latest/meta-data/",
            "http://100.64.0.1/carrier-nat"
        )

        for (targetUrl in privateUrls) {
            val exception = assertThrows(SecurityException::class.java) {
                validateOutboundUrl(targetUrl)
            }
            assertThat(exception.message).contains("disallowed IP")
        }
    }

    @Test
    fun testSecurityGuard_rejectsDnsRebindingToPrivateIp() {
        // Mock DNS resolver simulating DNS rebinding to RFC 1918 private address
        val fakeDns = object : Dns {
            override fun lookup(hostname: String): List<InetAddress> {
                return when (hostname) {
                    "api.external-public.com" -> listOf(InetAddress.getByName("192.168.1.50"))
                    else -> listOf(InetAddress.getByName("8.8.8.8"))
                }
            }
        }

        val exception = assertThrows(SecurityException::class.java) {
            validateOutboundUrl("https://api.external-public.com/data", fakeDns)
        }
        assertThat(exception.message).contains("disallowed IP")
    }

    @Test
    fun testSecurityGuard_allowsLegitimatePublicDestination() {
        val publicDns = object : Dns {
            override fun lookup(hostname: String): List<InetAddress> {
                return listOf(InetAddress.getByName("93.184.216.34")) // example.com public IP
            }
        }

        // Should not throw SecurityException
        validateOutboundUrl("https://api.example.com/v1/tasks", publicDns)
    }

    @Test
    fun testChicoryHostFunction_invokesOutboundBridgeFromWasm() {
        val testUrl = "https://api.androgrid.org/ping"
        val urlBytes = testUrl.toByteArray(Charsets.UTF_8)
        val urlPtr = 64
        val urlLen = urlBytes.size

        val wasmBytes = buildSpikeWasmModule(urlPtr = urlPtr, urlLen = urlLen)
        val module = Parser.parse(wasmBytes)

        val capturedUrl = AtomicBoolean(false)
        val hostFetch = HostFunction(
            "androgrid_net",
            "http_fetch",
            FunctionType.of(listOf(ValType.I32, ValType.I32), listOf(ValType.I32))
        ) { instance, args ->
            val mem = instance.memory()
            val ptr = args[0].toInt()
            val len = args[1].toInt()
            val extractedString = mem.readString(ptr, len)

            if (extractedString == testUrl) {
                capturedUrl.set(true)
            }
            longArrayOf(200L) // HTTP 200
        }

        val store = Store().addFunction(hostFetch)
        val instance = Instance.builder(module)
            .withStart(false)
            .withImportValues(store.toImportValues())
            .build()

        // Write test URL into Chicory WASM memory at urlPtr
        instance.memory().writeString(urlPtr, testUrl)

        // Invoke exported _start
        val startFunc = instance.export("_start")
        val result = startFunc.apply()

        assertThat(capturedUrl.get()).isTrue()
        assertThat(result).hasLength(1)
        assertThat(result[0]).isEqualTo(200L)
    }

    @OptIn(kotlinx.coroutines.InternalCoroutinesApi::class)
    @Test
    fun testCancellationIntegration_abortsInFlightRequestCleanly(): Unit = runBlocking {
        mockServer.start()
        val mockBaseUrl = mockServer.url("/delay").toString()

        // Enqueue delayed response
        mockServer.enqueue(
            MockResponse()
                .setBody("delayed payload")
                .setBodyDelay(5, TimeUnit.SECONDS)
        )

        val client = OkHttpClient.Builder()
            .connectTimeout(5, TimeUnit.SECONDS)
            .readTimeout(5, TimeUnit.SECONDS)
            .build()

        val callCancelled = AtomicBoolean(false)
        val requestStarted = CompletableDeferred<Unit>()
        val connectionAborted = CompletableDeferred<Unit>()

        val activeCallRef = java.util.concurrent.atomic.AtomicReference<Call?>(null)

        val job: Job = CoroutineScope(Dispatchers.IO).launch {
            val request = Request.Builder()
                .url(mockBaseUrl)
                .build()

            val call = client.newCall(request)
            activeCallRef.set(call)

            try {
                requestStarted.complete(Unit)
                call.execute().use { response ->
                    response.body?.string()
                }
            } catch (e: IOException) {
                if (call.isCanceled()) {
                    connectionAborted.complete(Unit)
                }
            }
        }

        // Register cancellation hook attached to this job with onCancelling = true
        val handle = job.invokeOnCompletion(onCancelling = true) { cause ->
            if (cause != null) {
                activeCallRef.get()?.cancel()
                callCancelled.set(true)
            }
        }

        // Wait for request to start in background
        withTimeout(2000) {
            requestStarted.await()
        }

        // Give socket a brief moment to connect
        delayMs(50)

        // Measure time taken to abort when coroutine job is cancelled
        val cancelStartMs = System.currentTimeMillis()
        job.cancelAndJoin()
        val cancelDurationMs = System.currentTimeMillis() - cancelStartMs
        handle.dispose()

        // Assert structured cancellation terminated immediately without waiting for 5s delay
        assertThat(callCancelled.get()).isTrue()
        assertThat(connectionAborted.isCompleted).isTrue()
        assertThat(cancelDurationMs).isLessThan(500L)
    }

    @OptIn(kotlinx.coroutines.InternalCoroutinesApi::class)
    @Test
    fun testCancellationIntegration_preventsHangsOnOrchestratorPreemption(): Unit = runBlocking {
        mockServer.start()
        val mockBaseUrl = mockServer.url("/hang").toString()

        // Server hangs indefinitely on headers or body
        mockServer.enqueue(
            MockResponse()
                .setHeadersDelay(10, TimeUnit.SECONDS)
                .setBody("hang payload")
        )

        val client = OkHttpClient.Builder()
            .readTimeout(30, TimeUnit.SECONDS)
            .build()

        val activeCallRef = AtomicInteger(0)
        val abortedRef = AtomicBoolean(false)
        val inFlightCallRef = java.util.concurrent.atomic.AtomicReference<Call?>(null)
        val preemptionStarted = CompletableDeferred<Unit>()

        val computeJob = CoroutineScope(Dispatchers.IO).launch {
            val call = client.newCall(Request.Builder().url(mockBaseUrl).build())
            inFlightCallRef.set(call)
            activeCallRef.incrementAndGet()

            try {
                preemptionStarted.complete(Unit)
                call.execute().use { response ->
                    response.body?.string()
                }
            } catch (t: Throwable) {
                if (call.isCanceled() || t is IOException) {
                    abortedRef.set(true)
                }
            }
        }

        // Simulate WasmComputeEngine structured cancellation hook with onCancelling = true
        val handle = computeJob.invokeOnCompletion(onCancelling = true) { cause ->
            if (cause != null) {
                inFlightCallRef.get()?.cancel()
            }
        }

        // Wait deterministically for request to begin
        withTimeout(2000) {
            preemptionStarted.await()
        }
        delayMs(50)

        // Simulate WorkerForegroundService or orchestrator preemption cancellation
        val startMs = System.currentTimeMillis()
        computeJob.cancelAndJoin()
        val elapsedMs = System.currentTimeMillis() - startMs
        handle.dispose()

        assertThat(abortedRef.get()).isTrue()
        assertThat(elapsedMs).isLessThan(500L)
    }

    private fun delayMs(ms: Long) {
        try {
            Thread.sleep(ms)
        } catch (_: InterruptedException) {
            Thread.currentThread().interrupt()
        }
    }
}
