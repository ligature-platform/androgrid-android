package com.androgrid.worker.engine

import com.androgrid.v1.TaskSpec
import com.dylibso.chicory.runtime.HostFunction
import com.dylibso.chicory.runtime.Instance
import com.dylibso.chicory.wasm.types.FunctionType
import com.dylibso.chicory.wasm.types.ValType
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.InternalCoroutinesApi
import kotlinx.coroutines.Job
import okhttp3.Call
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import java.io.IOException
import java.util.concurrent.atomic.AtomicLong
import java.util.concurrent.atomic.AtomicReference

/**
 * Host function module exporting controlled outbound network egress functions (`androgrid_net`)
 * into the in-memory Chicory WebAssembly runtime environment.
 *
 * Exposes:
 * - `androgrid_net:http_fetch(url_ptr, url_len, method_ptr, method_len, body_ptr, body_len, out_buf_ptr, out_buf_cap, out_written_ptr) -> i32`
 * - `androgrid_net:http_get(url_ptr, url_len, out_buf_ptr, out_buf_cap, out_written_ptr) -> i32`
 *
 * Enforces:
 * 1. Allowlist and SSRF verification via [WasmNetworkEgressSecurityGuard].
 * 2. Cumulative egress transfer quotas ([TaskSpec.getMaxEgressBytes]).
 * 3. 16 MB maximum message frame limits ([NFR-PERF-001]).
 * 4. Structured cooperative coroutine cancellation hooks to prevent worker thread hanging.
 *
 * Traces to: [INV-001], [INV-003], [INV-006], [ANTI-003], [NFR-SEC-001], [NFR-POW-001], [NFR-PERF-001], ADR-011
 */
class WasmNetworkEgressHostModule(
    private val task: TaskSpec,
    private val securityGuard: WasmNetworkEgressSecurityGuard,
    private val okHttpClient: OkHttpClient,
    private val executionJob: Job? = null
) {

    private val cumulativeBytesTransferred = AtomicLong(0L)

    companion object {
        const val MODULE_NAME = "androgrid_net"
        const val ERR_IO_FAILURE = -1
        const val ERR_SECURITY_VIOLATION = -403
        const val ERR_QUOTA_EXCEEDED = -429
    }

    /**
     * Constructs and returns the host functions to be registered with the Chicory Store.
     *
     * @return Array of [HostFunction] definitions for the `androgrid_net` module.
     */
    fun toHostFunctions(): Array<HostFunction> {
        val httpFetch = HostFunction(
            MODULE_NAME,
            "http_fetch",
            FunctionType.of(
                listOf(
                    ValType.I32, // 0: url_ptr
                    ValType.I32, // 1: url_len
                    ValType.I32, // 2: method_ptr
                    ValType.I32, // 3: method_len
                    ValType.I32, // 4: body_ptr
                    ValType.I32, // 5: body_len
                    ValType.I32, // 6: out_buf_ptr
                    ValType.I32, // 7: out_buf_cap
                    ValType.I32  // 8: out_written_ptr
                ),
                listOf(ValType.I32) // return status code
            )
        ) { instance, args ->
            val result = executeHttpFetch(
                instance = instance,
                urlPtr = args[0].toInt(),
                urlLen = args[1].toInt(),
                methodPtr = args[2].toInt(),
                methodLen = args[3].toInt(),
                bodyPtr = args[4].toInt(),
                bodyLen = args[5].toInt(),
                outBufPtr = args[6].toInt(),
                outBufCap = args[7].toInt(),
                outWrittenPtr = args[8].toInt()
            )
            longArrayOf(result.toLong())
        }

        val httpGet = HostFunction(
            MODULE_NAME,
            "http_get",
            FunctionType.of(
                listOf(
                    ValType.I32, // 0: url_ptr
                    ValType.I32, // 1: url_len
                    ValType.I32, // 2: out_buf_ptr
                    ValType.I32, // 3: out_buf_cap
                    ValType.I32  // 4: out_written_ptr
                ),
                listOf(ValType.I32) // return status code
            )
        ) { instance, args ->
            val result = executeHttpFetch(
                instance = instance,
                urlPtr = args[0].toInt(),
                urlLen = args[1].toInt(),
                methodPtr = 0,
                methodLen = 0,
                bodyPtr = 0,
                bodyLen = 0,
                outBufPtr = args[2].toInt(),
                outBufCap = args[3].toInt(),
                outWrittenPtr = args[4].toInt()
            )
            longArrayOf(result.toLong())
        }

        return arrayOf(httpFetch, httpGet)
    }

    /**
     * Executes the HTTP request from WASM memory arguments with full security and quota checks.
     */
    @OptIn(InternalCoroutinesApi::class)
    private fun executeHttpFetch(
        instance: Instance,
        urlPtr: Int,
        urlLen: Int,
        methodPtr: Int,
        methodLen: Int,
        bodyPtr: Int,
        bodyLen: Int,
        outBufPtr: Int,
        outBufCap: Int,
        outWrittenPtr: Int
    ): Int {
        val memory = instance.memory()

        // 1. Read destination URL from WASM linear memory
        if (urlLen <= 0) {
            throw IllegalArgumentException("Invalid URL length: $urlLen")
        }
        val urlString = memory.readString(urlPtr, urlLen)

        // 2. Read HTTP method (default to GET)
        val method = if (methodLen > 0) {
            memory.readString(methodPtr, methodLen).trim().uppercase()
        } else {
            "GET"
        }

        // 3. Read request body bytes if present
        val requestBodyBytes = if (bodyLen > 0) {
            memory.readBytes(bodyPtr, bodyLen)
        } else {
            ByteArray(0)
        }

        // 4. Validate URL, scheme, allowlist, metered state, and SSRF addresses
        val validatedUrl = securityGuard.validateOutboundUrl(
            urlString = urlString,
            policy = task.egressPolicy,
            allowedHostnames = task.allowedHostnamesList
        )

        // 5. Enforce max_egress_bytes transfer quota for request body
        val maxQuota = task.maxEgressBytes
        val reqBytes = requestBodyBytes.size.toLong()
        if (maxQuota > 0 && cumulativeBytesTransferred.get() + reqBytes > maxQuota) {
            throw SecurityException(
                "Egress quota exceeded: request body ($reqBytes bytes) exceeds remaining max_egress_bytes quota ($maxQuota)"
            )
        }
        cumulativeBytesTransferred.addAndGet(reqBytes)

        // 6. Build OkHttp request
        val okRequestBody = if (method in listOf("POST", "PUT", "PATCH")) {
            requestBodyBytes.toRequestBody(null)
        } else {
            null
        }

        val request = Request.Builder()
            .url(validatedUrl)
            .method(method, okRequestBody)
            .build()

        val callRef = AtomicReference<Call?>(null)
        val call = okHttpClient.newCall(request)
        callRef.set(call)

        // 7. Attach structured cancellation hook to enclosing coroutine Job
        val completionHandle = executionJob?.invokeOnCompletion(onCancelling = true) { cause ->
            if (cause != null) {
                callRef.get()?.cancel()
            }
        }

        return try {
            call.execute().use { response ->
                val statusCode = response.code
                val responseBytes = response.body?.bytes() ?: ByteArray(0)

                // Enforce [NFR-PERF-001] 16 MB frame limit
                if (responseBytes.size > WasmComputeEngine.MAX_FRAME_SIZE_BYTES) {
                    throw IllegalStateException(
                        "Response payload size (${responseBytes.size} bytes) exceeds maximum 16 MB frame limit [NFR-PERF-001]"
                    )
                }

                // Check quota for incoming response bytes
                val respBytesLen = responseBytes.size.toLong()
                if (maxQuota > 0 && cumulativeBytesTransferred.get() + respBytesLen > maxQuota) {
                    throw SecurityException(
                        "Egress quota exceeded: response payload ($respBytesLen bytes) exceeds max_egress_bytes quota ($maxQuota)"
                    )
                }
                cumulativeBytesTransferred.addAndGet(respBytesLen)

                // Write response bytes into WASM output buffer up to out_buf_cap
                val bytesToWrite = responseBytes.size.coerceAtMost(outBufCap)
                if (bytesToWrite > 0 && outBufPtr != 0) {
                    memory.write(outBufPtr, responseBytes, 0, bytesToWrite)
                }

                // Write actual written bytes count to out_written_ptr if non-zero
                if (outWrittenPtr != 0) {
                    memory.writeI32(outWrittenPtr, bytesToWrite)
                }

                statusCode
            }
        } catch (e: IOException) {
            if (call.isCanceled() || executionJob?.isActive == false) {
                throw CancellationException("WASM outbound network request cancelled", e)
            }
            ERR_IO_FAILURE
        } finally {
            completionHandle?.dispose()
            callRef.set(null)
        }
    }
}
