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
import okio.Buffer
import java.io.IOException
import java.util.concurrent.atomic.AtomicLong
import java.util.concurrent.atomic.AtomicReference

/**
 * Host function module exporting controlled outbound network egress functions (`androgrid_net`)
 * into the in-memory Chicory WebAssembly runtime environment.
 *
 * Exposes:
 * - `androgrid_net:http_fetch(url_ptr, url_len, method_ptr, method_len, headers_ptr, headers_len, body_ptr, body_len, out_buf_ptr, out_buf_cap, out_written_ptr) -> i32`
 * - `androgrid_net:http_get(url_ptr, url_len, out_buf_ptr, out_buf_cap, out_written_ptr) -> i32`
 *
 * Enforces:
 * 1. Allowlist, DNS TOCTOU, and SSRF verification via [WasmNetworkEgressSecurityGuard].
 * 2. Cumulative egress transfer quotas ([TaskSpec.getMaxEgressBytes]).
 * 3. 16 MB maximum message frame limits ([NFR-PERF-001]).
 * 4. Okio bounded chunk streaming to prevent JVM heap exhaustion without silent truncation.
 * 5. Structured cooperative coroutine cancellation hooks to prevent worker thread hanging.
 * 6. Standardized ABI: returns HTTP status code (>= 100) on success, or fixed negative error codes.
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

    // Derive a per-task child client with in-socket Dns and disabled redirects
    private val taskClient: OkHttpClient = okHttpClient.newBuilder()
        .proxy(java.net.Proxy.NO_PROXY)
        .dns(securityGuard.createTaskDns())
        .followRedirects(false)
        .followSslRedirects(false)
        .connectTimeout(minOf(10L, effectiveTimeoutSec()), java.util.concurrent.TimeUnit.SECONDS)
        .readTimeout(minOf(15L, effectiveTimeoutSec()), java.util.concurrent.TimeUnit.SECONDS)
        .writeTimeout(minOf(15L, effectiveTimeoutSec()), java.util.concurrent.TimeUnit.SECONDS)
        .callTimeout(minOf(30L, effectiveTimeoutSec()), java.util.concurrent.TimeUnit.SECONDS)
        .build()

    private fun effectiveTimeoutSec(): Long =
        if (task.timeoutSeconds > 0) task.timeoutSeconds.toLong() else 30L

    companion object {
        const val MODULE_NAME = "androgrid_net"

        // Maximum cumulative egress quota per task attempt (64 MB)
        const val MAX_TASK_EGRESS_BYTES: Long = 64L * 1024 * 1024

        // Fixed negative error code return enum per ADR-011
        const val ERR_IO_FAILURE = -1
        const val ERR_SECURITY_VIOLATION = -403
        const val ERR_BUFFER_TOO_SMALL = -413
        const val ERR_QUOTA_EXCEEDED = -429

        val ALLOWED_METHODS: Set<String> = setOf("GET", "HEAD", "POST", "PUT", "PATCH", "DELETE")

        private const val STREAM_CHUNK_SIZE: Long = 8192
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
                    ValType.I32, // 4: headers_ptr
                    ValType.I32, // 5: headers_len
                    ValType.I32, // 6: body_ptr
                    ValType.I32, // 7: body_len
                    ValType.I32, // 8: out_buf_ptr
                    ValType.I32, // 9: out_buf_cap
                    ValType.I32  // 10: out_written_ptr
                ),
                listOf(ValType.I32) // return status code (>= 100 on success, < 0 on failure)
            )
        ) { instance, args ->
            val result = executeHttpFetch(
                instance = instance,
                urlPtr = args[0].toInt(),
                urlLen = args[1].toInt(),
                methodPtr = args[2].toInt(),
                methodLen = args[3].toInt(),
                headersPtr = args[4].toInt(),
                headersLen = args[5].toInt(),
                bodyPtr = args[6].toInt(),
                bodyLen = args[7].toInt(),
                outBufPtr = args[8].toInt(),
                outBufCap = args[9].toInt(),
                outWrittenPtr = args[10].toInt()
            )
            longArrayOf(result.toLong())
        }

        return arrayOf(httpFetch)
    }

    private fun isValidMemoryRange(ptr: Int, len: Int, memorySizeBytes: Long): Boolean {
        if (ptr < 0 || len < 0) return false
        val end = ptr.toLong() + len.toLong()
        return end <= memorySizeBytes
    }

    /**
     * Executes the HTTP request from WASM memory arguments with full security and quota checks.
     * Returns HTTP response status code (>= 100) or negative error code without trapping the WASM instance.
     */
    @OptIn(InternalCoroutinesApi::class)
    private fun executeHttpFetch(
        instance: Instance,
        urlPtr: Int,
        urlLen: Int,
        methodPtr: Int,
        methodLen: Int,
        headersPtr: Int,
        headersLen: Int,
        bodyPtr: Int,
        bodyLen: Int,
        outBufPtr: Int,
        outBufCap: Int,
        outWrittenPtr: Int
    ): Int {
        // Enforce non-negative bounds
        if (urlPtr < 0 || urlLen < 0 || methodPtr < 0 || methodLen < 0 ||
            headersPtr < 0 || headersLen < 0 || bodyPtr < 0 || bodyLen < 0 ||
            outBufPtr < 0 || outBufCap < 0 || outWrittenPtr < 0
        ) {
            return ERR_SECURITY_VIOLATION
        }

        val memory = instance.memory()
        val maxQuota = task.maxEgressBytes

        // Fail-closed quota guard per ADR-011: max_egress_bytes must be > 0 and <= MAX_TASK_EGRESS_BYTES
        if (maxQuota <= 0 || maxQuota > MAX_TASK_EGRESS_BYTES) {
            return ERR_QUOTA_EXCEEDED
        }

        // Linear memory bounds pre-validation using Long arithmetic
        val memorySizeBytes = memory.pages().toLong() * 65536L
        if (!isValidMemoryRange(urlPtr, urlLen, memorySizeBytes) ||
            !isValidMemoryRange(methodPtr, methodLen, memorySizeBytes) ||
            !isValidMemoryRange(headersPtr, headersLen, memorySizeBytes) ||
            !isValidMemoryRange(bodyPtr, bodyLen, memorySizeBytes) ||
            !isValidMemoryRange(outBufPtr, outBufCap, memorySizeBytes) ||
            !isValidMemoryRange(outWrittenPtr, 4, memorySizeBytes)
        ) {
            return ERR_SECURITY_VIOLATION
        }

        // 1. Read and validate destination URL from WASM linear memory
        if (urlLen == 0) {
            return ERR_SECURITY_VIOLATION
        }
        val urlString = try {
            memory.readString(urlPtr, urlLen)
        } catch (e: Exception) {
            return ERR_SECURITY_VIOLATION
        }

        // 2. Read HTTP method (default to GET)
        val method = if (methodLen > 0) {
            try {
                memory.readString(methodPtr, methodLen).trim().uppercase()
            } catch (e: Exception) {
                return ERR_SECURITY_VIOLATION
            }
        } else {
            "GET"
        }
        if (method !in ALLOWED_METHODS) {
            return ERR_SECURITY_VIOLATION
        }

        // 3. Read and sanitize HTTP headers
        val headersList = if (headersLen > 0) {
            val headersStr = try {
                memory.readString(headersPtr, headersLen)
            } catch (e: Exception) {
                return ERR_SECURITY_VIOLATION
            }

            try {
                securityGuard.sanitizeHeaders(headersStr)
            } catch (e: SecurityException) {
                return ERR_SECURITY_VIOLATION
            } catch (e: Exception) {
                return ERR_SECURITY_VIOLATION
            }
        } else {
            emptyList()
        }

        // 4. Validate URL, scheme, allowlist, metered state, and pre-flight SSRF addresses
        val validatedUrl = try {
            securityGuard.validateOutboundUrl(
                urlString = urlString,
                policy = task.egressPolicy,
                allowedHostnames = task.allowedHostnamesList,
                maxEgressBytes = maxQuota
            )
        } catch (e: SecurityException) {
            return ERR_SECURITY_VIOLATION
        } catch (e: IllegalArgumentException) {
            return ERR_SECURITY_VIOLATION
        } catch (e: Exception) {
            return ERR_IO_FAILURE
        }

        // 5. Read request body bytes if present for methods that transmit body
        val sendsBody = method in listOf("POST", "PUT", "PATCH") || (method == "DELETE" && bodyLen > 0)
        val requestBodyBytes = if (bodyLen > 0 && sendsBody) {
            try {
                memory.readBytes(bodyPtr, bodyLen)
            } catch (e: Exception) {
                return ERR_SECURITY_VIOLATION
            }
        } else {
            ByteArray(0)
        }

        // 6. Check and bill outbound bytes (URL + headers + request body) ONLY after validation succeeds
        val uLen = urlLen.toLong()
        val hLen = headersLen.toLong()
        val reqBytes = requestBodyBytes.size.toLong()
        val totalOutboundBytes = uLen + hLen + reqBytes
        if (cumulativeBytesTransferred.get() + totalOutboundBytes > maxQuota) {
            return ERR_QUOTA_EXCEEDED
        }
        cumulativeBytesTransferred.addAndGet(totalOutboundBytes)

        val callRef = AtomicReference<Call?>(null)
        val cancelledByJob = java.util.concurrent.atomic.AtomicBoolean(false)
        val completionHandle = executionJob?.invokeOnCompletion(onCancelling = true) { cause ->
            if (cause != null) {
                cancelledByJob.set(true)
                callRef.get()?.cancel()
            }
        }
        if (executionJob?.isActive == false) {
            completionHandle?.dispose()
            throw CancellationException("WASM outbound network request cancelled before start")
        }

        return try {
            // 7. Build OkHttp request with sanitized headers
            val okRequestBody = if (sendsBody) {
                requestBodyBytes.toRequestBody(null)
            } else {
                null
            }

            val requestBuilder = Request.Builder()
                .url(validatedUrl)
                .method(method, okRequestBody)

            for ((key, value) in headersList) {
                requestBuilder.addHeader(key, value)
            }

            val request = requestBuilder.build()
            val call = taskClient.newCall(request)
            callRef.set(call)
            if (executionJob?.isActive == false) {
                call.cancel()
                throw CancellationException("WASM outbound network request cancelled before dispatch")
            }

            call.execute().use { response ->
                val responseHeadersBytes = response.headers.byteCount()
                if (cumulativeBytesTransferred.get() + responseHeadersBytes > maxQuota) {
                    call.cancel()
                    return ERR_QUOTA_EXCEEDED
                }
                cumulativeBytesTransferred.addAndGet(responseHeadersBytes)

                val statusCode = response.code
                val responseBody = response.body
                    ?: run {
                        if (outWrittenPtr >= 0) {
                            try {
                                memory.writeI32(outWrittenPtr, 0)
                            } catch (e: Exception) {
                                return ERR_SECURITY_VIOLATION
                            }
                        }
                        return statusCode
                    }

                val source = responseBody.source()
                val tempBuffer = ByteArray(STREAM_CHUNK_SIZE.toInt())
                var totalBytesRead = 0

                // 8. Stream response body in bounded chunks directly into WASM linear memory
                while (true) {
                    val readCount = source.read(tempBuffer)
                    if (readCount == -1) {
                        break
                    }

                    // Bill transferred bytes immediately upon read
                    cumulativeBytesTransferred.addAndGet(readCount.toLong())

                    // Assert cumulative quota limits
                    if (cumulativeBytesTransferred.get() > maxQuota) {
                        call.cancel()
                        return ERR_QUOTA_EXCEEDED
                    }

                    // Assert out_buf_cap bounds without silent truncation
                    if (totalBytesRead.toLong() + readCount.toLong() > outBufCap.toLong()) {
                        call.cancel()
                        return ERR_BUFFER_TOO_SMALL
                    }

                    // Assert 16 MB frame limit [NFR-PERF-001]
                    if (totalBytesRead.toLong() + readCount.toLong() > WasmComputeEngine.MAX_FRAME_SIZE_BYTES) {
                        call.cancel()
                        return ERR_BUFFER_TOO_SMALL
                    }

                    // Write chunk into linear memory
                    if (outBufCap > 0) {
                        try {
                            memory.write(outBufPtr + totalBytesRead, tempBuffer, 0, readCount)
                        } catch (e: Exception) {
                            call.cancel()
                            return ERR_SECURITY_VIOLATION
                        }
                    }

                    totalBytesRead += readCount
                }

                // Write exact byte count to out_written_ptr if non-negative
                if (outWrittenPtr >= 0) {
                    try {
                        memory.writeI32(outWrittenPtr, totalBytesRead)
                    } catch (e: Exception) {
                        return ERR_SECURITY_VIOLATION
                    }
                }

                statusCode
            }
        } catch (e: IllegalArgumentException) {
            ERR_SECURITY_VIOLATION
        } catch (e: SecurityException) {
            ERR_SECURITY_VIOLATION
        } catch (e: IOException) {
            if (cancelledByJob.get() || executionJob?.isActive == false) {
                throw CancellationException("WASM outbound network request cancelled by job", e)
            }
            ERR_IO_FAILURE
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            ERR_IO_FAILURE
        } finally {
            completionHandle?.dispose()
            callRef.set(null)
        }
    }
}
