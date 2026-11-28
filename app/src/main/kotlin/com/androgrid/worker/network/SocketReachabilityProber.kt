package com.androgrid.worker.network

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withContext
import java.io.IOException
import java.net.ConnectException
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.NoRouteToHostException
import java.net.Socket
import java.net.SocketException
import java.net.SocketTimeoutException
import java.net.UnknownHostException
import kotlin.coroutines.resume

/**
 * Non-blocking TCP socket reachability prober with strict cancellation and resource cleanup.
 *
 * Connects an outbound TCP client socket with strict timeout bounds,
 * verifying station-to-station routing and host firewall permissions
 * before initiating heavyweight mTLS certificate exchange or gRPC streaming.
 *
 * Strictly adheres to [INV-001]: Opens ONLY outbound client sockets and immediately closes them.
 * On coroutine cancellation or supersession, actively aborts pending connection attempts
 * by closing the underlying native socket via [suspendCancellableCoroutine] cancellation callback,
 * freeing carrier threads immediately without waiting for OS socket timeouts.
 *
 * Traces to: [REQ-OP-001], [INV-001], [INV-002], Gate L-02
 */
object SocketReachabilityProber {

    /**
     * Probes TCP reachability to specified host and port.
     *
     * @param host Host IPv4 address or hostname to probe.
     * @param port TCP port to probe (must be between 1 and 65535).
     * @param timeoutMs Connection timeout in milliseconds (must be > 0, default 2000 ms).
     * @return [PreFlightProbeResult.Reachable] on successful connection, or [PreFlightProbeResult.Unreachable].
     */
    suspend fun probe(
        host: String,
        port: Int,
        timeoutMs: Int = 2000
    ): PreFlightProbeResult {
        if (host.isBlank()) {
            return PreFlightProbeResult.Unreachable(
                host = host,
                port = port,
                message = "Target host is blank",
                actionableAdvice = "Please provide a valid IPv4 address or hostname."
            )
        }

        if (port !in 1..65535) {
            return PreFlightProbeResult.Unreachable(
                host = host,
                port = port,
                message = "Port $port is outside valid range (1-65535)",
                actionableAdvice = "Specify a valid port (default: 50051)."
            )
        }

        if (timeoutMs <= 0) {
            return PreFlightProbeResult.Unreachable(
                host = host,
                port = port,
                message = "Timeout must be greater than zero",
                actionableAdvice = "Specify a positive timeout value in milliseconds."
            )
        }

        return withContext(Dispatchers.IO) {
            suspendCancellableCoroutine { continuation ->
                val socket = Socket()

                continuation.invokeOnCancellation {
                    try {
                        socket.close()
                    } catch (_: Throwable) {}
                }

                try {
                    // If host is numeric IPv4 literal, construct InetSocketAddress without blocking DNS query
                    val endpoint = if (isIpv4Literal(host)) {
                        val addr = InetAddress.getByAddress(parseIpv4Bytes(host))
                        InetSocketAddress(addr, port)
                    } else {
                        InetSocketAddress(host, port)
                    }

                    socket.connect(endpoint, timeoutMs)
                    if (continuation.isActive) {
                        continuation.resume(PreFlightProbeResult.Reachable)
                    }
                } catch (e: SocketTimeoutException) {
                    if (continuation.isActive) {
                        continuation.resume(
                            PreFlightProbeResult.Unreachable(
                                host = host,
                                port = port,
                                message = "Connection timed out after ${timeoutMs}ms",
                                actionableAdvice = "Host unreachable on port $port. Check host firewall (Windows Defender Public profile) or AP station isolation."
                            )
                        )
                    }
                } catch (e: NoRouteToHostException) {
                    if (continuation.isActive) {
                        continuation.resume(
                            PreFlightProbeResult.Unreachable(
                                host = host,
                                port = port,
                                message = "No route to host: ${e.message}",
                                actionableAdvice = "Cannot route to $host. Verify Wi-Fi network association and subnet reachability."
                            )
                        )
                    }
                } catch (e: ConnectException) {
                    if (continuation.isActive) {
                        continuation.resume(
                            PreFlightProbeResult.Unreachable(
                                host = host,
                                port = port,
                                message = "Connection refused on port $port: ${e.message}",
                                actionableAdvice = "Port $port connection refused. Verify the AndroGrid orchestrator daemon is running on $host."
                            )
                        )
                    }
                } catch (e: UnknownHostException) {
                    if (continuation.isActive) {
                        continuation.resume(
                            PreFlightProbeResult.Unreachable(
                                host = host,
                                port = port,
                                message = "Unknown host: ${e.message}",
                                actionableAdvice = "Cannot resolve hostname '$host'. Use a direct IPv4 address or verify mDNS/DNS."
                            )
                        )
                    }
                } catch (e: SocketException) {
                    if (continuation.isActive) {
                        PreFlightProbeResult.Unreachable(
                            host = host,
                            port = port,
                            message = "Socket error: ${e.message}",
                            actionableAdvice = "Check network connectivity and interface routing."
                        ).let { continuation.resume(it) }
                    }
                } catch (e: IOException) {
                    if (continuation.isActive) {
                        continuation.resume(
                            PreFlightProbeResult.Unreachable(
                                host = host,
                                port = port,
                                message = "Network I/O error: ${e.message}",
                                actionableAdvice = "Failed to establish TCP socket to $host:$port. Check network permissions and firewall rules."
                            )
                        )
                    }
                } finally {
                    try {
                        if (!socket.isClosed) {
                            socket.close()
                        }
                    } catch (_: Throwable) {}
                }
            }
        }
    }

    internal fun isIpv4Literal(text: String): Boolean {
        val parts = text.split('.')
        if (parts.size != 4) return false
        return parts.all { part ->
            part.isNotEmpty() && part.length <= 3 && part.all { it in '0'..'9' } && part.toInt() in 0..255
        }
    }

    internal fun parseIpv4Bytes(text: String): ByteArray {
        val parts = text.split('.')
        return ByteArray(4) { i -> parts[i].toInt().toByte() }
    }
}
