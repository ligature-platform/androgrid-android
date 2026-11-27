package com.androgrid.worker.network

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.IOException
import java.net.ConnectException
import java.net.InetSocketAddress
import java.net.NoRouteToHostException
import java.net.Socket
import java.net.SocketTimeoutException
import java.net.UnknownHostException

/**
 * Non-blocking TCP socket reachability prober.
 *
 * Connects an outbound TCP client socket with strict timeout bounds,
 * verifying station-to-station routing and host firewall permissions
 * before initiating heavyweight mTLS certificate exchange or gRPC streaming.
 *
 * Strictly adheres to [INV-001]: Opens ONLY outbound client sockets and immediately closes them.
 *
 * Traces to: [REQ-OP-001], [INV-001], [INV-002], [NFR-SEC-001], [NFR-POW-001], Gate L-02
 */
object SocketReachabilityProber {

    /**
     * Probes TCP reachability to specified host and port.
     *
     * @param host Host IPv4 address or hostname to probe.
     * @param port TCP port to probe.
     * @param timeoutMs Connection timeout in milliseconds (default 2000 ms).
     * @return [PreFlightProbeResult.Reachable] on successful connection, or [PreFlightProbeResult.Unreachable].
     */
    suspend fun probe(
        host: String,
        port: Int,
        timeoutMs: Int = 2000
    ): PreFlightProbeResult = withContext(Dispatchers.IO) {
        if (host.isBlank()) {
            return@withContext PreFlightProbeResult.Unreachable(
                host = host,
                port = port,
                message = "Target host is blank",
                actionableAdvice = "Please provide a valid IPv4 address or hostname."
            )
        }

        if (port !in 1..65535) {
            return@withContext PreFlightProbeResult.Unreachable(
                host = host,
                port = port,
                message = "Port $port is outside valid range (1-65535)",
                actionableAdvice = "Specify a valid port (default: 50051)."
            )
        }

        try {
            Socket().use { socket ->
                socket.connect(InetSocketAddress(host, port), timeoutMs)
            }
            PreFlightProbeResult.Reachable
        } catch (e: SocketTimeoutException) {
            PreFlightProbeResult.Unreachable(
                host = host,
                port = port,
                message = "Connection timed out after ${timeoutMs}ms",
                actionableAdvice = "Host unreachable on port $port. Check host firewall (Windows Defender Public profile) or AP station isolation."
            )
        } catch (e: NoRouteToHostException) {
            PreFlightProbeResult.Unreachable(
                host = host,
                port = port,
                message = "No route to host: ${e.message}",
                actionableAdvice = "Cannot route to $host. Verify Wi-Fi network association and subnet reachability."
            )
        } catch (e: ConnectException) {
            PreFlightProbeResult.Unreachable(
                host = host,
                port = port,
                message = "Connection refused on port $port: ${e.message}",
                actionableAdvice = "Port $port connection refused. Verify the AndroGrid orchestrator daemon is running on $host."
            )
        } catch (e: UnknownHostException) {
            PreFlightProbeResult.Unreachable(
                host = host,
                port = port,
                message = "Unknown host: ${e.message}",
                actionableAdvice = "Cannot resolve hostname '$host'. Use a direct IPv4 address or verify mDNS/DNS."
            )
        } catch (e: IOException) {
            PreFlightProbeResult.Unreachable(
                host = host,
                port = port,
                message = "Network I/O error: ${e.message}",
                actionableAdvice = "Failed to establish TCP socket to $host:$port. Check network permissions and firewall rules."
            )
        }
    }
}
