package com.androgrid.worker.network

import kotlinx.coroutines.flow.StateFlow

/**
 * Result of non-blocking TCP socket pre-flight connectivity check.
 *
 * Traces to: [REQ-OP-001], [INV-001], [INV-002], Gate L-02
 */
sealed class PreFlightProbeResult {
    /** Host port is reachable and responsive to inbound connection. */
    object Reachable : PreFlightProbeResult()

    /** Host port is unreachable, dropped, or connection refused. */
    data class Unreachable(
        val host: String,
        val port: Int,
        val message: String,
        val actionableAdvice: String
    ) : PreFlightProbeResult()
}

/**
 * Interface governing zero-configuration local cluster discovery via mDNS / DNS-SD.
 * Operates strictly outbound-only in compliance with [INV-001].
 *
 * Traces to: [REQ-OP-001], [INV-001], [INV-002], [NFR-POW-001], Gate L-02
 */
interface ClusterDiscoveryManager {
    /**
     * Observable stream of discovered orchestrator clusters on the local Wi-Fi network.
     */
    val discoveredClusters: StateFlow<List<DiscoveredCluster>>

    /**
     * Whether mDNS service discovery is currently active.
     */
    val isDiscovering: StateFlow<Boolean>

    /**
     * Initiates Network Service Discovery for `_androgrid._tcp` services.
     * Defensively acquires Wi-Fi MulticastLock where required by OEM network stacks.
     */
    fun startDiscovery()

    /**
     * Halts Network Service Discovery and releases Wi-Fi MulticastLock to preserve battery power.
     */
    fun stopDiscovery()

    /**
     * Performs a non-blocking TCP socket pre-flight check to verify reachability
     * of the orchestrator host and port before attempting mTLS handshake or gRPC stream.
     * Operates strictly outbound-only in compliance with [INV-001].
     *
     * @param host Target host name or IPv4 address.
     * @param port Target TCP port (e.g. 50051).
     * @param timeoutMs Connection timeout in milliseconds (default: 2000 ms).
     * @return [PreFlightProbeResult.Reachable] or [PreFlightProbeResult.Unreachable] with actionable guidance.
     */
    suspend fun probeReachability(host: String, port: Int, timeoutMs: Int = 2000): PreFlightProbeResult {
        return SocketReachabilityProber.probe(host, port, timeoutMs)
    }
}
