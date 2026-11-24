package com.androgrid.worker.network

import kotlinx.coroutines.flow.StateFlow

/**
 * Interface governing zero-configuration local cluster discovery via mDNS / DNS-SD.
 * Operates strictly outbound-only in compliance with [INV-001].
 *
 * Traces to: [REQ-OP-001], [INV-001], [INV-002], [NFR-POW-001]
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
}
