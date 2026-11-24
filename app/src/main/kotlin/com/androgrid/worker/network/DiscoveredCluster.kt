package com.androgrid.worker.network

/**
 * Immutable representation of an AndroGrid Orchestrator cluster discovered via local mDNS / DNS-SD.
 *
 * Traces to: [REQ-OP-001], [INV-001], [INV-002]
 *
 * @property serviceName DNS-SD service instance name announced on the local network.
 * @property host Resolvable IPv4 or IPv6 address of the orchestrator node.
 * @property port gRPC service port (typically 50051).
 * @property clusterName Human-readable cluster identifier advertised via DNS-SD TXT metadata.
 * @property version Orchestrator software release version advertised via TXT record.
 * @property tlsVersion Mutual TLS version supported by the cluster (defaults to 1.3).
 * @property caFingerprint Lowercase hexadecimal SHA-256 fingerprint of the Root CA certificate.
 * @property nodeCount Number of currently connected worker nodes reported by the orchestrator.
 * @property resolvedAtEpochMs Local timestamp in milliseconds when resolution completed.
 */
data class DiscoveredCluster(
    val serviceName: String,
    val host: String,
    val port: Int,
    val clusterName: String = "default",
    val version: String = "",
    val tlsVersion: String = "1.3",
    val caFingerprint: String = "",
    val nodeCount: Int = 0,
    val resolvedAtEpochMs: Long = System.currentTimeMillis()
) {
    /**
     * Canonical cluster endpoint string in host:port format.
     * Encloses IPv6 address literals in RFC 3986 brackets.
     */
    fun endpoint(): String {
        return if (host.contains(':') && !host.startsWith("[")) {
            "[$host]:$port"
        } else {
            "$host:$port"
        }
    }
}
