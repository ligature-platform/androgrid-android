package com.androgrid.worker.network

import com.google.common.truth.Truth.assertThat
import kotlinx.coroutines.runBlocking
import org.junit.Test
import java.net.ServerSocket

/**
 * Unit tests for [SocketReachabilityProber] verifying non-blocking TCP socket pre-flight checks,
 * actionable diagnostics, error classification, and port bounds validation.
 *
 * Traces to: [REQ-OP-001], [INV-001], [INV-002], Gate L-02
 */
class SocketReachabilityProberTest {

    @Test
    fun probe_openListeningSocket_returnsReachable() = runBlocking {
        val server = ServerSocket(0)
        val port = server.localPort
        try {
            val result = SocketReachabilityProber.probe("127.0.0.1", port, timeoutMs = 1000)
            assertThat(result).isInstanceOf(PreFlightProbeResult.Reachable::class.java)
        } finally {
            server.close()
        }
    }

    @Test
    fun probe_closedPort_returnsConnectionRefusedWithGuidance() = runBlocking {
        val server = ServerSocket(0)
        val closedPort = server.localPort
        server.close()

        val result = SocketReachabilityProber.probe("127.0.0.1", closedPort, timeoutMs = 1000)
        assertThat(result).isInstanceOf(PreFlightProbeResult.Unreachable::class.java)
        val unreachable = result as PreFlightProbeResult.Unreachable
        assertThat(unreachable.host).isEqualTo("127.0.0.1")
        assertThat(unreachable.port).isEqualTo(closedPort)
        assertThat(unreachable.actionableAdvice).contains("orchestrator daemon")
    }

    @Test
    fun probe_blankHost_returnsUnreachable() = runBlocking {
        val result = SocketReachabilityProber.probe("", 50051)
        assertThat(result).isInstanceOf(PreFlightProbeResult.Unreachable::class.java)
        val unreachable = result as PreFlightProbeResult.Unreachable
        assertThat(unreachable.message).contains("blank")
    }

    @Test
    fun probe_invalidPort_returnsUnreachable() = runBlocking {
        val result1 = SocketReachabilityProber.probe("127.0.0.1", 0)
        val result2 = SocketReachabilityProber.probe("127.0.0.1", 70000)

        assertThat(result1).isInstanceOf(PreFlightProbeResult.Unreachable::class.java)
        assertThat(result2).isInstanceOf(PreFlightProbeResult.Unreachable::class.java)
    }

    @Test
    fun probe_unreachableHost_returnsFirewallOrIsolationGuidance() = runBlocking {
        val result = SocketReachabilityProber.probe("198.51.100.1", 50051, timeoutMs = 200)
        assertThat(result).isInstanceOf(PreFlightProbeResult.Unreachable::class.java)
        val unreachable = result as PreFlightProbeResult.Unreachable
        assertThat(unreachable.actionableAdvice).contains("firewall")
    }
}
