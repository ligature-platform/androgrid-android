package com.androgrid.worker.network

import com.google.common.truth.Truth.assertThat
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import org.junit.Test
import java.net.ServerSocket
import kotlin.system.measureTimeMillis

/**
 * Feasibility spike tests demonstrating bounded caller deadline, immediate resource cleanup,
 * and rapid supersession during TCP socket reachability probing.
 *
 * Traces to: [REQ-OP-001], [INV-001], [INV-002], Gate L-02
 */
class ProbeFeasibilityTest {

    @Test
    fun probeCancellation_terminatesUnderlyingSocketImmediatelyWithoutWaitingFullTimeout() = runBlocking {
        // Attempting to connect to 198.51.100.1 with 5000ms timeout would block for 5s
        // if socket cancellation were ineffective.
        val longTimeoutMs = 5000
        val cancellationDelayMs = 100L

        var finishedBeforeTimeout = false
        val elapsed = measureTimeMillis {
            val job = launch(Dispatchers.Default) {
                SocketReachabilityProber.probe("198.51.100.1", 50051, timeoutMs = longTimeoutMs)
            }
            delay(cancellationDelayMs)
            job.cancel()
            job.join()
            finishedBeforeTimeout = true
        }

        assertThat(finishedBeforeTimeout).isTrue()
        // The job should complete promptly after cancellation (well under the 5000ms timeout)
        assertThat(elapsed).isLessThan(1500L)
    }

    @Test
    fun probeSupersession_cancelsEarlierProbeAndDeliversLatestResult() = runBlocking {
        val server = ServerSocket(0)
        val validPort = server.localPort

        try {
            // Probe 1 targets a non-responsive address
            var probe1Result: PreFlightProbeResult? = null
            var probe2Result: PreFlightProbeResult? = null

            val job1 = launch(Dispatchers.Default) {
                probe1Result = SocketReachabilityProber.probe("198.51.100.1", 50051, timeoutMs = 4000)
            }

            // Immediately supersede with Probe 2 targeting valid listening server
            delay(50)
            job1.cancel()

            val job2 = launch(Dispatchers.Default) {
                probe2Result = SocketReachabilityProber.probe("127.0.0.1", validPort, timeoutMs = 1000)
            }

            job1.join()
            job2.join()

            assertThat(probe2Result).isInstanceOf(PreFlightProbeResult.Reachable::class.java)
        } finally {
            server.close()
        }
    }

    @Test
    fun isIpv4Literal_correctlyIdentifiesNumericAddresses() {
        assertThat(SocketReachabilityProber.isIpv4Literal("10.100.102.6")).isTrue()
        assertThat(SocketReachabilityProber.isIpv4Literal("127.0.0.1")).isTrue()
        assertThat(SocketReachabilityProber.isIpv4Literal("192.168.1.1")).isTrue()
        assertThat(SocketReachabilityProber.isIpv4Literal("androgrid.local")).isFalse()
        assertThat(SocketReachabilityProber.isIpv4Literal("256.0.0.1")).isFalse()
        assertThat(SocketReachabilityProber.isIpv4Literal("10.0.0")).isFalse()
        assertThat(SocketReachabilityProber.isIpv4Literal("")).isFalse()
    }

    @Test
    fun probe_rejectsNonPositiveTimeout() = runBlocking {
        val resultZero = SocketReachabilityProber.probe("127.0.0.1", 50051, timeoutMs = 0)
        val resultNegative = SocketReachabilityProber.probe("127.0.0.1", 50051, timeoutMs = -100)

        assertThat(resultZero).isInstanceOf(PreFlightProbeResult.Unreachable::class.java)
        assertThat((resultZero as PreFlightProbeResult.Unreachable).message).contains("greater than zero")

        assertThat(resultNegative).isInstanceOf(PreFlightProbeResult.Unreachable::class.java)
        assertThat((resultNegative as PreFlightProbeResult.Unreachable).message).contains("greater than zero")
    }
}
