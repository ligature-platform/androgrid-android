package com.androgrid.worker.network

import android.net.nsd.NsdManager
import android.net.nsd.NsdServiceInfo
import android.net.wifi.WifiManager
import androidx.test.core.app.ApplicationProvider
import com.google.common.truth.Truth.assertThat
import io.mockk.every
import io.mockk.mockk
import io.mockk.slot
import io.mockk.verify
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.net.InetAddress

/**
 * Unit tests for [NsdClusterDiscoveryManager] verifying mDNS service discovery,
 * resolution queueing, multicast lock lifecycle, session fencing, and input validation.
 *
 * Traces to: [REQ-OP-001], [INV-001], [INV-002], [NFR-POW-001]
 */
@Suppress("DEPRECATION")
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class ClusterDiscoveryManagerTest {

    private lateinit var mockNsdManager: NsdManager
    private lateinit var mockWifiManager: WifiManager
    private lateinit var mockMulticastLock: WifiManager.MulticastLock
    private val discoveryListenerSlot = slot<NsdManager.DiscoveryListener>()
    private val resolveListenerSlot = slot<NsdManager.ResolveListener>()

    @Before
    fun setUp() {
        mockNsdManager = mockk(relaxed = true)
        mockWifiManager = mockk(relaxed = true)
        mockMulticastLock = mockk(relaxed = true)

        every { mockWifiManager.createMulticastLock(any()) } returns mockMulticastLock
        every { mockMulticastLock.isHeld } returns false
    }

    @Test
    fun testStartDiscovery_acquiresMulticastLockAndRegistersListener() {
        val manager = NsdClusterDiscoveryManager(
            context = ApplicationProvider.getApplicationContext(),
            nsdManager = mockNsdManager,
            wifiManager = mockWifiManager
        )

        manager.startDiscovery()

        verify { mockMulticastLock.acquire() }
        verify {
            mockNsdManager.discoverServices(
                NsdClusterDiscoveryManager.SERVICE_TYPE,
                NsdManager.PROTOCOL_DNS_SD,
                capture(discoveryListenerSlot)
            )
        }
        discoveryListenerSlot.captured.onDiscoveryStarted(NsdClusterDiscoveryManager.SERVICE_TYPE)
        assertThat(manager.isDiscovering.value).isTrue()
    }

    @Test
    fun testStopDiscovery_releasesMulticastLockAndStopsNsd() {
        val manager = NsdClusterDiscoveryManager(
            context = ApplicationProvider.getApplicationContext(),
            nsdManager = mockNsdManager,
            wifiManager = mockWifiManager
        )

        manager.startDiscovery()
        verify { mockNsdManager.discoverServices(any(), any(), capture(discoveryListenerSlot)) }
        discoveryListenerSlot.captured.onDiscoveryStarted(NsdClusterDiscoveryManager.SERVICE_TYPE)

        every { mockMulticastLock.isHeld } returns true

        manager.stopDiscovery()

        verify { mockNsdManager.stopServiceDiscovery(discoveryListenerSlot.captured) }
        verify { mockMulticastLock.release() }
        assertThat(manager.isDiscovering.value).isFalse()
        assertThat(manager.discoveredClusters.value).isEmpty()
    }

    @Test
    fun testOnServiceFound_triggersResolveService() {
        val manager = NsdClusterDiscoveryManager(
            context = ApplicationProvider.getApplicationContext(),
            nsdManager = mockNsdManager,
            wifiManager = mockWifiManager
        )

        manager.startDiscovery()
        verify { mockNsdManager.discoverServices(any(), any(), capture(discoveryListenerSlot)) }
        discoveryListenerSlot.captured.onDiscoveryStarted(NsdClusterDiscoveryManager.SERVICE_TYPE)

        val serviceInfo = NsdServiceInfo().apply {
            serviceName = "androgrid-orchestrator"
            serviceType = "_androgrid._tcp"
        }

        discoveryListenerSlot.captured.onServiceFound(serviceInfo)

        verify { mockNsdManager.resolveService(serviceInfo, capture(resolveListenerSlot)) }
    }

    @Test
    fun testOnServiceResolved_parsesTxtRecordsAndPopulatesStateFlow() {
        val manager = NsdClusterDiscoveryManager(
            context = ApplicationProvider.getApplicationContext(),
            nsdManager = mockNsdManager,
            wifiManager = mockWifiManager
        )

        manager.startDiscovery()
        verify { mockNsdManager.discoverServices(any(), any(), capture(discoveryListenerSlot)) }
        discoveryListenerSlot.captured.onDiscoveryStarted(NsdClusterDiscoveryManager.SERVICE_TYPE)

        val rawService = NsdServiceInfo().apply {
            serviceName = "androgrid-orchestrator"
            serviceType = "_androgrid._tcp."
        }
        discoveryListenerSlot.captured.onServiceFound(rawService)
        verify { mockNsdManager.resolveService(rawService, capture(resolveListenerSlot)) }

        val resolvedService = NsdServiceInfo().apply {
            serviceName = "androgrid-orchestrator"
            serviceType = "_androgrid._tcp."
            host = InetAddress.getByName("192.168.1.15")
            port = 50051
            setAttribute("name", "production-cluster")
            setAttribute("version", "0.0.1-alpha.5")
            setAttribute("tls", "1.3")
            setAttribute("ca_fingerprint", "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890")
            setAttribute("nodes", "4")
        }

        resolveListenerSlot.captured.onServiceResolved(resolvedService)

        val clusters = manager.discoveredClusters.value
        assertThat(clusters).hasSize(1)
        val cluster = clusters[0]
        assertThat(cluster.serviceName).isEqualTo("androgrid-orchestrator")
        assertThat(cluster.host).isEqualTo("192.168.1.15")
        assertThat(cluster.port).isEqualTo(50051)
        assertThat(cluster.clusterName).isEqualTo("production-cluster")
        assertThat(cluster.version).isEqualTo("0.0.1-alpha.5")
        assertThat(cluster.tlsVersion).isEqualTo("1.3")
        assertThat(cluster.caFingerprint).isEqualTo("abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890")
        assertThat(cluster.nodeCount).isEqualTo(4)
        assertThat(cluster.endpoint()).isEqualTo("192.168.1.15:50051")
    }

    @Test
    fun testOnServiceLost_removesClusterFromList() {
        val manager = NsdClusterDiscoveryManager(
            context = ApplicationProvider.getApplicationContext(),
            nsdManager = mockNsdManager,
            wifiManager = mockWifiManager
        )

        manager.startDiscovery()
        verify { mockNsdManager.discoverServices(any(), any(), capture(discoveryListenerSlot)) }
        discoveryListenerSlot.captured.onDiscoveryStarted(NsdClusterDiscoveryManager.SERVICE_TYPE)

        val resolvedService = NsdServiceInfo().apply {
            serviceName = "cluster-a"
            serviceType = "_androgrid._tcp."
            host = InetAddress.getByName("192.168.1.20")
            port = 50051
        }
        discoveryListenerSlot.captured.onServiceFound(resolvedService)
        verify { mockNsdManager.resolveService(resolvedService, capture(resolveListenerSlot)) }
        resolveListenerSlot.captured.onServiceResolved(resolvedService)

        assertThat(manager.discoveredClusters.value).hasSize(1)

        val lostService = NsdServiceInfo().apply {
            serviceName = "cluster-a"
            serviceType = "_androgrid._tcp."
        }
        discoveryListenerSlot.captured.onServiceLost(lostService)

        assertThat(manager.discoveredClusters.value).isEmpty()
    }

    @Test
    fun testFailureCallbacks_handledWithoutCrashing() {
        val listeners = mutableListOf<NsdManager.DiscoveryListener>()
        every { mockNsdManager.discoverServices(any(), any(), capture(listeners)) } returns Unit

        val manager = NsdClusterDiscoveryManager(
            context = ApplicationProvider.getApplicationContext(),
            nsdManager = mockNsdManager,
            wifiManager = mockWifiManager
        )

        manager.startDiscovery()
        assertThat(listeners).hasSize(1)
        listeners[0].onDiscoveryStarted(NsdClusterDiscoveryManager.SERVICE_TYPE)

        every { mockMulticastLock.isHeld } returns true

        listeners[0].onStartDiscoveryFailed("_androgrid._tcp", NsdManager.FAILURE_INTERNAL_ERROR)
        assertThat(manager.isDiscovering.value).isFalse()
        verify { mockMulticastLock.release() }

        listeners[0].onStopDiscoveryFailed("_androgrid._tcp", NsdManager.FAILURE_INTERNAL_ERROR)
        assertThat(manager.isDiscovering.value).isFalse()

        // Re-start discovery to test resolve failure handling during active session
        manager.startDiscovery()
        assertThat(listeners).hasSize(2)
        listeners[1].onDiscoveryStarted(NsdClusterDiscoveryManager.SERVICE_TYPE)

        val service = NsdServiceInfo().apply {
            serviceName = "faulty"
            serviceType = "_androgrid._tcp"
        }
        listeners[1].onServiceFound(service)
        verify { mockNsdManager.resolveService(service, capture(resolveListenerSlot)) }
        resolveListenerSlot.captured.onResolveFailed(service, NsdManager.FAILURE_INTERNAL_ERROR)

        assertThat(manager.discoveredClusters.value).isEmpty()
    }

    @Test
    fun testLateResolveCallbackAfterStopDiscovery_isIgnoredBySessionFencing() {
        val manager = NsdClusterDiscoveryManager(
            context = ApplicationProvider.getApplicationContext(),
            nsdManager = mockNsdManager,
            wifiManager = mockWifiManager
        )

        manager.startDiscovery()
        verify { mockNsdManager.discoverServices(any(), any(), capture(discoveryListenerSlot)) }
        discoveryListenerSlot.captured.onDiscoveryStarted(NsdClusterDiscoveryManager.SERVICE_TYPE)

        val service = NsdServiceInfo().apply {
            serviceName = "slow-cluster"
            serviceType = "_androgrid._tcp"
        }
        discoveryListenerSlot.captured.onServiceFound(service)
        verify { mockNsdManager.resolveService(service, capture(resolveListenerSlot)) }

        // Stop discovery before the async resolve callback completes
        manager.stopDiscovery()
        assertThat(manager.discoveredClusters.value).isEmpty()

        // Late callback arrives after discovery was stopped
        val resolvedService = NsdServiceInfo().apply {
            serviceName = "slow-cluster"
            serviceType = "_androgrid._tcp"
            host = InetAddress.getByName("192.168.1.100")
            port = 50051
        }
        resolveListenerSlot.captured.onServiceResolved(resolvedService)

        // Session fencing must prevent resurrecting the cluster
        assertThat(manager.discoveredClusters.value).isEmpty()
    }

    @Test
    fun testHostValidation_rejectsLoopbackMulticastAndPublicIps() {
        val manager = NsdClusterDiscoveryManager(
            context = ApplicationProvider.getApplicationContext(),
            nsdManager = mockNsdManager,
            wifiManager = mockWifiManager
        )

        manager.startDiscovery()
        verify { mockNsdManager.discoverServices(any(), any(), capture(discoveryListenerSlot)) }
        discoveryListenerSlot.captured.onDiscoveryStarted(NsdClusterDiscoveryManager.SERVICE_TYPE)

        val testCases = listOf(
            "127.0.0.1",       // Loopback
            "8.8.8.8",         // Public IP
            "224.0.0.1",       // Multicast
            "0.0.0.0"          // Unspecified
        )

        for ((idx, ip) in testCases.withIndex()) {
            val service = NsdServiceInfo().apply {
                serviceName = "rogue-$idx"
                serviceType = "_androgrid._tcp"
                host = InetAddress.getByName(ip)
                port = 50051
            }
            discoveryListenerSlot.captured.onServiceFound(service)
            verify { mockNsdManager.resolveService(service, capture(resolveListenerSlot)) }
            resolveListenerSlot.captured.onServiceResolved(service)
        }

        // None of the non-private IPs should be accepted
        assertThat(manager.discoveredClusters.value).isEmpty()
    }

    @Test
    fun testPortValidation_rejectsZeroAndOutOfRangePorts() {
        val manager = NsdClusterDiscoveryManager(
            context = ApplicationProvider.getApplicationContext(),
            nsdManager = mockNsdManager,
            wifiManager = mockWifiManager
        )

        manager.startDiscovery()
        verify { mockNsdManager.discoverServices(any(), any(), capture(discoveryListenerSlot)) }
        discoveryListenerSlot.captured.onDiscoveryStarted(NsdClusterDiscoveryManager.SERVICE_TYPE)

        val invalidPorts = listOf(0, -1, 70000)
        for ((idx, port) in invalidPorts.withIndex()) {
            val service = NsdServiceInfo().apply {
                serviceName = "bad-port-$idx"
                serviceType = "_androgrid._tcp"
                host = InetAddress.getByName("192.168.1.50")
                this.port = port
            }
            discoveryListenerSlot.captured.onServiceFound(service)
            verify { mockNsdManager.resolveService(service, capture(resolveListenerSlot)) }
            resolveListenerSlot.captured.onServiceResolved(service)
        }

        assertThat(manager.discoveredClusters.value).isEmpty()
    }

    @Test
    fun testIpv6Endpoint_bracketsLiterals() {
        val cluster = DiscoveredCluster(
            serviceName = "ipv6-cluster",
            host = "fd00::1",
            port = 50051
        )
        assertThat(cluster.endpoint()).isEqualTo("[fd00::1]:50051")
    }

    @Test
    fun testMalformedCaFingerprint_sanitizedToEmpty() {
        val manager = NsdClusterDiscoveryManager(
            context = ApplicationProvider.getApplicationContext(),
            nsdManager = mockNsdManager,
            wifiManager = mockWifiManager
        )

        manager.startDiscovery()
        verify { mockNsdManager.discoverServices(any(), any(), capture(discoveryListenerSlot)) }
        discoveryListenerSlot.captured.onDiscoveryStarted(NsdClusterDiscoveryManager.SERVICE_TYPE)

        val service = NsdServiceInfo().apply {
            serviceName = "bad-fingerprint"
            serviceType = "_androgrid._tcp"
            host = InetAddress.getByName("192.168.1.100")
            port = 50051
            setAttribute("ca_fingerprint", "not-a-valid-64-hex-sha256")
        }
        discoveryListenerSlot.captured.onServiceFound(service)
        verify { mockNsdManager.resolveService(service, capture(resolveListenerSlot)) }
        resolveListenerSlot.captured.onServiceResolved(service)

        val clusters = manager.discoveredClusters.value
        assertThat(clusters).hasSize(1)
        assertThat(clusters[0].caFingerprint).isEmpty()
    }

    @Test
    fun testResolveQueue_serializesMultipleAnnouncements_fifoOrder() {
        val manager = NsdClusterDiscoveryManager(
            context = ApplicationProvider.getApplicationContext(),
            nsdManager = mockNsdManager,
            wifiManager = mockWifiManager
        )

        val resolveSlots = mutableListOf<NsdManager.ResolveListener>()
        every { mockNsdManager.resolveService(any(), capture(resolveSlots)) } returns Unit

        manager.startDiscovery()
        verify { mockNsdManager.discoverServices(any(), any(), capture(discoveryListenerSlot)) }
        discoveryListenerSlot.captured.onDiscoveryStarted(NsdClusterDiscoveryManager.SERVICE_TYPE)

        val svcA = NsdServiceInfo().apply {
            serviceName = "cluster-a"
            serviceType = "_androgrid._tcp"
        }
        val svcB = NsdServiceInfo().apply {
            serviceName = "cluster-b"
            serviceType = "_androgrid._tcp"
        }

        // Announce service A then service B back-to-back
        discoveryListenerSlot.captured.onServiceFound(svcA)
        discoveryListenerSlot.captured.onServiceFound(svcB)

        // Only service A should be resolving; service B must wait in queue
        verify(exactly = 1) { mockNsdManager.resolveService(svcA, any()) }
        verify(exactly = 0) { mockNsdManager.resolveService(svcB, any()) }

        // Complete service A resolution
        val resolvedA = NsdServiceInfo().apply {
            serviceName = "cluster-a"
            serviceType = "_androgrid._tcp"
            host = InetAddress.getByName("192.168.1.10")
            port = 50051
        }
        resolveSlots.last().onServiceResolved(resolvedA)

        // Service B must now be popped from queue and invoked
        verify(exactly = 1) { mockNsdManager.resolveService(svcB, any()) }

        // Complete service B resolution
        val resolvedB = NsdServiceInfo().apply {
            serviceName = "cluster-b"
            serviceType = "_androgrid._tcp"
            host = InetAddress.getByName("192.168.1.20")
            port = 50051
        }
        resolveSlots.last().onServiceResolved(resolvedB)

        assertThat(manager.discoveredClusters.value).hasSize(2)
    }

    @Test
    fun testResolveQueue_deduplicatesPendingServiceNames() {
        val manager = NsdClusterDiscoveryManager(
            context = ApplicationProvider.getApplicationContext(),
            nsdManager = mockNsdManager,
            wifiManager = mockWifiManager
        )

        val resolveSlots = mutableListOf<NsdManager.ResolveListener>()
        every { mockNsdManager.resolveService(any(), capture(resolveSlots)) } returns Unit

        manager.startDiscovery()
        verify { mockNsdManager.discoverServices(any(), any(), capture(discoveryListenerSlot)) }
        discoveryListenerSlot.captured.onDiscoveryStarted(NsdClusterDiscoveryManager.SERVICE_TYPE)

        val service = NsdServiceInfo().apply {
            serviceName = "cluster-dup"
            serviceType = "_androgrid._tcp"
        }

        // Announce same service twice while first is still resolving
        discoveryListenerSlot.captured.onServiceFound(service)
        discoveryListenerSlot.captured.onServiceFound(service)

        val resolved = NsdServiceInfo().apply {
            serviceName = "cluster-dup"
            serviceType = "_androgrid._tcp"
            host = InetAddress.getByName("192.168.1.15")
            port = 50051
        }
        resolveSlots.last().onServiceResolved(resolved)

        // resolveService must be called exactly once for cluster-dup
        verify(exactly = 1) { mockNsdManager.resolveService(service, any()) }
    }

    @Test
    fun testResolveQueue_dropsWhenQueueCapacityExceeded() {
        val manager = NsdClusterDiscoveryManager(
            context = ApplicationProvider.getApplicationContext(),
            nsdManager = mockNsdManager,
            wifiManager = mockWifiManager
        )

        val resolveSlots = mutableListOf<NsdManager.ResolveListener>()
        every { mockNsdManager.resolveService(any(), capture(resolveSlots)) } returns Unit

        manager.startDiscovery()
        verify { mockNsdManager.discoverServices(any(), any(), capture(discoveryListenerSlot)) }
        discoveryListenerSlot.captured.onDiscoveryStarted(NsdClusterDiscoveryManager.SERVICE_TYPE)

        // First service starts resolving immediately
        val svc0 = NsdServiceInfo().apply {
            serviceName = "cluster-0"
            serviceType = "_androgrid._tcp"
        }
        discoveryListenerSlot.captured.onServiceFound(svc0)

        // Next 16 services fill the resolve queue (capacity = 16)
        for (i in 1..16) {
            val svc = NsdServiceInfo().apply {
                serviceName = "cluster-$i"
                serviceType = "_androgrid._tcp"
            }
            discoveryListenerSlot.captured.onServiceFound(svc)
        }

        // 17th queued service (cluster-17) must be dropped due to queue overflow
        val overflowSvc = NsdServiceInfo().apply {
            serviceName = "cluster-17"
            serviceType = "_androgrid._tcp"
        }
        discoveryListenerSlot.captured.onServiceFound(overflowSvc)

        // Complete svc0
        val resolved0 = NsdServiceInfo().apply {
            serviceName = "cluster-0"
            serviceType = "_androgrid._tcp"
            host = InetAddress.getByName("192.168.1.100")
            port = 50051
        }
        resolveSlots.first().onServiceResolved(resolved0)

        // cluster-17 must never have been resolved
        verify(exactly = 0) { mockNsdManager.resolveService(overflowSvc, any()) }
    }

    @Test
    fun testStartingState_stopDuringStartingWindow_cancelsSessionAndReleasesLock() {
        val manager = NsdClusterDiscoveryManager(
            context = ApplicationProvider.getApplicationContext(),
            nsdManager = mockNsdManager,
            wifiManager = mockWifiManager
        )

        // 1. Call startDiscovery: transitions to STARTING
        manager.startDiscovery()
        verify { mockNsdManager.discoverServices(any(), any(), capture(discoveryListenerSlot)) }
        verify { mockMulticastLock.acquire() }

        every { mockMulticastLock.isHeld } returns true

        // 2. Before onDiscoveryStarted arrives, stopDiscovery is called
        manager.stopDiscovery()
        assertThat(manager.isDiscovering.value).isFalse()

        // 3. Late onDiscoveryStarted arrives from OS binder
        discoveryListenerSlot.captured.onDiscoveryStarted(NsdClusterDiscoveryManager.SERVICE_TYPE)

        // Must immediately call stopServiceDiscovery and release MulticastLock
        verify { mockNsdManager.stopServiceDiscovery(discoveryListenerSlot.captured) }
        verify { mockMulticastLock.release() }
        assertThat(manager.isDiscovering.value).isFalse()
    }

    @Test
    fun testDiscoveredClusters_boundedAtCapacity() {
        val manager = NsdClusterDiscoveryManager(
            context = ApplicationProvider.getApplicationContext(),
            nsdManager = mockNsdManager,
            wifiManager = mockWifiManager
        )

        val resolveSlots = mutableListOf<NsdManager.ResolveListener>()
        every { mockNsdManager.resolveService(any(), capture(resolveSlots)) } returns Unit

        manager.startDiscovery()
        verify { mockNsdManager.discoverServices(any(), any(), capture(discoveryListenerSlot)) }
        discoveryListenerSlot.captured.onDiscoveryStarted(NsdClusterDiscoveryManager.SERVICE_TYPE)

        for (i in 1..20) {
            val svc = NsdServiceInfo().apply {
                serviceName = "node-$i"
                serviceType = "_androgrid._tcp"
                host = InetAddress.getByName("192.168.1.$i")
                port = 50051
            }
            discoveryListenerSlot.captured.onServiceFound(svc)
            resolveSlots.last().onServiceResolved(svc)
        }

        // Must be capped at 16
        assertThat(manager.discoveredClusters.value).hasSize(16)
    }
}
