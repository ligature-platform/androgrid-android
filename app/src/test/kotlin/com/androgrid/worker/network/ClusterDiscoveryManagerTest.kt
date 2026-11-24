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
 * resolution queueing, multicast lock lifecycle, and error resilience.
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
        val manager = NsdClusterDiscoveryManager(
            context = ApplicationProvider.getApplicationContext(),
            nsdManager = mockNsdManager,
            wifiManager = mockWifiManager
        )

        manager.startDiscovery()
        verify { mockNsdManager.discoverServices(any(), any(), capture(discoveryListenerSlot)) }

        every { mockMulticastLock.isHeld } returns true

        discoveryListenerSlot.captured.onStartDiscoveryFailed("_androgrid._tcp", NsdManager.FAILURE_INTERNAL_ERROR)
        assertThat(manager.isDiscovering.value).isFalse()
        verify { mockMulticastLock.release() }

        discoveryListenerSlot.captured.onStopDiscoveryFailed("_androgrid._tcp", NsdManager.FAILURE_INTERNAL_ERROR)
        assertThat(manager.isDiscovering.value).isFalse()

        val service = NsdServiceInfo().apply {
            serviceName = "faulty"
            serviceType = "_androgrid._tcp"
        }
        discoveryListenerSlot.captured.onServiceFound(service)
        verify { mockNsdManager.resolveService(service, capture(resolveListenerSlot)) }
        resolveListenerSlot.captured.onResolveFailed(service, NsdManager.FAILURE_INTERNAL_ERROR)

        assertThat(manager.discoveredClusters.value).isEmpty()
    }
}
