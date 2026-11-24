package com.androgrid.worker.network

import android.content.Context
import android.net.nsd.NsdManager
import android.net.nsd.NsdServiceInfo
import android.net.wifi.WifiManager
import android.util.Log
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import java.util.ArrayDeque

/**
 * Standard Android Network Service Discovery (NSD) implementation of [ClusterDiscoveryManager].
 * Discovers orchestrator instances broadcasting `_androgrid._tcp` mDNS DNS-SD announcements.
 *
 * Adheres strictly to [INV-001]: Listens for multicast announcements without opening inbound mobile listening ports.
 * Adheres strictly to [NFR-POW-001]: Defensively holds Wi-Fi MulticastLock only during active Wi-Fi discovery.
 *
 * Traces to: [REQ-OP-001], [INV-001], [INV-002], [NFR-POW-001]
 */
@Suppress("DEPRECATION")
class NsdClusterDiscoveryManager(
    context: Context,
    private val nsdManager: NsdManager? = context.applicationContext.getSystemService(Context.NSD_SERVICE) as? NsdManager,
    private val wifiManager: WifiManager? = context.applicationContext.getSystemService(Context.WIFI_SERVICE) as? WifiManager
) : ClusterDiscoveryManager {

    companion object {
        private const val TAG = "NsdClusterDiscovery"
        const val SERVICE_TYPE = "_androgrid._tcp"
        private const val MULTICAST_LOCK_TAG = "AndroGridClusterDiscovery"
    }

    private val multicastLock: WifiManager.MulticastLock? by lazy {
        wifiManager?.createMulticastLock(MULTICAST_LOCK_TAG)?.apply {
            setReferenceCounted(false)
        }
    }

    private val _discoveredClusters = MutableStateFlow<List<DiscoveredCluster>>(emptyList())
    override val discoveredClusters: StateFlow<List<DiscoveredCluster>> = _discoveredClusters.asStateFlow()

    private val _isDiscovering = MutableStateFlow(false)
    override val isDiscovering: StateFlow<Boolean> = _isDiscovering.asStateFlow()

    private val resolveQueue = ArrayDeque<NsdServiceInfo>()
    private var isResolving = false

    private val discoveryListener = object : NsdManager.DiscoveryListener {
        override fun onDiscoveryStarted(regType: String) {
            Log.d(TAG, "mDNS discovery started for service type: $regType")
            _isDiscovering.value = true
        }

        override fun onServiceFound(serviceInfo: NsdServiceInfo) {
            Log.d(TAG, "Service found: ${serviceInfo.serviceName} (${serviceInfo.serviceType})")
            val type = serviceInfo.serviceType ?: ""
            if (type.contains("_androgrid._tcp", ignoreCase = true)) {
                enqueueResolve(serviceInfo)
            }
        }

        override fun onServiceLost(serviceInfo: NsdServiceInfo) {
            Log.d(TAG, "Service lost: ${serviceInfo.serviceName}")
            val name = serviceInfo.serviceName ?: return
            _discoveredClusters.update { list ->
                list.filterNot { it.serviceName == name }
            }
        }

        override fun onDiscoveryStopped(serviceType: String) {
            Log.d(TAG, "mDNS discovery stopped for service type: $serviceType")
            _isDiscovering.value = false
            releaseMulticastLock()
        }

        override fun onStartDiscoveryFailed(serviceType: String, errorCode: Int) {
            Log.e(TAG, "Start mDNS discovery failed: errorCode=$errorCode")
            _isDiscovering.value = false
            releaseMulticastLock()
        }

        override fun onStopDiscoveryFailed(serviceType: String, errorCode: Int) {
            Log.e(TAG, "Stop mDNS discovery failed: errorCode=$errorCode")
            _isDiscovering.value = false
            releaseMulticastLock()
        }
    }

    override fun startDiscovery() {
        if (_isDiscovering.value) {
            Log.d(TAG, "mDNS discovery already active; ignoring start request")
            return
        }

        acquireMulticastLock()

        val nsd = nsdManager
        if (nsd == null) {
            Log.w(TAG, "NsdManager is null on this platform; discovery unavailable")
            releaseMulticastLock()
            return
        }

        try {
            nsd.discoverServices(SERVICE_TYPE, NsdManager.PROTOCOL_DNS_SD, discoveryListener)
            _isDiscovering.value = true
        } catch (e: Exception) {
            Log.e(TAG, "Failed to initiate mDNS service discovery: ${e.message}", e)
            _isDiscovering.value = false
            releaseMulticastLock()
        }
    }

    override fun stopDiscovery() {
        if (!_isDiscovering.value) {
            return
        }

        try {
            nsdManager?.stopServiceDiscovery(discoveryListener)
        } catch (e: Exception) {
            Log.w(TAG, "Error stopping mDNS service discovery: ${e.message}")
        } finally {
            _isDiscovering.value = false
            releaseMulticastLock()
            synchronized(resolveQueue) {
                resolveQueue.clear()
                isResolving = false
            }
            _discoveredClusters.value = emptyList()
        }
    }

    private fun acquireMulticastLock() {
        try {
            multicastLock?.let { lock ->
                if (!lock.isHeld) {
                    lock.acquire()
                    Log.d(TAG, "MulticastLock acquired for mDNS discovery")
                }
            }
        } catch (e: Exception) {
            Log.w(TAG, "Defensive MulticastLock acquisition failed: ${e.message}")
        }
    }

    private fun releaseMulticastLock() {
        try {
            multicastLock?.let { lock ->
                if (lock.isHeld) {
                    lock.release()
                    Log.d(TAG, "MulticastLock released")
                }
            }
        } catch (e: Exception) {
            Log.w(TAG, "Defensive MulticastLock release failed: ${e.message}")
        }
    }

    private fun enqueueResolve(serviceInfo: NsdServiceInfo) {
        synchronized(resolveQueue) {
            resolveQueue.add(serviceInfo)
            if (!isResolving) {
                resolveNext()
            }
        }
    }

    private fun resolveNext() {
        val nextService: NsdServiceInfo
        synchronized(resolveQueue) {
            if (resolveQueue.isEmpty()) {
                isResolving = false
                return
            }
            isResolving = true
            nextService = resolveQueue.removeFirst()
        }

        val nsd = nsdManager
        if (nsd == null) {
            synchronized(resolveQueue) { isResolving = false }
            return
        }

        try {
            nsd.resolveService(nextService, object : NsdManager.ResolveListener {
                override fun onServiceResolved(resolvedService: NsdServiceInfo) {
                    handleServiceResolved(resolvedService)
                    synchronized(resolveQueue) { resolveNext() }
                }

                override fun onResolveFailed(serviceInfo: NsdServiceInfo, errorCode: Int) {
                    Log.w(TAG, "Resolve failed for ${serviceInfo.serviceName}: errorCode=$errorCode")
                    synchronized(resolveQueue) { resolveNext() }
                }
            })
        } catch (e: Exception) {
            Log.w(TAG, "Failed to invoke resolveService for ${nextService.serviceName}: ${e.message}")
            synchronized(resolveQueue) { resolveNext() }
        }
    }

    private fun handleServiceResolved(info: NsdServiceInfo) {
        val hostAddress = info.host?.hostAddress
        if (hostAddress.isNullOrBlank()) {
            Log.w(TAG, "Resolved service without valid host IP: ${info.serviceName}")
            return
        }

        // Strip IPv6 scope identifiers if present
        val cleanHost = if (hostAddress.contains("%")) {
            hostAddress.substringBefore("%")
        } else {
            hostAddress
        }

        val serviceName = info.serviceName ?: "androgrid-orchestrator"
        val port = info.port

        val attributes = info.attributes ?: emptyMap()
        val clusterName = attributes["name"]?.let { String(it, Charsets.UTF_8) }?.takeIf { it.isNotBlank() } ?: serviceName
        val version = attributes["version"]?.let { String(it, Charsets.UTF_8) } ?: ""
        val tlsVersion = attributes["tls"]?.let { String(it, Charsets.UTF_8) } ?: "1.3"
        val caFingerprint = attributes["ca_fingerprint"]?.let { String(it, Charsets.UTF_8) } ?: ""
        val nodeCount = attributes["nodes"]?.let { String(it, Charsets.UTF_8).toIntOrNull() } ?: 0

        val cluster = DiscoveredCluster(
            serviceName = serviceName,
            host = cleanHost,
            port = port,
            clusterName = clusterName,
            version = version,
            tlsVersion = tlsVersion,
            caFingerprint = caFingerprint,
            nodeCount = nodeCount
        )

        Log.i(TAG, "Discovered AndroGrid cluster: ${cluster.clusterName} at ${cluster.endpoint()} [REQ-OP-001]")

        _discoveredClusters.update { list ->
            val updated = list.filterNot { it.serviceName == serviceName || it.endpoint() == cluster.endpoint() }
            updated + cluster
        }
    }
}
