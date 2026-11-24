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
import java.net.Inet4Address
import java.net.Inet6Address
import java.net.InetAddress
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
        private const val MAX_RESOLVE_QUEUE_SIZE = 16
        private const val MAX_DISCOVERED_CLUSTERS = 16
    }

    private enum class DiscoveryState {
        STOPPED,
        STARTING,
        DISCOVERING,
        STOPPING
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

    private val stateLock = Any()
    private var discoveryState = DiscoveryState.STOPPED
    private var currentSessionId: Long = 0L
    private var activeDiscoveryListener: NsdManager.DiscoveryListener? = null
    private var isResolving: Boolean = false
    private val resolveQueue = ArrayDeque<NsdServiceInfo>()
    private val pendingServiceNames = HashSet<String>()

    private inner class SessionDiscoveryListener(private val sessionId: Long) : NsdManager.DiscoveryListener {
        override fun onDiscoveryStarted(regType: String) {
            val shouldStopImmediately = synchronized(stateLock) {
                if (sessionId != currentSessionId || discoveryState == DiscoveryState.STOPPING) {
                    true
                } else {
                    discoveryState = DiscoveryState.DISCOVERING
                    _isDiscovering.value = true
                    Log.d(TAG, "mDNS discovery active for session $sessionId ($regType)")
                    false
                }
            }

            if (shouldStopImmediately) {
                try {
                    nsdManager?.stopServiceDiscovery(this)
                } catch (e: Exception) {
                    Log.w(TAG, "Error stopping cancelled discovery session: ${e.message}")
                } finally {
                    synchronized(stateLock) {
                        if (sessionId == currentSessionId) {
                            discoveryState = DiscoveryState.STOPPED
                            _isDiscovering.value = false
                            activeDiscoveryListener = null
                        }
                    }
                    releaseMulticastLock()
                }
            }
        }

        override fun onServiceFound(serviceInfo: NsdServiceInfo) {
            val session = synchronized(stateLock) {
                if (sessionId == currentSessionId && discoveryState == DiscoveryState.DISCOVERING) {
                    sessionId
                } else {
                    null
                }
            }
            if (session != null) {
                val type = serviceInfo.serviceType ?: ""
                if (type.contains("_androgrid._tcp", ignoreCase = true)) {
                    enqueueResolve(serviceInfo, session)
                }
            }
        }

        override fun onServiceLost(serviceInfo: NsdServiceInfo) {
            synchronized(stateLock) {
                if (sessionId == currentSessionId) {
                    val name = serviceInfo.serviceName ?: return
                    pendingServiceNames.remove(name)
                    _discoveredClusters.update { list ->
                        list.filterNot { it.serviceName == name }
                    }
                }
            }
        }

        override fun onDiscoveryStopped(serviceType: String) {
            Log.d(TAG, "mDNS discovery stopped for session $sessionId")
            synchronized(stateLock) {
                if (sessionId == currentSessionId) {
                    discoveryState = DiscoveryState.STOPPED
                    _isDiscovering.value = false
                    activeDiscoveryListener = null
                    resolveQueue.clear()
                    pendingServiceNames.clear()
                    isResolving = false
                }
            }
            releaseMulticastLock()
        }

        override fun onStartDiscoveryFailed(serviceType: String, errorCode: Int) {
            Log.e(TAG, "Start mDNS discovery failed for session $sessionId: errorCode=$errorCode")
            synchronized(stateLock) {
                if (sessionId == currentSessionId) {
                    discoveryState = DiscoveryState.STOPPED
                    _isDiscovering.value = false
                    activeDiscoveryListener = null
                }
            }
            releaseMulticastLock()
        }

        override fun onStopDiscoveryFailed(serviceType: String, errorCode: Int) {
            Log.e(TAG, "Stop mDNS discovery failed for session $sessionId: errorCode=$errorCode")
            synchronized(stateLock) {
                if (sessionId == currentSessionId) {
                    discoveryState = DiscoveryState.STOPPED
                    _isDiscovering.value = false
                    activeDiscoveryListener = null
                }
            }
            releaseMulticastLock()
        }
    }

    override fun startDiscovery() {
        val (sessionId, listener) = synchronized(stateLock) {
            if (discoveryState == DiscoveryState.STARTING || discoveryState == DiscoveryState.DISCOVERING) {
                Log.d(TAG, "mDNS discovery already active or starting; ignoring start request")
                return
            }
            currentSessionId++
            val sid = currentSessionId
            discoveryState = DiscoveryState.STARTING
            val l = SessionDiscoveryListener(sid)
            activeDiscoveryListener = l
            sid to l
        }

        acquireMulticastLock()

        val nsd = nsdManager
        if (nsd == null) {
            Log.w(TAG, "NsdManager is null on this platform; discovery unavailable")
            synchronized(stateLock) {
                if (currentSessionId == sessionId) {
                    discoveryState = DiscoveryState.STOPPED
                    _isDiscovering.value = false
                    activeDiscoveryListener = null
                }
            }
            releaseMulticastLock()
            return
        }

        try {
            nsd.discoverServices(SERVICE_TYPE, NsdManager.PROTOCOL_DNS_SD, listener)
        } catch (e: Exception) {
            Log.e(TAG, "Failed to initiate mDNS service discovery: ${e.message}", e)
            synchronized(stateLock) {
                if (currentSessionId == sessionId) {
                    discoveryState = DiscoveryState.STOPPED
                    _isDiscovering.value = false
                    activeDiscoveryListener = null
                }
            }
            releaseMulticastLock()
        }
    }

    override fun stopDiscovery() {
        val listenerToStop: NsdManager.DiscoveryListener?
        synchronized(stateLock) {
            if (discoveryState == DiscoveryState.STOPPED) {
                return
            }
            currentSessionId++
            resolveQueue.clear()
            pendingServiceNames.clear()
            isResolving = false

            if (discoveryState == DiscoveryState.STARTING) {
                // Cancelled during the STARTING window before OS onDiscoveryStarted
                discoveryState = DiscoveryState.STOPPING
                _isDiscovering.value = false
                listenerToStop = null
            } else {
                discoveryState = DiscoveryState.STOPPING
                _isDiscovering.value = false
                listenerToStop = activeDiscoveryListener
            }
        }

        _discoveredClusters.value = emptyList()

        if (listenerToStop != null) {
            try {
                nsdManager?.stopServiceDiscovery(listenerToStop)
            } catch (e: Exception) {
                Log.w(TAG, "Error stopping mDNS service discovery: ${e.message}")
            } finally {
                synchronized(stateLock) {
                    discoveryState = DiscoveryState.STOPPED
                    activeDiscoveryListener = null
                }
                releaseMulticastLock()
            }
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

    private fun enqueueResolve(serviceInfo: NsdServiceInfo, sessionId: Long) {
        val toResolve: NsdServiceInfo? = synchronized(stateLock) {
            if (sessionId != currentSessionId || !_isDiscovering.value) return
            val name = serviceInfo.serviceName ?: return
            if (pendingServiceNames.size >= MAX_RESOLVE_QUEUE_SIZE || !pendingServiceNames.add(name)) {
                return
            }
            resolveQueue.addLast(serviceInfo)
            if (!isResolving) {
                isResolving = true
                resolveQueue.removeFirst()
            } else {
                null
            }
        }

        if (toResolve != null) {
            invokeResolveOutsideLock(toResolve, sessionId)
        }
    }

    private fun invokeResolveOutsideLock(serviceInfo: NsdServiceInfo, sessionId: Long) {
        val nsd = nsdManager
        if (nsd == null) {
            completeResolve(serviceInfo, sessionId)
            return
        }

        try {
            nsd.resolveService(serviceInfo, object : NsdManager.ResolveListener {
                override fun onServiceResolved(resolvedService: NsdServiceInfo) {
                    handleServiceResolved(resolvedService, sessionId)
                    completeResolve(serviceInfo, sessionId)
                }

                override fun onResolveFailed(info: NsdServiceInfo, errorCode: Int) {
                    Log.w(TAG, "Resolve failed for ${info.serviceName}: errorCode=$errorCode")
                    completeResolve(serviceInfo, sessionId)
                }
            })
        } catch (e: Exception) {
            Log.w(TAG, "Failed to invoke resolveService for ${serviceInfo.serviceName}: ${e.message}")
            completeResolve(serviceInfo, sessionId)
        }
    }

    private fun completeResolve(serviceInfo: NsdServiceInfo, sessionId: Long) {
        val nextService: NsdServiceInfo? = synchronized(stateLock) {
            serviceInfo.serviceName?.let { pendingServiceNames.remove(it) }
            if (sessionId != currentSessionId || !_isDiscovering.value || resolveQueue.isEmpty()) {
                isResolving = false
                null
            } else {
                resolveQueue.removeFirst()
            }
        }

        if (nextService != null) {
            invokeResolveOutsideLock(nextService, sessionId)
        }
    }

    private fun isValidLanHost(addr: InetAddress): Boolean {
        if (addr.isAnyLocalAddress || addr.isLoopbackAddress || addr.isMulticastAddress) return false
        if (addr is Inet4Address) {
            return addr.isSiteLocalAddress // 10/8, 172.16/12, 192.168/16
        }
        if (addr is Inet6Address) {
            // Reject unroutable link-local without scope
            if (addr.isLinkLocalAddress) return false
            // Allow RFC 4193 ULA fc00::/7
            val firstByte = addr.address[0].toInt() and 0xFF
            return (firstByte and 0xFE) == 0xFC
        }
        return false
    }

    private fun handleServiceResolved(info: NsdServiceInfo, sessionId: Long) {
        synchronized(stateLock) {
            if (sessionId != currentSessionId || !_isDiscovering.value) {
                Log.d(TAG, "Ignoring stale resolve callback for session $sessionId (active: $currentSessionId)")
                return
            }
        }

        val hostAddress = info.host?.hostAddress
        val hostInet = info.host
        if (hostAddress.isNullOrBlank() || hostInet == null) {
            Log.w(TAG, "Resolved service without valid host IP: ${info.serviceName}")
            return
        }

        if (!isValidLanHost(hostInet)) {
            Log.w(TAG, "Rejected non-private or loopback host IP: $hostAddress for ${info.serviceName}")
            return
        }

        val port = info.port
        if (port !in 1..65535) {
            Log.w(TAG, "Rejected out-of-range port: $port for ${info.serviceName}")
            return
        }

        // Clean IPv6 host address
        val cleanHost = if (hostAddress.contains("%")) {
            hostAddress.substringBefore("%")
        } else {
            hostAddress
        }

        val serviceName = info.serviceName ?: "androgrid-orchestrator"
        val attributes = info.attributes ?: emptyMap()
        val clusterName = attributes["name"]?.let { String(it, Charsets.UTF_8) }?.takeIf { it.isNotBlank() } ?: serviceName
        val version = attributes["version"]?.let { String(it, Charsets.UTF_8) } ?: ""
        val tlsVersion = attributes["tls"]?.let { String(it, Charsets.UTF_8) } ?: "1.3"
        val rawFingerprint = attributes["ca_fingerprint"]?.let { String(it, Charsets.UTF_8) }?.trim()?.lowercase() ?: ""
        val caFingerprint = if (rawFingerprint.matches(Regex("^[0-9a-f]{64}$"))) rawFingerprint else ""
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
            (listOf(cluster) + updated).take(MAX_DISCOVERED_CLUSTERS)
        }
    }
}
