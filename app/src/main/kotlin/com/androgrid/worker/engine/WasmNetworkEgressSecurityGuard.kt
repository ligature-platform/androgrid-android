package com.androgrid.worker.engine

import com.androgrid.v1.NetworkEgressPolicy
import okhttp3.Dns
import okhttp3.HttpUrl
import okhttp3.HttpUrl.Companion.toHttpUrlOrNull
import java.net.Inet6Address
import java.net.InetAddress

/**
 * Security guard enforcing network egress access controls, destination allowlisting,
 * SSRF protection, and metered network restrictions for sandboxed WebAssembly workloads.
 *
 * Verifies all destination addresses before socket connection is initiated:
 * 1. Policy Enforcement: Outbound access is permitted only if policy is NETWORK_EGRESS_POLICY_ALLOWLIST.
 * 2. Metered Network Guard: Rejects calls when running on metered cellular interfaces ([ANTI-003], [INV-003], [NFR-POW-001]).
 * 3. Scheme Restrictions: Permits only HTTP and HTTPS protocols ([INV-001]).
 * 4. Destination Allowlist: Validates hostname against exact or wildcard patterns ([INV-006]).
 * 5. DNS Pre-flight & SSRF Guard: Resolves all host IP addresses and deterministically rejects
 *    private spaces (RFC 1918), loopback (127.0.0.0/8, ::1), link-local (169.254.0.0/16, fe80::/10),
 *    carrier-grade NAT (100.64.0.0/10), multicast, and wildcard/unspecified addresses ([NFR-SEC-001]).
 *
 * Traces to: [INV-001], [INV-003], [INV-006], [ANTI-003], [NFR-SEC-001], [NFR-POW-001], ADR-011
 */
class WasmNetworkEgressSecurityGuard(
    private val dns: Dns = Dns.SYSTEM,
    private val isMeteredProvider: () -> Boolean = { false },
    private val allowLoopbackForTesting: Boolean = false
) {

    /**
     * Inspects target IP address to enforce SSRF, LAN isolation, and private subnet protection.
     *
     * @param addr The resolved IP address to inspect.
     * @return True if the address belongs to a disallowed private, local, or internal range.
     */
    fun isDisallowedAddress(addr: InetAddress): Boolean {
        if (allowLoopbackForTesting && addr.isLoopbackAddress) {
            return false
        }
        // Standard JDK checks for loopback (127.0.0.0/8, ::1), site-local (RFC 1918),
        // link-local (169.254.0.0/16, fe80::/10), any-local (0.0.0.0, ::), and multicast
        if (addr.isLoopbackAddress ||
            addr.isSiteLocalAddress ||
            addr.isLinkLocalAddress ||
            addr.isAnyLocalAddress ||
            addr.isMulticastAddress
        ) {
            return true
        }

        val raw = addr.address

        // IPv4-specific checks
        if (raw.size == 4) {
            val b0 = raw[0].toInt() and 0xFF
            val b1 = raw[1].toInt() and 0xFF

            // RFC 1918 redundancy checks in case JDK platform implementation differs
            if (b0 == 10) return true
            if (b0 == 172 && b1 in 16..31) return true
            if (b0 == 192 && b1 == 168) return true

            // RFC 6598 Carrier-Grade NAT (100.64.0.0/10: 100.64.0.0 to 100.127.255.255)
            if (b0 == 100 && b1 in 64..127) return true

            // Link-local / AWS/GCP metadata address (169.254.0.0/16)
            if (b0 == 169 && b1 == 254) return true

            // Current network / broadcast (0.0.0.0/8, 255.255.255.255)
            if (b0 == 0 || b0 == 255) return true
        }

        // IPv6-mapped IPv4 checks (e.g., ::ffff:192.168.1.1)
        if (addr is Inet6Address && raw.size == 16) {
            val isIpv4Mapped = raw[0] == 0.toByte() && raw[1] == 0.toByte() &&
                    raw[2] == 0.toByte() && raw[3] == 0.toByte() &&
                    raw[4] == 0.toByte() && raw[5] == 0.toByte() &&
                    raw[6] == 0.toByte() && raw[7] == 0.toByte() &&
                    raw[8] == 0.toByte() && raw[9] == 0.toByte() &&
                    raw[10] == 0xFF.toByte() && raw[11] == 0xFF.toByte()
            if (isIpv4Mapped) {
                val b12 = raw[12].toInt() and 0xFF
                val b13 = raw[13].toInt() and 0xFF
                if (b12 == 127) return true
                if (b12 == 10) return true
                if (b12 == 172 && b13 in 16..31) return true
                if (b12 == 192 && b13 == 168) return true
                if (b12 == 169 && b13 == 254) return true
                if (b12 == 100 && b13 in 64..127) return true
            }
        }

        return false
    }

    /**
     * Checks if a destination hostname matches an allowlist pattern.
     * Supports exact matches and wildcard subdomain prefixes (*.example.com).
     *
     * @param hostname The hostname to check.
     * @param pattern The allowlist pattern to match against.
     * @return True if hostname matches pattern, false otherwise.
     */
    fun matchesHostnamePattern(hostname: String, pattern: String): Boolean {
        val cleanHost = hostname.trim().lowercase()
        val cleanPattern = pattern.trim().lowercase()

        if (cleanPattern == "*") {
            return true
        }

        if (cleanPattern.startsWith("*.")) {
            val suffix = cleanPattern.removePrefix("*.")
            return cleanHost.endsWith(".$suffix") || cleanHost == suffix
        }

        return cleanHost == cleanPattern
    }

    /**
     * Validates destination URL and resolved network addresses against security policies.
     *
     * Traces to: [INV-001], [INV-003], [INV-006], [ANTI-003], [NFR-SEC-001], [NFR-POW-001], ADR-011
     *
     * @param urlString Target URL string to validate.
     * @param policy Active network egress policy from TaskSpec.
     * @param allowedHostnames List of permitted destination hostnames or wildcards.
     * @return Parsed and validated HttpUrl object.
     * @throws SecurityException If URL targets private IP, unlisted host, forbidden scheme, or metered cellular.
     * @throws IllegalArgumentException If URL is syntactically invalid.
     */
    fun validateOutboundUrl(
        urlString: String,
        policy: NetworkEgressPolicy,
        allowedHostnames: List<String>
    ): HttpUrl {
        // Step 1: Enforce task egress policy boundary
        if (policy != NetworkEgressPolicy.NETWORK_EGRESS_POLICY_ALLOWLIST) {
            throw SecurityException(
                "Outbound network access is disabled by task policy ($policy). [INV-006]"
            )
        }

        // Step 2: Enforce metered network guard per [ANTI-003], [INV-003], [NFR-POW-001]
        if (isMeteredProvider.invoke()) {
            throw SecurityException(
                "Outbound network access over metered connection is forbidden per [INV-003] and [ANTI-003]"
            )
        }

        // Step 3: Parse URL and validate HTTP/HTTPS transport scheme ([INV-001])
        val httpUrl = urlString.toHttpUrlOrNull()
            ?: throw IllegalArgumentException("Malformed URL: $urlString")

        val scheme = httpUrl.scheme.lowercase()
        if (scheme != "http" && scheme != "https") {
            throw SecurityException(
                "Forbidden scheme '$scheme'. Only HTTP and HTTPS are permitted per [INV-001]."
            )
        }

        val host = httpUrl.host

        // Step 4: Validate hostname against allowed_hostnames allowlist
        if (allowedHostnames.isEmpty()) {
            throw SecurityException(
                "Destination host '$host' rejected: allowed_hostnames allowlist is empty. [INV-006]"
            )
        }

        val isAllowlisted = allowedHostnames.any { pattern ->
            matchesHostnamePattern(host, pattern)
        }
        if (!isAllowlisted) {
            throw SecurityException(
                "Destination host '$host' is not in allowed_hostnames allowlist: $allowedHostnames. [INV-006]"
            )
        }

        // Step 5: DNS Pre-flight address inspection for SSRF and private space guard
        val resolvedAddresses = try {
            dns.lookup(host)
        } catch (e: Exception) {
            throw SecurityException("Unable to resolve destination host '$host': ${e.message}", e)
        }

        if (resolvedAddresses.isEmpty()) {
            throw SecurityException("Unable to resolve destination host '$host'")
        }

        for (addr in resolvedAddresses) {
            if (isDisallowedAddress(addr)) {
                throw SecurityException(
                    "SSRF Guard: Host '$host' resolved to disallowed IP ${addr.hostAddress} (RFC 1918 / Loopback / Link-Local guard). [INV-006], [NFR-SEC-001]"
                )
            }
        }

        return httpUrl
    }
}
