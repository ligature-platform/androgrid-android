package com.androgrid.worker.engine

import com.androgrid.v1.NetworkEgressPolicy
import okhttp3.Dns
import okhttp3.HttpUrl
import okhttp3.HttpUrl.Companion.toHttpUrlOrNull
import java.net.Inet6Address
import java.net.InetAddress
import java.net.UnknownHostException

/**
 * Security guard enforcing network egress access controls, destination allowlisting,
 * anti-TOCTOU DNS validation, SSRF protection, and metered network restrictions
 * for sandboxed WebAssembly workloads.
 *
 * Verifies all destination addresses before and during socket connection:
 * 1. Policy Enforcement: Outbound access is permitted only if policy is NETWORK_EGRESS_POLICY_ALLOWLIST.
 * 2. Metered Network Guard: Rejects calls when running on metered cellular interfaces ([ANTI-003], [INV-003], [NFR-POW-001]).
 *    Defaults to fail-closed (isMeteredProvider = { true }).
 * 3. Scheme Restrictions: Permits only HTTP and HTTPS protocols ([INV-001]).
 * 4. Destination Allowlist: Validates hostname against exact or wildcard patterns ([INV-006]).
 *    Bare wildcards (*) and apex matching (*.example.com matching example.com) are strictly forbidden.
 * 5. DNS Pre-flight & In-Socket SSRF Guard: Resolves host IP addresses and deterministically rejects
 *    private spaces (RFC 1918), IPv6 ULA (fc00::/7), loopback (127.0.0.0/8, ::1),
 *    link-local (169.254.0.0/16, fe80::/10), carrier-grade NAT (100.64.0.0/10), multicast,
 *    broadcast (255.255.255.255), and wildcard/unspecified addresses ([NFR-SEC-001]).
 * 6. Header Sanitization: Rejects hop-by-hop/framing headers and CRLF injection.
 *
 * Traces to: [INV-001], [INV-003], [INV-006], [ANTI-003], [NFR-SEC-001], [NFR-POW-001], ADR-011
 */
class WasmNetworkEgressSecurityGuard(
    private val dns: Dns = Dns.SYSTEM,
    private val isMeteredProvider: () -> Boolean = { true },
    private val allowLoopbackForTesting: Boolean = false
) {

    companion object {
        const val MAX_HEADERS_BYTES: Int = 8192

        val FORBIDDEN_HEADERS: Set<String> = setOf(
            "host",
            "transfer-encoding",
            "content-length",
            "connection",
            "keep-alive",
            "proxy-connection",
            "upgrade",
            "te",
            "trailer",
            "proxy-authorization",
            "proxy-authenticate"
        )
    }

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

        // Standard JDK checks
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

            // Loopback (127.0.0.0/8)
            if (b0 == 127) return true

            // RFC 1918 Private Spaces
            if (b0 == 10) return true
            if (b0 == 172 && b1 in 16..31) return true
            if (b0 == 192 && b1 == 168) return true

            // RFC 6598 Carrier-Grade NAT (100.64.0.0/10)
            if (b0 == 100 && b1 in 64..127) return true

            // Link-local / Cloud metadata (169.254.0.0/16)
            if (b0 == 169 && b1 == 254) return true

            // Current network / broadcast (0.0.0.0/8, 255.255.255.255)
            if (b0 == 0 || b0 == 255) return true

            // Multicast (224.0.0.0/4: 224 to 239)
            if (b0 in 224..239) return true
        }

        // IPv6-specific checks
        if (addr is Inet6Address && raw.size == 16) {
            val b0 = raw[0].toInt() and 0xFF
            val b1 = raw[1].toInt() and 0xFF

            // IPv6 Unique Local Addresses (fc00::/7: fc00::/8 and fd00::/8, RFC 4193)
            if ((b0 and 0xFE) == 0xFC) return true

            // IPv6 Link-Local Unicast (fe80::/10)
            if (b0 == 0xFE && (b1 and 0xC0) == 0x80) return true

            // IPv6 Multicast (ff00::/8)
            if (b0 == 0xFF) return true

            // Unspecified address (::)
            if (raw.all { it == 0.toByte() }) return true

            // Loopback (::1)
            if (raw.take(15).all { it == 0.toByte() } && raw[15] == 1.toByte()) return true

            // IPv4-mapped IPv6 checks (::ffff:a.b.c.d)
            val isIpv4Mapped = raw.take(10).all { it == 0.toByte() } &&
                    raw[10] == 0xFF.toByte() && raw[11] == 0xFF.toByte()
            if (isIpv4Mapped) {
                val ipv4Bytes = ByteArray(4) { i -> raw[12 + i] }
                val mappedAddr = try {
                    InetAddress.getByAddress(ipv4Bytes)
                } catch (e: Exception) {
                    return true
                }
                return isDisallowedAddress(mappedAddr)
            }
        }

        return false
    }

    /**
     * Checks if a destination hostname matches an allowlist pattern.
     * Supports exact matches and wildcard subdomain prefixes (*.api.example.com).
     *
     * Invariants:
     * - Bare '*' or '*.*' wildcards are strictly rejected.
     * - Wildcard '*.example.com' matches 'sub.example.com' but NEVER matches apex 'example.com'.
     *
     * @param hostname The hostname to check.
     * @param pattern The allowlist pattern to match against.
     * @return True if hostname matches pattern, false otherwise.
     */
    fun matchesHostnamePattern(hostname: String, pattern: String): Boolean {
        val cleanHost = hostname.trim().lowercase()
        val cleanPattern = pattern.trim().lowercase()

        // Bare wildcards are strictly forbidden
        if (cleanPattern == "*" || cleanPattern == "*.*") {
            return false
        }

        if (cleanPattern.startsWith("*.")) {
            val suffix = cleanPattern.removePrefix("*.")
            // Apex domain must NOT match the wildcard pattern
            if (cleanHost == suffix) {
                return false
            }
            return cleanHost.endsWith(".$suffix")
        }

        return cleanHost == cleanPattern
    }

    /**
     * Creates an in-socket custom [Dns] wrapper that intercepts all address resolutions
     * at socket connection time to completely eliminate TOCTOU DNS rebinding attacks.
     *
     * @param underlyingDns The base DNS provider to query (defaults to guard's dns).
     * @return A secure [Dns] implementation.
     */
    fun createTaskDns(underlyingDns: Dns = dns): Dns {
        return object : Dns {
            override fun lookup(hostname: String): List<InetAddress> {
                val addresses = try {
                    underlyingDns.lookup(hostname)
                } catch (e: UnknownHostException) {
                    throw e
                } catch (e: Exception) {
                    throw UnknownHostException("DNS resolution failed for host '$hostname': ${e.message}")
                }

                if (addresses.isEmpty()) {
                    throw UnknownHostException("No IP addresses returned for host '$hostname'")
                }

                for (addr in addresses) {
                    if (isDisallowedAddress(addr)) {
                        throw SecurityException(
                            "SSRF Guard: In-socket connection to host '$hostname' blocked: resolved to disallowed IP ${addr.hostAddress}. [INV-006], [NFR-SEC-001]"
                        )
                    }
                }

                return addresses
            }
        }
    }

    /**
     * Sanitizes and parses raw HTTP headers passed from WASM linear memory.
     * Enforces size bounds, CRLF anti-injection, and forbidden hop-by-hop/proxy headers.
     *
     * @param headersString Raw newline-delimited string of "Key: Value" headers.
     * @return Parsed map of header names to values.
     * @throws SecurityException If forbidden headers or CRLF injection are detected.
     */
    fun sanitizeHeaders(headersString: String): Map<String, String> {
        if (headersString.isEmpty()) return emptyMap()

        val bytes = headersString.toByteArray(Charsets.UTF_8)
        if (bytes.size > MAX_HEADERS_BYTES) {
            throw SecurityException(
                "Headers buffer size (${bytes.size} bytes) exceeds maximum allowed $MAX_HEADERS_BYTES bytes"
            )
        }

        val result = mutableMapOf<String, String>()
        val lines = headersString.split("\r\n", "\n")

        for (line in lines) {
            val trimmed = line.trim()
            if (trimmed.isEmpty()) continue

            val colonIdx = trimmed.indexOf(':')
            if (colonIdx <= 0) {
                throw IllegalArgumentException("Malformed header entry (missing colon separator): '$trimmed'")
            }

            val key = trimmed.substring(0, colonIdx).trim()
            val value = trimmed.substring(colonIdx + 1).trim()

            // Verify zero embedded control characters in key or value
            if (key.any { it == '\r' || it == '\n' || it == '\u0000' } ||
                value.any { it == '\r' || it == '\n' || it == '\u0000' }
            ) {
                throw SecurityException("CRLF or control character injection detected in header '$key'")
            }

            val lowerKey = key.lowercase()
            if (FORBIDDEN_HEADERS.contains(lowerKey)) {
                throw SecurityException("Forbidden hop-by-hop or framing header: '$key'")
            }

            result[key] = value
        }

        return result
    }

    /**
     * Validates destination URL and resolved network addresses against security policies.
     *
     * Traces to: [INV-001], [INV-003], [INV-006], [ANTI-003], [NFR-SEC-001], [NFR-POW-001], ADR-011
     *
     * @param urlString Target URL string to validate.
     * @param policy Active network egress policy from TaskSpec.
     * @param allowedHostnames List of permitted destination hostnames or wildcards.
     * @param maxEgressBytes Cumulative egress byte limit for the task attempt.
     * @return Parsed and validated HttpUrl object.
     * @throws SecurityException If URL targets private IP, unlisted host, forbidden scheme, or metered cellular.
     * @throws IllegalArgumentException If URL is syntactically invalid.
     */
    fun validateOutboundUrl(
        urlString: String,
        policy: NetworkEgressPolicy,
        allowedHostnames: List<String>,
        maxEgressBytes: Long = 1048576L
    ): HttpUrl {
        // Step 1: Enforce task egress policy boundary
        if (policy != NetworkEgressPolicy.NETWORK_EGRESS_POLICY_ALLOWLIST) {
            throw SecurityException(
                "Outbound network access is disabled by task policy ($policy). [INV-006]"
            )
        }

        // Step 2: Enforce fail-closed quota check
        if (maxEgressBytes <= 0) {
            throw SecurityException(
                "max_egress_bytes must be greater than zero when egress_policy is ALLOWLIST (fail-closed default)"
            )
        }

        // Step 3: Enforce metered network guard per [ANTI-003], [INV-003], [NFR-POW-001]
        if (isMeteredProvider.invoke()) {
            throw SecurityException(
                "Outbound network access over metered connection is forbidden per [INV-003] and [ANTI-003]"
            )
        }

        // Step 4: Parse URL and validate HTTP/HTTPS transport scheme ([INV-001])
        val httpUrl = urlString.toHttpUrlOrNull()
            ?: throw IllegalArgumentException("Malformed URL: $urlString")

        val scheme = httpUrl.scheme.lowercase()
        if (scheme != "http" && scheme != "https") {
            throw SecurityException(
                "Forbidden scheme '$scheme'. Only HTTP and HTTPS are permitted per [INV-001]."
            )
        }

        val host = httpUrl.host

        // Step 5: Validate hostname against allowed_hostnames allowlist
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

        // Step 6: DNS Pre-flight address inspection for SSRF and private space guard
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
