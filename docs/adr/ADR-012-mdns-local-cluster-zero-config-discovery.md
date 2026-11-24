# ADR-012: Local Cluster Zero-Configuration Discovery via mDNS / NSD

## Status
Accepted

## Architectural Scope & Requirements
- Issue Reference: #68 (feat(discovery): support local cluster zero-config discovery via mDNS / NSD)
- Traceability: [REQ-OP-001], [INV-001], [INV-002], [NFR-POW-001]
- Standard: ISO/IEC/IEEE 29148:2018

---

## Context
Onboarding an Android worker node currently requires manually entering the orchestrator LAN IP and port in SettingsActivity or scanning a terminal ANSI QR code with the device camera. Typing IP addresses on mobile virtual keyboards is friction-heavy and prone to typographical errors.

Furthermore, mobile devices operating as edge compute nodes are bound by strict power and networking invariants:
1. **Zero Inbound Mobile Ports ([INV-001]):** The mobile worker must never open inbound listening TCP or UDP server sockets on any network interface. Discovery must operate strictly as an outbound/multicast client listener.
2. **Cellular Radio Power Optimization ([NFR-POW-001], [INV-003]):** Multicast listening on cellular WAN networks drains mobile battery, keeps baseband RRC states active, and fails because cellular carriers universally drop broadcast and multicast packets. Discovery must halt immediately when disconnected from Wi-Fi or when operating on cellular WAN.
3. **OEM Multicast Filtering:** Modern Android OEM network stacks (e.g., Samsung, Xiaomi) enable aggressive multicast packet filtering at the Wi-Fi chipset driver level to conserve battery unless an explicit `WifiManager.MulticastLock` is held.
4. **Resolution Concurrency Bugs:** Prior to Android 14 (API 34), standard Android `NsdManager` allows only a single service resolution operation at any given time. Triggering concurrent `resolveService` calls throws `FAILURE_ALREADY_ACTIVE` (error code 3).
5. **Fallback Resilience:** Where Wi-Fi router client isolation or AP-isolation prevents mDNS multicast packets, manual entry and QR scanning must remain fully functional.

---

## Decision

We introduce standard Android Network Service Discovery (NSD) for zero-configuration cluster discovery across `androgrid-android` coordinated with the mDNS DNS-SD broadcaster introduced in `androgrid-backend#68`:

### 1. Zero Inbound Ports Compliance ([INV-001])
- Discovery operates via Android OS `NsdManager` (which hooks the system-level multicast DNS daemon listening on `224.0.0.251:5353`).
- The worker application process creates zero listening TCP server sockets and binds zero inbound network ports.
- Once an orchestrator is discovered and selected, the worker initiates an outbound gRPC connection to the advertised endpoint (`_androgrid._tcp`).

### 2. Battery & Radio Lifecycle Binding ([NFR-POW-001])
- `ClusterDiscoveryManager` lifecycle is bound reactively to `NetworkRouteMonitor`, UI lifecycle (`onStart` / `onStop`), and credential status (`isConfigured`).
- Discovery is activated automatically only when:
  1. The node is unconfigured (`!isConfigured`).
  2. The UI is in the foreground.
  3. `NetworkRoute.LanConnected` is active.
- Discovery is stopped immediately and releases `WifiManager.MulticastLock` when the network transitions to `NetworkRoute.CellularWan`, `NetworkRoute.Offline`, when the application moves to the background, or once the node is enrolled.

### 3. Defensive OEM Multicast Handling & Resolution Queueing
- `NsdClusterDiscoveryManager` acquires `WifiManager.MulticastLock("AndroGridClusterDiscovery")` defensively during active Wi-Fi discovery and releases it when stopping.
- To prevent `FAILURE_ALREADY_ACTIVE` across Android 9 (API 28) through Android 15 (API 35), `NsdClusterDiscoveryManager` maintains an internal FIFO queue serializing `NsdManager.resolveService` invocations.
- Session fencing guards against late callbacks from cancelled or stopped discovery sessions.
- Incoming TXT records and socket addresses undergo strict LAN validation (rejecting loopback, multicast, link-local, and public WAN addresses). Lowercase 64-character SHA-256 validation sanitizes advertised CA fingerprints.

### 4. Interactive Dashboard Discovery Card & Verified Pairing
- When an orchestrator is discovered on LAN and the device is currently unconfigured (`!isConfigured`), `MainActivity` renders a prominent top card:
  * Header: "AndroGrid Cluster Detected"
  * Details: "Host: <host>:<port> (Cluster: <name>)"
  * Action Button: "[Connect & Pair]"
- Tapping "[Connect & Pair]" presents a pairing dialog displaying the advertised cluster endpoint and SHA-256 CA fingerprint for operator verification against the orchestrator console before submitting the pairing token.
- If the cluster advertises a missing or invalid CA fingerprint, enrollment is blocked immediately to prevent MITM interception.
- The Wi-Fi endpoint in `ClusterSettingsRepository` is updated atomically only upon verified, successful enrollment, preventing premature configuration corruption on cancel or failure.
- Already enrolled nodes do not initiate discovery or show the banner to preserve battery and radio state.

---

## Consequences

### Positive
- Eliminates manual IP and port keyboard entry during local development and private cluster onboarding.
- Adheres strictly to [INV-001] (zero inbound ports) and [NFR-POW-001] (radio sleep on cellular WAN).
- Fully supports Android 9 (API 28) through Android 15+ (API 35) without requiring root privileges.
- Prevents in-band TLS pinning hijacking by displaying the advertised CA fingerprint for operator confirmation.
- Gracefully degrades to manual Settings entry and camera QR scanning when mDNS is unavailable.

### Negative / Trade-offs
- Wi-Fi multicast lock consumes slightly higher idle power while scanning on local Wi-Fi networks (mitigated by only scanning when Wi-Fi is actively connected and the node is unconfigured).
- Routers with strict client isolation (guest networks) block mDNS; fallback to QR scanning or manual input remains necessary in such environments.
