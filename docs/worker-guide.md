# Android Worker Node Onboarding & Contributor Guide

Welcome to the **AndroGrid Mobile Worker** onboarding manual. This guide walks you through provisioning an Android device (physical smartphone, tablet, or emulator) to participate as a distributed edge-compute worker node in the AndroGrid cluster.

Traceability: `[REQ-OP-001]`, `[REQ-OP-002]`, `[REQ-OP-003]`, `[REQ-VER-001]`, `[REQ-VER-002]`, `[INV-001]`, `[INV-002]`, `[INV-003]`, `[NFR-POW-001]`.

---

## Device Prerequisites & Compatibility Matrix

> [!IMPORTANT]
> **Alpha Promotion Hardware Boundary Notice:**
> The public alpha release APK distribution (`androgrid-worker-v0.0.1-alpha.5.apk`) is explicitly bounded to **Android 12+ (API 31+) ARM64 (`arm64-v8a`)** devices. This hardware boundary enforces 16 KB page-size ELF alignment per Android 15 compatibility guidelines, eliminates legacy crypto provider friction, and keeps binary package footprints under 25 MB (`[NFR-PERF-001]`). The core codebase maintains minimum SDK 28 (Android 9 Pie) compatibility (`[REQ-VER-002]`) for custom source builds.

Before enrolling a device, verify that it meets the following hardware and operating system requirements:

| Metric | Minimum Requirement | Recommended Specification | Rationale & Traceability |
| :--- | :--- | :--- | :--- |
| **Android Version** | Android 9 (Pie, API 28) | Android 14+ (API 34) | Min SDK 28 is required for core crypto libraries and desugared Java time APIs (`[REQ-VER-002]`). API 34+ enforces typed foreground services (`[REQ-VER-001]`). Alpha releases target Android 12+ ARM64. |
| **Processor Architecture** | ARM64 (arm64-v8a) | ARM64-v8.2A+ (8 cores) | Required for hardware AES, 16 KB memory paging, and high-performance in-memory WASI execution. |
| **RAM** | 2.0 GB Total RAM | 4.0 GB+ LPDDR4X | Ensures sufficient head-room for in-memory WebAssembly bytecode execution without triggering Android low-memory killer (LMK). |
| **Free Storage** | 500 MB | 2.0 GB | Storage for local WASM bytecode cache and execution logs. |
| **Network Interfaces** | Wi-Fi (802.11n/ac) or Cellular 4G/5G | Dual Wi-Fi 6 + 5G NR | Supports dual-route operation: high-bandwidth Wi-Fi sync and low-power cellular spot execution. |
| **Root Status** | Unrooted (`is_rooted = false`) | Rooted or Unrooted | Unrooted devices safely execute WASM payloads within the in-process sandbox (`[INV-006]`). Rooted devices can optionally execute unprivileged shell benchmarks. |

---

## Step 1: Installing the Worker APK

### Option A (Recommended): 2-Step QR Sideloading Walkthrough

For alpha testers and standalone physical devices, install the worker application directly from GitHub Releases without developer tools:

<p align="center">
  <img src="assets/download-qr.png" alt="Scan to Download AndroGrid Worker APK" width="180" height="180" />
  <br />
  <a href="https://github.com/ligature-platform/androgrid-android/releases/latest/download/androgrid-worker.apk">
    <strong>Direct Download: androgrid-worker.apk (Permanent Latest Release)</strong>
  </a>
</p>

1. **Step 1: Scan QR Code and Tap "Download":**
   - Point your phone camera or QR scanner at the code above, or tap the direct download link in your mobile browser.
   - The signed `androgrid-worker.apk` binary (under 25 MB) will download to your device's `Download` directory.
   - Every release asset includes an immutable SHA-256 ledger in `SHA256SUMS.txt` for cryptographic integrity verification.

2. **Step 2: Toggle "Allow from this source" and Complete Installation:**
   - Tap the completed download notification or open the APK in your device's Files/Downloads app.
   - If prompted by Android with *"For your security, your phone is not allowed to install unknown apps from this source"*, tap **Settings** and toggle **Allow from this source** to ON.
   - Tap **Install** on the system package prompt.
   - Once installed, open **AndroGrid Worker**. Subsequent updates will be delivered and applied automatically over the cluster control plane via the Over-The-Air (OTA) pipeline.

---

### Option B (Developer & CI): Installing the Worker APK via ADB

You can install the pre-compiled debug or release APK directly onto your device using the Android Debug Bridge (ADB).

```bash
# Enable USB Debugging in Developer Options on your device, then connect via USB:
adb devices

# Install or upgrade the worker application:
adb install -r -g ./app/build/outputs/apk/debug/app-debug.apk
```

### Command Argument Breakdown

| Argument / Flag | Purpose & Operational Impact |
| :--- | :--- |
| `adb install` | Initiates the package manager installation stream over ADB transport to `/data/local/tmp`. |
| `-r` (Replace) | Reinstalls an existing application while keeping all user settings, cluster certificates, and cached task history intact. |
| `-g` (Grant Permissions) | Automatically grants all requested runtime permissions declared in `AndroidManifest.xml` (including `POST_NOTIFICATIONS`, `ACCESS_NETWORK_STATE`, and `FOREGROUND_SERVICE_DATA_SYNC`). Prevents manual prompt dialogs during headless onboarding. |

---

## Step 2: Provisioning mTLS 1.3 Keystore Identity

All control plane communications require Mutual TLS 1.3 (`[INV-002]`, `[NFR-SEC-001]`). The Android client generates an on-device ECDSA NIST P-256 key pair anchored inside the Android KeyStore and acquires a certificate signed by the cluster Root CA.

### Option A (Recommended): Zero-Touch Camera QR Code Enrollment

The fastest and most secure method to onboard mobile workers is single-scan QR code enrollment:

1. **Generate Ephemeral Pairing QR Code on Host Workstation:**
   ```bash
   androgrid-cli pair --expires-in 300
   ```
   This displays a high-contrast ANSI UTF-8 QR code directly in the terminal, embedding the cluster endpoint, Root CA SHA-256 fingerprint, and a single-use token.

2. **Scan with the Worker Application:**
   - Launch the **AndroGrid Worker** app.
   - Tap **Scan Enrollment QR Code** on the main dashboard or within **Settings**.
   - Align the viewfinder over the terminal QR code.

3. **Automatic Hardware Keystore Provisioning:**
   - The device automatically generates an on-device NIST P-256 key pair in the hardware-backed `AndroidKeyStore`.
   - The device constructs a PKCS#10 Certificate Signing Request (CSR) and signs it using the hardware private key.
   - The bootstrap client connects to the orchestrator over TLS pinned to the Root CA fingerprint, submits the CSR and single-use pairing token, and receives the signed client certificate.
   - The issued certificate is installed into the KeyStore. The device immediately transitions to active compute status.

---

### Option B (Manual / Headless): PKCS#12 Archive File Import

For headless CI test runners or emulators lacking camera hardware, you can manually generate keys using OpenSSL and import a `.p12` archive:

#### Generating the Client Key and Certificate with OpenSSL

If you are enrolling a new device named `node_pixel_7_01`, run the following commands on your cluster management workstation:

```bash
# 1. Generate an unencrypted ECDSA private key using the NIST P-256 curve:
openssl ecparam -name prime256v1 -genkey -noout -out client_node_pixel_7_01.key

# 2. Create a Certificate Signing Request (CSR) specifying the device identity:
openssl req -new -key client_node_pixel_7_01.key \
  -out client_node_pixel_7_01.csr \
  -subj "/CN=node_pixel_7_01/O=AndroGrid Cluster/OU=Mobile Worker"

# 3. Sign the CSR with the cluster Root CA (valid for 365 days):
openssl x509 -req -in client_node_pixel_7_01.csr \
  -CA deploy/pki/ca.crt -CAkey deploy/pki/ca.key -CAcreateserial \
  -out client_node_pixel_7_01.crt -days 365 -sha256

# 4. Package the certificate, private key, and Root CA into an encrypted PKCS#12 bundle:
# Note: Modern OpenSSL 3.x defaults to PBES2/AES-256 keybags which Android KeyStore fails to unwrap.
# The explicit 3DES flags (-certpbe PBE-SHA1-3DES -keypbe PBE-SHA1-3DES -macalg sha1) are required for Android compatibility.
openssl pkcs12 -export \
  -inkey client_node_pixel_7_01.key \
  -in client_node_pixel_7_01.crt \
  -certfile deploy/pki/ca.crt \
  -out client.p12 \
  -certpbe PBE-SHA1-3DES \
  -keypbe PBE-SHA1-3DES \
  -macalg sha1 \
  -password pass:androgrid_secure_pki
```

### OpenSSL Argument Reference

| Flag / Option | Cryptographic Purpose & Architectural Significance |
| :--- | :--- |
| `ecparam -name prime256v1` | Selects NIST curve P-256 (FIPS 186-4). Provides 128-bit security with ultra-fast scalar multiplication on mobile ARM processors. |
| `-genkey -noout` | Directly emits the private key in SEC1/PKCS#8 PEM format without printing curve parameter metadata. |
| `-subj "/CN=.../O=..."` | Sets X.509 Distinguished Name fields. The Common Name (CN) is used by the orchestrator for node audit logging. |
| `-export -out client.p12` | Constructs a PKCS#12 (PFX) cryptographic archive containing both the public certificate chain and the private key. |
| `-certpbe PBE-SHA1-3DES` | Enforces 3DES PKCS#12 encryption for certificates, required by Android KeyStore BouncyCastle provider. |
| `-keypbe PBE-SHA1-3DES` | Enforces 3DES PKCS#12 encryption for private key bags, preventing `exception unwrapping private key`. |
| `-macalg sha1` | Enforces SHA-1 MAC digest for archive verification integrity under Android KeyStore provider expectations. |
| `-password pass:androgrid_secure_pki` | Encrypts the PKCS#12 keystore using password-based encryption, protecting the private key in transit. |

### Provisioning `client.p12` to the Android Device

Push the generated `client.p12` and `ca.crt` to the device storage or import via the in-app settings UI:

```bash
# Push PKCS#12 file to device downloads folder:
adb push client.p12 /sdcard/Download/client.p12
```

In the AndroGrid Worker application:
1. Open **Settings** (gear icon in the top right).
2. Tap **Import Client Certificate**.
3. Select `/sdcard/Download/client.p12` and enter password `androgrid_secure_pki`.
4. The key is securely stored in the hardware-backed Android KeyStore.

---

## Step 3: Connecting to the Control Plane Orchestrator

In the application settings, configure the orchestrator target endpoint:

- **Local Machine Testing with Physical Device over USB (ADB Reverse Tunnel):**
  Use `127.0.0.1:50051`. Because physical hardware connected over USB resides in an isolated network namespace, reverse port forwarding must be configured from the host workstation:
  ```bash
  # Forward control plane mTLS gRPC traffic from phone to host:
  adb reverse tcp:50051 tcp:50051

  # Forward HTTP static artifact & pairing token traffic:
  adb reverse tcp:50052 tcp:50052
  ```
  This routes connections made on the device to `127.0.0.1:50051` directly back to the orchestrator listening on the host machine.
- **Local Machine Testing with Podman (Android Emulator):**
  Use `https://10.0.2.2:50051`. In the Android emulator, `10.0.2.2` automatically routes to host machine `localhost` where Podman publishes port `50051`.
- **Local Machine Testing with Podman (Physical Device over Wi-Fi):**
  Use `https://192.168.1.100:50051` (replace with your workstation local LAN IP address).
- **Remote Cellular WAN Ingress (Cloudflare Tunnel):**
  Use `https://grpc.cluster.domain.com`.

---

## Step 4: OEM Battery Optimization Exemption Guidelines

Android device manufacturers (OEMs) implement aggressive proprietary battery managers that terminate background foreground services unless explicitly whitelisted.

### 1. Samsung (One UI)
- Open **Settings** -> **Apps** -> **AndroGrid Worker**.
- Tap **Battery** -> Select **Unrestricted**.
- Go to **Device Care** -> **Battery** -> **Background usage limits** -> Add AndroGrid Worker to **Never sleeping apps**.
- **Troubleshooting One UI Background Suspension:**
  - If tasks halt when the screen turns off, navigate to **Settings** -> **Device Care** -> **Battery** -> **More battery settings** and disable **Adaptive battery**.
  - In **Device Care** -> **Memory**, check if **RAM Plus** or aggressive memory cleaning is killing background foreground services; add AndroGrid Worker to **Excluded apps**.

### 2. Xiaomi / Redmi / POCO (MIUI & HyperOS)
- Open **Settings** -> **Apps** -> **Manage Apps** -> **AndroGrid Worker**.
- Enable **Autostart** toggle.
- Under **Battery saver**, select **No restrictions**.
- In the Recents app switcher, long-press AndroGrid Worker and tap the **Lock icon** to prevent task clearance.
- **Troubleshooting HyperOS Process Eviction:**
  - On Xiaomi devices running HyperOS, navigate to **Settings** -> **Additional settings** -> **Developer options** and verify **MIUI / System optimizations** are not aggressively killing sticky foreground services.
  - If OTA background download jobs fail to awaken, navigate to **Security** app -> **Manage apps** -> **Permissions** -> **Autostart in background** and enable AndroGrid Worker.

### 3. Huawei / Honor (EMUI & MagicOS)
- Open **Settings** -> **Battery** -> **App Launch**.
- Find **AndroGrid Worker**, toggle off **Manage automatically**, and ensure **Auto-launch**, **Secondary launch**, and **Run in background** are all enabled.

### 4. Google Pixel & Motorola (Stock Android)
- Open **Settings** -> **Apps** -> **See all apps** -> **AndroGrid Worker**.
- Tap **App battery usage** -> Select **Unrestricted**.

---

## Step 5: Verifying Worker Enrollment

Once started:
1. Tap **Start Worker** in the main dashboard.
2. A persistent notification appears indicating:
   `AndroGrid Worker: Connected (Wi-Fi LAN) - Ready for spot tasks`
3. On your host machine, run:
   ```bash
   ./target/release/androgrid-cli \
     --endpoint https://127.0.0.1:50051 \
     --ca-cert ./deploy/pki/ca.crt \
     --client-cert ./deploy/pki/client.crt \
     --client-key ./deploy/pki/client.key \
     nodes
   ```
4. Your Android device will appear in the active worker node inventory!

---

## Step 6: Over-the-Air (OTA) Node Upgrades & Unattended Root Stdin Streaming

When deployed as an unattended or rooted node, the worker supports zero-touch Over-the-Air (OTA) upgrades driven by orchestrator directives:

### 1. Root Stdin Streaming Architecture (`pm install -r -S`)
Modern Android platform security forbids `system_server` from reading application-private directories (`neverallow system_server app_data_file:file read`).
The worker executes upgrades by streaming the downloaded APK payload directly into the standard input of the package manager:
```bash
su -c "pm install -r -S <byteSize>" < <privateApkStream>
```
This eliminates world-readable filesystem staging risks and guarantees atomic installation across modern Android versions (API 34-36+).

### 2. Headless Service Revival & Battery Exemption
- **Post-Install Broadcast:** Upon installation, Android sends `android.intent.action.MY_PACKAGE_REPLACED`. `PackageReplacedReceiver` automatically restarts `WorkerForegroundService` in headless mode.
- **WorkManager Recovery Fallback:** If aggressive OEM battery managers block direct foreground service startup from background receivers, `PackageReplacedRecoveryWorker` bootstraps service revival via Jetpack WorkManager.
- **Battery Optimization:** Ensure the app is exempted from battery optimizations (Step 4) so background OTA installations and revivals proceed without OS suppression.

### 3. Signing Lineage & Rollback Protection
- **Pre-Install Signature Verification:** APK signatures are checked against the installed certificate lineage before initiating root shell commands. Mismatched or corrupted APKs are rejected immediately.
- **Anti-Rollback Enforcement:** Production builds strictly omit the `-d` downgrade flag, enforcing monotonic platform version increments.
