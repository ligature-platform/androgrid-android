package com.androgrid.worker.upgrade

import android.content.Context
import android.content.Intent
import android.content.pm.PackageInfo
import com.androgrid.v1.NodeUpgradeDirective
import com.androgrid.v1.UpgradeInstallStatus
import com.androgrid.v1.UpgradeNetworkPolicy
import com.androgrid.worker.capability.RootChecker
import com.google.common.truth.Truth.assertThat
import kotlinx.coroutines.test.runTest
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.annotation.Config
import java.io.File
import java.security.MessageDigest

/**
 * Hermetic Robolectric unit tests for [UpgradeManager].
 * Validates version thresholds, metered cellular guards ([ANTI-003], [NFR-POW-001]),
 * cryptographic SHA-256 integrity verification ([NFR-SEC-001]), pre-install signing lineage verification,
 * terminal failure recording, and heterogeneous installation routing.
 *
 * Traces to: [REQ-OP-001], [REQ-OP-002], [INV-001], [INV-002], [INV-003], [ANTI-003], [NFR-POW-001], [NFR-SEC-001]
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class UpgradeManagerTest {

    @get:Rule
    val tempFolder = TemporaryFolder()

    private lateinit var context: Context

    private class FakeRootChecker(private val rooted: Boolean) : RootChecker {
        override fun isDeviceRooted(): Boolean = rooted
    }

    @Before
    fun setUp() {
        context = RuntimeEnvironment.getApplication()
        val prefs = context.getSharedPreferences(
            SharedPreferencesUpgradeLedger.PREFS_NAME,
            Context.MODE_PRIVATE
        )
        prefs.edit().clear().commit()
    }

    private fun computeSha256(bytes: ByteArray): String {
        val md = MessageDigest.getInstance("SHA-256")
        return md.digest(bytes).joinToString("") { "%02x".format(it) }
    }

    private fun createValidArchiveInfo(
        pkgName: String = context.packageName,
        verCode: Long = 100L
    ): PackageInfo {
        return PackageInfo().apply {
            packageName = pkgName
            if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.P) {
                longVersionCode = verCode
            }
            @Suppress("DEPRECATION")
            versionCode = verCode.toInt()
        }
    }

    @Test
    fun testProcessUpgradeDirective_alreadyUpToDate_returnsUpToDate() = runTest {
        val manager = DefaultUpgradeManager(
            context = context,
            rootChecker = FakeRootChecker(rooted = false),
            currentVersionProvider = { "0.2.0" }
        )

        val directive = NodeUpgradeDirective.newBuilder()
            .setTargetVersion("0.2.0")
            .setApkUrl("https://example.com/app.apk")
            .build()

        val outcome = manager.processUpgradeDirective(
            directive = directive,
            isMetered = false,
            isWifi = true
        )

        assertThat(outcome).isInstanceOf(UpgradeOutcome.UpToDate::class.java)
        val upToDate = outcome as UpgradeOutcome.UpToDate
        assertThat(upToDate.currentVersion).isEqualTo("0.2.0")
    }

    @Test
    fun testProcessUpgradeDirective_emptyTargetVersion_returnsUpToDate() = runTest {
        val manager = DefaultUpgradeManager(
            context = context,
            rootChecker = FakeRootChecker(rooted = false),
            currentVersionProvider = { "0.1.0" }
        )

        val directive = NodeUpgradeDirective.newBuilder()
            .setTargetVersion("")
            .build()

        val outcome = manager.processUpgradeDirective(
            directive = directive,
            isMetered = false,
            isWifi = true
        )

        assertThat(outcome).isInstanceOf(UpgradeOutcome.UpToDate::class.java)
    }

    @Test
    fun testProcessUpgradeDirective_meteredCellularWithWifiOnlyPolicy_returnsNetworkPolicyViolation() = runTest {
        val manager = DefaultUpgradeManager(
            context = context,
            rootChecker = FakeRootChecker(rooted = false),
            currentVersionProvider = { "0.1.0" }
        )

        val directive = NodeUpgradeDirective.newBuilder()
            .setTargetVersion("0.2.0")
            .setApkUrl("https://example.com/app.apk")
            .setNetworkPolicy(UpgradeNetworkPolicy.UPGRADE_NETWORK_POLICY_WIFI_ONLY)
            .build()

        val outcome = manager.processUpgradeDirective(
            directive = directive,
            isMetered = true,
            isWifi = false
        )

        assertThat(outcome).isInstanceOf(UpgradeOutcome.NetworkPolicyViolation::class.java)
        val violation = outcome as UpgradeOutcome.NetworkPolicyViolation
        assertThat(violation.reason).contains("[ANTI-003]")
    }

    @Test
    fun testProcessUpgradeDirective_meteredCellularWithAllowCellularPolicy_downloadsAndVerifies() = runTest {
        val apkPayload = "fake-apk-binary-payload-v0.2.0".toByteArray()
        val payloadSha256 = computeSha256(apkPayload)

        val manager = DefaultUpgradeManager(
            context = context,
            rootChecker = FakeRootChecker(rooted = false),
            currentVersionProvider = { "0.1.0" },
            downloadClient = { _, destFile ->
                destFile.writeBytes(apkPayload)
                true
            },
            archiveInfoParser = { createValidArchiveInfo() },
            signatureVerifier = { _, _ -> true }
        )

        val directive = NodeUpgradeDirective.newBuilder()
            .setTargetVersion("0.2.0")
            .setApkUrl("https://example.com/app.apk")
            .setApkSha256(payloadSha256)
            .setNetworkPolicy(UpgradeNetworkPolicy.UPGRADE_NETWORK_POLICY_ALLOW_CELLULAR)
            .build()

        val outcome = manager.processUpgradeDirective(
            directive = directive,
            isMetered = true,
            isWifi = false
        )

        assertThat(outcome).isInstanceOf(UpgradeOutcome.PromptUserInstall::class.java)
    }

    @Test
    fun testProcessUpgradeDirective_emptyApkUrl_returnsDownloadFailed() = runTest {
        val manager = DefaultUpgradeManager(
            context = context,
            rootChecker = FakeRootChecker(rooted = false),
            currentVersionProvider = { "0.1.0" }
        )

        val directive = NodeUpgradeDirective.newBuilder()
            .setTargetVersion("0.2.0")
            .setApkUrl("")
            .build()

        val outcome = manager.processUpgradeDirective(
            directive = directive,
            isMetered = false,
            isWifi = true
        )

        assertThat(outcome).isInstanceOf(UpgradeOutcome.DownloadFailed::class.java)
    }

    @Test
    fun testProcessUpgradeDirective_integrityCheck_mismatchedSha256_deletesFileAndFails() = runTest {
        val apkPayload = "genuine-apk-content".toByteArray()
        val mismatchedSha256 = "0000000000000000000000000000000000000000000000000000000000000000"

        var createdFile: File? = null
        val manager = DefaultUpgradeManager(
            context = context,
            rootChecker = FakeRootChecker(rooted = false),
            currentVersionProvider = { "0.1.0" },
            downloadClient = { _, destFile ->
                destFile.writeBytes(apkPayload)
                createdFile = destFile
                true
            }
        )

        val directive = NodeUpgradeDirective.newBuilder()
            .setTargetVersion("0.2.0")
            .setApkUrl("https://example.com/app.apk")
            .setApkSha256(mismatchedSha256)
            .build()

        val outcome = manager.processUpgradeDirective(
            directive = directive,
            isMetered = false,
            isWifi = true
        )

        assertThat(outcome).isInstanceOf(UpgradeOutcome.IntegrityVerificationFailed::class.java)
        val failure = outcome as UpgradeOutcome.IntegrityVerificationFailed
        assertThat(failure.expectedSha256).isEqualTo(mismatchedSha256)
        assertThat(failure.actualSha256).isEqualTo(computeSha256(apkPayload))

        // File must have been deleted for safety
        assertThat(createdFile?.exists()).isFalse()
    }

    @Test
    fun testProcessUpgradeDirective_corruptArchive_nullArchiveInfo_failsAndPurgesFile() = runTest {
        val apkPayload = "corrupted-unparseable-apk".toByteArray()
        val payloadSha256 = computeSha256(apkPayload)

        var createdFile: File? = null
        val manager = DefaultUpgradeManager(
            context = context,
            rootChecker = FakeRootChecker(rooted = false),
            currentVersionProvider = { "0.1.0" },
            downloadClient = { _, destFile ->
                destFile.writeBytes(apkPayload)
                createdFile = destFile
                true
            },
            archiveInfoParser = { null }
        )

        val directive = NodeUpgradeDirective.newBuilder()
            .setTargetVersion("0.2.0")
            .setApkUrl("https://example.com/app.apk")
            .setApkSha256(payloadSha256)
            .build()

        val outcome = manager.processUpgradeDirective(
            directive = directive,
            isMetered = false,
            isWifi = true
        )

        assertThat(outcome).isInstanceOf(UpgradeOutcome.IntegrityVerificationFailed::class.java)
        val failure = outcome as UpgradeOutcome.IntegrityVerificationFailed
        assertThat(failure.actualSha256).isEqualTo("CORRUPT_ARCHIVE")
        assertThat(createdFile?.exists()).isFalse()
    }

    @Test
    fun testProcessUpgradeDirective_signingCertificateMismatch_deletesApkAndFails() = runTest {
        val apkPayload = "untrusted-signed-apk".toByteArray()
        val payloadSha256 = computeSha256(apkPayload)

        var createdFile: File? = null
        val manager = DefaultUpgradeManager(
            context = context,
            rootChecker = FakeRootChecker(rooted = true),
            currentVersionProvider = { "0.1.0" },
            downloadClient = { _, destFile ->
                destFile.writeBytes(apkPayload)
                createdFile = destFile
                true
            },
            archiveInfoParser = { createValidArchiveInfo() },
            signatureVerifier = { _, _ -> false }
        )

        val directive = NodeUpgradeDirective.newBuilder()
            .setTargetVersion("0.2.0")
            .setApkUrl("https://example.com/app.apk")
            .setApkSha256(payloadSha256)
            .build()

        val outcome = manager.processUpgradeDirective(
            directive = directive,
            isMetered = false,
            isWifi = true
        )

        assertThat(outcome).isInstanceOf(UpgradeOutcome.SignatureVerificationFailed::class.java)
        assertThat(createdFile?.exists()).isFalse()

        // Check ledger recorded terminal failure
        val lastOutcome = manager.getLastOutcome()
        assertThat(lastOutcome).isNotNull()
        assertThat(lastOutcome?.status).isEqualTo(UpgradeInstallStatus.UPGRADE_INSTALL_STATUS_TERMINALLY_REJECTED)
        assertThat(lastOutcome?.errorCode).isEqualTo("SIGNATURE_MISMATCH")
    }

    @Test
    fun testProcessUpgradeDirective_terminallyRejected_abortsImmediatelyWithoutDownload() = runTest {
        val ledger = SharedPreferencesUpgradeLedger(context)
        val targetVersion = "0.2.0"
        val apkSha256 = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"

        ledger.recordTerminalFailure(
            targetVersion = targetVersion,
            apkSha256 = apkSha256,
            errorCode = "INSTALL_FAILED_VERSION_DOWNGRADE",
            errorMessage = "Downgrade not allowed"
        )

        var downloadCalled = false
        val manager = DefaultUpgradeManager(
            context = context,
            rootChecker = FakeRootChecker(rooted = false),
            currentVersionProvider = { "0.1.0" },
            downloadClient = { _, _ ->
                downloadCalled = true
                true
            },
            ledger = ledger
        )

        val directive = NodeUpgradeDirective.newBuilder()
            .setTargetVersion(targetVersion)
            .setApkUrl("https://example.com/app.apk")
            .setApkSha256(apkSha256)
            .build()

        val outcome = manager.processUpgradeDirective(
            directive = directive,
            isMetered = false,
            isWifi = true
        )

        assertThat(outcome).isInstanceOf(UpgradeOutcome.TerminallyRejected::class.java)
        assertThat(downloadCalled).isFalse()
    }

    @Test
    fun testProcessUpgradeDirective_rootedNode_executesRootInstall() = runTest {
        val apkPayload = "rooted-apk-binary".toByteArray()
        val payloadSha256 = computeSha256(apkPayload)

        var executedCommand: String? = null
        val manager = DefaultUpgradeManager(
            context = context,
            rootChecker = FakeRootChecker(rooted = true),
            currentVersionProvider = { "0.1.0" },
            downloadClient = { _, destFile ->
                destFile.writeBytes(apkPayload)
                true
            },
            shellRunner = { cmd ->
                executedCommand = cmd
                Pair(0, "Success")
            },
            archiveInfoParser = { createValidArchiveInfo() },
            signatureVerifier = { _, _ -> true }
        )

        val directive = NodeUpgradeDirective.newBuilder()
            .setTargetVersion("0.2.0")
            .setApkUrl("https://example.com/app.apk")
            .setApkSha256(payloadSha256)
            .build()

        val outcome = manager.processUpgradeDirective(
            directive = directive,
            isMetered = false,
            isWifi = true
        )

        assertThat(outcome).isInstanceOf(UpgradeOutcome.InstalledRoot::class.java)
        val installed = outcome as UpgradeOutcome.InstalledRoot
        assertThat(installed.exitCode).isEqualTo(0)
        assertThat(executedCommand).isEqualTo("pm install -r -S ${apkPayload.size}")
    }

    @Test
    fun testProcessUpgradeDirective_signingCertificateMismatch_rejectsBeforeSuInvocation() = runTest {
        val apkPayload = "mismatched-cert-payload".toByteArray()
        val payloadSha256 = computeSha256(apkPayload)

        var shellRunnerInvoked = false
        val manager = DefaultUpgradeManager(
            context = context,
            rootChecker = FakeRootChecker(rooted = true),
            currentVersionProvider = { "0.1.0" },
            downloadClient = { _, destFile ->
                destFile.writeBytes(apkPayload)
                true
            },
            shellRunner = { _ ->
                shellRunnerInvoked = true
                Pair(0, "Success")
            },
            archiveInfoParser = { createValidArchiveInfo() },
            signatureVerifier = { _, _ -> false }
        )

        val directive = NodeUpgradeDirective.newBuilder()
            .setTargetVersion("0.2.0")
            .setApkUrl("https://example.com/app.apk")
            .setApkSha256(payloadSha256)
            .build()

        val outcome = manager.processUpgradeDirective(
            directive = directive,
            isMetered = false,
            isWifi = true
        )

        assertThat(outcome).isInstanceOf(UpgradeOutcome.SignatureVerificationFailed::class.java)
        // Verify root shell command was NEVER executed
        assertThat(shellRunnerInvoked).isFalse()
    }

    @Test
    fun testProcessUpgradeDirective_unrootedNode_createsInstallIntentWithReadPermission() = runTest {
        val apkPayload = "unrooted-consumer-apk".toByteArray()
        val payloadSha256 = computeSha256(apkPayload)

        val manager = DefaultUpgradeManager(
            context = context,
            rootChecker = FakeRootChecker(rooted = false),
            currentVersionProvider = { "0.1.0" },
            downloadClient = { _, destFile ->
                destFile.writeBytes(apkPayload)
                true
            },
            archiveInfoParser = { createValidArchiveInfo() },
            signatureVerifier = { _, _ -> true }
        )

        val directive = NodeUpgradeDirective.newBuilder()
            .setTargetVersion("0.2.0")
            .setApkUrl("https://example.com/app.apk")
            .setApkSha256(payloadSha256)
            .build()

        val outcome = manager.processUpgradeDirective(
            directive = directive,
            isMetered = false,
            isWifi = true
        )

        assertThat(outcome).isInstanceOf(UpgradeOutcome.PromptUserInstall::class.java)
        val prompt = outcome as UpgradeOutcome.PromptUserInstall
        val intent = prompt.intent

        assertThat(intent.action).isEqualTo(Intent.ACTION_VIEW)
        assertThat(intent.type).isEqualTo("application/vnd.android.package-archive")
        assertThat(intent.flags and Intent.FLAG_GRANT_READ_URI_PERMISSION).isNotEqualTo(0)
    }

    @Test
    fun testProcessUpgradeDirective_packageNameMismatch_terminallyRejected() = runTest {
        val apkPayload = "valid-binary-different-package".toByteArray()
        val payloadSha256 = computeSha256(apkPayload)

        val manager = DefaultUpgradeManager(
            context = context,
            rootChecker = FakeRootChecker(rooted = false),
            currentVersionProvider = { "0.1.0" },
            downloadClient = { _, destFile ->
                destFile.writeBytes(apkPayload)
                true
            },
            archiveInfoParser = { createValidArchiveInfo(pkgName = "com.other.malicious") },
            signatureVerifier = { _, _ -> true }
        )

        val directive = NodeUpgradeDirective.newBuilder()
            .setTargetVersion("0.2.0")
            .setApkUrl("https://example.com/app.apk")
            .setApkSha256(payloadSha256)
            .build()

        val outcome = manager.processUpgradeDirective(directive, isMetered = false, isWifi = true)
        assertThat(outcome).isInstanceOf(UpgradeOutcome.TerminallyRejected::class.java)
        val term = outcome as UpgradeOutcome.TerminallyRejected
        assertThat(term.reason).contains("package name mismatch")
    }

    @Test
    fun testProcessUpgradeDirective_versionCodeDowngrade_terminallyRejected() = runTest {
        val apkPayload = "valid-binary-downgrade".toByteArray()
        val payloadSha256 = computeSha256(apkPayload)

        val manager = DefaultUpgradeManager(
            context = context,
            rootChecker = FakeRootChecker(rooted = false),
            currentVersionProvider = { "0.1.0" },
            downloadClient = { _, destFile ->
                destFile.writeBytes(apkPayload)
                true
            },
            archiveInfoParser = { createValidArchiveInfo(verCode = 0L) },
            signatureVerifier = { _, _ -> true }
        )

        val directive = NodeUpgradeDirective.newBuilder()
            .setTargetVersion("0.2.0")
            .setApkUrl("https://example.com/app.apk")
            .setApkSha256(payloadSha256)
            .build()

        val outcome = manager.processUpgradeDirective(directive, isMetered = false, isWifi = true)
        assertThat(outcome).isInstanceOf(UpgradeOutcome.TerminallyRejected::class.java)
        val term = outcome as UpgradeOutcome.TerminallyRejected
        assertThat(term.reason).contains("version code downgrade")
    }

    @Test
    fun testProcessUpgradeDirective_invalidSha256_terminallyRejected() = runTest {
        val manager = DefaultUpgradeManager(
            context = context,
            rootChecker = FakeRootChecker(rooted = false),
            currentVersionProvider = { "0.1.0" }
        )

        val directive = NodeUpgradeDirective.newBuilder()
            .setTargetVersion("0.2.0")
            .setApkUrl("https://example.com/app.apk")
            .setApkSha256("invalid_hash_not_64_hex")
            .build()

        val outcome = manager.processUpgradeDirective(directive, isMetered = false, isWifi = true)
        assertThat(outcome).isInstanceOf(UpgradeOutcome.TerminallyRejected::class.java)
        val term = outcome as UpgradeOutcome.TerminallyRejected
        assertThat(term.reason).contains("invalid 64-hex SHA-256")
    }

    @Test
    fun testProcessUpgradeDirective_relativeBlobUrl_resolvesTransportSpecificBaseUrl() = runTest {
        var requestedUrl = ""
        val manager = DefaultUpgradeManager(
            context = context,
            rootChecker = FakeRootChecker(rooted = true),
            currentVersionProvider = { "0.1.0" },
            downloadClient = { url, _ ->
                requestedUrl = url
                false
            },
            baseUrlProvider = { isWifi ->
                if (isWifi) "https://192.168.1.100:50051" else "https://cellular.cloud.androgrid.com:50051"
            }
        )

        val sha = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        val directive = NodeUpgradeDirective.newBuilder()
            .setTargetVersion("0.2.0")
            .setApkUrl("/v1/blobs/$sha")
            .setApkSha256(sha)
            .setNetworkPolicy(UpgradeNetworkPolicy.UPGRADE_NETWORK_POLICY_ALLOW_CELLULAR)
            .build()

        // Cellular call
        manager.processUpgradeDirective(directive, isMetered = true, isWifi = false)
        assertThat(requestedUrl).isEqualTo("https://cellular.cloud.androgrid.com:50051/v1/blobs/$sha")

        // Wi-Fi call with distinct version to avoid backoff suppression
        val shaWifi = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"
        val directiveWifi = NodeUpgradeDirective.newBuilder()
            .setTargetVersion("0.3.0")
            .setApkUrl("/v1/blobs/$shaWifi")
            .setApkSha256(shaWifi)
            .setNetworkPolicy(UpgradeNetworkPolicy.UPGRADE_NETWORK_POLICY_ALLOW_CELLULAR)
            .build()
        manager.processUpgradeDirective(directiveWifi, isMetered = false, isWifi = true)
        assertThat(requestedUrl).isEqualTo("https://192.168.1.100:50051/v1/blobs/$shaWifi")
    }
}
