package com.androgrid.worker.upgrade

import android.content.Context
import android.content.Intent
import com.androgrid.v1.NodeUpgradeDirective
import com.androgrid.v1.UpgradeNetworkPolicy
import com.androgrid.v1.UpgradeRolloutStrategy
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
 * cryptographic SHA-256 integrity verification ([NFR-SEC-001]), and heterogeneous installation routing.
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
    }

    private fun computeSha256(bytes: ByteArray): String {
        val md = MessageDigest.getInstance("SHA-256")
        return md.digest(bytes).joinToString("") { "%02x".format(it) }
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
        // Enforces [ANTI-003] & [NFR-POW-001]: APK downloads MUST NOT occur over metered cellular under wifi-only
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
            }
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
        // Enforces [NFR-SEC-001]: Corrupted APK binaries must be rejected and purged
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
                0
            }
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
        assertThat(executedCommand).contains("pm install -r")
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
            }
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
}
