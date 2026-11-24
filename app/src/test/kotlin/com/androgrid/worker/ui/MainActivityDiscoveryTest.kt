package com.androgrid.worker.ui

import android.content.pm.ApplicationInfo
import android.util.Log
import android.view.View
import androidx.work.Configuration
import androidx.work.testing.SynchronousExecutor
import androidx.work.testing.WorkManagerTestInitHelper
import com.androgrid.worker.AndroGridApplication
import com.androgrid.worker.network.DiscoveredCluster
import com.androgrid.worker.network.InMemoryClusterSettingsRepository
import com.google.common.truth.Truth.assertThat
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.Robolectric
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.Shadows
import org.robolectric.annotation.Config

/**
 * Robolectric unit tests verifying the local cluster zero-config discovery UI banner,
 * unconfigured device detection, and one-tap Connect & Pair action flow in [MainActivity].
 *
 * Traces to: Section 6.1, [REQ-OP-001], [INV-001], [INV-002], [NFR-POW-001]
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34], application = AndroGridApplication::class)
class MainActivityDiscoveryTest {

    private lateinit var app: AndroGridApplication
    private lateinit var repo: InMemoryClusterSettingsRepository

    @Before
    fun setUp() {
        app = RuntimeEnvironment.getApplication() as AndroGridApplication
        app.applicationInfo.flags = app.applicationInfo.flags or ApplicationInfo.FLAG_DEBUGGABLE
        val config = Configuration.Builder()
            .setMinimumLoggingLevel(Log.DEBUG)
            .setExecutor(SynchronousExecutor())
            .build()
        WorkManagerTestInitHelper.initializeTestWorkManager(app, config)
        repo = InMemoryClusterSettingsRepository()
    }

    @Test
    fun testDiscoveryBanner_initiallyHiddenWhenNoClustersDiscovered() {
        val controller = Robolectric.buildActivity(MainActivity::class.java)
        val activity = controller.get()
        activity.settingsRepository = repo

        controller.create().start().resume()
        Shadows.shadowOf(android.os.Looper.getMainLooper()).idle()

        assertThat(activity.discoveryCardView.visibility).isEqualTo(View.GONE)

        controller.destroy()
    }

    @Test
    fun testDiscoveryBanner_surfacesWhenClusterDiscoveredAndDeviceUnconfigured() {
        val controller = Robolectric.buildActivity(MainActivity::class.java)
        val activity = controller.get()
        activity.settingsRepository = repo

        controller.create().start().resume()
        Shadows.shadowOf(android.os.Looper.getMainLooper()).idle()

        val cluster = DiscoveredCluster(
            serviceName = "androgrid-orchestrator",
            host = "192.168.1.15",
            port = 50051,
            clusterName = "default",
            version = "0.0.1-alpha.5",
            caFingerprint = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
        )

        // Reactive render call driven by state flow
        val state = activity.getDashboardViewModel().uiState.value.copy(
            discoveredClusters = listOf(cluster),
            isConfigured = false
        )
        activity.runOnUiThread {
            activity.renderState(state)
        }
        Shadows.shadowOf(android.os.Looper.getMainLooper()).idle()

        assertThat(activity.discoveryCardView.visibility).isEqualTo(View.VISIBLE)
        assertThat(activity.discoveryHeaderView.text.toString()).isEqualTo("AndroGrid Cluster Detected")
        assertThat(activity.discoveryDetailsView.text.toString()).isEqualTo("Host: 192.168.1.15:50051 (Cluster: default)")
        assertThat(activity.connectAndPairButton.text.toString()).isEqualTo("Connect & Pair")

        controller.destroy()
    }

    @Test
    fun testDiscoveryBanner_hiddenWhenDeviceIsAlreadyConfigured() {
        val controller = Robolectric.buildActivity(MainActivity::class.java)
        val activity = controller.get()
        activity.settingsRepository = repo

        controller.create().start().resume()
        Shadows.shadowOf(android.os.Looper.getMainLooper()).idle()

        val cluster = DiscoveredCluster(
            serviceName = "androgrid-orchestrator",
            host = "192.168.1.15",
            port = 50051,
            clusterName = "default"
        )

        // Device is already configured: banner must remain hidden
        val state = activity.getDashboardViewModel().uiState.value.copy(
            discoveredClusters = listOf(cluster),
            isConfigured = true
        )
        activity.runOnUiThread {
            activity.renderState(state)
        }
        Shadows.shadowOf(android.os.Looper.getMainLooper()).idle()

        assertThat(activity.discoveryCardView.visibility).isEqualTo(View.GONE)

        controller.destroy()
    }

    @Test
    fun testConnectAndPair_whenUnconfigured_doesNotMutateWifiEndpointPrematurely() {
        val controller = Robolectric.buildActivity(MainActivity::class.java)
        val activity = controller.get()
        activity.settingsRepository = repo

        controller.create().start().resume()
        Shadows.shadowOf(android.os.Looper.getMainLooper()).idle()

        val initialHost = repo.getSettings().wifiHost
        val initialPort = repo.getSettings().wifiPort

        val cluster = DiscoveredCluster(
            serviceName = "androgrid-orchestrator",
            host = "192.168.1.15",
            port = 50051,
            clusterName = "default"
        )

        // Invoke 1-tap Connect & Pair handler without pairing token (opens dialog)
        activity.handleConnectAndPair(cluster)
        Shadows.shadowOf(android.os.Looper.getMainLooper()).idle()

        // Endpoint must NOT be prematurely updated before confirmed enrollment
        val currentSettings = repo.getSettings()
        assertThat(currentSettings.wifiHost).isEqualTo(initialHost)
        assertThat(currentSettings.wifiPort).isEqualTo(initialPort)

        controller.destroy()
    }

    @Test
    fun testPromptPairingDialog_whenFingerprintBlank_omitsPairButtonAndShowsWarning() {
        val controller = Robolectric.buildActivity(MainActivity::class.java)
        val activity = controller.get()
        activity.settingsRepository = repo

        controller.create().start().resume()
        Shadows.shadowOf(android.os.Looper.getMainLooper()).idle()

        val cluster = DiscoveredCluster(
            serviceName = "unsecured-cluster",
            host = "192.168.1.55",
            port = 50051,
            clusterName = "unsecured",
            caFingerprint = ""
        )

        activity.handleConnectAndPair(cluster)
        Shadows.shadowOf(android.os.Looper.getMainLooper()).idle()

        val dialog = org.robolectric.shadows.ShadowAlertDialog.getLatestAlertDialog()
        assertThat(dialog).isNotNull()
        val shadowDialog = Shadows.shadowOf(dialog)
        assertThat(shadowDialog.message.toString()).contains("Warning: This cluster advertises no CA fingerprint")
        assertThat(dialog.getButton(android.app.AlertDialog.BUTTON_POSITIVE).visibility).isEqualTo(View.GONE)

        controller.destroy()
    }

    @Test
    fun testPromptPairingDialog_whenFingerprintPresent_formatsChunksAndEnablesPairButton() {
        val controller = Robolectric.buildActivity(MainActivity::class.java)
        val activity = controller.get()
        activity.settingsRepository = repo

        controller.create().start().resume()
        Shadows.shadowOf(android.os.Looper.getMainLooper()).idle()

        val rawFingerprint = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
        val cluster = DiscoveredCluster(
            serviceName = "secured-cluster",
            host = "192.168.1.66",
            port = 50051,
            clusterName = "secured",
            caFingerprint = rawFingerprint
        )

        activity.handleConnectAndPair(cluster)
        Shadows.shadowOf(android.os.Looper.getMainLooper()).idle()

        val dialog = org.robolectric.shadows.ShadowAlertDialog.getLatestAlertDialog()
        assertThat(dialog).isNotNull()
        val shadowDialog = Shadows.shadowOf(dialog)
        assertThat(shadowDialog.message.toString()).contains("Verify CA Fingerprint against orchestrator terminal")
        assertThat(shadowDialog.message.toString()).contains("ABCD EF12")
        assertThat(dialog.getButton(android.app.AlertDialog.BUTTON_POSITIVE).visibility).isEqualTo(View.VISIBLE)

        controller.destroy()
    }

    @Test
    fun testExecuteEnrollment_withMissingCaFingerprint_abortsWithoutMutatingSettings() {
        val controller = Robolectric.buildActivity(MainActivity::class.java)
        val activity = controller.get()
        activity.settingsRepository = repo

        controller.create().start().resume()
        Shadows.shadowOf(android.os.Looper.getMainLooper()).idle()

        val initialHost = repo.getSettings().wifiHost
        val cluster = DiscoveredCluster(
            serviceName = "rogue-orchestrator",
            host = "192.168.1.99",
            port = 50051,
            clusterName = "untrusted",
            caFingerprint = "" // Empty fingerprint must be rejected
        )

        activity.executeEnrollmentWithToken(cluster, "test-token")
        Shadows.shadowOf(android.os.Looper.getMainLooper()).idle()

        // Settings must not be updated with untrusted endpoint
        assertThat(repo.getSettings().wifiHost).isEqualTo(initialHost)

        controller.destroy()
    }
}
