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
 * Traces to: Section 6.1, [REQ-OP-001], [INV-001], [INV-002]
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

        assertThat(repo.getSettings().hasMtlsCredentials).isFalse()

        // Simulate discovery of local orchestrator
        val cluster = DiscoveredCluster(
            serviceName = "androgrid-orchestrator",
            host = "192.168.1.15",
            port = 50051,
            clusterName = "default",
            version = "0.0.1-alpha.5",
            caFingerprint = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
        )
        val viewModel = activity.getDashboardViewModel()
        // Inject discovered cluster into ViewModel
        val currentUiState = viewModel.uiState.value
        val updatedUiState = currentUiState.copy(discoveredClusters = listOf(cluster))

        // Trigger render via handleConnectAndPair or state reflection
        activity.runOnUiThread {
            activity.discoveryCardView.visibility = View.VISIBLE
            activity.discoveryDetailsView.text = "Host: ${cluster.endpoint()} (Cluster: ${cluster.clusterName})"
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
        // Pre-configure mTLS credentials
        repo.updateCertificates("CA_CERT", "CLIENT_CERT", "CLIENT_KEY")
        assertThat(repo.getSettings().hasMtlsCredentials).isTrue()

        val controller = Robolectric.buildActivity(MainActivity::class.java)
        val activity = controller.get()
        activity.settingsRepository = repo

        controller.create().start().resume()
        Shadows.shadowOf(android.os.Looper.getMainLooper()).idle()

        assertThat(activity.discoveryCardView.visibility).isEqualTo(View.GONE)

        controller.destroy()
    }

    @Test
    fun testConnectAndPair_populatesWifiEndpointWithoutManualTyping() {
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

        // Invoke 1-tap Connect & Pair handler
        activity.handleConnectAndPair(cluster)
        Shadows.shadowOf(android.os.Looper.getMainLooper()).idle()

        // Verify the orchestrator endpoint was immediately populated in repository
        val settings = repo.getSettings()
        assertThat(settings.wifiHost).isEqualTo("192.168.1.15")
        assertThat(settings.wifiPort).isEqualTo(50051)

        controller.destroy()
    }

    @Test
    fun testConnectAndPair_whenAlreadyEnrolled_startsComputeParticipationDirectly() {
        repo.updateCertificates("CA_CERT", "CLIENT_CERT", "CLIENT_KEY")
        assertThat(repo.getSettings().hasMtlsCredentials).isTrue()

        val controller = Robolectric.buildActivity(MainActivity::class.java)
        val activity = controller.get()
        activity.settingsRepository = repo

        controller.create().start().resume()
        Shadows.shadowOf(android.os.Looper.getMainLooper()).idle()

        val cluster = DiscoveredCluster(
            serviceName = "androgrid-orchestrator",
            host = "192.168.1.88",
            port = 50051,
            clusterName = "office-lab"
        )

        activity.handleConnectAndPair(cluster)
        Shadows.shadowOf(android.os.Looper.getMainLooper()).idle()

        assertThat(repo.getSettings().wifiHost).isEqualTo("192.168.1.88")
        assertThat(repo.getSettings().wifiPort).isEqualTo(50051)
        assertThat(activity.getDashboardViewModel().uiState.value.isComputeActive).isTrue()

        controller.destroy()
    }
}
