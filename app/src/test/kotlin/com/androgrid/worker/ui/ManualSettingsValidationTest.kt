package com.androgrid.worker.ui

import android.content.pm.ApplicationInfo
import android.util.Log
import androidx.work.Configuration
import androidx.work.testing.SynchronousExecutor
import androidx.work.testing.WorkManagerTestInitHelper
import com.androgrid.worker.AndroGridApplication
import com.androgrid.worker.enrollment.EnrollmentPayload
import com.androgrid.worker.enrollment.EnrollmentPayloadParser
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
import org.robolectric.shadows.ShadowToast

/**
 * Unit tests verifying input validation, crash prevention, and transactional settings preservation
 * in manual cluster endpoint configuration and enrollment payload parsing.
 *
 * Traces to: [REQ-OP-001], [INV-001], [INV-002], [NFR-SEC-001], Gate L-02
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34], application = AndroGridApplication::class)
class ManualSettingsValidationTest {

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
    fun applyManualSettings_blankHost_abortsWithoutMutatingSettings() {
        val controller = Robolectric.buildActivity(MainActivity::class.java)
        val activity = controller.get()
        activity.settingsRepository = repo
        controller.create().start().resume()

        val initialHost = repo.getSettings().wifiHost
        activity.applyManualSettings("   ", 50051, "token123", "a".repeat(64))
        Shadows.shadowOf(android.os.Looper.getMainLooper()).idle()

        assertThat(repo.getSettings().wifiHost).isEqualTo(initialHost)
        assertThat(ShadowToast.getTextOfLatestToast()).contains("Host address cannot be empty")
        controller.destroy()
    }

    @Test
    fun applyManualSettings_invalidPortRange_abortsWithoutMutatingSettings() {
        val controller = Robolectric.buildActivity(MainActivity::class.java)
        val activity = controller.get()
        activity.settingsRepository = repo
        controller.create().start().resume()

        val initialPort = repo.getSettings().wifiPort
        activity.applyManualSettings("10.100.102.6", 0, "token123", "a".repeat(64))
        activity.applyManualSettings("10.100.102.6", 70000, "token123", "a".repeat(64))
        Shadows.shadowOf(android.os.Looper.getMainLooper()).idle()

        assertThat(repo.getSettings().wifiPort).isEqualTo(initialPort)
        assertThat(ShadowToast.getTextOfLatestToast()).contains("outside valid range")
        controller.destroy()
    }

    @Test
    fun applyManualSettings_nonHexFingerprint_doesNotCrashAndPreservesSettings() {
        val controller = Robolectric.buildActivity(MainActivity::class.java)
        val activity = controller.get()
        activity.settingsRepository = repo
        controller.create().start().resume()

        val initialHost = repo.getSettings().wifiHost
        // 64 non-hexadecimal characters (e.g. 'z')
        val malformedFp = "z".repeat(64)

        // Must not throw uncaught IllegalArgumentException or crash the UI thread
        activity.applyManualSettings("10.100.102.6", 50051, "valid-token", malformedFp)
        Shadows.shadowOf(android.os.Looper.getMainLooper()).idle()

        assertThat(repo.getSettings().wifiHost).isEqualTo(initialHost)
        assertThat(ShadowToast.getTextOfLatestToast()).contains("hexadecimal")
        controller.destroy()
    }

    @Test
    fun applyManualSettings_unprovisionedWorkerWithoutCredentials_reportsMissingInputWithoutMutating() {
        val controller = Robolectric.buildActivity(MainActivity::class.java)
        val activity = controller.get()
        activity.settingsRepository = repo
        controller.create().start().resume()

        val initialHost = repo.getSettings().wifiHost
        // Worker has no mTLS credentials yet and provides no token
        activity.applyManualSettings("10.100.102.6", 50051, "", "")
        Shadows.shadowOf(android.os.Looper.getMainLooper()).idle()

        assertThat(repo.getSettings().wifiHost).isEqualTo(initialHost)
        assertThat(ShadowToast.getTextOfLatestToast()).contains("Incomplete credentials")
        controller.destroy()
    }

    @Test
    fun applyManualSettings_alreadyProvisionedWorker_updatesEndpointSuccessfully() {
        val controller = Robolectric.buildActivity(MainActivity::class.java)
        val activity = controller.get()
        activity.settingsRepository = repo
        controller.create().start().resume()

        // Provision device with valid mock credentials
        repo.updateCertificates("mock-ca", "mock-cert", "mock-key")
        assertThat(repo.getSettings().hasMtlsCredentials).isTrue()

        activity.applyManualSettings("10.100.102.88", 50052, "", "")
        Shadows.shadowOf(android.os.Looper.getMainLooper()).idle()

        assertThat(repo.getSettings().wifiHost).isEqualTo("10.100.102.88")
        assertThat(repo.getSettings().wifiPort).isEqualTo(50052)
        assertThat(ShadowToast.getTextOfLatestToast()).contains("Endpoint updated")
        controller.destroy()
    }

    @Test
    fun enrollmentPayloadParser_rejectsInvalidPortBoundariesInJson() {
        val validJson = """
            {
                "cluster_endpoint": "10.0.0.1:50051",
                "ca_fingerprint": "${"a".repeat(64)}",
                "pairing_token": "token123",
                "direct_ip": "10.0.0.1",
                "direct_port": 70000
            }
        """.trimIndent()

        try {
            EnrollmentPayloadParser.parse(validJson)
            assertThat(false).isTrue() // Should not reach here
        } catch (e: IllegalArgumentException) {
            assertThat(e.message).contains("between 1 and 65535")
        }
    }

    @Test
    fun enrollmentPayloadParser_rejectsInvalidPortBoundariesInUri() {
        val invalidUri = "androgrid://enroll?endpoint=10.0.0.1:50051&token=tok&ca=${"a".repeat(64)}&direct_port=99999"

        try {
            EnrollmentPayloadParser.parse(invalidUri)
            assertThat(false).isTrue() // Should not reach here
        } catch (e: IllegalArgumentException) {
            assertThat(e.message).contains("between 1 and 65535")
        }
    }

    @Test
    fun enrollmentPayloadParser_acceptsMissingDirectEndpoint() {
        val jsonWithoutDirect = """
            {
                "cluster_endpoint": "10.0.0.1:50051",
                "ca_fingerprint": "${"b".repeat(64)}",
                "pairing_token": "token123"
            }
        """.trimIndent()

        val payload = EnrollmentPayloadParser.parse(jsonWithoutDirect)
        assertThat(payload.directIp).isNull()
        assertThat(payload.directPort).isNull()
        val (host, port) = payload.parseEndpoint()
        assertThat(host).isEqualTo("10.0.0.1")
        assertThat(port).isEqualTo(50051)
    }
}
