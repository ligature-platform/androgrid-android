package com.androgrid.worker.receiver

import android.content.Context
import android.content.Intent
import com.androgrid.worker.network.ClusterSettings
import com.androgrid.worker.network.SharedPreferencesClusterSettingsRepository
import com.androgrid.worker.service.DefaultWorkerParticipationController
import com.androgrid.worker.service.WorkerForegroundService
import com.google.common.truth.Truth.assertThat
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.Shadows.shadowOf
import org.robolectric.annotation.Config

/**
 * Unit and Robolectric tests for [PackageReplacedReceiver].
 * Validates deterministic process revival upon ACTION_MY_PACKAGE_REPLACED.
 *
 * Traces to: [REQ-OP-001], [REQ-OP-002], [INV-001], [INV-002]
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class PackageReplacedReceiverTest {

    private lateinit var context: Context
    private lateinit var receiver: PackageReplacedReceiver

    @Before
    fun setUp() {
        context = RuntimeEnvironment.getApplication()
        receiver = PackageReplacedReceiver()
    }

    @Test
    fun testOnReceive_myPackageReplaced_participationActive_startsWorkerForegroundService() {
        val repo = SharedPreferencesClusterSettingsRepository.getInstance(context)
        repo.updateSettings(
            ClusterSettings(
                wifiHost = "192.168.1.100",
                wifiPort = 50051,
                caCertPem = "-----BEGIN CERTIFICATE-----\nCA\n-----END CERTIFICATE-----",
                clientCertPem = "-----BEGIN CERTIFICATE-----\nCLIENT\n-----END CERTIFICATE-----",
                clientKeyPem = "-----BEGIN PRIVATE KEY-----\nKEY\n-----END PRIVATE KEY-----"
            )
        )
        val prefs = context.getSharedPreferences(
            DefaultWorkerParticipationController.PREFS_NAME,
            Context.MODE_PRIVATE
        )
        prefs.edit().putBoolean(DefaultWorkerParticipationController.KEY_IS_COMPUTE_ACTIVE, true).commit()

        val intent = Intent(Intent.ACTION_MY_PACKAGE_REPLACED)
        receiver.onReceive(context, intent)

        val shadowApp = shadowOf(RuntimeEnvironment.getApplication())
        val nextServiceIntent = shadowApp.nextStartedService
        assertThat(nextServiceIntent).isNotNull()
        assertThat(nextServiceIntent.component?.className).isEqualTo(WorkerForegroundService::class.java.name)
        assertThat(nextServiceIntent.action).isEqualTo(WorkerForegroundService.ACTION_START_SYNC)
    }

    @Test
    fun testOnReceive_myPackageReplaced_participationInactive_doesNotStartService() {
        val repo = SharedPreferencesClusterSettingsRepository.getInstance(context)
        repo.updateSettings(
            ClusterSettings(
                wifiHost = "192.168.1.100",
                wifiPort = 50051,
                caCertPem = "-----BEGIN CERTIFICATE-----\nCA\n-----END CERTIFICATE-----",
                clientCertPem = "-----BEGIN CERTIFICATE-----\nCLIENT\n-----END CERTIFICATE-----",
                clientKeyPem = "-----BEGIN PRIVATE KEY-----\nKEY\n-----END PRIVATE KEY-----"
            )
        )
        val prefs = context.getSharedPreferences(
            DefaultWorkerParticipationController.PREFS_NAME,
            Context.MODE_PRIVATE
        )
        prefs.edit().putBoolean(DefaultWorkerParticipationController.KEY_IS_COMPUTE_ACTIVE, false).commit()

        val intent = Intent(Intent.ACTION_MY_PACKAGE_REPLACED)
        receiver.onReceive(context, intent)

        val shadowApp = shadowOf(RuntimeEnvironment.getApplication())
        val nextServiceIntent = shadowApp.nextStartedService
        assertThat(nextServiceIntent).isNull()
    }

    @Test
    fun testOnReceive_otherAction_doesNotStartService() {
        val intent = Intent(Intent.ACTION_BOOT_COMPLETED)
        receiver.onReceive(context, intent)

        val shadowApp = shadowOf(RuntimeEnvironment.getApplication())
        assertThat(shadowApp.nextStartedService).isNull()
    }
}
