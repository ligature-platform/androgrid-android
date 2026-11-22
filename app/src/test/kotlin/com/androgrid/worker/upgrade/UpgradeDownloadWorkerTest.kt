package com.androgrid.worker.upgrade

import android.content.Context
import androidx.work.ListenableWorker
import androidx.work.NetworkType
import androidx.work.testing.TestListenableWorkerBuilder
import com.androgrid.v1.NodeUpgradeDirective
import com.androgrid.v1.UpgradeNetworkPolicy
import com.google.common.truth.Truth.assertThat
import kotlinx.coroutines.test.runTest
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.annotation.Config

/**
 * Unit and Robolectric tests for [UpgradeDownloadWorker].
 * Validates asynchronous cellular download scheduling with hardware safety constraints.
 *
 * Traces to: [REQ-OP-001], [REQ-OP-002], [INV-003], [NFR-POW-001]
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class UpgradeDownloadWorkerTest {

    private lateinit var context: Context

    @Before
    fun setUp() {
        context = RuntimeEnvironment.getApplication()
    }

    @Test
    fun testSchedule_enforcesHardwareSafetyConstraints() {
        val directive = NodeUpgradeDirective.newBuilder()
            .setTargetVersion("0.2.0")
            .setApkUrl("https://cluster.domain.com/v1/blobs/abc")
            .setApkSha256("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
            .setNetworkPolicy(UpgradeNetworkPolicy.UPGRADE_NETWORK_POLICY_ALLOW_CELLULAR)
            .build()

        val workRequest = UpgradeDownloadWorker.schedule(context, directive)

        val constraints = workRequest.workSpec.constraints
        assertThat(constraints.requiredNetworkType).isEqualTo(NetworkType.CONNECTED)
        assertThat(constraints.requiresBatteryNotLow()).isTrue()
        assertThat(constraints.requiresStorageNotLow()).isTrue()

        val data = workRequest.workSpec.input
        assertThat(data.getString(UpgradeDownloadWorker.KEY_TARGET_VERSION)).isEqualTo("0.2.0")
        assertThat(data.getString(UpgradeDownloadWorker.KEY_APK_URL)).isEqualTo("https://cluster.domain.com/v1/blobs/abc")
        assertThat(data.getString(UpgradeDownloadWorker.KEY_APK_SHA256)).isEqualTo("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
    }

    @Test
    fun testDoWork_withMissingData_returnsFailure() = runTest {
        val worker = TestListenableWorkerBuilder<UpgradeDownloadWorker>(context)
            .build()

        val result = worker.doWork()
        assertThat(result).isEqualTo(ListenableWorker.Result.failure())
    }
}
