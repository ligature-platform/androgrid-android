package com.androgrid.worker.upgrade

import android.content.Context
import androidx.work.BackoffPolicy
import androidx.work.Constraints
import androidx.work.CoroutineWorker
import androidx.work.Data
import androidx.work.NetworkType
import androidx.work.OneTimeWorkRequest
import androidx.work.OneTimeWorkRequestBuilder
import androidx.work.WorkManager
import androidx.work.WorkRequest
import androidx.work.WorkerParameters
import com.androgrid.v1.NodeUpgradeDirective
import com.androgrid.v1.UpgradeNetworkPolicy
import com.androgrid.worker.AndroGridApplication
import java.util.concurrent.TimeUnit

/**
 * Background worker for asynchronous OTA APK downloads over cellular WAN or Wi-Fi.
 * Enforces battery and storage constraints and isolates multi-megabyte transfers
 * completely from ephemeral gRPC spot-claim cycles ([INV-003], [NFR-POW-001], [ANTI-003]).
 *
 * Traces to: [REQ-OP-001], [REQ-OP-002], [INV-003], [NFR-POW-001]
 */
class UpgradeDownloadWorker(
    appContext: Context,
    workerParams: WorkerParameters
) : CoroutineWorker(appContext, workerParams) {

    override suspend fun doWork(): Result {
        val app = applicationContext as? AndroGridApplication
        val upgradeManager = app?.upgradeManager ?: DefaultUpgradeManager(applicationContext)

        val targetVersion = inputData.getString(KEY_TARGET_VERSION) ?: return Result.failure()
        val apkUrl = inputData.getString(KEY_APK_URL) ?: return Result.failure()
        val apkSha256 = inputData.getString(KEY_APK_SHA256) ?: ""
        val networkPolicyOrdinal = inputData.getInt(
            KEY_NETWORK_POLICY,
            UpgradeNetworkPolicy.UPGRADE_NETWORK_POLICY_WIFI_ONLY_VALUE
        )
        val networkPolicy = UpgradeNetworkPolicy.forNumber(networkPolicyOrdinal)
            ?: UpgradeNetworkPolicy.UPGRADE_NETWORK_POLICY_WIFI_ONLY

        val directive = NodeUpgradeDirective.newBuilder()
            .setTargetVersion(targetVersion)
            .setApkUrl(apkUrl)
            .setApkSha256(apkSha256)
            .setNetworkPolicy(networkPolicy)
            .build()

        return when (val outcome = upgradeManager.processUpgradeDirective(directive, isMetered = true, isWifi = false)) {
            is UpgradeOutcome.InstalledRoot,
            is UpgradeOutcome.UpToDate -> Result.success()
            is UpgradeOutcome.PromptUserInstall -> {
                applicationContext.startActivity(outcome.intent.addFlags(android.content.Intent.FLAG_ACTIVITY_NEW_TASK))
                Result.success()
            }
            is UpgradeOutcome.BackoffSuppressed -> Result.retry()
            is UpgradeOutcome.TerminallyRejected,
            is UpgradeOutcome.SignatureVerificationFailed,
            is UpgradeOutcome.NetworkPolicyViolation -> Result.failure()
            is UpgradeOutcome.DownloadFailed,
            is UpgradeOutcome.IntegrityVerificationFailed -> Result.retry()
        }
    }

    companion object {
        const val WORK_NAME = "androgrid_ota_download_work"
        const val KEY_TARGET_VERSION = "target_version"
        const val KEY_APK_URL = "apk_url"
        const val KEY_APK_SHA256 = "apk_sha256"
        const val KEY_NETWORK_POLICY = "network_policy"

        fun schedule(context: Context, directive: NodeUpgradeDirective): OneTimeWorkRequest {
            val constraints = Constraints.Builder()
                .setRequiredNetworkType(NetworkType.CONNECTED)
                .setRequiresBatteryNotLow(true)
                .setRequiresStorageNotLow(true)
                .build()

            val data = Data.Builder()
                .putString(KEY_TARGET_VERSION, directive.targetVersion)
                .putString(KEY_APK_URL, directive.apkUrl)
                .putString(KEY_APK_SHA256, directive.apkSha256)
                .putInt(KEY_NETWORK_POLICY, directive.networkPolicyValue)
                .build()

            val request = OneTimeWorkRequestBuilder<UpgradeDownloadWorker>()
                .setConstraints(constraints)
                .setInputData(data)
                .setBackoffCriteria(
                    BackoffPolicy.EXPONENTIAL,
                    WorkRequest.MIN_BACKOFF_MILLIS,
                    TimeUnit.MILLISECONDS
                )
                .build()

            WorkManager.getInstance(context).enqueueUniqueWork(
                WORK_NAME,
                androidx.work.ExistingWorkPolicy.KEEP,
                request
            )
            return request
        }
    }
}
