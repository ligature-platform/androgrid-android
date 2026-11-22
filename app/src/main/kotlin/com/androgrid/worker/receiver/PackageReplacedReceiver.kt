package com.androgrid.worker.receiver

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.util.Log
import androidx.core.content.ContextCompat
import androidx.work.ExistingWorkPolicy
import androidx.work.OneTimeWorkRequestBuilder
import androidx.work.OutOfQuotaPolicy
import androidx.work.WorkManager
import com.androgrid.worker.network.SharedPreferencesClusterSettingsRepository
import com.androgrid.worker.service.DefaultWorkerParticipationController
import com.androgrid.worker.service.WorkerForegroundService

/**
 * Deterministic process revival receiver triggered on package upgrade.
 * Intercepts explicit android.intent.action.MY_PACKAGE_REPLACED broadcast,
 * inspects cluster settings and participation state, and restores WorkerForegroundService.
 * If direct startForegroundService throws (e.g., ForegroundServiceStartNotAllowedException on Android 12-16),
 * enqueues an expedited OneTimeWorkRequest fallback to guarantee headless service recovery.
 *
 * Traces to: [REQ-OP-001], [REQ-OP-002], [INV-001], [INV-002], [NFR-REL-001]
 */
class PackageReplacedReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != Intent.ACTION_MY_PACKAGE_REPLACED) {
            return
        }

        // Reconcile pending upgrade outcome across process replacement
        val upgradeLedger = com.androgrid.worker.upgrade.SharedPreferencesUpgradeLedger(context)
        val currentVersion = try {
            val pkgInfo = context.packageManager.getPackageInfo(context.packageName, 0)
            pkgInfo.versionName ?: "0.0.1-alpha.4"
        } catch (_: Exception) {
            "0.0.1-alpha.4"
        }
        upgradeLedger.checkPendingUpgradeOnStartup(currentVersion)

        val settingsRepo = SharedPreferencesClusterSettingsRepository.getInstance(context)
        val settings = settingsRepo.getSettings()
        val prefs = context.getSharedPreferences(
            DefaultWorkerParticipationController.PREFS_NAME,
            Context.MODE_PRIVATE
        )
        val isComputeActive = prefs.getBoolean(
            DefaultWorkerParticipationController.KEY_IS_COMPUTE_ACTIVE,
            false
        )

        // Only start service if node is enrolled with mTLS credentials and participation was active
        if (settings.hasMtlsCredentials && isComputeActive) {
            val serviceIntent = Intent(context, WorkerForegroundService::class.java).apply {
                action = WorkerForegroundService.ACTION_START_SYNC
            }
            try {
                ContextCompat.startForegroundService(context, serviceIntent)
                Log.i(TAG, "WorkerForegroundService restarted successfully via startForegroundService")
            } catch (e: Exception) {
                Log.w(
                    TAG,
                    "Direct startForegroundService failed post-upgrade, enqueuing expedited WorkManager fallback: ${e.message}"
                )
                val recoveryRequest = OneTimeWorkRequestBuilder<PackageReplacedRecoveryWorker>()
                    .setExpedited(OutOfQuotaPolicy.RUN_AS_NON_EXPEDITED_WORK_REQUEST)
                    .build()
                WorkManager.getInstance(context).enqueueUniqueWork(
                    WORK_RECOVERY_NAME,
                    ExistingWorkPolicy.REPLACE,
                    recoveryRequest
                )
            }
        }
    }

    companion object {
        private const val TAG = "PackageReplacedReceiver"
        const val WORK_RECOVERY_NAME = "PackageReplacedRecovery"
    }
}
