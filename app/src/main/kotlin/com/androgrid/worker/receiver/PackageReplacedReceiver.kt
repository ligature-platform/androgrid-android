package com.androgrid.worker.receiver

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import androidx.core.content.ContextCompat
import com.androgrid.worker.network.SharedPreferencesClusterSettingsRepository
import com.androgrid.worker.service.DefaultWorkerParticipationController
import com.androgrid.worker.service.WorkerForegroundService

/**
 * Deterministic process revival receiver triggered on package upgrade.
 * Intercepts explicit android.intent.action.MY_PACKAGE_REPLACED broadcast,
 * inspects cluster settings and participation state, and restores WorkerForegroundService.
 *
 * Traces to: [REQ-OP-001], [REQ-OP-002], [INV-001], [INV-002]
 */
class PackageReplacedReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != Intent.ACTION_MY_PACKAGE_REPLACED) {
            return
        }

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
            ContextCompat.startForegroundService(context, serviceIntent)
        }
    }
}
