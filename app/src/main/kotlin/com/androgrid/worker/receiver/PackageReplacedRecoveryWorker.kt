package com.androgrid.worker.receiver

import android.content.Context
import android.content.Intent
import android.util.Log
import androidx.core.content.ContextCompat
import androidx.work.CoroutineWorker
import androidx.work.WorkerParameters
import com.androgrid.worker.service.WorkerForegroundService

/**
 * High-priority expedited WorkManager worker to bootstrap WorkerForegroundService
 * if PackageReplacedReceiver hits ForegroundServiceStartNotAllowedException on Android 12-16 OEM ROMs.
 *
 * Traces to: [REQ-OP-001], [REQ-OP-002], [NFR-REL-001], [INV-001]
 */
class PackageReplacedRecoveryWorker(
    appContext: Context,
    workerParams: WorkerParameters
) : CoroutineWorker(appContext, workerParams) {

    override suspend fun doWork(): Result {
        Log.i(TAG, "PackageReplacedRecoveryWorker executed; attempting to restore WorkerForegroundService")
        val serviceIntent = Intent(applicationContext, WorkerForegroundService::class.java).apply {
            action = WorkerForegroundService.ACTION_START_SYNC
        }
        return try {
            ContextCompat.startForegroundService(applicationContext, serviceIntent)
            Log.i(TAG, "WorkerForegroundService successfully restored via WorkManager recovery bootstrap")
            Result.success()
        } catch (e: Exception) {
            Log.e(TAG, "Failed to restore WorkerForegroundService from WorkManager bootstrap: ${e.message}", e)
            Result.retry()
        }
    }

    companion object {
        private const val TAG = "PackageReplacedRecovery"
    }
}
