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

    override suspend fun getForegroundInfo(): androidx.work.ForegroundInfo {
        val notificationManager = applicationContext.getSystemService(Context.NOTIFICATION_SERVICE) as android.app.NotificationManager
        val channelId = "androgrid_recovery_channel"
        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.O) {
            val channel = android.app.NotificationChannel(
                channelId,
                "Package Replacement Recovery",
                android.app.NotificationManager.IMPORTANCE_LOW
            )
            notificationManager.createNotificationChannel(channel)
        }
        val notification = androidx.core.app.NotificationCompat.Builder(applicationContext, channelId)
            .setContentTitle("AndroGrid Recovery")
            .setContentText("Restoring worker service...")
            .setSmallIcon(com.androgrid.worker.R.drawable.ic_stat_androgrid)
            .setPriority(androidx.core.app.NotificationCompat.PRIORITY_LOW)
            .build()
        return androidx.work.ForegroundInfo(9999, notification)
    }

    companion object {
        private const val TAG = "PackageReplacedRecovery"
    }
}
