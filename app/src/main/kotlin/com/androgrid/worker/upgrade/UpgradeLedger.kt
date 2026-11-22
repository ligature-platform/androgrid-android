package com.androgrid.worker.upgrade

import android.content.Context
import android.content.SharedPreferences
import com.androgrid.v1.LastUpgradeOutcome
import com.androgrid.v1.UpgradeInstallStatus
import org.json.JSONObject

/**
 * Persistent ledger tracking OTA upgrade attempts and terminal failure states.
 * Enforces exponential backoff for transient failures and permanent rejection
 * for fatal installer errors ([ANTI-003], [NFR-POW-001], [NFR-SEC-001]).
 *
 * Traces to: [REQ-OP-001], [REQ-OP-002], [ANTI-003], [NFR-POW-001]
 */
interface UpgradeLedger {
    /**
     * Checks whether an upgrade directive for (targetVersion, apkSha256) should be attempted.
     * Returns false if terminally rejected or currently suppressed by exponential backoff.
     */
    fun shouldAttempt(targetVersion: String, apkSha256: String): Boolean

    /**
     * Records a new attempt for (targetVersion, apkSha256).
     */
    fun recordAttempt(targetVersion: String, apkSha256: String)

    /**
     * Records successful upgrade completion for (targetVersion, apkSha256).
     */
    fun recordSuccess(targetVersion: String, apkSha256: String)

    /**
     * Records a terminal, non-retryable failure (e.g. signature mismatch, version downgrade).
     */
    fun recordTerminalFailure(
        targetVersion: String,
        apkSha256: String,
        errorCode: String,
        errorMessage: String
    )

    /**
     * Records a transient failure (e.g. network timeout), applying exponential backoff
     * or escalating to terminal rejection after maximum attempts.
     */
    fun recordTransientFailure(
        targetVersion: String,
        apkSha256: String,
        errorCode: String,
        errorMessage: String
    )

    /**
     * Returns the structured outcome of the most recent upgrade attempt to report to the orchestrator.
     */
    fun getLastOutcome(): LastUpgradeOutcome?
}

/**
 * Production implementation of [UpgradeLedger] backed by Android SharedPreferences.
 */
class SharedPreferencesUpgradeLedger(
    context: Context,
    private val timeProvider: () -> Long = { System.currentTimeMillis() }
) : UpgradeLedger {

    private val prefs: SharedPreferences = context.getSharedPreferences(
        PREFS_NAME,
        Context.MODE_PRIVATE
    )

    override fun shouldAttempt(targetVersion: String, apkSha256: String): Boolean {
        val key = buildKey(targetVersion, apkSha256)
        val rawJson = prefs.getString(key, null) ?: return true

        return try {
            val json = JSONObject(rawJson)
            val status = json.optString("status", "")
            if (status == UpgradeInstallStatus.UPGRADE_INSTALL_STATUS_TERMINALLY_REJECTED.name ||
                status == UpgradeInstallStatus.UPGRADE_INSTALL_STATUS_SUCCEEDED.name
            ) {
                return false
            }

            val attemptCount = json.optInt("attempt_count", 0)
            if (attemptCount >= MAX_TRANSIENT_ATTEMPTS) {
                return false
            }

            val lastAttemptEpochMs = json.optLong("last_attempt_epoch_ms", 0L)
            val elapsedMs = timeProvider() - lastAttemptEpochMs
            val requiredBackoffMs = computeBackoffMs(attemptCount)
            elapsedMs >= requiredBackoffMs
        } catch (_: Exception) {
            true
        }
    }

    override fun recordAttempt(targetVersion: String, apkSha256: String) {
        val key = buildKey(targetVersion, apkSha256)
        val existing = readJson(key)
        val currentAttempts = existing?.optInt("attempt_count", 0) ?: 0
        val json = JSONObject().apply {
            put("target_version", targetVersion)
            put("apk_sha256", apkSha256)
            put("attempt_count", currentAttempts + 1)
            put("last_attempt_epoch_ms", timeProvider())
            put("status", UpgradeInstallStatus.UPGRADE_INSTALL_STATUS_FAILED_TRANSIENT.name)
        }
        prefs.edit().putString(key, json.toString()).commit()
    }

    override fun recordSuccess(targetVersion: String, apkSha256: String) {
        val key = buildKey(targetVersion, apkSha256)
        val existing = readJson(key)
        val attempts = existing?.optInt("attempt_count", 1) ?: 1
        val json = JSONObject().apply {
            put("target_version", targetVersion)
            put("apk_sha256", apkSha256)
            put("attempt_count", attempts)
            put("last_attempt_epoch_ms", timeProvider())
            put("status", UpgradeInstallStatus.UPGRADE_INSTALL_STATUS_SUCCEEDED.name)
            put("error_code", "")
            put("error_message", "")
        }
        prefs.edit()
            .putString(key, json.toString())
            .putString(KEY_LAST_OUTCOME, json.toString())
            .commit()
    }

    override fun recordTerminalFailure(
        targetVersion: String,
        apkSha256: String,
        errorCode: String,
        errorMessage: String
    ) {
        val key = buildKey(targetVersion, apkSha256)
        val existing = readJson(key)
        val attempts = existing?.optInt("attempt_count", 1) ?: 1
        val json = JSONObject().apply {
            put("target_version", targetVersion)
            put("apk_sha256", apkSha256)
            put("attempt_count", attempts)
            put("last_attempt_epoch_ms", timeProvider())
            put("status", UpgradeInstallStatus.UPGRADE_INSTALL_STATUS_TERMINALLY_REJECTED.name)
            put("error_code", errorCode)
            put("error_message", errorMessage)
        }
        prefs.edit()
            .putString(key, json.toString())
            .putString(KEY_LAST_OUTCOME, json.toString())
            .commit()
    }

    override fun recordTransientFailure(
        targetVersion: String,
        apkSha256: String,
        errorCode: String,
        errorMessage: String
    ) {
        val key = buildKey(targetVersion, apkSha256)
        val existing = readJson(key)
        val attempts = existing?.optInt("attempt_count", 1) ?: 1
        val isTerminal = attempts >= MAX_TRANSIENT_ATTEMPTS
        val status = if (isTerminal) {
            UpgradeInstallStatus.UPGRADE_INSTALL_STATUS_TERMINALLY_REJECTED
        } else {
            UpgradeInstallStatus.UPGRADE_INSTALL_STATUS_FAILED_TRANSIENT
        }

        val json = JSONObject().apply {
            put("target_version", targetVersion)
            put("apk_sha256", apkSha256)
            put("attempt_count", attempts)
            put("last_attempt_epoch_ms", timeProvider())
            put("status", status.name)
            put("error_code", errorCode)
            put("error_message", errorMessage)
        }
        prefs.edit()
            .putString(key, json.toString())
            .putString(KEY_LAST_OUTCOME, json.toString())
            .commit()
    }

    override fun getLastOutcome(): LastUpgradeOutcome? {
        val rawJson = prefs.getString(KEY_LAST_OUTCOME, null) ?: return null
        return try {
            val json = JSONObject(rawJson)
            val statusStr = json.optString("status", "")
            val status = when (statusStr) {
                UpgradeInstallStatus.UPGRADE_INSTALL_STATUS_SUCCEEDED.name ->
                    UpgradeInstallStatus.UPGRADE_INSTALL_STATUS_SUCCEEDED
                UpgradeInstallStatus.UPGRADE_INSTALL_STATUS_TERMINALLY_REJECTED.name ->
                    UpgradeInstallStatus.UPGRADE_INSTALL_STATUS_TERMINALLY_REJECTED
                UpgradeInstallStatus.UPGRADE_INSTALL_STATUS_FAILED_TRANSIENT.name ->
                    UpgradeInstallStatus.UPGRADE_INSTALL_STATUS_FAILED_TRANSIENT
                else -> UpgradeInstallStatus.UPGRADE_INSTALL_STATUS_UNSPECIFIED
            }

            LastUpgradeOutcome.newBuilder()
                .setTargetVersion(json.optString("target_version", ""))
                .setApkSha256(json.optString("apk_sha256", ""))
                .setStatus(status)
                .setErrorCode(json.optString("error_code", ""))
                .setErrorMessage(json.optString("error_message", ""))
                .setAttemptCount(json.optInt("attempt_count", 0))
                .build()
        } catch (_: Exception) {
            null
        }
    }

    private fun readJson(key: String): JSONObject? {
        val raw = prefs.getString(key, null) ?: return null
        return try {
            JSONObject(raw)
        } catch (_: Exception) {
            null
        }
    }

    private fun buildKey(targetVersion: String, apkSha256: String): String {
        return "upgrade_${targetVersion}_${apkSha256}"
    }

    private fun computeBackoffMs(attemptCount: Int): Long {
        return when (attemptCount) {
            1 -> 60_000L // 1 minute
            2 -> 300_000L // 5 minutes
            else -> 1_800_000L // 30 minutes
        }
    }

    companion object {
        const val PREFS_NAME = "androgrid_upgrade_ledger"
        const val KEY_LAST_OUTCOME = "last_upgrade_outcome"
        const val MAX_TRANSIENT_ATTEMPTS = 3

        /**
         * Identifies whether a PackageManager install failure is non-retryable.
         */
        fun isNonRetryableInstallerError(errorOutput: String): Boolean {
            return errorOutput.contains("INSTALL_FAILED_VERSION_DOWNGRADE") ||
                errorOutput.contains("INSTALL_FAILED_UPDATE_INCOMPATIBLE") ||
                errorOutput.contains("INSTALL_FAILED_INVALID_APK") ||
                errorOutput.contains("SIGNATURE_MISMATCH") ||
                errorOutput.contains("CORRUPT_ARCHIVE") ||
                errorOutput.contains("ABI_MISMATCH")
        }
    }
}
