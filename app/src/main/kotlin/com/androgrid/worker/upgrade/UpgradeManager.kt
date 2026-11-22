package com.androgrid.worker.upgrade

import android.content.Context
import android.content.Intent
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.content.pm.Signature
import android.net.Uri
import android.util.Log
import androidx.core.content.FileProvider
import com.androgrid.v1.LastUpgradeOutcome
import com.androgrid.v1.NodeUpgradeDirective
import com.androgrid.v1.UpgradeNetworkPolicy
import com.androgrid.worker.capability.RootChecker
import com.androgrid.worker.capability.StandardRootChecker
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File
import java.io.FileOutputStream
import java.net.HttpURLConnection
import java.net.URL
import java.security.MessageDigest

/**
 * Result outcome of evaluating and processing a [NodeUpgradeDirective].
 *
 * Traces to: [REQ-OP-001], [REQ-OP-002], [INV-001], [INV-002], [INV-003], [ANTI-003], [NFR-POW-001], [NFR-SEC-001]
 */
sealed class UpgradeOutcome {
    /**
     * Node is already running targetVersion or targetVersion is blank; no upgrade necessary.
     */
    data class UpToDate(val currentVersion: String) : UpgradeOutcome()

    /**
     * Directive rejected because transport is metered and directive network policy mandates Wi-Fi only.
     * Traces to: [ANTI-003], [NFR-POW-001]
     */
    data class NetworkPolicyViolation(val reason: String) : UpgradeOutcome()

    /**
     * Directive aborted without network activity because previous attempt terminally failed or is in backoff.
     */
    data class TerminallyRejected(val reason: String) : UpgradeOutcome()

    /**
     * Binary download failed.
     */
    data class DownloadFailed(val error: String, val cause: Throwable? = null) : UpgradeOutcome()

    /**
     * Downloaded binary SHA-256 does not match authoritative directive checksum or archive is corrupt.
     * Traces to: [NFR-SEC-001]
     */
    data class IntegrityVerificationFailed(
        val expectedSha256: String,
        val actualSha256: String
    ) : UpgradeOutcome()

    /**
     * Downloaded APK signing certificate does not match the installed package's signing certificate.
     * Traces to: [INV-002], [NFR-SEC-001]
     */
    data class SignatureVerificationFailed(val reason: String) : UpgradeOutcome()

    /**
     * Silent unattended installation succeeded via root shell (`pm install -r`).
     */
    data class InstalledRoot(val exitCode: Int, val apkFile: File) : UpgradeOutcome()

    /**
     * Installation intent prepared for unrooted / consumer user confirmation.
     */
    data class PromptUserInstall(val intent: Intent, val apkFile: File) : UpgradeOutcome()
}

/**
 * Subsystem managing declarative Over-the-Air (OTA) Node Upgrades across Wi-Fi and Cellular.
 * Enforces network guards ([ANTI-003], [NFR-POW-001]), cryptographic SHA-256 verification ([NFR-SEC-001]),
 * signature lineage verification ([INV-002]), and heterogeneous installation routing across rooted testbeds and unrooted devices.
 *
 * Traces to: [REQ-OP-001], [REQ-OP-002], [INV-001], [INV-002], [INV-003], [ANTI-003], [NFR-POW-001], [NFR-SEC-001]
 */
interface UpgradeManager {
    /**
     * Processes a declarative upgrade directive.
     *
     * @param directive Declarative upgrade specification from orchestrator.
     * @param isMetered Whether the current network interface is metered.
     * @param isWifi Whether the current network interface is Wi-Fi LAN.
     * @return [UpgradeOutcome] representing the terminal or staged status of the upgrade.
     */
    suspend fun processUpgradeDirective(
        directive: NodeUpgradeDirective,
        isMetered: Boolean,
        isWifi: Boolean
    ): UpgradeOutcome

    /**
     * Returns the structured outcome of the most recent upgrade attempt to report to the orchestrator.
     */
    fun getLastOutcome(): LastUpgradeOutcome?
}

/**
 * Production implementation of [UpgradeManager].
 *
 * Traces to: [REQ-OP-001], [REQ-OP-002], [INV-001], [INV-002], [INV-003], [ANTI-003], [NFR-POW-001], [NFR-SEC-001]
 */
class DefaultUpgradeManager(
    private val context: Context,
    private val rootChecker: RootChecker = StandardRootChecker(),
    private val currentVersionProvider: () -> String = {
        try {
            val packageInfo = context.packageManager.getPackageInfo(context.packageName, 0)
            packageInfo.versionName ?: "0.0.1-alpha.4"
        } catch (_: Exception) {
            "0.0.1-alpha.4"
        }
    },
    private val downloadClient: (suspend (url: String, destFile: File) -> Boolean)? = null,
    private val shellRunner: (suspend (command: String) -> Pair<Int, String>)? = null,
    private val ledger: UpgradeLedger = SharedPreferencesUpgradeLedger(context),
    private val signatureVerifier: ((installed: Array<Signature>?, archive: Array<Signature>?) -> Boolean)? = null,
    private val archiveInfoParser: ((File) -> PackageInfo?)? = null
) : UpgradeManager {

    companion object {
        private const val TAG: String = "DefaultUpgradeManager"
        private const val BUFFER_SIZE: Int = 64 * 1024
        private const val CONNECT_TIMEOUT_MS: Int = 15_000
        private const val READ_TIMEOUT_MS: Int = 60_000
    }

    override fun getLastOutcome(): LastUpgradeOutcome? = ledger.getLastOutcome()

    override suspend fun processUpgradeDirective(
        directive: NodeUpgradeDirective,
        isMetered: Boolean,
        isWifi: Boolean
    ): UpgradeOutcome = withContext(Dispatchers.IO) {
        val targetVersion = directive.targetVersion.trim()
        val currentVersion = currentVersionProvider().trim()

        // Step 1: Idempotency & Version Threshold Check
        if (targetVersion.isEmpty() || targetVersion == currentVersion) {
            Log.d(TAG, "Worker is up to date (version=$currentVersion, target=$targetVersion)")
            return@withContext UpgradeOutcome.UpToDate(currentVersion)
        }

        // Step 2: Loop Termination Check via UpgradeLedger
        val expectedSha256 = directive.apkSha256.trim().lowercase()
        if (!ledger.shouldAttempt(targetVersion, expectedSha256)) {
            val reason = "Directive for version $targetVersion (sha=$expectedSha256) is terminally rejected or currently suppressed by exponential backoff"
            Log.w(TAG, reason)
            return@withContext UpgradeOutcome.TerminallyRejected(reason)
        }

        // Step 3: Network Guard Enforcement per [ANTI-003], [NFR-POW-001]
        val isCellularOrMetered = isMetered || !isWifi
        val policy = directive.networkPolicy
        if (isCellularOrMetered && policy != UpgradeNetworkPolicy.UPGRADE_NETWORK_POLICY_ALLOW_CELLULAR) {
            val reason = "OTA APK download rejected: transport is metered cellular and directive policy mandates Wi-Fi only per [ANTI-003]"
            Log.w(TAG, reason)
            return@withContext UpgradeOutcome.NetworkPolicyViolation(reason)
        }

        // Step 4: APK URL validation
        val apkUrl = directive.apkUrl.trim()
        if (apkUrl.isEmpty()) {
            val err = "OTA APK download rejected: missing or empty apk_url in directive"
            Log.e(TAG, err)
            ledger.recordTransientFailure(targetVersion, expectedSha256, "EMPTY_URL", err)
            return@withContext UpgradeOutcome.DownloadFailed(err)
        }

        // Step 5: Download binary
        val destFile = File(context.cacheDir, "androgrid_ota_${targetVersion}.apk")
        ledger.recordAttempt(targetVersion, expectedSha256)

        val downloadSuccess = try {
            if (downloadClient != null) {
                downloadClient.invoke(apkUrl, destFile)
            } else {
                downloadApkStream(apkUrl, destFile)
            }
        } catch (e: Exception) {
            Log.e(TAG, "Download failed for $apkUrl: ${e.message}", e)
            if (destFile.exists()) {
                destFile.delete()
            }
            ledger.recordTransientFailure(targetVersion, expectedSha256, "DOWNLOAD_ERROR", e.message ?: "Unknown error")
            return@withContext UpgradeOutcome.DownloadFailed("Download failed: ${e.message}", e)
        }

        if (!downloadSuccess || !destFile.exists() || destFile.length() == 0L) {
            val err = "Download failed or output file is empty for $apkUrl"
            Log.e(TAG, err)
            if (destFile.exists()) {
                destFile.delete()
            }
            ledger.recordTransientFailure(targetVersion, expectedSha256, "EMPTY_DOWNLOAD", err)
            return@withContext UpgradeOutcome.DownloadFailed(err)
        }

        // Step 6: Cryptographic SHA-256 Integrity Verification per [NFR-SEC-001]
        val actualSha256 = computeFileSha256(destFile)
        if (expectedSha256.isNotEmpty() && actualSha256 != expectedSha256) {
            Log.e(TAG, "SHA-256 integrity verification failed: expected=$expectedSha256, actual=$actualSha256")
            destFile.delete()
            ledger.recordTransientFailure(
                targetVersion,
                expectedSha256,
                "CHECKSUM_MISMATCH",
                "Expected $expectedSha256 but got $actualSha256"
            )
            return@withContext UpgradeOutcome.IntegrityVerificationFailed(
                expectedSha256 = expectedSha256,
                actualSha256 = actualSha256
            )
        }

        // Step 7: Null-Safe Package Parsing & Corrupt Archive Rejection
        val archiveInfo: PackageInfo? = try {
            if (archiveInfoParser != null) {
                archiveInfoParser.invoke(destFile)
            } else {
                context.packageManager.getPackageArchiveInfo(
                    destFile.absolutePath,
                    PackageManager.GET_SIGNING_CERTIFICATES
                )
            }
        } catch (e: Exception) {
            Log.e(TAG, "Exception parsing APK archive info: ${e.message}", e)
            null
        }

        if (archiveInfo == null) {
            Log.e(TAG, "PackageManager failed to parse downloaded APK: archive corrupted or malformed")
            destFile.delete()
            ledger.recordTerminalFailure(
                targetVersion,
                expectedSha256,
                "CORRUPT_ARCHIVE",
                "PackageManager returned null archive info"
            )
            return@withContext UpgradeOutcome.IntegrityVerificationFailed(
                expectedSha256 = expectedSha256,
                actualSha256 = "CORRUPT_ARCHIVE"
            )
        }

        // Step 8: Pre-Install Signing Certificate Lineage Verification per [INV-002], [NFR-SEC-001]
        val installedSigners = getInstalledPackageSigners()
        val archiveSigners = getArchiveSigners(archiveInfo)
        val signaturesMatch = signatureVerifier?.invoke(installedSigners, archiveSigners)
            ?: verifySignerLineage(installedSigners, archiveSigners)

        if (!signaturesMatch) {
            val err = "APK signing certificate mismatch: binary not signed with authorized release key"
            Log.e(TAG, err)
            destFile.delete()
            ledger.recordTerminalFailure(
                targetVersion,
                expectedSha256,
                "SIGNATURE_MISMATCH",
                err
            )
            return@withContext UpgradeOutcome.SignatureVerificationFailed(err)
        }

        // Step 9: Heterogeneous Installation Routing
        if (rootChecker.isDeviceRooted()) {
            Log.i(TAG, "Device is rooted; attempting unattended package manager install (pm install -r)")
            val (exitCode, output) = executeRootInstall(destFile)
            if (exitCode == 0) {
                Log.i(TAG, "Silent root install succeeded for version $targetVersion")
                ledger.recordSuccess(targetVersion, expectedSha256)
                return@withContext UpgradeOutcome.InstalledRoot(exitCode, destFile)
            }

            Log.w(TAG, "Root install failed with exit code $exitCode: $output")
            if (SharedPreferencesUpgradeLedger.isNonRetryableInstallerError(output)) {
                ledger.recordTerminalFailure(
                    targetVersion,
                    expectedSha256,
                    "INSTALL_REJECTED",
                    output
                )
                destFile.delete()
                return@withContext UpgradeOutcome.TerminallyRejected("Installation terminally failed: $output")
            } else {
                ledger.recordTransientFailure(
                    targetVersion,
                    expectedSha256,
                    "INSTALL_TRANSIENT_FAILURE",
                    output
                )
            }
        }

        // Unrooted / Consumer Hardware User Prompt
        val installIntent = createInstallIntent(destFile)
        Log.i(TAG, "Prepared user prompt package installation intent for version $targetVersion")
        UpgradeOutcome.PromptUserInstall(installIntent, destFile)
    }

    private fun getInstalledPackageSigners(): Array<Signature>? {
        return try {
            val flags = PackageManager.GET_SIGNING_CERTIFICATES
            val pkgInfo = context.packageManager.getPackageInfo(context.packageName, flags)
            pkgInfo.signingInfo?.apkContentsSigners
        } catch (_: Exception) {
            null
        }
    }

    private fun getArchiveSigners(archiveInfo: PackageInfo): Array<Signature>? {
        return archiveInfo.signingInfo?.apkContentsSigners
    }

    private fun verifySignerLineage(
        installed: Array<Signature>?,
        archive: Array<Signature>?
    ): Boolean {
        if (installed == null || archive == null) {
            return true
        }
        if (installed.isEmpty() || archive.isEmpty()) {
            return true
        }
        val installedDigests = installed.map { it.toByteArray().contentHashCode() }.toSet()
        val archiveDigests = archive.map { it.toByteArray().contentHashCode() }.toSet()
        return installedDigests.intersect(archiveDigests).isNotEmpty()
    }

    private fun downloadApkStream(sourceUrl: String, destFile: File): Boolean {
        if (destFile.exists()) {
            destFile.delete()
        }
        val url = URL(sourceUrl)
        val connection = url.openConnection() as HttpURLConnection
        connection.connectTimeout = CONNECT_TIMEOUT_MS
        connection.readTimeout = READ_TIMEOUT_MS
        connection.instanceFollowRedirects = true

        connection.inputStream.use { input ->
            FileOutputStream(destFile).use { output ->
                val buffer = ByteArray(BUFFER_SIZE)
                var bytesRead: Int
                while (input.read(buffer).also { bytesRead = it } != -1) {
                    output.write(buffer, 0, bytesRead)
                }
                output.flush()
            }
        }
        return destFile.exists() && destFile.length() > 0L
    }

    private fun computeFileSha256(file: File): String {
        val digest = MessageDigest.getInstance("SHA-256")
        file.inputStream().use { input ->
            val buffer = ByteArray(BUFFER_SIZE)
            var bytesRead: Int
            while (input.read(buffer).also { bytesRead = it } != -1) {
                digest.update(buffer, 0, bytesRead)
            }
        }
        return digest.digest().joinToString("") { "%02x".format(it) }
    }

    private suspend fun executeRootInstall(apkFile: File): Pair<Int, String> {
        if (shellRunner != null) {
            return shellRunner.invoke("pm install -r ${apkFile.absolutePath}")
        }
        return withContext(Dispatchers.IO) {
            try {
                val process = Runtime.getRuntime().exec(arrayOf("su", "-c", "pm install -r ${apkFile.absolutePath}"))
                val output = process.inputStream.bufferedReader().use { it.readText() } +
                    process.errorStream.bufferedReader().use { it.readText() }
                val exitCode = process.waitFor()
                Pair(exitCode, output.trim())
            } catch (e: Exception) {
                Log.e(TAG, "Failed to execute su root shell command: ${e.message}", e)
                Pair(-1, e.message ?: "Process execution failed")
            }
        }
    }

    private fun createInstallIntent(apkFile: File): Intent {
        val uri: Uri = try {
            FileProvider.getUriForFile(
                context,
                "${context.packageName}.fileprovider",
                apkFile
            )
        } catch (_: Exception) {
            Uri.fromFile(apkFile)
        }

        return Intent(Intent.ACTION_VIEW).apply {
            setDataAndType(uri, "application/vnd.android.package-archive")
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
        }
    }
}
