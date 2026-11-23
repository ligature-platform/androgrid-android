package com.androgrid.worker.upgrade

import android.content.Context
import android.content.Intent
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.content.pm.Signature
import android.net.Uri
import android.os.PowerManager
import android.util.Log
import androidx.core.content.FileProvider
import androidx.core.content.pm.PackageInfoCompat
import com.androgrid.v1.LastUpgradeOutcome
import com.androgrid.v1.NodeUpgradeDirective
import com.androgrid.v1.UpgradeNetworkPolicy
import com.androgrid.worker.capability.RootChecker
import com.androgrid.worker.capability.StandardRootChecker
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import okhttp3.OkHttpClient
import okhttp3.Request
import java.io.File
import java.io.FileOutputStream
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
     * Directive aborted without network activity because previous attempt terminally failed.
     */
    data class TerminallyRejected(val reason: String) : UpgradeOutcome()

    /**
     * Directive execution is suppressed because exponential backoff delay has not elapsed.
     */
    data class BackoffSuppressed(val remainingBackoffMs: Long) : UpgradeOutcome()

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
     * Current installed application version name.
     */
    val currentVersion: String

    /**
     * Returns the structured outcome of the most recent upgrade attempt to report to the orchestrator.
     */
    fun getLastOutcome(): LastUpgradeOutcome?

    /**
     * Clears the cached last upgrade outcome once acknowledged by the orchestrator.
     */
    fun clearLastOutcome()

    /**
     * Verifies whether the application is exempt from battery optimizations for unattended execution.
     */
    fun isBatteryOptimizationIgnored(): Boolean = false
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
            packageInfo.versionName ?: "0.0.1-alpha.5"
        } catch (_: Exception) {
            "0.0.1-alpha.5"
        }
    },
    private val downloadClient: (suspend (url: String, destFile: File) -> Boolean)? = null,
    private val shellRunner: (suspend (command: String) -> Pair<Int, String>)? = null,
    private val ledger: UpgradeLedger = SharedPreferencesUpgradeLedger(context),
    private val signatureVerifier: ((installed: Array<Signature>?, archive: Array<Signature>?) -> Boolean)? = null,
    private val archiveInfoParser: ((File) -> PackageInfo?)? = null,
    private val mtlsClientProvider: (() -> okhttp3.OkHttpClient?)? = null,
    private val baseUrlProvider: ((isWifi: Boolean) -> String?)? = null
) : UpgradeManager {

    init {
        ledger.checkPendingUpgradeOnStartup(currentVersionProvider())
    }

    private val upgradeMutex = Mutex()

    companion object {
        private const val TAG: String = "DefaultUpgradeManager"
        private const val BUFFER_SIZE: Int = 64 * 1024
        private const val CONNECT_TIMEOUT_MS: Int = 15_000
        private const val READ_TIMEOUT_MS: Int = 60_000
        private val SHA256_REGEX = Regex("^[0-9a-f]{64}$")
    }

    override val currentVersion: String get() = currentVersionProvider().trim()

    override fun getLastOutcome(): LastUpgradeOutcome? = ledger.getLastOutcome()

    override fun clearLastOutcome() {
        ledger.clearLastOutcome()
    }

    override suspend fun processUpgradeDirective(
        directive: NodeUpgradeDirective,
        isMetered: Boolean,
        isWifi: Boolean
    ): UpgradeOutcome = upgradeMutex.withLock {
        withContext(Dispatchers.IO) {
            val targetVersion = directive.targetVersion.trim()
            val currentVersion = currentVersionProvider().trim()

            // Step 1: Idempotency & Version Threshold Check
            if (targetVersion.isEmpty() || targetVersion == currentVersion) {
                Log.d(TAG, "Worker is up to date (version=$currentVersion, target=$targetVersion)")
                return@withContext UpgradeOutcome.UpToDate(currentVersion)
            }

            // Step 2: Loop Termination Check via UpgradeLedger
            val expectedSha256 = directive.apkSha256.trim().lowercase()
            val remainingBackoffMs = ledger.getRemainingBackoffMs(targetVersion, expectedSha256)
            if (remainingBackoffMs < 0L) {
                val reason = "Directive for version $targetVersion (sha=$expectedSha256) is terminally rejected or exceeded max attempts"
                Log.w(TAG, reason)
                return@withContext UpgradeOutcome.TerminallyRejected(reason)
            } else if (remainingBackoffMs > 0L) {
                val reason = "Directive for version $targetVersion (sha=$expectedSha256) suppressed by backoff ($remainingBackoffMs ms remaining)"
                Log.i(TAG, reason)
                return@withContext UpgradeOutcome.BackoffSuppressed(remainingBackoffMs)
            }

            // Step 3: Network Guard Enforcement per [ANTI-003], [NFR-POW-001]
            val isCellularOrMetered = isMetered || !isWifi
            val policy = directive.networkPolicy
            if (isCellularOrMetered && policy != UpgradeNetworkPolicy.UPGRADE_NETWORK_POLICY_ALLOW_CELLULAR) {
                val reason = "OTA APK download rejected: transport is metered cellular and directive policy mandates Wi-Fi only per [ANTI-003]"
                Log.w(TAG, reason)
                return@withContext UpgradeOutcome.NetworkPolicyViolation(reason)
            }

            // Step 4: APK URL validation and relative path resolution
            val rawApkUrl = directive.apkUrl.trim()
            if (rawApkUrl.isEmpty()) {
                val err = "OTA APK download rejected: missing or empty apk_url in directive"
                Log.e(TAG, err)
                ledger.recordTransientFailure(targetVersion, expectedSha256, "EMPTY_URL", err)
                return@withContext UpgradeOutcome.DownloadFailed(err)
            }

            val apkUrl = if (rawApkUrl.startsWith("/")) {
                val base = baseUrlProvider?.invoke(isWifi)?.trimEnd('/') ?: ""
                if (base.isEmpty()) {
                    rawApkUrl
                } else {
                    "$base$rawApkUrl"
                }
            } else {
                rawApkUrl
            }

            // Step 5: Cryptographic SHA-256 Format Verification per [NFR-SEC-001]
            if (!SHA256_REGEX.matches(expectedSha256)) {
                val err = "OTA APK download rejected: invalid 64-hex SHA-256 hash '$expectedSha256'"
                Log.e(TAG, err)
                ledger.recordTerminalFailure(targetVersion, expectedSha256, "INVALID_SHA256", err)
                return@withContext UpgradeOutcome.TerminallyRejected(err)
            }

            // Step 6: Secure Staging in cacheDir/ota
            val otaDir = File(context.cacheDir, "ota")
            if (!otaDir.exists()) {
                otaDir.mkdirs()
            }
            val destFile = File(otaDir, "${expectedSha256}.apk")
            val canonicalParent = destFile.canonicalFile.parentFile?.canonicalPath
            val canonicalOtaDir = otaDir.canonicalPath
            if (canonicalParent != canonicalOtaDir) {
                val err = "OTA staging path traversal detected: ${destFile.absolutePath}"
                Log.e(TAG, err)
                ledger.recordTerminalFailure(targetVersion, expectedSha256, "PATH_TRAVERSAL", err)
                return@withContext UpgradeOutcome.TerminallyRejected(err)
            }
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

            // Step 7.1: Package Name and Monotonic Version Verification
            if (archiveInfo.packageName.isNullOrEmpty() || archiveInfo.packageName != context.packageName) {
                val err = "APK package name mismatch: expected ${context.packageName} but got ${archiveInfo.packageName}"
                Log.e(TAG, err)
                destFile.delete()
                ledger.recordTerminalFailure(targetVersion, expectedSha256, "PACKAGE_NAME_MISMATCH", err)
                return@withContext UpgradeOutcome.TerminallyRejected(err)
            }

            val installedPackageInfo = try {
                context.packageManager.getPackageInfo(context.packageName, 0)
            } catch (_: Exception) {
                null
            }
            val installedVersionCode = installedPackageInfo?.let {
                PackageInfoCompat.getLongVersionCode(it)
            } ?: 0L
            val archiveVersionCode = PackageInfoCompat.getLongVersionCode(archiveInfo)

            if (archiveVersionCode <= installedVersionCode) {
                val err = "APK version code downgrade or equal rejected: installed=$installedVersionCode, archive=$archiveVersionCode"
                Log.e(TAG, err)
                destFile.delete()
                ledger.recordTerminalFailure(targetVersion, expectedSha256, "VERSION_CODE_DOWNGRADE", err)
                return@withContext UpgradeOutcome.TerminallyRejected(err)
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
                val (exitCode, output) = executeRootInstall(destFile, targetVersion, expectedSha256)
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
            ledger.recordAwaitingUserConfirmation(targetVersion, expectedSha256)
            ledger.recordPendingUpgrade(targetVersion, expectedSha256)
            UpgradeOutcome.PromptUserInstall(installIntent, destFile)
        }
    }

    override fun isBatteryOptimizationIgnored(): Boolean {
        val powerManager = context.getSystemService(Context.POWER_SERVICE) as? PowerManager
        return powerManager?.isIgnoringBatteryOptimizations(context.packageName) ?: false
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
        val signingInfo = archiveInfo.signingInfo ?: return null
        val signers = mutableListOf<Signature>()
        signingInfo.apkContentsSigners?.let { signers.addAll(it) }
        signingInfo.signingCertificateHistory?.let { signers.addAll(it) }
        return if (signers.isNotEmpty()) signers.toTypedArray() else null
    }

    private fun computeCertSha256(signature: Signature): String {
        val digest = MessageDigest.getInstance("SHA-256")
        return digest.digest(signature.toByteArray()).joinToString("") { "%02x".format(it) }
    }

    private fun verifySignerLineage(
        installed: Array<Signature>?,
        archive: Array<Signature>?
    ): Boolean {
        if (installed.isNullOrEmpty() || archive.isNullOrEmpty()) {
            return false
        }
        val installedDigests = installed.map { computeCertSha256(it) }.toSet()
        val archiveDigests = archive.map { computeCertSha256(it) }.toSet()
        return installedDigests.intersect(archiveDigests).isNotEmpty()
    }

    private fun downloadApkStream(sourceUrl: String, destFile: File): Boolean {
        if (destFile.exists()) {
            destFile.delete()
        }
        val baseClient = mtlsClientProvider?.invoke() ?: OkHttpClient()
        val client = baseClient.newBuilder()
            .followRedirects(false)
            .followSslRedirects(false)
            .connectTimeout(CONNECT_TIMEOUT_MS.toLong(), java.util.concurrent.TimeUnit.MILLISECONDS)
            .readTimeout(READ_TIMEOUT_MS.toLong(), java.util.concurrent.TimeUnit.MILLISECONDS)
            .callTimeout(10, java.util.concurrent.TimeUnit.MINUTES)
            .build()

        val request = Request.Builder().url(sourceUrl).get().build()
        client.newCall(request).execute().use { response ->
            if (!response.isSuccessful) {
                throw java.io.IOException("HTTP ${response.code} downloading OTA APK from $sourceUrl")
            }
            val body = response.body ?: throw java.io.IOException("Empty HTTP body from $sourceUrl")
            val maxBytes = 100L * 1024L * 1024L // 100 MB ceiling
            var totalRead = 0L
            body.byteStream().use { input ->
                FileOutputStream(destFile).use { output ->
                    val buffer = ByteArray(BUFFER_SIZE)
                    var bytesRead: Int
                    while (input.read(buffer).also { bytesRead = it } != -1) {
                        totalRead += bytesRead
                        if (totalRead > maxBytes) {
                            throw java.io.IOException("Downloaded APK exceeded maximum size limit of 100 MB ($totalRead bytes)")
                        }
                        output.write(buffer, 0, bytesRead)
                    }
                    output.flush()
                }
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

    private suspend fun executeRootInstall(
        apkFile: File,
        targetVersion: String,
        expectedSha256: String
    ): Pair<Int, String> {
        val size = apkFile.length()
        val cmd = "pm install -r -S $size"
        if (shellRunner != null) {
            ledger.recordPendingUpgrade(targetVersion, expectedSha256)
            return shellRunner.invoke(cmd)
        }
        return withContext(Dispatchers.IO) {
            try {
                ledger.recordPendingUpgrade(targetVersion, expectedSha256)
                val pb = ProcessBuilder("su", "-c", cmd)
                pb.redirectErrorStream(true)
                val process = pb.start()

                // Concurrently read stdout/stderr to prevent OS pipe buffer deadlocks
                val outputDeferred = async(Dispatchers.IO) {
                    process.inputStream.bufferedReader().use { it.readText() }
                }

                // Stream APK bytes via stdin concurrently to avoid blocking timeout if su hangs
                val stdinDeferred = async(Dispatchers.IO) {
                    apkFile.inputStream().use { input ->
                        process.outputStream.use { output ->
                            input.copyTo(output)
                            output.flush()
                        }
                    }
                }

                // Wait with 120-second timeout protecting both stdin streaming and output reading
                val finished = withTimeoutOrNull(120_000L) {
                    stdinDeferred.await()
                    val out = outputDeferred.await()
                    val exit = process.waitFor()
                    Pair(exit, out.trim())
                }

                if (finished == null) {
                    process.destroyForcibly()
                    Log.e(TAG, "Root install timed out after 120 seconds")
                    Pair(-1, "Installation timed out after 120s")
                } else {
                    val (exitCode, output) = finished
                    val isSuccess = exitCode == 0 && output.contains("Success") && !output.contains("Failure")
                    if (isSuccess) {
                        Pair(0, output)
                    } else {
                        Pair(if (exitCode == 0) -1 else exitCode, output)
                    }
                }
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
