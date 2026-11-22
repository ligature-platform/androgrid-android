package com.androgrid.worker.upgrade

import android.content.Context
import com.androgrid.v1.UpgradeInstallStatus
import com.google.common.truth.Truth.assertThat
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.annotation.Config

/**
 * Unit and Robolectric tests for [UpgradeLedger].
 * Validates terminal failure classification, exponential backoff, attempt capping,
 * and loop prevention ([ANTI-003], [NFR-POW-001]).
 *
 * Traces to: [REQ-OP-001], [REQ-OP-002], [ANTI-003], [NFR-POW-001]
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class UpgradeLedgerTest {

    private lateinit var context: Context

    @Before
    fun setUp() {
        context = RuntimeEnvironment.getApplication()
        val prefs = context.getSharedPreferences(
            SharedPreferencesUpgradeLedger.PREFS_NAME,
            Context.MODE_PRIVATE
        )
        prefs.edit().clear().commit()
    }

    @Test
    fun testTerminalFailure_permanentlySuppressesSubsequentAttempts() {
        var currentTime = 1_000_000L
        val ledger = SharedPreferencesUpgradeLedger(context) { currentTime }

        val version = "0.3.0"
        val sha = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"

        assertThat(ledger.shouldAttempt(version, sha)).isTrue()

        ledger.recordTerminalFailure(
            targetVersion = version,
            apkSha256 = sha,
            errorCode = "INSTALL_FAILED_VERSION_DOWNGRADE",
            errorMessage = "Downgrade not permitted"
        )

        assertThat(ledger.shouldAttempt(version, sha)).isFalse()

        // Even after 100 days, terminal failure must remain suppressed
        currentTime += 100L * 24 * 3600 * 1000
        assertThat(ledger.shouldAttempt(version, sha)).isFalse()

        val outcome = ledger.getLastOutcome()
        assertThat(outcome).isNotNull()
        assertThat(outcome?.status).isEqualTo(UpgradeInstallStatus.UPGRADE_INSTALL_STATUS_TERMINALLY_REJECTED)
        assertThat(outcome?.errorCode).isEqualTo("INSTALL_FAILED_VERSION_DOWNGRADE")
    }

    @Test
    fun testTransientFailure_enforcesExponentialBackoff_andEscalatesAfterMaxAttempts() {
        var currentTime = 1_000_000L
        val ledger = SharedPreferencesUpgradeLedger(context) { currentTime }

        val version = "0.3.0"
        val sha = "1111222233334444555566667777888899990000aaaabbbbccccddddeeeeffff"

        // Attempt 1 fails transiently (backoff is 60s)
        ledger.recordAttempt(version, sha)
        ledger.recordTransientFailure(version, sha, "TIMEOUT", "Connection reset")
        assertThat(ledger.shouldAttempt(version, sha)).isFalse()

        // Advance 30s: still suppressed
        currentTime += 30_000L
        assertThat(ledger.shouldAttempt(version, sha)).isFalse()

        // Advance past 60s: eligible again
        currentTime += 35_000L
        assertThat(ledger.shouldAttempt(version, sha)).isTrue()

        // Attempt 2 fails transiently (backoff is 300s)
        ledger.recordAttempt(version, sha)
        ledger.recordTransientFailure(version, sha, "TIMEOUT", "Connection reset")
        assertThat(ledger.shouldAttempt(version, sha)).isFalse()

        // Advance 200s: still suppressed
        currentTime += 200_000L
        assertThat(ledger.shouldAttempt(version, sha)).isFalse()

        // Advance past 300s: eligible again
        currentTime += 110_000L
        assertThat(ledger.shouldAttempt(version, sha)).isTrue()

        // Attempt 3 fails: reaches MAX_TRANSIENT_ATTEMPTS (3) and escalates to TERMINALLY_REJECTED
        ledger.recordAttempt(version, sha)
        ledger.recordTransientFailure(version, sha, "TIMEOUT", "Connection reset")
        assertThat(ledger.shouldAttempt(version, sha)).isFalse()

        val outcome = ledger.getLastOutcome()
        assertThat(outcome?.status).isEqualTo(UpgradeInstallStatus.UPGRADE_INSTALL_STATUS_TERMINALLY_REJECTED)
        assertThat(outcome?.attemptCount).isEqualTo(3)

        // Advance 1 year: permanently terminally rejected
        currentTime += 365L * 24 * 3600 * 1000
        assertThat(ledger.shouldAttempt(version, sha)).isFalse()
    }

    @Test
    fun testSuccess_suppressesFurtherAttemptsAndRecordsOutcome() {
        val ledger = SharedPreferencesUpgradeLedger(context)
        val version = "0.2.0"
        val sha = "222233334444555566667777888899990000aaaabbbbccccddddeeeeffff1111"

        ledger.recordAttempt(version, sha)
        ledger.recordSuccess(version, sha)

        assertThat(ledger.shouldAttempt(version, sha)).isFalse()

        val outcome = ledger.getLastOutcome()
        assertThat(outcome).isNotNull()
        assertThat(outcome?.status).isEqualTo(UpgradeInstallStatus.UPGRADE_INSTALL_STATUS_SUCCEEDED)
        assertThat(outcome?.targetVersion).isEqualTo(version)
    }

    @Test
    fun testNonRetryableErrorIdentification() {
        assertThat(
            SharedPreferencesUpgradeLedger.isNonRetryableInstallerError(
                "Failure [INSTALL_FAILED_VERSION_DOWNGRADE]"
            )
        ).isTrue()
        assertThat(
            SharedPreferencesUpgradeLedger.isNonRetryableInstallerError(
                "Failure [INSTALL_FAILED_UPDATE_INCOMPATIBLE: Package signatures do not match]"
            )
        ).isTrue()
        assertThat(
            SharedPreferencesUpgradeLedger.isNonRetryableInstallerError(
                "SIGNATURE_MISMATCH: untrusted certificate"
            )
        ).isTrue()
        assertThat(
            SharedPreferencesUpgradeLedger.isNonRetryableInstallerError(
                "Connection timed out"
            )
        ).isFalse()
    }

    @Test
    fun testPendingUpgradeReconciliation_andClearLastOutcome() {
        val ledger = SharedPreferencesUpgradeLedger(context)
        val targetVersion = "0.4.0"
        val sha = "aabbccdd11223344aabbccdd11223344aabbccdd11223344aabbccdd11223344"

        ledger.recordPendingUpgrade(targetVersion, sha)

        // Version mismatch during startup check
        assertThat(ledger.checkPendingUpgradeOnStartup("0.3.9")).isFalse()
        assertThat(ledger.getLastOutcome()).isNull()

        // Version match during startup check
        assertThat(ledger.checkPendingUpgradeOnStartup("0.4.0")).isTrue()

        val outcome = ledger.getLastOutcome()
        assertThat(outcome).isNotNull()
        assertThat(outcome?.status).isEqualTo(UpgradeInstallStatus.UPGRADE_INSTALL_STATUS_SUCCEEDED)
        assertThat(outcome?.targetVersion).isEqualTo(targetVersion)
        assertThat(outcome?.apkSha256).isEqualTo(sha)

        // Subsequent check returns false since pending was cleared
        assertThat(ledger.checkPendingUpgradeOnStartup("0.4.0")).isFalse()

        // Clear last outcome
        ledger.clearLastOutcome()
        assertThat(ledger.getLastOutcome()).isNull()
    }

    @Test
    fun testGetRemainingBackoffMs() {
        var currentTime = 1_000_000L
        val ledger = SharedPreferencesUpgradeLedger(context) { currentTime }
        val version = "0.2.0"
        val sha = "33334444555566667777888899990000aaaabbbbccccddddeeeeffff11112222"

        // Untried version has 0 remaining backoff
        assertThat(ledger.getRemainingBackoffMs(version, sha)).isEqualTo(0L)

        // Record a transient failure (first backoff is 60s)
        ledger.recordAttempt(version, sha)
        ledger.recordTransientFailure(version, sha, "TIMEOUT", "Download timed out")

        // Should have active positive backoff ms
        val remaining = ledger.getRemainingBackoffMs(version, sha)
        assertThat(remaining).isEqualTo(60_000L)

        // Advance 20s
        currentTime += 20_000L
        assertThat(ledger.getRemainingBackoffMs(version, sha)).isEqualTo(40_000L)

        // Advance past 60s
        currentTime += 45_000L
        assertThat(ledger.getRemainingBackoffMs(version, sha)).isEqualTo(0L)

        // Terminal failure returns -1
        val termSha = "4444555566667777888899990000aaaabbbbccccddddeeeeffff111122223333"
        ledger.recordAttempt(version, termSha)
        ledger.recordTerminalFailure(version, termSha, "INSTALL_FAILED_VERSION_DOWNGRADE", "Failure")
        assertThat(ledger.getRemainingBackoffMs(version, termSha)).isEqualTo(-1L)
    }

    @Test
    fun testAwaitingUserConfirmation_suppressesRedownloadsWithoutReportingFailure() {
        val ledger = SharedPreferencesUpgradeLedger(context)
        val version = "0.5.0"
        val sha = "555566667777888899990000aaaabbbbccccddddeeeeffff1111222233334444"

        ledger.recordAttempt(version, sha)
        ledger.recordAwaitingUserConfirmation(version, sha)

        // shouldAttempt must return false, getRemainingBackoffMs returns -1L
        assertThat(ledger.shouldAttempt(version, sha)).isFalse()
        assertThat(ledger.getRemainingBackoffMs(version, sha)).isEqualTo(-1L)

        // Crucially, getLastOutcome must NOT return a failure outcome
        assertThat(ledger.getLastOutcome()).isNull()
    }
}
