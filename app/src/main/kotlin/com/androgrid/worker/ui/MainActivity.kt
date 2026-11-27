package com.androgrid.worker.ui

import android.Manifest
import android.app.AlertDialog
import android.app.Application
import android.content.Context
import android.content.Intent
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.graphics.Color
import android.graphics.Typeface
import android.net.ConnectivityManager
import android.os.Build
import android.os.Bundle
import android.text.InputType
import android.view.Gravity
import android.view.View
import android.widget.Button
import android.widget.EditText
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.result.contract.ActivityResultContracts
import androidx.core.content.ContextCompat
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.lifecycleScope
import androidx.lifecycle.repeatOnLifecycle
import com.androgrid.worker.AndroGridApplication
import com.androgrid.worker.telemetry.AndroidDeviceThermalStatusListener
import com.androgrid.worker.telemetry.InMemoryTaskLedgerRepository
import com.androgrid.worker.service.WorkerParticipationController
import com.androgrid.worker.R
import com.androgrid.worker.automation.PkiCredentialLoader
import com.androgrid.worker.automation.TestAutomationReceiver
import com.androgrid.worker.capability.AndroidBatteryStatusProvider
import com.androgrid.worker.capability.AndroidSystemInfoProvider
import com.androgrid.worker.capability.DeviceCapabilityProvider
import com.androgrid.worker.capability.NodeIdProvider
import com.androgrid.worker.capability.StandardRootChecker
import com.androgrid.worker.enrollment.EnrollmentCoordinator
import com.androgrid.worker.enrollment.EnrollmentPayload
import com.androgrid.worker.enrollment.EnrollmentPayloadParser
import com.androgrid.worker.enrollment.EnrollmentResult
import com.androgrid.worker.network.ClusterSettingsRepository
import com.androgrid.worker.network.DiscoveredCluster
import com.androgrid.worker.network.NetworkRoute
import com.androgrid.worker.network.NetworkRouteMonitor
import com.androgrid.worker.network.NsdClusterDiscoveryManager
import com.androgrid.worker.network.PreFlightProbeResult
import com.androgrid.worker.network.SharedPreferencesClusterSettingsRepository
import com.androgrid.worker.network.SocketReachabilityProber
import com.androgrid.worker.service.AndroidServiceController
import com.androgrid.worker.service.AndroidWorkScheduler
import com.androgrid.worker.service.WorkerLifecycleCoordinator
import kotlinx.coroutines.launch
import java.io.File

/**
 * Interactive Worker Dashboard Activity providing operator observability and control.
 * Handles Android 13+ POST_NOTIFICATIONS runtime permissions and displays live telemetry.
 *
 * Traces to: Section 6.1, [REQ-VER-001], [REQ-VER-002], [INV-002]
 */
class MainActivity : ComponentActivity() {

    internal var settingsRepository: ClusterSettingsRepository? = null

    private lateinit var viewModel: WorkerDashboardViewModel
    private var participationController: WorkerParticipationController? = null

    private lateinit var statusBannerView: TextView
    internal lateinit var discoveryCardView: LinearLayout
    internal lateinit var discoveryHeaderView: TextView
    internal lateinit var discoveryDetailsView: TextView
    internal lateinit var connectAndPairButton: Button
    private lateinit var nodeIdView: TextView
    private lateinit var hardwareView: TextView
    private lateinit var osView: TextView
    private lateinit var sandboxView: TextView
    private lateinit var batteryView: TextView
    private lateinit var thermalBadgeView: TextView
    private lateinit var telemetryView: TextView
    private lateinit var recentLedgerView: TextView
    private lateinit var toggleButton: Button
    private lateinit var scanEnrollmentButton: Button
    internal lateinit var manualEndpointButton: Button
    private lateinit var settingsButton: Button

    private val qrScanLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == RESULT_OK) {
            val payload = result.data?.getStringExtra(QrScannerActivity.EXTRA_SCANNED_PAYLOAD)
            if (!payload.isNullOrBlank()) {
                handleScannedQrPayload(payload)
            }
        }
    }

    private val notificationPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) { _ ->
        // Notification permission evaluated
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        initDependencies()
        setupContentView()
        requestNotificationPermission()
        observeState()
        handleAutomationIntent(intent)
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        handleAutomationIntent(intent)
    }

    internal fun getDashboardViewModel(): WorkerDashboardViewModel = viewModel

    private fun handleAutomationIntent(intent: Intent?) {
        if (intent == null) return
        val isDebuggable = (applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE) != 0
        if (!isDebuggable) return

        val repo = settingsRepository ?: SharedPreferencesClusterSettingsRepository.getInstance(applicationContext)

        when (intent.action) {
            TestAutomationReceiver.ACTION_CONFIGURE_ENDPOINT -> {
                val current = repo.getSettings()
                val wifiHost = intent.getStringExtra(TestAutomationReceiver.EXTRA_WIFI_HOST) ?: current.wifiHost
                val wifiPort = intent.getIntExtra(TestAutomationReceiver.EXTRA_WIFI_PORT, current.wifiPort)
                val cellularHost = intent.getStringExtra(TestAutomationReceiver.EXTRA_CELLULAR_HOST) ?: current.cellularHost
                val cellularPort = intent.getIntExtra(TestAutomationReceiver.EXTRA_CELLULAR_PORT, current.cellularPort)

                val caCertPem = intent.getStringExtra(TestAutomationReceiver.EXTRA_CA_CERT_PEM) ?: current.caCertPem
                val clientCertPem = intent.getStringExtra(TestAutomationReceiver.EXTRA_CLIENT_CERT_PEM) ?: current.clientCertPem
                val clientKeyPem = intent.getStringExtra(TestAutomationReceiver.EXTRA_CLIENT_KEY_PEM) ?: current.clientKeyPem

                repo.updateSettings(
                    current.copy(
                        wifiHost = wifiHost,
                        wifiPort = wifiPort,
                        cellularHost = cellularHost,
                        cellularPort = cellularPort
                    )
                )

                val pkiDirExtra = intent.getStringExtra(TestAutomationReceiver.EXTRA_PKI_DIR)
                val caPath = intent.getStringExtra(TestAutomationReceiver.EXTRA_CA_CERT_PATH)
                val certPath = intent.getStringExtra(TestAutomationReceiver.EXTRA_CLIENT_CERT_PATH)
                val keyPath = intent.getStringExtra(TestAutomationReceiver.EXTRA_CLIENT_KEY_PATH)

                if (pkiDirExtra != null) {
                    PkiCredentialLoader.loadFromDirectory(File(pkiDirExtra), repo)
                } else if (caPath != null && certPath != null && keyPath != null) {
                    PkiCredentialLoader.loadFromPaths(caPath, certPath, keyPath, repo)
                } else if (caCertPem.isNotBlank() && clientCertPem.isNotBlank() && clientKeyPem.isNotBlank()) {
                    repo.updateCertificates(caCertPem, clientCertPem, clientKeyPem)
                } else {
                    PkiCredentialLoader.syncCanonicalDirectoryIfPresent(applicationContext, repo)
                }

                val autoStart = intent.getBooleanExtra(TestAutomationReceiver.EXTRA_AUTO_START, false)
                if (autoStart) {
                    viewModel.startParticipation()
                }
            }
            TestAutomationReceiver.ACTION_START_PARTICIPATION -> {
                viewModel.startParticipation()
            }
            TestAutomationReceiver.ACTION_STOP_PARTICIPATION -> {
                viewModel.stopParticipation()
            }
        }
    }

    internal fun handleScannedQrPayload(rawContent: String) {
        lifecycleScope.launch {
            try {
                val payload = EnrollmentPayloadParser.parse(rawContent)
                val (host, port) = payload.parseEndpoint()

                // Non-blocking pre-flight reachability check [REQ-OP-001], Gate L-02
                val probeResult = SocketReachabilityProber.probe(host, port, timeoutMs = 2500)
                if (probeResult is PreFlightProbeResult.Unreachable) {
                    AlertDialog.Builder(this@MainActivity)
                        .setTitle("Cluster Pre-Flight Check Failed")
                        .setMessage(
                            "Target: $host:$port\n\n" +
                            "${probeResult.message}\n\n" +
                            "Actionable Guidance:\n" +
                            "${probeResult.actionableAdvice}\n\n" +
                            "Do you wish to proceed with enrollment anyway?"
                        )
                        .setPositiveButton("Proceed") { _, _ ->
                            executeEnrollmentPayload(payload)
                        }
                        .setNegativeButton("Cancel", null)
                        .show()
                    return@launch
                }

                executeEnrollmentPayload(payload)
            } catch (e: Exception) {
                Toast.makeText(this@MainActivity, "Invalid QR payload: ${e.message}", Toast.LENGTH_LONG).show()
            }
        }
    }

    internal fun executeEnrollmentPayload(payload: EnrollmentPayload) {
        lifecycleScope.launch {
            val repo = settingsRepository ?: SharedPreferencesClusterSettingsRepository.getInstance(applicationContext)
            try {
                val coordinator = EnrollmentCoordinator(settingsRepository = repo)
                val nodeId = viewModel.uiState.value.nodeId
                val result = coordinator.executeEnrollment(payload, nodeId)

                when (result) {
                    is EnrollmentResult.Success -> {
                        Toast.makeText(this@MainActivity, "Device enrolled in cluster! Starting compute participation...", Toast.LENGTH_LONG).show()
                        viewModel.startParticipation()
                    }
                    is EnrollmentResult.Failure -> {
                        Toast.makeText(this@MainActivity, "Enrollment failed: ${result.errorMessage}", Toast.LENGTH_LONG).show()
                    }
                }
            } catch (e: Exception) {
                Toast.makeText(this@MainActivity, "Enrollment error: ${e.message}", Toast.LENGTH_LONG).show()
            }
        }
    }

    override fun onStart() {
        super.onStart()
        participationController?.onUiStarted()
        viewModel.onUiStarted()
    }

    override fun onStop() {
        super.onStop()
        participationController?.onUiStopped()
        viewModel.onUiStopped()
    }

    private fun initDependencies() {
        val app = application as? AndroGridApplication
        participationController = app?.participationController
        viewModel = ViewModelProvider(
            this,
            WorkerDashboardViewModelFactory(application)
        )[WorkerDashboardViewModel::class.java]
    }

    private fun setupContentView() {
        val rootLayout = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(48, 64, 48, 64)
            setBackgroundColor(Color.parseColor("#121212"))
        }

        val logoView = ImageView(this).apply {
            setImageResource(R.drawable.androgrid_logo)
            contentDescription = "AndroGrid Logo"
            scaleType = ImageView.ScaleType.FIT_CENTER
        }
        val logoParams = LinearLayout.LayoutParams(
            (72 * resources.displayMetrics.density).toInt(),
            (72 * resources.displayMetrics.density).toInt()
        ).apply {
            gravity = Gravity.CENTER_HORIZONTAL
            bottomMargin = (16 * resources.displayMetrics.density).toInt()
        }
        rootLayout.addView(logoView, logoParams)

        val titleView = TextView(this).apply {
            text = "AndroGrid Edge Compute"
            textSize = 24f
            setTextColor(Color.WHITE)
            typeface = Typeface.DEFAULT_BOLD
            gravity = Gravity.CENTER_HORIZONTAL
        }
        rootLayout.addView(titleView)

        statusBannerView = TextView(this).apply {
            textSize = 15f
            setTextColor(Color.WHITE)
            setPadding(32, 24, 32, 24)
            gravity = Gravity.CENTER
            setBackgroundColor(Color.parseColor("#333333"))
        }
        val bannerParams = LinearLayout.LayoutParams(
            LinearLayout.LayoutParams.MATCH_PARENT,
            LinearLayout.LayoutParams.WRAP_CONTENT
        ).apply {
            setMargins(0, 32, 0, 32)
        }
        rootLayout.addView(statusBannerView, bannerParams)

        discoveryCardView = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(36, 28, 36, 28)
            setBackgroundColor(Color.parseColor("#1B3A24")) // Dark emerald container
            visibility = View.GONE
        }
        val cardParams = LinearLayout.LayoutParams(
            LinearLayout.LayoutParams.MATCH_PARENT,
            LinearLayout.LayoutParams.WRAP_CONTENT
        ).apply {
            setMargins(0, 0, 0, 32)
        }

        discoveryHeaderView = TextView(this).apply {
            text = "AndroGrid Cluster Detected"
            textSize = 16f
            setTextColor(Color.parseColor("#81C784"))
            typeface = Typeface.DEFAULT_BOLD
        }
        discoveryCardView.addView(discoveryHeaderView)

        discoveryDetailsView = TextView(this).apply {
            textSize = 14f
            setTextColor(Color.WHITE)
            setPadding(0, 8, 0, 16)
        }
        discoveryCardView.addView(discoveryDetailsView)

        connectAndPairButton = Button(this).apply {
            text = "Connect & Pair"
            textSize = 15f
            setBackgroundColor(Color.parseColor("#2E7D32"))
            setTextColor(Color.WHITE)
            setOnClickListener {
                val cluster = viewModel.uiState.value.discoveredClusters.firstOrNull() ?: return@setOnClickListener
                handleConnectAndPair(cluster)
            }
        }
        discoveryCardView.addView(connectAndPairButton)

        rootLayout.addView(discoveryCardView, cardParams)

        nodeIdView = createMetricView()
        hardwareView = createMetricView()
        osView = createMetricView()
        sandboxView = createMetricView()
        batteryView = createMetricView()
        thermalBadgeView = createMetricView()
        telemetryView = createMetricView()
        recentLedgerView = createMetricView()

        rootLayout.addView(nodeIdView)
        rootLayout.addView(hardwareView)
        rootLayout.addView(osView)
        rootLayout.addView(sandboxView)
        rootLayout.addView(batteryView)
        rootLayout.addView(thermalBadgeView)
        rootLayout.addView(telemetryView)
        rootLayout.addView(recentLedgerView)

        scanEnrollmentButton = Button(this).apply {
            text = "Scan Enrollment QR Code"
            textSize = 15f
            setBackgroundColor(Color.parseColor("#1B5E20")) // Deep green
            setTextColor(Color.WHITE)
            setOnClickListener {
                val intent = Intent(this@MainActivity, QrScannerActivity::class.java)
                qrScanLauncher.launch(intent)
            }
        }
        val scanParams = LinearLayout.LayoutParams(
            LinearLayout.LayoutParams.MATCH_PARENT,
            LinearLayout.LayoutParams.WRAP_CONTENT
        ).apply {
            setMargins(0, 36, 0, 0)
        }
        rootLayout.addView(scanEnrollmentButton, scanParams)

        manualEndpointButton = Button(this).apply {
            text = "Manual Endpoint Connect"
            textSize = 15f
            setBackgroundColor(Color.parseColor("#37474F")) // Slate gray
            setTextColor(Color.WHITE)
            setOnClickListener {
                showManualEndpointDialog()
            }
        }
        val manualParams = LinearLayout.LayoutParams(
            LinearLayout.LayoutParams.MATCH_PARENT,
            LinearLayout.LayoutParams.WRAP_CONTENT
        ).apply {
            setMargins(0, 16, 0, 0)
        }
        rootLayout.addView(manualEndpointButton, manualParams)

        toggleButton = Button(this).apply {
            text = "Start Compute Participation"
            textSize = 16f
            setBackgroundColor(Color.parseColor("#2E7D32"))
            setTextColor(Color.WHITE)
            setOnClickListener {
                if (viewModel.uiState.value.isComputeActive) {
                    viewModel.stopParticipation()
                } else {
                    viewModel.startParticipation()
                }
            }
        }
        val buttonParams = LinearLayout.LayoutParams(
            LinearLayout.LayoutParams.MATCH_PARENT,
            LinearLayout.LayoutParams.WRAP_CONTENT
        ).apply {
            setMargins(0, 16, 0, 0)
        }
        rootLayout.addView(toggleButton, buttonParams)

        settingsButton = Button(this).apply {
            text = "Cluster Network & mTLS Settings"
            textSize = 14f
            setBackgroundColor(Color.parseColor("#37474F"))
            setTextColor(Color.WHITE)
            setOnClickListener {
                val intent = Intent(this@MainActivity, SettingsActivity::class.java)
                startActivity(intent)
            }
        }
        val settingsParams = LinearLayout.LayoutParams(
            LinearLayout.LayoutParams.MATCH_PARENT,
            LinearLayout.LayoutParams.WRAP_CONTENT
        ).apply {
            setMargins(0, 24, 0, 0)
        }
        rootLayout.addView(settingsButton, settingsParams)

        val scrollView = ScrollView(this).apply {
            addView(rootLayout)
        }
        setContentView(scrollView)
    }

    private fun createMetricView(): TextView {
        return TextView(this).apply {
            textSize = 14f
            setTextColor(Color.parseColor("#CCCCCC"))
            setPadding(0, 12, 0, 12)
        }
    }

    private fun requestNotificationPermission() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            val permission = Manifest.permission.POST_NOTIFICATIONS
            if (ContextCompat.checkSelfPermission(this, permission) != PackageManager.PERMISSION_GRANTED) {
                notificationPermissionLauncher.launch(permission)
            }
        }
    }

    private fun observeState() {
        lifecycleScope.launch {
            repeatOnLifecycle(Lifecycle.State.STARTED) {
                viewModel.uiState.collect { state ->
                    renderState(state)
                }
            }
        }
    }

    internal fun renderState(state: WorkerDashboardState) {
        statusBannerView.text = state.statusBannerText

        val bannerColor = when (state.route) {
            is NetworkRoute.LanConnected -> Color.parseColor("#2E7D32") // Green
            is NetworkRoute.CellularWan -> Color.parseColor("#1565C0")  // Blue
            is NetworkRoute.Offline -> Color.parseColor("#424242")      // Gray
        }
        statusBannerView.setBackgroundColor(bannerColor)

        nodeIdView.text = "Node ID: ${state.nodeId}"
        hardwareView.text = "Hardware: ${state.cpuCores} Cores | ${state.totalRamFormatted()} RAM"
        osView.text = "Platform: Android ${state.osVersion} (${state.abi})"
        sandboxView.text = "Sandbox Boundary: ${if (state.isRooted) "Rooted Access" else "WASM / Toybox Guarded"}"
        batteryView.text = "Power State: ${state.batteryFormatted()}"
        val tempText = if (state.batteryTemperatureCelsius > 0) "${state.batteryTemperatureCelsius} C" else "N/A"
        thermalBadgeView.text = "Thermal Guard: $tempText [${state.thermalStatusFormatted()}]"
        thermalBadgeView.setTextColor(Color.parseColor(state.thermalBadgeColorHex()))
        telemetryView.text = "Tasks Executed: ${state.tasksCompletedCount} | Failed: ${state.tasksFailedCount}"
        recentLedgerView.text = if (state.recentEntries.isEmpty()) {
            "Recent Tasks: None yet"
        } else {
            val lines = state.recentEntries.take(5).joinToString("\n") { entry ->
                "  ${entry.taskId} #${entry.runAttempt} [${entry.route}] ${entry.status}"
            }
            "Recent Tasks:\n$lines"
        }

        if (state.isComputeActive) {
            toggleButton.text = "Stop Compute Participation"
            toggleButton.setBackgroundColor(Color.parseColor("#C62828")) // Red
        } else {
            toggleButton.text = "Start Compute Participation"
            toggleButton.setBackgroundColor(Color.parseColor("#2E7D32")) // Green
        }

        val isUnconfigured = !state.isConfigured
        val cluster = state.discoveredClusters.firstOrNull()

        if (cluster != null && isUnconfigured) {
            discoveryCardView.visibility = View.VISIBLE
            discoveryDetailsView.text = "Host: ${cluster.endpoint()} (Cluster: ${cluster.clusterName})"
            discoveryDetailsView.setTextColor(Color.WHITE)

            lifecycleScope.launch {
                val probe = SocketReachabilityProber.probe(cluster.host, cluster.port, timeoutMs = 1500)
                if (probe is PreFlightProbeResult.Unreachable) {
                    discoveryDetailsView.text = "Host: ${cluster.endpoint()} (Cluster: ${cluster.clusterName})\n⚠️ Reachability Warning: ${probe.actionableAdvice}"
                    discoveryDetailsView.setTextColor(Color.parseColor("#FFCC80"))
                }
            }
        } else {
            discoveryCardView.visibility = View.GONE
        }
    }

    internal fun handleConnectAndPair(cluster: DiscoveredCluster, pairingToken: String? = null) {
        if (!pairingToken.isNullOrBlank()) {
            executeEnrollmentWithToken(cluster, pairingToken)
            return
        }

        promptPairingDialog(cluster)
    }

    private fun promptPairingDialog(cluster: DiscoveredCluster) {
        if (cluster.caFingerprint.isBlank()) {
            AlertDialog.Builder(this)
                .setTitle("AndroGrid Cluster Detected")
                .setMessage(
                    "Host: ${cluster.endpoint()} (Cluster: ${cluster.clusterName})\n\n" +
                    "Warning: This cluster advertises no CA fingerprint.\n\n" +
                    "Zero-config pairing is blocked to prevent MITM interception. Please use QR scan or configure credentials manually."
                )
                .setNeutralButton("Scan QR") { _, _ ->
                    val intent = Intent(this@MainActivity, QrScannerActivity::class.java)
                    qrScanLauncher.launch(intent)
                }
                .setNegativeButton("Cancel", null)
                .show()
            return
        }

        val formattedFp = cluster.caFingerprint.chunked(4).joinToString(" ").uppercase()
        val input = EditText(this).apply {
            hint = "Pairing Token"
            inputType = InputType.TYPE_CLASS_TEXT
            setTextColor(Color.WHITE)
            setHintTextColor(Color.parseColor("#888888"))
            setBackgroundColor(Color.parseColor("#222222"))
            setPadding(24, 20, 24, 20)
        }

        AlertDialog.Builder(this)
            .setTitle("AndroGrid Cluster Detected")
            .setMessage(
                "Host: ${cluster.endpoint()} (Cluster: ${cluster.clusterName})\n\n" +
                "Verify CA Fingerprint against orchestrator terminal:\n" +
                "$formattedFp\n\n" +
                "Enter pairing token from orchestrator dashboard or scan QR code:"
            )
            .setView(input)
            .setPositiveButton("Connect & Pair") { _, _ ->
                val token = input.text.toString().trim()
                if (token.isNotBlank()) {
                    lifecycleScope.launch {
                        val probe = SocketReachabilityProber.probe(cluster.host, cluster.port, timeoutMs = 2500)
                        if (probe is PreFlightProbeResult.Unreachable) {
                            AlertDialog.Builder(this@MainActivity)
                                .setTitle("Cluster Pre-Flight Check Failed")
                                .setMessage(
                                    "Target: ${cluster.endpoint()}\n\n" +
                                    "${probe.message}\n\n" +
                                    "Actionable Guidance:\n" +
                                    "${probe.actionableAdvice}\n\n" +
                                    "Do you wish to proceed with enrollment anyway?"
                                )
                                .setPositiveButton("Proceed") { _, _ ->
                                    executeEnrollmentWithToken(cluster, token)
                                }
                                .setNegativeButton("Cancel", null)
                                .show()
                        } else {
                            executeEnrollmentWithToken(cluster, token)
                        }
                    }
                } else {
                    Toast.makeText(this, "Pairing token cannot be empty", Toast.LENGTH_SHORT).show()
                }
            }
            .setNeutralButton("Scan QR") { _, _ ->
                val intent = Intent(this@MainActivity, QrScannerActivity::class.java)
                qrScanLauncher.launch(intent)
            }
            .setNegativeButton("Cancel", null)
            .show()
    }

    internal fun showManualEndpointDialog() {
        val repo = settingsRepository ?: SharedPreferencesClusterSettingsRepository.getInstance(applicationContext)
        val currentSettings = repo.getSettings()

        val layout = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(48, 32, 48, 16)
        }

        val hostInput = EditText(this).apply {
            hint = "Host IP or Hostname (e.g. 10.100.102.6)"
            setText(if (currentSettings.wifiHost != "127.0.0.1") currentSettings.wifiHost else "")
            inputType = InputType.TYPE_CLASS_TEXT
            setTextColor(Color.WHITE)
            setHintTextColor(Color.parseColor("#888888"))
        }
        val portInput = EditText(this).apply {
            hint = "gRPC Port (default: 50051)"
            setText(currentSettings.wifiPort.toString())
            inputType = InputType.TYPE_CLASS_NUMBER
            setTextColor(Color.WHITE)
            setHintTextColor(Color.parseColor("#888888"))
        }
        val tokenInput = EditText(this).apply {
            hint = "Pairing Token (optional if enrolled)"
            inputType = InputType.TYPE_CLASS_TEXT
            setTextColor(Color.WHITE)
            setHintTextColor(Color.parseColor("#888888"))
        }
        val caInput = EditText(this).apply {
            hint = "CA Fingerprint (64 hex characters, optional)"
            inputType = InputType.TYPE_CLASS_TEXT
            setTextColor(Color.WHITE)
            setHintTextColor(Color.parseColor("#888888"))
        }

        layout.addView(TextView(this).apply { text = "Host Address:"; setTextColor(Color.LTGRAY) })
        layout.addView(hostInput)
        layout.addView(TextView(this).apply { text = "Port:"; setTextColor(Color.LTGRAY) })
        layout.addView(portInput)
        layout.addView(TextView(this).apply { text = "Pairing Token:"; setTextColor(Color.LTGRAY) })
        layout.addView(tokenInput)
        layout.addView(TextView(this).apply { text = "CA Fingerprint:"; setTextColor(Color.LTGRAY) })
        layout.addView(caInput)

        AlertDialog.Builder(this)
            .setTitle("Manual Cluster Endpoint Fallback")
            .setView(layout)
            .setPositiveButton("Probe & Connect") { _, _ ->
                val host = hostInput.text.toString().trim()
                val portStr = portInput.text.toString().trim()
                val port = portStr.toIntOrNull() ?: 50051
                val token = tokenInput.text.toString().trim()
                val ca = caInput.text.toString().trim()

                if (host.isBlank()) {
                    Toast.makeText(this, "Host address cannot be empty", Toast.LENGTH_SHORT).show()
                    return@setPositiveButton
                }

                lifecycleScope.launch {
                    val probeResult = SocketReachabilityProber.probe(host, port, timeoutMs = 2500)
                    if (probeResult is PreFlightProbeResult.Unreachable) {
                        AlertDialog.Builder(this@MainActivity)
                            .setTitle("Pre-Flight Check Failed")
                            .setMessage(
                                "Target: $host:$port\n\n" +
                                "${probeResult.message}\n\n" +
                                "Actionable Guidance:\n" +
                                "${probeResult.actionableAdvice}\n\n" +
                                "Do you want to save this endpoint anyway?"
                            )
                            .setPositiveButton("Save Anyway") { _, _ ->
                                applyManualSettings(host, port, token, ca)
                            }
                            .setNegativeButton("Cancel", null)
                            .show()
                    } else {
                        Toast.makeText(this@MainActivity, "Host $host:$port is reachable!", Toast.LENGTH_SHORT).show()
                        applyManualSettings(host, port, token, ca)
                    }
                }
            }
            .setNeutralButton("Scan QR") { _, _ ->
                val intent = Intent(this@MainActivity, QrScannerActivity::class.java)
                qrScanLauncher.launch(intent)
            }
            .setNegativeButton("Cancel", null)
            .show()
    }

    internal fun applyManualSettings(host: String, port: Int, token: String, caFingerprint: String) {
        val repo = settingsRepository ?: SharedPreferencesClusterSettingsRepository.getInstance(applicationContext)
        val current = repo.getSettings()
        repo.updateSettings(current.copy(wifiHost = host, wifiPort = port))

        if (token.isNotBlank() && caFingerprint.length == 64) {
            val payload = EnrollmentPayload(
                clusterEndpoint = "$host:$port",
                caFingerprint = caFingerprint,
                pairingToken = token,
                nodeId = viewModel.uiState.value.nodeId,
                directIp = host,
                directPort = port
            )
            executeEnrollmentPayload(payload)
        } else if (current.hasMtlsCredentials) {
            Toast.makeText(this, "Endpoint updated to $host:$port. Starting compute...", Toast.LENGTH_SHORT).show()
            viewModel.startParticipation()
        } else {
            Toast.makeText(this, "Endpoint updated to $host:$port. Please pair or provision mTLS credentials.", Toast.LENGTH_LONG).show()
        }
    }

    internal fun executeEnrollmentWithToken(cluster: DiscoveredCluster, token: String) {
        if (cluster.caFingerprint.isBlank()) {
            Toast.makeText(this, "Enrollment blocked: Missing or invalid cluster CA fingerprint", Toast.LENGTH_LONG).show()
            return
        }

        lifecycleScope.launch {
            val repo = settingsRepository ?: SharedPreferencesClusterSettingsRepository.getInstance(applicationContext)
            try {
                val payload = EnrollmentPayload(
                    clusterEndpoint = cluster.endpoint(),
                    caFingerprint = cluster.caFingerprint,
                    pairingToken = token,
                    nodeId = viewModel.uiState.value.nodeId
                )
                val coordinator = EnrollmentCoordinator(settingsRepository = repo)
                val result = coordinator.executeEnrollment(payload, viewModel.uiState.value.nodeId)
                when (result) {
                    is EnrollmentResult.Success -> {
                        Toast.makeText(this@MainActivity, "Device enrolled in cluster! Starting compute participation...", Toast.LENGTH_LONG).show()
                        viewModel.startParticipation()
                    }
                    is EnrollmentResult.Failure -> {
                        Toast.makeText(this@MainActivity, "Enrollment failed: ${result.errorMessage}", Toast.LENGTH_LONG).show()
                    }
                }
            } catch (e: Exception) {
                Toast.makeText(this@MainActivity, "Enrollment error: ${e.message}", Toast.LENGTH_LONG).show()
            }
        }
    }

    /**
     * ViewModelProvider.Factory resolving Application-scoped dependencies for [WorkerDashboardViewModel]
     * while preserving safe fallbacks in Robolectric test environments without [AndroGridApplication].
     *
     * Traces to: Section 6.1, [INV-003], [NFR-POW-001], ADR-008
     */
    private class WorkerDashboardViewModelFactory(
        private val application: Application
    ) : ViewModelProvider.Factory {
        @Suppress("UNCHECKED_CAST")
        override fun <T : ViewModel> create(modelClass: Class<T>): T {
            val context = application.applicationContext
            val app = application as? AndroGridApplication

            val rootChecker = StandardRootChecker()
            val systemInfo = AndroidSystemInfoProvider(context)
            val capabilityProvider = DeviceCapabilityProvider(rootChecker, systemInfo)
            val batteryProvider = AndroidBatteryStatusProvider(context)
            val serial = NodeIdProvider.getOrCreateNodeId(context)
            val discoveryManager = app?.clusterDiscoveryManager ?: NsdClusterDiscoveryManager(context)

            if (app != null) {
                return WorkerDashboardViewModel(
                    nodeId = serial,
                    routeFlow = app.networkRouteMonitor.currentRoute,
                    capabilityProvider = capabilityProvider,
                    batteryProvider = batteryProvider,
                    coordinator = app.lifecycleCoordinator,
                    thermalStatusListener = app.thermalStatusListener,
                    ledgerRepository = app.taskLedgerRepository,
                    participationController = app.participationController,
                    discoveryManager = discoveryManager,
                    settingsRepository = app.settingsRepository
                ) as T
            }

            // Fallback for isolated unit/Robolectric tests using plain android.app.Application
            val connectivityManager = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
            val networkMonitor = NetworkRouteMonitor(connectivityManager).apply { startMonitoring() }
            val thermalListener = AndroidDeviceThermalStatusListener(context).apply {
                startListening()
            }
            val coordinator = WorkerLifecycleCoordinator(
                routeFlow = networkMonitor.currentRoute,
                serviceController = AndroidServiceController(context),
                workScheduler = AndroidWorkScheduler(context)
            )
            val repo = SharedPreferencesClusterSettingsRepository.getInstance(context)
            return WorkerDashboardViewModel(
                nodeId = serial,
                routeFlow = networkMonitor.currentRoute,
                capabilityProvider = capabilityProvider,
                batteryProvider = batteryProvider,
                coordinator = coordinator,
                thermalStatusListener = thermalListener,
                ledgerRepository = InMemoryTaskLedgerRepository(),
                participationController = null,
                discoveryManager = discoveryManager,
                settingsRepository = repo
            ) as T
        }
    }
}
