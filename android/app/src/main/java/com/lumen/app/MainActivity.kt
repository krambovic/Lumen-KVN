package com.lumen.app

import android.Manifest
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.content.res.Configuration
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.activity.viewModels
import androidx.compose.runtime.getValue
import androidx.core.content.ContextCompat
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.lumen.app.navigation.LumenApp
import com.lumen.app.vm.MainViewModel
import androidx.lifecycle.lifecycleScope
import com.lumen.core.vpn.LumenVpnService
import com.lumen.ui.theme.LumenTheme
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeoutOrNull
import java.util.Locale

import androidx.activity.SystemBarStyle
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.runtime.DisposableEffect
import com.lumen.ui.screens.ThemeMode

class MainActivity : ComponentActivity() {
    private val viewModel: MainViewModel by viewModels()
    private val firstRunVpnPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode != RESULT_OK) {
            viewModel.log("VPN permission was not granted during first-run setup")
        }
    }
    private val runtimePermissionLauncher = registerForActivityResult(
        ActivityResultContracts.RequestMultiplePermissions()
    ) {
        requestFirstRunVpnConsent()
    }
    private val vpnPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == RESULT_OK) startVpn()
        else viewModel.log("VPN permission denied by user")
    }

    override fun attachBaseContext(newBase: Context) {
        val prefs = newBase.getSharedPreferences(MainViewModel.PREFS_NAME, Context.MODE_PRIVATE)
        val saved = prefs.getString("language", "en").orEmpty()
        val language = if (saved in SUPPORTED_LANGUAGES) saved else "en"
        val locale = Locale.forLanguageTag(language)
        Locale.setDefault(locale)
        val config = Configuration(newBase.resources.configuration).apply { setLocale(locale) }
        super.attachBaseContext(newBase.createConfigurationContext(config))
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // Request 120Hz High Refresh Rate on supporting displays
        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.M) {
            val currentDisplay = if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.R) {
                display
            } else {
                @Suppress("DEPRECATION")
                windowManager.defaultDisplay
            }
            val modes = currentDisplay?.supportedModes ?: emptyArray()
            val maxMode = modes.maxByOrNull { it.refreshRate }
            if (maxMode != null && maxMode.refreshRate >= 90f) {
                val lp = window.attributes
                lp.preferredDisplayModeId = maxMode.modeId
                if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.O) {
                    lp.preferredRefreshRate = maxMode.refreshRate
                }
                window.attributes = lp
            }
        }

        handleIntent(intent)
        setContent {
            val settings by viewModel.settings.collectAsStateWithLifecycle()
            val isDark = settings.themePreset != com.lumen.ui.screens.ThemePreset.LIGHT
            DisposableEffect(isDark) {
                enableEdgeToEdge(
                    statusBarStyle = if (isDark) {
                        SystemBarStyle.dark(android.graphics.Color.TRANSPARENT)
                    } else {
                        SystemBarStyle.light(android.graphics.Color.TRANSPARENT, android.graphics.Color.TRANSPARENT)
                    },
                    navigationBarStyle = if (isDark) {
                        SystemBarStyle.dark(android.graphics.Color.TRANSPARENT)
                    } else {
                        SystemBarStyle.light(android.graphics.Color.TRANSPARENT, android.graphics.Color.TRANSPARENT)
                    }
                )
                onDispose {}
            }
            LumenTheme(
                themePreset = settings.themePreset,
                useAmoledBlack = settings.useAmoledBlack,
                useMaterialYou = settings.useMaterialYou
            ) {
                LumenApp(viewModel, ::toggleConnection, ::restartVpnForNewServer) { recreate() }
            }
        }
        lifecycleScope.launch {
            delay(350)
            requestFirstRunPermissions()
        }
    }

    override fun onStart() {
        super.onStart()
        viewModel.checkForAndroidUpdateIfDue()
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        // Without this getIntent() keeps returning the launch intent, so a language
        // change (recreate) replays the original deep link in onCreate.
        setIntent(intent)
        handleIntent(intent)
    }

    private fun toggleConnection() {
        if (LumenVpnService.isRunning.value || LumenVpnService.isStarting.value) {
            startService(viewModel.buildStopIntent(this))
        } else {
            if (viewModel.nodes.value.isEmpty()) {
                android.widget.Toast.makeText(this, "No servers available. Please import a server.", android.widget.Toast.LENGTH_SHORT).show()
                return
            }
            if (viewModel.settings.value.proxyOnly) {
                startVpn()
            } else {
                VpnService.prepare(this)?.let(vpnPermissionLauncher::launch) ?: startVpn()
            }
        }
    }

    private fun requestFirstRunPermissions() {
        val prefs = getSharedPreferences(MainViewModel.PREFS_NAME, Context.MODE_PRIVATE)
        if (prefs.getBoolean("first_run_permissions_requested", false)) return
        prefs.edit().putBoolean("first_run_permissions_requested", true).apply()

        // CAMERA is deliberately absent: a VPN asking for the camera on first launch
        // looks like spyware. The QR scanner asks for it when it is opened instead
        // (openQrScanner in NavGraph).
        val required = buildList {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
                ContextCompat.checkSelfPermission(
                    this@MainActivity,
                    Manifest.permission.POST_NOTIFICATIONS
                ) != PackageManager.PERMISSION_GRANTED
            ) {
                add(Manifest.permission.POST_NOTIFICATIONS)
            }
        }
        if (required.isEmpty()) {
            requestFirstRunVpnConsent()
        } else {
            runtimePermissionLauncher.launch(required.toTypedArray())
        }
    }

    private fun requestFirstRunVpnConsent() {
        if (viewModel.settings.value.proxyOnly) return
        VpnService.prepare(this)?.let(firstRunVpnPermissionLauncher::launch)
    }

    /**
     * Restarts the tunnel on the newly selected server. A selection made while
     * startup is still in progress must cancel that attempt as well; otherwise the
     * UI names the new server while the old generated config finishes connecting.
     */
    private fun restartVpnForNewServer() {
        if (!LumenVpnService.isRunning.value && !LumenVpnService.isStarting.value) return
        lifecycleScope.launch {
            startService(viewModel.buildStopIntent(this@MainActivity))
            val stopped = withTimeoutOrNull(10_000) {
                combine(
                    LumenVpnService.isRunning,
                    LumenVpnService.isStarting
                ) { running, starting -> !running && !starting }
                    .first { it }
            } == true
            if (!stopped) {
                viewModel.reportConnectError("Could not stop the previous VPN session")
                return@launch
            }
            delay(250)
            if (viewModel.settings.value.proxyOnly) {
                startVpn()
            } else {
                VpnService.prepare(this@MainActivity)?.let(vpnPermissionLauncher::launch) ?: startVpn()
            }
        }
    }

    private fun startVpn() {
        if (viewModel.nodes.value.isEmpty()) {
            android.widget.Toast.makeText(this, "No servers available. Please import a server.", android.widget.Toast.LENGTH_SHORT).show()
            return
        }
        lifecycleScope.launch {
            val intent = viewModel.buildStartIntent(this@MainActivity) ?: run {
                android.widget.Toast.makeText(this@MainActivity, "No valid server configuration found.", android.widget.Toast.LENGTH_SHORT).show()
                return@launch
            }
            // A very large AUTO pool can parcel past the Binder limit; the config is
            // already persisted in prefs, so fail with a message instead of crashing.
            runCatching { ContextCompat.startForegroundService(this@MainActivity, intent) }
                .onSuccess { viewModel.markConnecting() }
                .onFailure { error ->
                    viewModel.log("Failed to start the VPN service: ${error.message}")
                    android.widget.Toast.makeText(
                        this@MainActivity,
                        "Could not start the VPN service.",
                        android.widget.Toast.LENGTH_SHORT
                    ).show()
                }
        }
    }

    private fun handleIntent(intent: Intent?) {
        intent ?: return
        // Streams are read by the view model on IO with a size bound: shared content
        // is untrusted and used to be materialised on the UI thread.
        var streamUri: android.net.Uri? = null
        val importText = runCatching {
            when {
                intent.action == Intent.ACTION_SEND -> {
                    val extraText = intent.getStringExtra(Intent.EXTRA_TEXT)
                    if (!extraText.isNullOrBlank()) {
                        extraText
                    } else {
                        @Suppress("DEPRECATION")
                        val stream = intent.getParcelableExtra<android.net.Uri>(Intent.EXTRA_STREAM)
                        streamUri = stream
                        null
                    }
                }
                intent.data != null -> {
                    val uri = intent.data ?: return@runCatching null
                    val scheme = uri.scheme?.lowercase(Locale.ROOT)
                    if (scheme == "content" || scheme == "file") {
                        streamUri = uri
                        null
                    } else if (scheme == "lumen") {
                        uri.getQueryParameter("url")?.takeIf { it.isNotBlank() }
                            ?: uri.toString().removePrefix("lumen://add/").removePrefix("lumen://import/")
                    } else uri.toString()
                }
                else -> null
            }
        }.getOrNull()

        // Mark the intent consumed so a recreate() does not re-import it.
        intent.data = null
        intent.removeExtra(Intent.EXTRA_TEXT)
        intent.removeExtra(Intent.EXTRA_STREAM)

        val uri = streamUri
        if (uri != null) {
            // A config file opened from outside the app belongs to the manual bucket;
            // switch there up front so the user does not land on the dashboard.
            viewModel.focusDefaultServerGroup()
            viewModel.prepareImportFromUri(this, uri, asFile = true)
        } else if (!importText.isNullOrBlank()) {
            viewModel.prepareImportText(importText)
        }
    }

    companion object {
        private val SUPPORTED_LANGUAGES = setOf("en", "ru", "fa", "zh")
    }
}
