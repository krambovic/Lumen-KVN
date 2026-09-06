package com.lumen.app.vm

import android.app.Application
import android.content.Context
import android.content.Intent
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.os.Build
import androidx.compose.ui.graphics.asImageBitmap
import androidx.core.graphics.drawable.toBitmap
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import androidx.room.Room
import androidx.room.withTransaction
import com.lumen.app.LauncherIconManager
import com.lumen.app.subscription.ImportClassification
import com.lumen.app.subscription.ImportClassifier
import com.lumen.app.subscription.ImportKind
import com.lumen.app.subscription.SubscriptionClient
import com.lumen.app.subscription.SubscriptionMetadata
import com.lumen.app.update.AndroidUpdateChecker
import com.lumen.app.update.AndroidUpdateInstaller
import com.lumen.app.update.AndroidUpdateState
import com.lumen.app.util.NodeDraftMapper
import com.lumen.core.config.builder.SingboxConfigBuilder
import com.lumen.core.config.builder.SingboxConfigOptions
import com.lumen.core.config.parser.LinkParser
import com.lumen.core.config.parser.ParsedNode
import org.json.JSONObject
import com.lumen.core.database.AppDatabase
import com.lumen.core.database.model.NodeEntity
import com.lumen.core.database.model.NodeGroupMemberEntity
import com.lumen.core.database.model.ServerGroupEntity
import com.lumen.core.database.model.SubscriptionEntity
import com.lumen.core.database.model.groupKey
import com.lumen.core.vpn.LumenVpnService
import com.lumen.core.vpn.ObfsRelay
import com.lumen.core.vpn.VpnLogBus
import com.lumen.core.vpn.VpnLogEntry
import com.lumen.core.vpn.VpnLogLevel
import com.lumen.core.vpn.VpnLogSettings
import com.lumen.core.vpn.VpnStartIntentFactory
import com.lumen.core.vpn.VpnStartParams
import com.lumen.ui.components.ConnectionState
import com.lumen.ui.components.CountryFlagHelper
import com.lumen.ui.screens.AppEntryUiModel
import com.lumen.ui.screens.DashboardStyle
import com.lumen.ui.screens.GeoResourceUiModel
import com.lumen.ui.screens.ImportKindUi
import com.lumen.ui.screens.ImportPhaseUi
import com.lumen.ui.screens.ImportUiState
import com.lumen.ui.screens.LauncherIconOption
import com.lumen.ui.screens.LogEntryUi
import com.lumen.ui.screens.NodeDraft
import com.lumen.ui.screens.NodeUiModel
import com.lumen.ui.screens.ServerGroupUiModel
import com.lumen.ui.screens.SettingsUiState
import com.lumen.ui.screens.SplitModeUi
import com.lumen.ui.screens.SubscriptionUiModel
import com.lumen.ui.screens.ThemeMode
import com.lumen.ui.screens.ThemePreset
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.delay
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.collectLatest
import kotlinx.coroutines.flow.flowOn
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withPermit
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import java.io.File
import java.net.HttpURLConnection
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.net.URL
import java.nio.file.AtomicMoveNotSupportedException
import java.nio.file.Files
import java.nio.file.StandardCopyOption
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.UUID
import java.util.concurrent.TimeUnit
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory
import net.kramb.lumen.BuildConfig

/**
 * One-shot things that happened, for the UI to react to once. Collected by the
 * navigator, which turns each into a haptic tick.
 */
enum class LumenEvent {
    /** The tunnel came up. */
    Connected,

    /** The tunnel went away, whether the user asked for it or it dropped. */
    Disconnected,

    /** At least one server reached the database: manual save, import or subscription. */
    ServerAdded
}

/**
 * What one subscription refresh actually changed. Kept as numbers instead of a ready
 * sentence so the UI can phrase it in the user's language.
 */
data class SubscriptionUpdateSummary(
    val subscriptionName: String,
    val added: Int,
    val updated: Int,
    val removed: Int,
    val total: Int
) {
    val unchanged: Boolean get() = added == 0 && updated == 0 && removed == 0
}

/**
 * Identity of a subscription server across refreshes. The row id is regenerated on
 * every refresh, so the endpoint itself is what tells "added" from "updated".
 */
internal fun subscriptionNodeKey(
    server: String,
    port: Int,
    protocol: String,
    name: String = ""
): String {
    val normalizedProtocol = protocol.trim().lowercase(Locale.US)
    // AUTO rows deliberately have no endpoint, so endpoint-only identity collapsed every
    // country pool into "auto||0". The display name is the provider's stable selector
    // identity and keeps Netherlands AUTO distinct from United States AUTO.
    return if (normalizedProtocol == "auto" || (server.isBlank() && port == 0)) {
        "$normalizedProtocol|selector|${name.trim().lowercase(Locale.US)}"
    } else {
        "$normalizedProtocol|${server.trim().lowercase(Locale.US)}|$port"
    }
}

private val AUTO_REGION_GEO_TAGS = setOf(
    "geosite:ru", "geosite:category-ru", "geoip:ru",
    "geosite:cn", "geosite:category-cn", "geoip:cn",
    "geosite:ir", "geosite:category-ir", "geoip:ir"
)

private fun withoutRoutingAction(value: String): String {
    val trimmed = value.trim()
    val prefix = listOf("proxy:", "block:", "reject:", "direct:")
        .firstOrNull { trimmed.startsWith(it, true) }
    return if (prefix == null) trimmed else trimmed.substring(prefix.length).trim()
}

internal fun geoRegionCode(source: String): String {
    val normalized = source.lowercase(Locale.US)
    return when {
        "loyalsoldier" in normalized -> "cn"
        "chocolate4u" in normalized -> "ir"
        else -> "ru"
    }
}

/** Only a completed persisted result can trigger destructive ping cleanup. */
internal fun isPingRemovalCandidate(pingMs: Int?, thresholdMs: Int): Boolean =
    pingMs != null && pingMs >= 0 && pingMs <= thresholdMs.coerceAtLeast(0)

/**
 * The selected region is the only regional pair in the new set. Regional rules left
 * by the previous automatic preset are deliberately ignored before downloads begin.
 */
internal fun geoRuleSetsForRegion(
    code: String,
    directDomains: String,
    directIpCidrs: String
): List<Pair<String, String>> {
    val wanted = LinkedHashSet<Pair<String, String>>()
    wanted += "geosite" to if (code == "ru") "category-ru" else code
    wanted += "geoip" to code
    // Block Ads is a global preset, not a regional one. Keep its binary set in
    // every managed download so enabling the preset never produces a visible
    // rule that the strict local-only builder has to discard.
    wanted += "geosite" to "category-ads-all"
    (directDomains + "\n" + directIpCidrs)
        .split(Regex("[\\n,;]+"))
        .map(::withoutRoutingAction)
        .filter(String::isNotEmpty)
        .forEach { value ->
            val lower = value.lowercase(Locale.US)
            if (lower in AUTO_REGION_GEO_TAGS) return@forEach
            when {
                lower.startsWith("geosite:") ->
                    wanted += "geosite" to lower.removePrefix("geosite:").trim()
                lower.startsWith("geoip:") ->
                    wanted += "geoip" to lower.removePrefix("geoip:").trim()
            }
        }
    return wanted.filter { it.second.isNotEmpty() }
}

/** Replaces every automatic regional routing entry while preserving non-regional rules. */
internal fun switchAutomaticGeoRegion(settings: SettingsUiState, code: String): SettingsUiState {
    fun clean(raw: String): List<String> = raw
        .split(Regex("[\\n,;]+"))
        .map(String::trim)
        .filter(String::isNotEmpty)
        .filterNot { withoutRoutingAction(it).lowercase(Locale.US) in AUTO_REGION_GEO_TAGS }

    val siteTag = if (code == "ru") "geosite:category-ru" else "geosite:$code"
    return settings.copy(
        directDomains = (clean(settings.directDomains) + "direct:$siteTag" + "direct:geoip:$code")
            .distinct()
            .joinToString("\n"),
        directIpCidrs = clean(settings.directIpCidrs).joinToString("\n")
    )
}

class MainViewModel(app: Application) : AndroidViewModel(app) {

    private val _androidUpdateState = MutableStateFlow(AndroidUpdateState())
    internal val androidUpdateState: StateFlow<AndroidUpdateState> = _androidUpdateState

    internal fun checkForAndroidUpdate(force: Boolean = false) {
        if (!force) {
            if (!_settings.value.autoCheckUpdates) return
            val now = System.currentTimeMillis()
            val last = prefs.getLong(PREF_LAST_ANDROID_UPDATE_CHECK, 0L)
            if (!AndroidUpdateChecker.isAutoCheckDue(now, last)) return
        }
        checkForAndroidUpdateInternal(force = force, userInitiated = force)
    }

    /** Called when the activity returns to the foreground; the check itself is daily. */
    internal fun checkForAndroidUpdateIfDue() {
        checkForAndroidUpdate(force = false)
    }

    private fun checkForAndroidUpdateInternal(force: Boolean, userInitiated: Boolean) {
        val current = _androidUpdateState.value
        if (current.isChecking || (!force && !_settings.value.autoCheckUpdates)) return
        prefs.edit()
            .putLong(PREF_LAST_ANDROID_UPDATE_CHECK, System.currentTimeMillis())
            .apply()
        _androidUpdateState.value = current.copy(isChecking = true, error = null)
        viewModelScope.launch(Dispatchers.IO) {
            runCatching {
                AndroidUpdateChecker.fetch(Build.SUPPORTED_ABIS.toList())
            }.onSuccess { release ->
                _androidUpdateState.value = AndroidUpdateState(
                    isChecking = false,
                    latest = release,
                    updateAvailable = AndroidUpdateChecker.isNewer(
                        release.version,
                        BuildConfig.VERSION_NAME
                    ),
                    checked = true
                )
            }.onFailure { error ->
                _androidUpdateState.value = AndroidUpdateState(
                    isChecking = false,
                    error = if (userInitiated) {
                        error.message ?: "Could not check GitHub releases"
                    } else {
                        null
                    },
                    checked = true
                )
                VpnLogBus.warning("UPDATE", "Android update check failed: ${error.message}")
            }
        }
    }

    internal fun prepareAndroidUpdate() {
        val current = _androidUpdateState.value
        val release = current.latest
        if (current.isDownloading || !current.updateAvailable || release?.apkUrl.isNullOrBlank()) {
            return
        }
        _androidUpdateState.update {
            it.copy(isDownloading = true, downloadProgress = null, error = null)
        }
        val application = getApplication<Application>()
        viewModelScope.launch(Dispatchers.IO) {
            try {
                val apk = AndroidUpdateInstaller.downloadAndValidate(
                    context = application,
                    release = release,
                    onProgress = { progress ->
                        _androidUpdateState.update { state ->
                            if (state.latest?.tag == release.tag && state.isDownloading) {
                                state.copy(downloadProgress = progress)
                            } else {
                                state
                            }
                        }
                    }
                )
                _androidUpdateState.update { state ->
                    if (state.latest?.tag == release.tag) {
                        state.copy(
                            isDownloading = false,
                            downloadProgress = 100,
                            downloadedApkPath = apk.absolutePath,
                            installRequestId = state.installRequestId + 1L,
                            error = null
                        )
                    } else {
                        state
                    }
                }
            } catch (cancelled: CancellationException) {
                throw cancelled
            } catch (error: Throwable) {
                _androidUpdateState.update {
                    it.copy(
                        isDownloading = false,
                        downloadProgress = null,
                        downloadedApkPath = null,
                        error = error.message ?: "Could not prepare the Android update"
                    )
                }
                VpnLogBus.warning(
                    "UPDATE",
                    "Android update download failed: ${error.message ?: error::class.java.simpleName}"
                )
            }
        }
    }

    internal fun reportAndroidUpdateError(message: String) {
        _androidUpdateState.update {
            it.copy(
                isDownloading = false,
                downloadProgress = null,
                downloadedApkPath = null,
                error = message
            )
        }
        VpnLogBus.warning("UPDATE", message)
    }

    /**
     * Clears a one-shot installer request before the PackageInstaller session is
     * created. This prevents a rotation or activity recreation from committing the
     * same APK twice while Android's confirmation UI is already open.
     */
    internal fun consumeAndroidUpdateInstallRequest(requestId: Long) {
        _androidUpdateState.update { state ->
            if (state.installRequestId == requestId) {
                state.copy(downloadedApkPath = null)
            } else {
                state
            }
        }
    }

    // No destructive fallback: `nodes` holds hand-typed servers and keys that
    // cannot be recovered, so a missing migration must fail loudly instead.
    private val db = Room.databaseBuilder(app, AppDatabase::class.java, "lumen.db")
        .addMigrations(
            AppDatabase.MIGRATION_1_2,
            AppDatabase.MIGRATION_2_3,
            AppDatabase.MIGRATION_3_4,
            AppDatabase.MIGRATION_4_5
        )
        .build()
    private val nodeDao = db.nodeDao()
    private val subscriptionDao = db.subscriptionDao()
    private val serverGroupDao = db.serverGroupDao()
    private val prefs = app.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
    private var storedVpnConfigRefreshJob: Job? = null
    private val storedVpnConfigWriteMutex = Mutex()
    private val subscriptionHwid: String by lazy {
        prefs.getString("subscription_hwid", null)?.takeIf { it.isNotBlank() } ?: UUID.randomUUID().toString().also {
            prefs.edit().putString("subscription_hwid", it).apply()
        }
    }

    init {
        // The service inits the log bus for itself, but a widget or tile start is the
        // only path that creates it: without this the app process persists nothing
        // until the first connection.
        VpnLogBus.init(app)
        // Single source of truth for the version shown in the UI and sent in headers.
        com.lumen.ui.screens.LumenVersion.appVersion = net.kramb.lumen.BuildConfig.VERSION_NAME
        com.lumen.core.vpn.TelemetryManager.appVersion = net.kramb.lumen.BuildConfig.VERSION_NAME
        // Keep Android visible in the same 45-minute "online now" window as desktop.
        com.lumen.core.vpn.TelemetryManager.startHeartbeatLoop(app, viewModelScope)
        com.lumen.core.vpn.TelemetryManager.startErrorUploadLoop(app, viewModelScope)
        reconcileLauncherIcon()
    }

    /**
     * Component-enabled state persists across updates but a fresh install starts from
     * the manifest defaults, so a user who picked the dark icon would silently get the
     * auto-theming one back after reinstalling. Re-applying the stored preference on
     * every launch closes that gap; it is a no-op whenever the two already agree.
     *
     * The preference is read straight from [prefs] because this runs before
     * [_settings] is constructed.
     */
    private fun reconcileLauncherIcon() {
        val stored = runCatching {
            LauncherIconOption.valueOf(
                prefs.getString(PREF_LAUNCHER_ICON, LauncherIconOption.SYSTEM.name)
                    ?: LauncherIconOption.SYSTEM.name
            )
        }.getOrDefault(LauncherIconOption.SYSTEM)
        viewModelScope.launch(Dispatchers.IO) {
            // Binder calls only; failures are non-fatal and leave the current icon alone.
            runCatching { LauncherIconManager.applyOption(getApplication<Application>(), stored) }
        }
    }

    // ---------- Logs ----------
    // Log text is only formatted while the logs tab is open; elsewhere the flow stays empty.
    private val _logsVisible = MutableStateFlow(false)

    fun setLogsVisible(visible: Boolean) { _logsVisible.value = visible }

    val logs: StateFlow<List<String>> = combine(VpnLogBus.entries, _logsVisible) { entries, visible ->
        if (!visible) emptyList() else entries.map { entry ->
            "[${entry.formattedTime}] [${entry.level.name}] [${entry.component}] ${entry.message}"
        }
    }.stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), emptyList())

    // History pulled from the persisted log, oldest first. Empty until the user asks
    // for it: the live tail already covers the current session.
    private val _olderLogEntries = MutableStateFlow<List<VpnLogEntry>>(emptyList())

    /** Goes false once the persisted log has nothing older left, so the viewer can
     *  stop offering a button that would do nothing. */
    private val _moreLogHistory = MutableStateFlow(true)
    val moreLogHistory: StateFlow<Boolean> = _moreLogHistory

    /** The structured log the viewer renders: the loaded history followed by the live tail. */
    val logEntries: StateFlow<List<LogEntryUi>> =
        combine(VpnLogBus.entries, _olderLogEntries, _logsVisible) { live, older, visible ->
            if (!visible) emptyList() else (older + live).map { entry ->
                LogEntryUi(
                    timestamp = entry.timestamp,
                    time = entry.formattedTime,
                    level = entry.level.name.lowercase(Locale.US),
                    component = entry.component,
                    message = entry.message
                )
            }
        }.stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), emptyList())

    /**
     * Pulls one more page of persisted history in front of what is already shown. The
     * live tail is the newest slice of the same file, so skipping past both is what
     * keeps the pages contiguous.
     */
    fun loadOlderLogs() {
        if (!_moreLogHistory.value) return
        viewModelScope.launch(Dispatchers.IO) {
            val skip = VpnLogBus.entries.value.size + _olderLogEntries.value.size
            val page = VpnLogBus.readPersisted(VpnLogBus.DEFAULT_PAGE_SIZE, skip)
            if (page.isEmpty()) _moreLogHistory.value = false
            else _olderLogEntries.update { page + it }
        }
    }

    fun log(message: String) = VpnLogBus.info("APP", message)

    fun clearLogs() {
        _olderLogEntries.value = emptyList()
        _moreLogHistory.value = true
        VpnLogBus.clear()
    }

    /** Shares the persisted log, not just the lines the viewer happens to hold. */
    fun exportLogs(context: Context) {
        viewModelScope.launch {
            val text = withContext(Dispatchers.IO) { VpnLogBus.exportText() }
            shareLogText(context, text)
        }
    }

    /** Shares exactly what the viewer's filter selected. */
    fun exportLogText(context: Context, text: String) = shareLogText(context, text)

    private fun shareLogText(context: Context, text: String) {
        if (text.isBlank()) return
        val intent = Intent(Intent.ACTION_SEND).apply {
            type = "text/plain"
            putExtra(Intent.EXTRA_SUBJECT, "Lumen logs")
            putExtra(Intent.EXTRA_TEXT, text)
        }
        context.startActivity(
            Intent.createChooser(intent, "Export logs").addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        )
    }

    // ---------- Settings ----------
    private val _settings = MutableStateFlow(loadSettings())
    val settings: StateFlow<SettingsUiState> = _settings

    private fun normalizedPingType(raw: String?): String = when (raw?.trim()?.lowercase()) {
        "tcp", "tcping" -> "tcping"
        "icmp" -> "icmp"
        "url", "real" -> "real"
        // Plain HTTP GET through the node: same temporary core as "real", but it times
        // the request/response round trip alone instead of the whole connect.
        "http", "httpget", "http-get", "get" -> "http"
        // UDP "ping" was never reliable for arbitrary VPN ports and is not a
        // desktop Lumen mode. Migrate old installations to TCPing.
        else -> "tcping"
    }

    // The core only knows sing-box level names. "warn" — written by older builds and
    // still the shipped default — is not one of them, so the builder silently fell
    // back to "info", the noisiest and most battery hungry setting the app has.
    private fun normalizedLogLevel(raw: String?): String = when (raw?.trim()?.lowercase(Locale.US)) {
        "trace" -> "trace"
        "debug" -> "debug"
        "info" -> "info"
        "error" -> "error"
        "fatal" -> "fatal"
        "panic" -> "panic"
        // The core refuses to start on "none" ("parse log level: unknown log level:
        // none"), so an installation that stored "off" gets the quietest level it
        // does accept instead of a config it rejects.
        "off", "none" -> "error"
        else -> "warning"
    }

    private fun loadSettings() = SettingsUiState(
        engine = "SINGBOX",
        muxEnabled = prefs.getBoolean("mux_enabled", false),
        muxConcurrency = prefs.getInt("mux_concurrency", 8),
        multiplexProtocol = prefs.getString("mux_protocol", "smux") ?: "smux",
        multiplexMinStreams = prefs.getInt("mux_min_streams", 4),
        multiplexPadding = prefs.getBoolean("mux_padding", true),
        multiplexBrutalEnabled = prefs.getBoolean("mux_brutal_enabled", false),
        multiplexBrutalUpMbps = prefs.getInt("mux_brutal_up_mbps", 0),
        multiplexBrutalDownMbps = prefs.getInt("mux_brutal_down_mbps", 0),
        outboundTcpFastOpen = prefs.getBoolean("outbound_tcp_fast_open", false),
        outboundTcpMultiPath = prefs.getBoolean("outbound_tcp_multi_path", false),
        outboundUdpFragment = prefs.getBoolean("outbound_udp_fragment", false),
        udpOverTcp = prefs.getBoolean("udp_over_tcp", false),
        outboundConnectTimeoutSeconds = prefs.getInt("outbound_connect_timeout_s", 0),
        fragmentEnabled = prefs.getBoolean("fragment_enabled", false),
        fragmentPackets = prefs.getString("fragment_packets", "tlshello") ?: "tlshello",
        fragmentLength = prefs.getString("fragment_length", "50-100") ?: "50-100",
        fragmentDelay = prefs.getString("fragment_delay", "10-20") ?: "10-20",
        localInboundEnabled = prefs.getBoolean("local_inbound", true) ||
            prefs.getBoolean("proxy_only", false),
        localSocksPort = prefs.getInt("local_socks_port", 10808),
        localHttpPort = prefs.getInt("local_http_port", 10809),
        lanSharingEnabled = prefs.getBoolean("lan_sharing", false),
        socks5AuthEnabled = prefs.getBoolean("socks5_auth_enabled", true),
        socks5Username = ensureSocks5Username(),
        socks5Password = ensureSocks5Password(),
        proxyOnly = prefs.getBoolean("proxy_only", false),
        autoConnectOnBoot = prefs.getBoolean("boot_auto_connect", false),
        enableSpeedStats = prefs.getBoolean("enable_speed_stats", true),
        showNotification = prefs.getBoolean("show_notification", true),
        showNotificationSpeed = prefs.getBoolean("show_notification_speed", true),
        preferIpv6 = prefs.getBoolean("prefer_ipv6", false),
        blockQuic = prefs.getBoolean("block_quic", false),
        sniffRouteOnly = prefs.getBoolean("sniff_route_only", false),
        mtu = prefs.getInt("mtu", 1500),
        directDomains = prefs.getString("routing_direct_domains", null)?.takeIf { it.isNotBlank() } ?: com.lumen.ui.screens.DEFAULT_DIRECT_DOMAINS,
        directIpCidrs = prefs.getString("routing_direct_ip_cidrs", "") ?: "",
        geoResourceSource = prefs.getString(
            "geo_resource_source",
            "https://github.com/runetfreedom/russia-v2ray-rules-dat/"
        ) ?: "https://github.com/runetfreedom/russia-v2ray-rules-dat/",
        proxyDnsServer = prefs.getString("proxy_dns", "cloudflare-dns.com") ?: "cloudflare-dns.com",
        directDnsServer = prefs.getString("direct_dns", "1.1.1.1") ?: "1.1.1.1",
        dnsMode = prefs.getString("dns_mode", "automatic") ?: "automatic",
        dnsCustomJson = prefs.getString("dns_custom_json", "")?.take(65_536) ?: "",
        dnsDirectServers = prefs.getString("dns_direct_servers", null)
            ?: (prefs.getString("direct_dns", "1.1.1.1") + "\n8.8.8.8"),
        dnsProxyServers = prefs.getString("dns_proxy_servers", null)
            ?: (prefs.getString("proxy_dns", "cloudflare-dns.com") + "\ndns.google"),
        dnsDirectType = prefs.getString("dns_direct_type", "udp") ?: "udp",
        dnsProxyType = prefs.getString("dns_proxy_type", "https") ?: "https",
        dnsDirectStrategy = prefs.getString("dns_direct_strategy", "ipv4_only") ?: "ipv4_only",
        dnsProxyStrategy = prefs.getString("dns_proxy_strategy", "ipv4_only") ?: "ipv4_only",
        dnsHijackEnabled = prefs.getBoolean("dns_hijack_enabled", true),
        dnsFakeIpEnabled = prefs.getBoolean("dns_fake_ip_enabled", false),
        dnsParallelQuery = prefs.getBoolean("dns_parallel_query", false),
        dnsOptimisticCache = prefs.getBoolean("dns_optimistic_cache", false),
        dnsGeoCheck = prefs.getBoolean("dns_geo_check", true),
        dnsProxyIpv4Only = prefs.getBoolean("dns_proxy_ipv4_only", true),
        dnsHosts = prefs.getString("dns_hosts", "") ?: "",
        // Older builds silently enabled a product-specific ntc.party hosts entry for
        // every user. It is not a DNS default and can redirect traffic, so migrate
        // that exact legacy pair to off; explicit custom entries remain available.
        dnsOverrideEnabled = prefs.getBoolean("dns_override_enabled", false) &&
            !(prefs.getString("dns_override_hostname", "").equals("ntc.party", true) &&
                prefs.getString("dns_override_ipv4", "") == "130.255.77.28"),
        dnsOverrideHostname = prefs.getString("dns_override_hostname", "") ?: "",
        dnsOverrideIpv4 = prefs.getString("dns_override_ipv4", "") ?: "",
        urlTestUrl = prefs.getString("url_test_url", "https://www.gstatic.com/generate_204")
            ?: "https://www.gstatic.com/generate_204",
        urlTestIntervalMinutes = prefs.getInt("url_test_interval_minutes", 3),
        urlTestToleranceMs = prefs.getInt("url_test_tolerance_ms", 50),
        urlTestIdleTimeoutMinutes = prefs.getInt("url_test_idle_timeout_minutes", 0),
        urlTestInterruptExistConnections = prefs.getBoolean("url_test_interrupt_exist", true),
        subscriptionUserAgent = prefs.getString("subscription_user_agent", "Happ/2.18.3/Windows/2606241603601")
            ?: "Happ/2.18.3/Windows/2606241603601",
        subscriptionHwid = prefs.getString("subscription_hwid", subscriptionHwid) ?: subscriptionHwid,
        subscriptionSendHwid = prefs.getBoolean("subscription_send_hwid", true),
        subscriptionDirect = prefs.getBoolean("subscription_direct", true),
        allowSubscriptionOverrides = prefs.getBoolean("allow_subscription_overrides", true),
        subscriptionAutoUpdateMinutes = prefs.getInt("subscription_auto_update_minutes", 240),
        subscriptionIncludeRegex = prefs.getString("subscription_include_regex", "") ?: "",
        subscriptionExcludeRegex = prefs.getString("subscription_exclude_regex", "") ?: "",
        subscriptionUseProxyTun = prefs.getBoolean("subscription_use_proxy_tun", false),
        subscriptionAllowHttp = prefs.getBoolean("subscription_allow_http", false),
        subscriptionConverterEnabled = prefs.getBoolean("subscription_converter_enabled", false),
        subscriptionConverterUrl = prefs.getString("subscription_converter_url", "") ?: "",
        language = prefs.getString("language", "en")?.takeIf { it in setOf("en", "ru", "fa", "zh") } ?: "en",
        themeMode = runCatching {
            ThemeMode.valueOf(prefs.getString("theme_mode", ThemeMode.DARK.name) ?: ThemeMode.DARK.name)
        }.getOrDefault(ThemeMode.DARK),
        themePreset = runCatching {
            ThemePreset.valueOf(prefs.getString("theme_preset", ThemePreset.DARK.name) ?: ThemePreset.DARK.name)
        }.getOrDefault(ThemePreset.DARK),
        useMaterialYou = prefs.getBoolean("use_material_you", false),
        useAmoledBlack = prefs.getBoolean("use_amoled_black", false),
        hapticsEnabled = prefs.getBoolean("haptics_enabled", true),
        telemetryEnabled = prefs.getBoolean(
            com.lumen.core.vpn.TelemetryManager.PREF_TELEMETRY_ENABLED,
            true
        ),
        reconnectOnNetworkChange = prefs.getBoolean("reconnect_on_network_change", true),
        validateProxyDataPath = prefs.getBoolean("validate_proxy_data_path", false),
        pingType = normalizedPingType(prefs.getString("server_speed_test_type", "http")),
        pingTimeoutMs = prefs.getInt("ping_timeout_ms", 2000),
        pingConcurrency = prefs.getInt("ping_concurrency", 16),
        pingUrl = prefs.getString("ping_url", "https://www.gstatic.com/generate_204")
            ?: "https://www.gstatic.com/generate_204",
        pingAttempts = prefs.getInt("ping_attempts", 1),
        pingAggregate = prefs.getString("ping_aggregate", "min")?.lowercase()
            ?.takeIf { it in setOf("min", "avg", "median") } ?: "min",
        pingRetryDelayMs = prefs.getInt("ping_retry_delay_ms", 200),
        pingGoodMs = prefs.getInt("ping_good_ms", 150),
        pingFairMs = prefs.getInt("ping_fair_ms", 300),
        pingAutoOnOpen = prefs.getBoolean("ping_auto_on_open", false),
        pingAutoDeleteUnreachable = prefs.getBoolean("ping_auto_delete_unreachable", false),
        pingAutoDeleteThresholdMs = prefs.getInt("ping_auto_delete_threshold_ms", 1)
            .coerceIn(0, 100),
        autoCheckUpdates = prefs.getBoolean("auto_check_updates", true),
        dashboardStyle = runCatching {
            DashboardStyle.valueOf(prefs.getString("dashboard_style", DashboardStyle.DEFAULT.name) ?: DashboardStyle.DEFAULT.name)
        }.getOrDefault(DashboardStyle.DEFAULT),
        launcherIcon = runCatching {
            LauncherIconOption.valueOf(
                prefs.getString(PREF_LAUNCHER_ICON, LauncherIconOption.SYSTEM.name)
                    ?: LauncherIconOption.SYSTEM.name
            )
        }.getOrDefault(LauncherIconOption.SYSTEM),
        // One master switch owns the whole pipeline; the store keeps it under its
        // own "app_log_enabled" key, so read it back from there.
        loggingEnabled = appLogSettings.enabled
    )

    /** Current application-log settings, straight from the store's own preferences. */
    private val appLogSettings: VpnLogSettings
        get() = VpnLogBus.loadSettings(getApplication<Application>())


    fun updateSettings(s: SettingsUiState) {
        val telemetryChanged = _settings.value.telemetryEnabled != s.telemetryEnabled
        val launcherIconChanged = _settings.value.launcherIcon != s.launcherIcon
        val autoUpdatesEnabled = !_settings.value.autoCheckUpdates && s.autoCheckUpdates
        _settings.value = s
        prefs.edit()
            .putString("engine_type", s.engine)
            .putBoolean("mux_enabled", s.muxEnabled)
            .putInt("mux_concurrency", s.muxConcurrency.coerceIn(1, 1024))
            .putString("mux_protocol", s.multiplexProtocol)
            .putInt("mux_min_streams", s.multiplexMinStreams.coerceIn(0, 1024))
            .putBoolean("mux_padding", s.multiplexPadding)
            .putBoolean("mux_brutal_enabled", s.multiplexBrutalEnabled)
            .putInt("mux_brutal_up_mbps", s.multiplexBrutalUpMbps.coerceIn(0, 10000))
            .putInt("mux_brutal_down_mbps", s.multiplexBrutalDownMbps.coerceIn(0, 10000))
            .putBoolean("outbound_tcp_fast_open", s.outboundTcpFastOpen)
            .putBoolean("outbound_tcp_multi_path", s.outboundTcpMultiPath)
            .putBoolean("outbound_udp_fragment", s.outboundUdpFragment)
            .putBoolean("udp_over_tcp", s.udpOverTcp)
            .putInt("outbound_connect_timeout_s", s.outboundConnectTimeoutSeconds.coerceIn(0, 600))
            .putBoolean("fragment_enabled", s.fragmentEnabled)
            .putString("fragment_packets", s.fragmentPackets)
            .putString("fragment_length", s.fragmentLength)
            .putString("fragment_delay", s.fragmentDelay)
            .putBoolean("local_inbound", s.localInboundEnabled)
            .putInt("local_socks_port", s.localSocksPort.coerceIn(1024, 65535))
            .putInt("local_http_port", s.localHttpPort.coerceIn(1024, 65535))
            .putBoolean("lan_sharing", s.lanSharingEnabled)
            .putBoolean("socks5_auth_enabled", s.socks5AuthEnabled)
            .putString("socks5_username", s.socks5Username.trim().take(64))
            .putString("socks5_password", s.socks5Password.trim().take(128))
            .putBoolean("proxy_only", s.proxyOnly)
            .putBoolean("boot_auto_connect", s.autoConnectOnBoot)
            .putBoolean("enable_speed_stats", s.enableSpeedStats)
            .putBoolean("show_notification", s.showNotification)
            .putBoolean("show_notification_speed", s.showNotificationSpeed)
            .putBoolean("prefer_ipv6", s.preferIpv6)
            .putBoolean("block_quic", s.blockQuic)
            .putBoolean("sniff_route_only", s.sniffRouteOnly)
            .putInt("mtu", s.mtu.coerceIn(1280, 9000))
            .putString("routing_direct_domains", s.directDomains)
            .putString("routing_direct_ip_cidrs", s.directIpCidrs)
            .putString("geo_resource_source", s.geoResourceSource)
            .putString("proxy_dns", s.dnsProxyServers.lineSequence().firstOrNull()?.trim().orEmpty().take(253))
            .putString("direct_dns", s.dnsDirectServers.lineSequence().firstOrNull()?.trim().orEmpty().take(253))
            .putString("dns_mode", s.dnsMode)
            .putString("dns_custom_json", s.dnsCustomJson.take(65_536))
            .putString("dns_direct_servers", s.dnsDirectServers.take(2048))
            .putString("dns_proxy_servers", s.dnsProxyServers.take(2048))
            .putString("dns_direct_type", s.dnsDirectType)
            .putString("dns_proxy_type", s.dnsProxyType)
            .putString("dns_direct_strategy", s.dnsDirectStrategy)
            .putString("dns_proxy_strategy", s.dnsProxyStrategy)
            .putBoolean("dns_hijack_enabled", s.dnsHijackEnabled)
            .putBoolean("dns_fake_ip_enabled", s.dnsFakeIpEnabled)
            .putBoolean("dns_parallel_query", s.dnsParallelQuery)
            .putBoolean("dns_optimistic_cache", s.dnsOptimisticCache)
            .putBoolean("dns_geo_check", s.dnsGeoCheck)
            .putBoolean("dns_proxy_ipv4_only", s.dnsProxyIpv4Only)
            .putString("dns_hosts", s.dnsHosts.take(4096))
            .putBoolean("dns_override_enabled", s.dnsOverrideEnabled)
            .putString("dns_override_hostname", s.dnsOverrideHostname.trim().take(253))
            .putString("dns_override_ipv4", s.dnsOverrideIpv4.trim().take(15))
            .putString("url_test_url", s.urlTestUrl.trim().take(512))
            .putInt("url_test_interval_minutes", s.urlTestIntervalMinutes.coerceIn(1, 1440))
            .putInt("url_test_tolerance_ms", s.urlTestToleranceMs.coerceIn(0, 5000))
            .putInt("url_test_idle_timeout_minutes", s.urlTestIdleTimeoutMinutes.coerceIn(0, 1440))
            .putBoolean("url_test_interrupt_exist", s.urlTestInterruptExistConnections)
            .putString("subscription_user_agent", s.subscriptionUserAgent.trim().take(256))
            .putString("subscription_hwid", s.subscriptionHwid.trim().take(256))
            .putBoolean("subscription_send_hwid", s.subscriptionSendHwid)
            .putBoolean("subscription_direct", s.subscriptionDirect)
            .putBoolean("allow_subscription_overrides", s.allowSubscriptionOverrides)
            .putInt("subscription_auto_update_minutes", s.subscriptionAutoUpdateMinutes.coerceIn(15, 1440))
            .putString("subscription_include_regex", s.subscriptionIncludeRegex.trim().take(512))
            .putString("subscription_exclude_regex", s.subscriptionExcludeRegex.trim().take(512))
            .putBoolean("subscription_use_proxy_tun", s.subscriptionUseProxyTun)
            .putBoolean("subscription_allow_http", s.subscriptionAllowHttp)
            .putBoolean("subscription_converter_enabled", s.subscriptionConverterEnabled)
            .putString("subscription_converter_url", s.subscriptionConverterUrl.trim().take(512))
            .putString("engine_log_level", "debug")
            .putString("language", s.language)
            .putString("theme_mode", s.themeMode.name)
            .putString("theme_preset", s.themePreset.name)
            .putBoolean("use_material_you", s.useMaterialYou)
            .putBoolean("use_amoled_black", s.useAmoledBlack)
            .putBoolean("haptics_enabled", s.hapticsEnabled)
            .putBoolean(
                com.lumen.core.vpn.TelemetryManager.PREF_TELEMETRY_ENABLED,
                s.telemetryEnabled
            )
            .putBoolean("reconnect_on_network_change", s.reconnectOnNetworkChange)
            .putBoolean("validate_proxy_data_path", s.validateProxyDataPath)
            .putString("server_speed_test_type", s.pingType)
            .putInt("ping_timeout_ms", s.pingTimeoutMs.coerceIn(500, 20000))
            .putInt("ping_concurrency", s.pingConcurrency.coerceIn(1, 32))
            .putString("ping_url", s.pingUrl.trim().take(512))
            .putInt("ping_attempts", s.pingAttempts.coerceIn(1, 10))
            .putString("ping_aggregate", s.pingAggregate)
            .putInt("ping_retry_delay_ms", s.pingRetryDelayMs.coerceIn(0, 5000))
            .putInt("ping_good_ms", s.pingGoodMs.coerceIn(10, 2000))
            .putInt("ping_fair_ms", s.pingFairMs.coerceIn(20, 5000))
            .putBoolean("ping_auto_on_open", s.pingAutoOnOpen)
            .putBoolean("ping_auto_delete_unreachable", s.pingAutoDeleteUnreachable)
            .putInt("ping_auto_delete_threshold_ms", s.pingAutoDeleteThresholdMs.coerceIn(0, 100))
            .putBoolean("auto_check_updates", s.autoCheckUpdates)
            .putString("dashboard_style", s.dashboardStyle.name)
            .putString(PREF_LAUNCHER_ICON, s.launcherIcon.name)
            .apply()
        // Persist first, then flip the components: if the process dies in between, the
        // startup reconcile re-applies the stored choice instead of losing it.
        if (launcherIconChanged) {
            val wanted = s.launcherIcon
            viewModelScope.launch(Dispatchers.IO) {
                runCatching { LauncherIconManager.applyOption(getApplication<Application>(), wanted) }
            }
        }
        if (autoUpdatesEnabled) checkForAndroidUpdate(force = true)
        // The log settings live in the bus under its own keys. Only the master switch
        // is user facing now; verbosity and retention keep their stored defaults so
        // turning logging back on restores the behaviour it had before.
        VpnLogBus.updateSettings(
            getApplication<Application>(),
            VpnLogBus.settings.value.copy(
                enabled = s.loggingEnabled,
                persist = s.loggingEnabled
            )
        )
        if (telemetryChanged) {
            val application = getApplication<Application>()
            com.lumen.core.vpn.TelemetryManager.setEnabled(application, s.telemetryEnabled)
            if (s.telemetryEnabled) {
                com.lumen.core.vpn.TelemetryManager.sendHeartbeatNow(application, viewModelScope)
            }
        }
        scheduleStoredVpnConfigRefresh()
    }

    // ---------- Socks5 authorization ----------
    // The credentials live in preferences and are generated once, so the local
    // proxy keeps the same login between restarts until the user resets it.
    private fun ensureSocks5Username(): String {
        val stored = prefs.getString("socks5_username", null)?.trim().orEmpty()
        if (stored.isNotEmpty()) return stored
        val generated = com.lumen.ui.screens.generateSocks5Username()
        prefs.edit().putString("socks5_username", generated).apply()
        return generated
    }

    private fun ensureSocks5Password(): String {
        val stored = prefs.getString("socks5_password", null)?.trim().orEmpty()
        if (stored.isNotEmpty()) return stored
        val generated = com.lumen.ui.screens.generateSocks5Password()
        prefs.edit().putString("socks5_password", generated).apply()
        return generated
    }

    // ---------- Geo resources ----------
    private val geoResourcesDir = File(app.filesDir, "georesources").apply { mkdirs() }
    private val _geoResources = MutableStateFlow(
        run {
            installBundledGeoResources()
            scanGeoResources()
        }
    )
    val geoResources: StateFlow<List<GeoResourceUiModel>> = _geoResources
    private val _isUpdatingGeoResources = MutableStateFlow(false)
    val isUpdatingGeoResources: StateFlow<Boolean> = _isUpdatingGeoResources

    // Only binary rule sets are listed: the core stopped reading the legacy .dat
    // databases, so a leftover geosite.dat says nothing about what it will load.
    private fun scanGeoResources(): List<GeoResourceUiModel> =
        (geoResourcesDir.listFiles()?.asList() ?: emptyList())
            .filter { it.isFile && it.name.endsWith(".srs", ignoreCase = true) }
            .sortedBy { it.name.lowercase(Locale.US) }
            .map { GeoResourceUiModel(it.name, it.length(), it.lastModified()) }

    /**
     * A fresh install must be able to apply the default Russian routes before it
     * has network access to GitHub. The ads set is provider-independent and is
     * always installed, while the Russian pair is only restored when Russia is
     * the active source. Existing downloaded files are never overwritten.
     */
    private fun installBundledGeoResources() {
        val names = buildList {
            add("geosite-category-ads-all.srs")
            if (geoRegionCode(_settings.value.geoResourceSource) == "ru") {
                add("geosite-category-ru.srs")
                add("geoip-ru.srs")
            }
        }
        names.forEach { name ->
            val target = File(geoResourcesDir, name)
            if (target.isFile && target.length() > 0L) return@forEach
            val temporary = File(geoResourcesDir, "$name.bundled")
            runCatching {
                getApplication<Application>().assets.open("georesources/$name").use { input ->
                    temporary.outputStream().use { output -> input.copyTo(output) }
                }
                check(temporary.length() > 0L) { "Bundled geo resource is empty: $name" }
                replaceGeoResource(temporary, target)
            }.onFailure {
                temporary.delete()
            }
        }
    }

    fun refreshGeoResources() {
        _geoResources.value = scanGeoResources()
    }

    fun downloadGeoResources(requestedSource: String) {
        // Claim the flag before launching: reading it here and setting it inside the
        // coroutine let two calls in the dispatch window share the same temp files.
        if (!_isUpdatingGeoResources.compareAndSet(expect = false, update = true)) return
        viewModelScope.launch(Dispatchers.IO) {
            val staged = mutableListOf<Pair<String, File>>()
            try {
                val source = requestedSource.trim().ifBlank { _settings.value.geoResourceSource }
                val code = geoRegionCode(source)
                val settingsBeforeSwitch = _settings.value
                val required = setOf(
                    "geosite" to if (code == "ru") "category-ru" else code,
                    "geoip" to code
                )
                // Downloading the sets here is what keeps a start offline-safe: a
                // remote rule set is fetched while the core boots and a blocked
                // raw.githubusercontent.com aborts the whole tunnel.
                val targets = geoRuleSetsForRegion(
                    code = code,
                    directDomains = settingsBeforeSwitch.directDomains,
                    directIpCidrs = settingsBeforeSwitch.directIpCidrs
                ).map { ruleSet ->
                    val (kind, geoCode) = ruleSet
                    Triple(
                        "$kind-$geoCode.srs",
                        com.lumen.core.config.builder.SingboxConfigBuilder
                            .ruleSetUrl(kind, geoCode, source),
                        ruleSet in required
                    )
                }
                targets.forEach { (name, link, isRequired) ->
                    val temporary = File(geoResourcesDir, "$name.${UUID.randomUUID()}.download")
                    runCatching {
                        downloadGeoRuleSet(name, link, temporary)
                        staged += name to temporary
                    }.onFailure { failure ->
                        temporary.delete()
                        if (isRequired) throw failure
                        // Optional custom categories may not be published by every source.
                        // They are omitted from the new one-region set instead of retaining
                        // an identically named file from the previous provider.
                        log("Optional geo rule set skipped: $name: ${failure.message}")
                    }
                }

                // Every required file exists in staging before the active set is touched.
                staged.forEach { (name, temporary) ->
                    val target = File(geoResourcesDir, name)
                    replaceGeoResource(temporary, target)
                    log("Geo rule set updated: $name (${target.length()} bytes)")
                }
                val keep = staged.map { it.first.lowercase(Locale.US) }.toSet()
                geoResourcesDir.listFiles()?.forEach { file ->
                    if (!file.isFile) return@forEach
                    val lower = file.name.lowercase(Locale.US)
                    val stale = lower.endsWith(".download") ||
                        (lower.endsWith(".srs") && lower !in keep)
                    if (stale && file.delete()) log("Geo rule set removed: ${file.name}")
                }

                // Source and automatic rules switch together, only after the complete
                // mandatory set is installed. A failed download leaves the old region live.
                withContext(Dispatchers.Main) {
                    updateSettings(
                        switchAutomaticGeoRegion(_settings.value, code).copy(
                            geoResourceSource = source
                        )
                    )
                    refreshGeoResources()
                    log("Geo resources and routing switched to $code")
                }
            } catch (e: Exception) {
                log("Geo resources update failed: ${e.message}")
            } finally {
                staged.forEach { (_, file) -> if (file.exists()) file.delete() }
                _isUpdatingGeoResources.value = false
            }
        }
    }

    private fun downloadGeoRuleSet(name: String, link: String, temporary: File) {
        val connection = URL(link).openConnection() as HttpURLConnection
        connection.connectTimeout = 20_000
        connection.readTimeout = 120_000
        connection.instanceFollowRedirects = true
        connection.setRequestProperty("User-Agent", "Lumen/${net.kramb.lumen.BuildConfig.VERSION_NAME}")
        try {
            if (connection.responseCode !in 200..299) {
                error("$name: HTTP ${connection.responseCode}")
            }
            if (connection.contentLengthLong > GEO_RESOURCE_MAX_BYTES) {
                error("$name: exceeded the 256 MB limit")
            }
            connection.inputStream.use { input ->
                temporary.outputStream().use { output ->
                    val buffer = ByteArray(DEFAULT_BUFFER_SIZE)
                    var copied = 0L
                    while (true) {
                        val count = input.read(buffer)
                        if (count < 0) break
                        copied += count
                        if (copied > GEO_RESOURCE_MAX_BYTES) {
                            error("$name: exceeded the 256 MB limit")
                        }
                        output.write(buffer, 0, count)
                    }
                    if (copied < 64L) error("$name: file is too small")
                }
            }
        } finally {
            connection.disconnect()
        }
    }

    private fun replaceGeoResource(source: File, target: File) {
        try {
            Files.move(
                source.toPath(),
                target.toPath(),
                StandardCopyOption.ATOMIC_MOVE,
                StandardCopyOption.REPLACE_EXISTING
            )
        } catch (_: AtomicMoveNotSupportedException) {
            Files.move(
                source.toPath(),
                target.toPath(),
                StandardCopyOption.REPLACE_EXISTING
            )
        }
    }

    // ---------- Split tunneling ----------
    private val _splitMode = MutableStateFlow(
        runCatching { SplitModeUi.valueOf(prefs.getString("split_mode", "DISABLED") ?: "DISABLED") }
            .getOrDefault(SplitModeUi.DISABLED)
    )
    val splitMode: StateFlow<SplitModeUi> = _splitMode

    private val _splitPackages = MutableStateFlow(
        prefs.getStringSet("split_packages", emptySet())?.toSet() ?: emptySet()
    )

    private val _installedApps = MutableStateFlow<List<AppEntryUiModel>>(emptyList())
    private val _isLoadingApps = MutableStateFlow(false)
    val isLoadingApps: StateFlow<Boolean> = _isLoadingApps
    // Pinned copy of v2rayNG's maintained proxy package list at commit
    // 9896dd2974a9739090e5d48e421a7971cb484a08. Keeping it in the APK makes
    // Auto-select immediate and deterministic even without Internet.
    private val proxyAutoSelectPackages: Set<String> by lazy {
        runCatching {
            getApplication<Application>().assets.open("proxy_package_name")
                .bufferedReader()
                .useLines { lines ->
                    lines.map(String::trim)
                        .filter { it.isNotEmpty() && !it.startsWith("#") }
                        .toSet()
                }
        }.getOrDefault(emptySet())
    }

    val apps: StateFlow<List<AppEntryUiModel>> =
        combine(_installedApps, _splitPackages) { list, selected ->
            list.map { it.copy(isSelected = it.packageName in selected) }
        }.stateIn(viewModelScope, SharingStarted.Eagerly, emptyList())

    fun setSplitMode(mode: SplitModeUi) {
        _splitMode.value = mode
        prefs.edit().putString("split_mode", mode.name).apply()
        if (mode != SplitModeUi.DISABLED) loadInstalledApps()
        scheduleStoredVpnConfigRefresh()
    }

    fun toggleApp(app: AppEntryUiModel) {
        val next = _splitPackages.value.toMutableSet()
        if (!next.add(app.packageName)) next.remove(app.packageName)
        _splitPackages.value = next
        prefs.edit().putStringSet("split_packages", next).apply()
        scheduleStoredVpnConfigRefresh()
    }

    fun autoSelectApps() {
        val selected = SplitAppAutoSelector.select(
            mode = _splitMode.value,
            apps = _installedApps.value,
            proxyPackages = proxyAutoSelectPackages
        )
        _splitPackages.value = selected
        prefs.edit().putStringSet("split_packages", selected).apply()
        scheduleStoredVpnConfigRefresh()
    }

    fun clearAppSelection() {
        _splitPackages.value = emptySet()
        prefs.edit().putStringSet("split_packages", emptySet()).apply()
        scheduleStoredVpnConfigRefresh()
    }

    fun loadInstalledApps() {
        if (_isLoadingApps.value) return
        _isLoadingApps.value = true
        viewModelScope.launch(Dispatchers.IO) {
            try {
                val application = getApplication<Application>()
                val pm = application.packageManager
                val list = pm.getInstalledApplications(PackageManager.GET_META_DATA)
                    .asSequence()
                    .filter { it.packageName != application.packageName && it.enabled }
                    .filter {
                        pm.checkPermission(
                            android.Manifest.permission.INTERNET,
                            it.packageName
                        ) == PackageManager.PERMISSION_GRANTED
                    }
                    .map {
                        AppEntryUiModel(
                            packageName = it.packageName,
                            label = pm.getApplicationLabel(it).toString(),
                            icon = runCatching {
                                pm.getApplicationIcon(it).toBitmap(width = 48, height = 48).asImageBitmap()
                            }.getOrNull(),
                            isSystem = it.flags and ApplicationInfo.FLAG_SYSTEM != 0
                        )
                    }
                    .sortedBy { it.label.lowercase(Locale.getDefault()) }
                    .toList()
                _installedApps.value = list
                log("Found ${list.size} network-capable apps")
                // Uninstalled packages left in the split list make the service fall
                // back silently, so drop them once the real inventory is known.
                val stale = _splitPackages.value.filterNot { packageName ->
                    runCatching { pm.getApplicationInfo(packageName, 0) }.isSuccess
                }
                if (stale.isNotEmpty()) {
                    val kept = _splitPackages.value - stale.toSet()
                    _splitPackages.value = kept
                    prefs.edit().putStringSet("split_packages", kept).apply()
                    scheduleStoredVpnConfigRefresh()
                    log("Removed ${stale.size} uninstalled app(s) from the split list")
                }
            } catch (e: Exception) {
                log("Failed to list apps: ${e.message}")
            } finally {
                _isLoadingApps.value = false
            }
        }
    }

    // ---------- Nodes ----------
    private val _selectedNodeId = MutableStateFlow(prefs.getString("selected_node_id", null))

    private val nodeEntities: StateFlow<List<NodeEntity>> = nodeDao.getNodes()
        .stateIn(viewModelScope, SharingStarted.Eagerly, emptyList())

    private val countryCachePrefs =
        app.getSharedPreferences("lumen_country_cache", Context.MODE_PRIVATE)
    private val _resolvedCountryCodes = MutableStateFlow(
        countryCachePrefs.all.mapNotNull { (host, value) ->
            (value as? String)?.takeIf { it.length == 2 }?.let { host to it.uppercase(Locale.US) }
        }.toMap()
    )
    private val countryLookupAttempted =
        java.util.concurrent.ConcurrentHashMap.newKeySet<String>()

    init {
        // Desktop Lumen resolves otherwise anonymous WireGuard endpoints through
        // GeoIP. Android does the same asynchronously and caches the result; WARP
        // is deliberately excluded because its endpoint location is not the
        // virtual location represented by the profile.
        viewModelScope.launch(Dispatchers.IO) {
            var previousConfigFingerprint: List<NodeConfigFingerprint>? = null
            nodeEntities.collectLatest { entities ->
                val fingerprint = entities.map { NodeConfigFingerprint.from(it) }
                if (fingerprint != previousConfigFingerprint) {
                    previousConfigFingerprint = fingerprint
                    scheduleStoredVpnConfigRefresh()
                }
                entities.forEach { entity ->
                    if (!shouldResolveWireGuardCountry(entity)) return@forEach
                    val host = normalizedEndpointHost(entity.server)
                    if (host.isEmpty() || host in _resolvedCountryCodes.value) return@forEach
                    if (!countryLookupAttempted.add(host)) return@forEach
                    val code = resolveCountryCode(host)
                    if (code.isNotEmpty()) {
                        countryCachePrefs.edit().putString(host, code).apply()
                        _resolvedCountryCodes.value = _resolvedCountryCodes.value + (host to code)
                    }
                }
            }
        }
    }

    // Cache of expensive per-node computations (flag stripping, country detection,
    // display-protocol extraction). Keyed by node id + content fingerprint so ping
    // updates or selection changes don't recompute regex/uppercase work per node.
    private data class NodeUiCacheEntry(val fingerprint: Int, val base: NodeUiModel)
    private data class NodeConfigFingerprint(
        val id: String,
        val name: String,
        val protocol: String,
        val server: String,
        val port: Int,
        val link: String,
        val outboundJson: String,
        val subscriptionId: String?,
        val isAutoNode: Boolean
    ) {
        companion object {
            fun from(entity: NodeEntity) = NodeConfigFingerprint(
                id = entity.id,
                name = entity.name,
                protocol = entity.protocol,
                server = entity.server,
                port = entity.port,
                link = entity.link,
                outboundJson = entity.outboundJson,
                subscriptionId = entity.subscriptionId,
                isAutoNode = entity.isAutoNode
            )
        }
    }
    private val nodeUiCache = java.util.concurrent.ConcurrentHashMap<String, NodeUiCacheEntry>()

    // ---------- Custom server groups ----------
    private val groupEntities: StateFlow<List<ServerGroupEntity>> = serverGroupDao.getGroups()
        .stateIn(viewModelScope, SharingStarted.Eagerly, emptyList())
    private val groupMembers: StateFlow<List<NodeGroupMemberEntity>> = serverGroupDao.getMembers()
        .stateIn(viewModelScope, SharingStarted.Eagerly, emptyList())

    val nodes: StateFlow<List<NodeUiModel>> =
        combine(
            nodeEntities,
            _selectedNodeId,
            _resolvedCountryCodes,
            groupEntities,
            groupMembers
        ) { list, selectedId, resolvedCountryCodes, customGroups, members ->
            val liveIds = HashSet<String>(list.size * 2)
            // Membership is keyed on the node's stable key, not its row id, so it
            // survives the delete/re-insert a subscription refresh does. Rows pointing
            // at a group that no longer exists are ignored rather than hiding a server.
            val liveGroupIds = customGroups.mapTo(HashSet()) { it.id }
            val membership = members.asSequence()
                .filter { it.groupId in liveGroupIds }
                .associate { it.nodeKey to it.groupId }
            val mapped = list.mapNotNull { e ->
                runCatching {
                    liveIds.add(e.id)
                    val resolvedCountry = resolvedCountryCodes[normalizedEndpointHost(e.server)].orEmpty()
                    val fingerprint = 31 * (31 * (31 * e.name.hashCode() + e.server.hashCode()) +
                        e.protocol.hashCode()) +
                        (e.outboundJson.hashCode() xor e.link.hashCode() xor resolvedCountry.hashCode())
                    val cached = nodeUiCache[e.id]
                    val base = if (cached != null && cached.fingerprint == fingerprint) {
                        cached.base
                    } else {
                        val sourceName = e.name.ifBlank { e.server.ifBlank { "Server" } }
                        val safeServer = e.server
                        val countryCode = runCatching {
                            CountryFlagHelper.detectCountryStrict(sourceName, safeServer)
                                .ifBlank { resolvedCountry }
                                .uppercase(Locale.US)
                        }.getOrDefault(resolvedCountry)
                        val strippedName = CountryFlagHelper
                            .serverDisplayNameWithoutCountryPrefix(sourceName, countryCode)
                            .let(::stripFlagEmoji)
                            .ifBlank { safeServer.ifBlank { "Server" } }
                        // AWG/WireGuard links carry no human name, so the parser generates a
                        // technical one ("AmneziaWG-1.2.3.4"). Show the location instead, the
                        // same way VLESS subscription entries already do.
                        val safeName =
                            locationNameOrNull(strippedName, safeServer, countryCode) ?: strippedName
                        val safeProtocol = e.protocol.ifBlank { "vless" }
                        val autoFlag = e.isAutoNode || safeProtocol.equals("auto", true)
                        val extractedProtocol =
                            extractDisplayProtocol(safeProtocol, e.outboundJson, e.link)
                        // WARP selector pools remain urltest nodes internally, but their
                        // public protocol is MASQUE/WARP or AWG/WARP rather than AUTO.
                        val displayProto = if (
                            autoFlag &&
                            !extractedProtocol.equals("WARP", true) &&
                            !extractedProtocol.endsWith("/WARP", true)
                        ) "AUTO" else extractedProtocol
                        NodeUiModel(
                            id = e.id,
                            name = safeName,
                            protocol = safeProtocol,
                            server = safeServer,
                            port = e.port,
                            pingMs = null,
                            countryCode = countryCode,
                            isAutoNode = autoFlag,
                            isSelected = false,
                            subscriptionId = e.subscriptionId,
                            displayProtocol = displayProto
                        ).also { nodeUiCache[e.id] = NodeUiCacheEntry(fingerprint, it) }
                    }
                    base.copy(
                        port = e.port,
                        pingMs = e.pingMs,
                        isAutoNode = e.isAutoNode || e.protocol.equals("auto", true),
                        subscriptionId = e.subscriptionId,
                        groupId = membership[e.groupKey()],
                        isSelected = e.id == selectedId
                    )
                }.getOrNull()
            }
            nodeUiCache.keys.retainAll(liveIds)
            // Ordering is a UI concern: the screens sort with the shared, persisted choice.
            mapped
        }.flowOn(Dispatchers.Default)
            .stateIn(viewModelScope, SharingStarted.Eagerly, emptyList())

    val activeNode: StateFlow<NodeUiModel?> = nodes
        .map { list -> list.firstOrNull { it.isSelected } ?: list.firstOrNull() }
        .stateIn(viewModelScope, SharingStarted.Eagerly, null)

    fun selectNode(node: NodeUiModel) {
        if (_selectedNodeId.value != node.id) resetConnectedPing()
        persistSelectedNodeIdentity(node.id, node.name)
        scheduleStoredVpnConfigRefresh()
        log("Selected ${node.name}")
    }

    private fun persistSelectedNodeIdentity(id: String, name: String) {
        _selectedNodeId.value = id
        // The name is mirrored into prefs so the home screen widget can label
        // itself without opening the database.
        // Base64 of the UTF-8 bytes avoids any charset mangling between the app
        // process and the widget process.
        val nameB64 = android.util.Base64.encodeToString(
            name.toByteArray(Charsets.UTF_8),
            android.util.Base64.NO_WRAP
        )
        prefs.edit()
            .putString("selected_node_id", id)
            .putString("selected_node_name", name)
            .putString("selected_node_name_b64", nameB64)
            .apply()
        com.lumen.app.widget.LumenWidgetProvider.sendUpdateBroadcast(getApplication())
    }

    fun deleteNode(node: NodeUiModel) {
        viewModelScope.launch(Dispatchers.IO) {
            val key = nodeEntities.value.firstOrNull { it.id == node.id }?.groupKey()
            nodeDao.deleteNodeById(node.id)
            if (key != null) serverGroupDao.assignNodes(listOf(key), null)
            log("Deleted node ${node.name}")
        }
    }

    // Deletes servers belonging to the default / manual group only.
    fun deleteAllNodes() {
        viewModelScope.launch(Dispatchers.IO) {
            val keys = nodeEntities.value.filter { it.subscriptionId == null }.map { it.groupKey() }
            nodeDao.deleteManualNodes()
            if (keys.isNotEmpty()) serverGroupDao.assignNodes(keys, null)
            log("Deleted all manual nodes")
        }
    }

    /**
     * Groups the user made, with the number of servers currently assigned to each.
     */
    val serverGroups: StateFlow<List<ServerGroupUiModel>> =
        combine(groupEntities, nodes) { groups, nodeList ->
            groups.map { entity ->
                ServerGroupUiModel(
                    id = entity.id,
                    name = entity.name,
                    nodeCount = nodeList.count { it.groupId == entity.id }
                )
            }
        }.stateIn(viewModelScope, SharingStarted.Eagerly, emptyList())

    fun createServerGroup(name: String) {
        val clean = name.trim().take(64)
        if (clean.isEmpty()) return
        viewModelScope.launch(Dispatchers.IO) {
            serverGroupDao.insertGroup(ServerGroupEntity(name = clean))
            log("Created server group $clean")
        }
    }

    fun renameServerGroup(groupId: String, name: String) {
        val clean = name.trim().take(64)
        if (clean.isEmpty()) return
        viewModelScope.launch(Dispatchers.IO) {
            serverGroupDao.renameGroup(groupId, clean)
            log("Renamed server group to $clean")
        }
    }

    /** Drops the group only: its servers stay and fall back to their default bucket. */
    fun deleteServerGroup(groupId: String) {
        viewModelScope.launch(Dispatchers.IO) {
            val freed = serverGroupDao.membersOf(groupId).size
            serverGroupDao.deleteGroup(groupId)
            log("Deleted server group, $freed server(s) moved back to the default group")
        }
    }

    /**
     * Moves [targets] into [groupId]; null clears the assignment. Keyed on the node's
     * stable key so a later subscription refresh keeps the grouping.
     */
    fun assignNodesToGroup(targets: List<NodeUiModel>, groupId: String?) {
        if (targets.isEmpty()) return
        val ids = targets.mapTo(HashSet()) { it.id }
        viewModelScope.launch(Dispatchers.IO) {
            val keys = nodeEntities.value.filter { it.id in ids }.map { it.groupKey() }.distinct()
            if (keys.isEmpty()) return@launch
            serverGroupDao.assignNodes(keys, groupId)
            val destination = if (groupId == null) "no group" else "a group"
            log("Moved ${keys.size} server(s) to $destination")
        }
    }

    fun draftForNode(node: NodeUiModel): NodeDraft =
        NodeDraftMapper.draftFromEntity(nodeEntities.value.firstOrNull { it.id == node.id })
            ?: NodeDraft()

    /**
     * [onResult] receives null on success and the reason on failure, so the editor
     * can stay open instead of pretending an unparsable draft was saved.
     */
    fun saveDraft(draft: NodeDraft, onResult: (String?) -> Unit = {}) {
        viewModelScope.launch(Dispatchers.IO) {
            try {
                val existing = draft.id?.let { id -> nodeEntities.value.firstOrNull { it.id == id } }
                // The mapper leaves subscriptionId null, which is what a hand-made
                // node needs: it belongs to the default (manual) group. An edited
                // node must keep the group it came from instead, otherwise saving a
                // subscription server silently detaches it from its subscription.
                val entity = NodeDraftMapper.entityFromDraft(draft)
                    .copy(subscriptionId = existing?.subscriptionId)
                if (draft.id != null) nodeDao.updateNode(entity) else nodeDao.insertNode(entity)
                log("Saved node ${entity.name}")
                // A new node is only visible in the default group, so open it there.
                if (draft.id == null) {
                    focusServerGroup(SERVER_GROUP_MANUAL)
                    emitEvent(LumenEvent.ServerAdded)
                }
                withContext(Dispatchers.Main) { onResult(null) }
            } catch (e: Exception) {
                log("Failed to save node: ${e.message}")
                withContext(Dispatchers.Main) { onResult(e.message ?: "Failed to save node") }
            }
        }
    }

    private val _importState = MutableStateFlow(ImportUiState())
    val importState: StateFlow<ImportUiState> = _importState

    // ---------- Where an import lands ----------
    // ServerListScreen reads the group it opens on from KEY_SERVERS_LAST_GROUP, and so
    // does the dashboard, so an import drives that one preference instead of growing a
    // second source of truth. The counter only tells the navigator that it changed.
    private val _serverGroupFocus = MutableStateFlow(0)
    val serverGroupFocus: StateFlow<Int> = _serverGroupFocus
    private var consumedServerGroupFocus = 0

    private fun focusServerGroup(group: String) {
        prefs.edit().putString(KEY_SERVERS_LAST_GROUP, group).apply()
        _serverGroupFocus.update { it + 1 }
    }

    /** A file or link opened from outside the app always lands in the default group. */
    fun focusDefaultServerGroup() = focusServerGroup(SERVER_GROUP_MANUAL)

    /**
     * The user-made group an import should land in: the group currently open on the
     * Servers tab / dashboard, but only when it is a custom one. "All", "Default" and
     * subscription groups return null, which keeps the historic Default behaviour
     * (a subscription group cannot own hand-imported servers).
     */
    private fun importTargetGroup(): ServerGroupUiModel? {
        val current = prefs.getString(KEY_SERVERS_LAST_GROUP, null) ?: return null
        return serverGroups.value.firstOrNull { it.id == current }
    }

    /**
     * True exactly once per request, so a recreate() (language change) does not
     * replay the last import's navigation.
     */
    fun consumeServerGroupFocus(): Boolean {
        val pending = _serverGroupFocus.value
        if (pending == consumedServerGroupFocus) return false
        consumedServerGroupFocus = pending
        return true
    }

    // Classification parses the payload, so it never runs on the caller's thread:
    // a shared file or a pasted blob can be megabytes of links.
    fun prepareImportText(text: String?) {
        viewModelScope.launch(Dispatchers.Default) {
            val state = classifiedImportState(text)
            withContext(Dispatchers.Main) { _importState.value = state }
        }
    }

    private fun classifiedImportState(text: String?): ImportUiState =
        when (val classification = ImportClassifier.classify(text)) {
            is ImportClassification.Rejected -> ImportUiState(
                phase = ImportPhaseUi.ERROR,
                title = "Nothing to import",
                message = classification.message
            )
            is ImportClassification.Ready -> ImportUiState(
                phase = ImportPhaseUi.AWAITING,
                kind = if (classification.kind == ImportKind.SUBSCRIPTION) {
                    ImportKindUi.SUBSCRIPTION
                } else ImportKindUi.CONFIG,
                raw = classification.normalized,
                title = if (classification.kind == ImportKind.SUBSCRIPTION) {
                    "Import subscription?"
                } else "Import server config?",
                message = if (classification.kind == ImportKind.SUBSCRIPTION) {
                    "The link will be downloaded and added as a subscription."
                } else "Supported servers will be added to Default."
            )
        }

    /**
     * Deep-linked / shared / picked content: the stream is read on IO and aborted
     * past the parser's byte limit, so a hostile ACTION_SEND cannot freeze the UI
     * thread or exhaust the heap before any size check runs.
     */
    fun prepareImportFromUri(context: Context, uri: android.net.Uri, asFile: Boolean) {
        val resolver = context.contentResolver
        viewModelScope.launch(Dispatchers.IO) {
            val content = readBoundedStream(resolver, uri)
            val state = when {
                content == null -> ImportUiState(
                    phase = ImportPhaseUi.ERROR,
                    title = "Nothing to import",
                    message = "The file is empty, unreadable or exceeds the " +
                        "${LinkParser.MAX_IMPORT_BYTES / 1024 / 1024} MiB import limit"
                )
                asFile -> fileImportState(content)
                else -> classifiedImportState(content)
            }
            withContext(Dispatchers.Main) { _importState.value = state }
        }
    }

    private fun readBoundedStream(
        resolver: android.content.ContentResolver,
        uri: android.net.Uri
    ): String? = runCatching {
        resolver.openInputStream(uri)?.use { input ->
            val output = java.io.ByteArrayOutputStream()
            val buffer = ByteArray(DEFAULT_BUFFER_SIZE)
            var total = 0L
            while (true) {
                val count = input.read(buffer)
                if (count < 0) break
                total += count
                if (total > LinkParser.MAX_IMPORT_BYTES) return@use null
                output.write(buffer, 0, count)
            }
            output.toByteArray().toString(Charsets.UTF_8).takeIf { it.isNotBlank() }
        }
    }.getOrNull()

    fun dismissImport() {
        if (_importState.value.phase != ImportPhaseUi.IMPORTING) {
            _importState.value = ImportUiState()
        }
    }

    fun confirmImport() {
        val pending = _importState.value
        if (pending.phase != ImportPhaseUi.AWAITING || pending.kind == null) return
        _importState.value = pending.copy(phase = ImportPhaseUi.IMPORTING, message = "Importing…")
        viewModelScope.launch(Dispatchers.IO) {
            try {
                when (pending.kind) {
                    ImportKindUi.SUBSCRIPTION -> {
                        val url = (ImportClassifier.classify(pending.raw) as? ImportClassification.Ready)
                            ?.takeIf { it.kind == ImportKind.SUBSCRIPTION }?.normalized
                            ?: error("Invalid subscription URL")
                        val sub = SubscriptionEntity(
                            name = url.substringAfter("://").substringBefore('/').take(80),
                            url = url
                        )
                        subscriptionDao.insertSubscription(sub)
                        val imported = try {
                            refreshSubscriptionInternal(sub, rethrow = true)
                        } catch (error: Exception) {
                            nodeDao.deleteNodesBySubscription(sub.id)
                            subscriptionDao.deleteSubscriptionById(sub.id)
                            throw error
                        }
                        if (imported <= 0) {
                            nodeDao.deleteNodesBySubscription(sub.id)
                            subscriptionDao.deleteSubscriptionById(sub.id)
                            error("Subscription contains no supported servers")
                        }
                        // Open the server list on the group that just appeared.
                        focusServerGroup(sub.id)
                        emitEvent(LumenEvent.ServerAdded)
                        _importState.value = ImportUiState(
                            phase = ImportPhaseUi.SUCCESS,
                            title = "Subscription imported",
                            message = "$imported server(s) added"
                        )
                    }
                    ImportKindUi.CONFIG -> {
                        val (parsed, errors) = LinkParser.parseLinksText(pending.raw)
                        errors.take(3).forEach { log("Import warning: $it") }
                        val valid = parsed.filter {
                            it.name.length <= 512 && it.server.length <= 512 &&
                                (it.scheme == "auto" || it.server.isNotBlank()) &&
                                (it.scheme == "auto" || it.port in 1..65535) && it.link.length <= 65_536
                        }.take(LinkParser.MAX_IMPORT_NODES)
                        if (valid.isEmpty()) error("No supported server configs found")
                        val entities = valid.map { it.toEntity(null) }
                        db.withTransaction { nodeDao.insertNodes(entities) }
                        // A user-made group that is currently open owns the import: only
                        // subscriptions and "all" fall back to Default. Assignment is keyed
                        // the same way as a manual move, so the servers stay in the group.
                        val target = importTargetGroup()
                        if (target != null) {
                            serverGroupDao.assignNodes(entities.map { it.groupKey() }.distinct(), target.id)
                        }
                        focusServerGroup(target?.id ?: SERVER_GROUP_MANUAL)
                        emitEvent(LumenEvent.ServerAdded)
                        val destinationName = target?.name ?: "Default"
                        _importState.value = ImportUiState(
                            phase = ImportPhaseUi.SUCCESS,
                            title = "Import complete",
                            message = "${valid.size} server(s) added to $destinationName"
                        )
                        log("Imported ${valid.size} node(s) into $destinationName")
                    }
                    null -> error("Import request expired")
                }
            } catch (e: Exception) {
                val reason = e.message?.take(240) ?: "Unknown import error"
                _importState.value = ImportUiState(
                    phase = ImportPhaseUi.ERROR,
                    title = "Import failed",
                    message = reason
                )
                log("Import failed: $reason")
            }
        }
    }

    @Deprecated("Use prepareImportText so untrusted input requires confirmation")
    fun importText(text: String) = prepareImportText(text)

    /**
     * Like [prepareImportText] but for files: bypasses the clipboard-size limit,
     * reads charset-safe bytes, and skips the 1 MiB ImportClassifier gate.
     * For files we trust the user selected them intentionally, so we go straight
     * to the parser and show a confirmation dialog with the result count.
     */
    fun prepareImportFileContent(content: String?) {
        viewModelScope.launch(Dispatchers.Default) {
            val state = fileImportState(content)
            withContext(Dispatchers.Main) { _importState.value = state }
        }
    }

    private fun fileImportState(content: String?): ImportUiState {
        if (content.isNullOrBlank()) {
            return ImportUiState(
                phase = ImportPhaseUi.ERROR,
                title = "Nothing to import",
                message = "The file is empty"
            )
        }
        val bytes = content.toByteArray(Charsets.UTF_8)
        if (bytes.size > LinkParser.MAX_IMPORT_BYTES) {
            return ImportUiState(
                phase = ImportPhaseUi.ERROR,
                title = "File too large",
                message = "File exceeds the ${LinkParser.MAX_IMPORT_BYTES / 1024 / 1024} MiB import limit"
            )
        }
        // Quick-check: if it's a bare http/https URL treat it as a subscription URL.
        val trimmed = content.trim()
        if (!trimmed.contains('\n') && (trimmed.startsWith("http://") || trimmed.startsWith("https://"))) {
            return classifiedImportState(trimmed)
        }
        // Pre-parse so we can show a meaningful summary before the user confirms.
        val (parsed, parseErrors) = try {
            LinkParser.parseLinksText(content)
        } catch (e: Exception) {
            return ImportUiState(
                phase = ImportPhaseUi.ERROR,
                title = "File parse error",
                message = e.message?.take(240) ?: "Unknown error"
            )
        }
        val valid = parsed.filter {
            it.name.length <= 512 && it.server.length <= 512 &&
                (it.scheme == "auto" || it.server.isNotBlank()) &&
                (it.scheme == "auto" || it.port in 1..65535) && it.link.length <= 65_536
        }.take(LinkParser.MAX_IMPORT_NODES)
        if (valid.isEmpty()) {
            return ImportUiState(
                phase = ImportPhaseUi.ERROR,
                title = "No supported servers",
                message = if (parseErrors.isNotEmpty()) parseErrors.take(3).joinToString("\n") else "No recognised server configs found in file"
            )
        }
        return ImportUiState(
            phase = ImportPhaseUi.AWAITING,
            kind = ImportKindUi.CONFIG,
            raw = content,
            title = "Import from file?",
            message = "${valid.size} server(s) found. They will be added to Default."
        )
    }

    private fun ParsedNode.toEntity(subscriptionId: String?) = NodeEntity(
        name = name.ifBlank { server },
        protocol = scheme,
        server = server,
        port = port,
        link = link,
        outboundJson = if (outbound.isNotEmpty()) LinkParser.toJsonString(outbound) else "",
        subscriptionId = subscriptionId,
        isAutoNode = scheme == "auto"
    )

    // ---------- Subscriptions ----------
    private val subEntities: StateFlow<List<SubscriptionEntity>> = subscriptionDao.getSubscriptions()
        .stateIn(viewModelScope, SharingStarted.Eagerly, emptyList())
    private val _subscriptionPremium = MutableStateFlow<Map<String, Map<String, String>>>(emptyMap())
    // The usage figures live in _subscriptionUsage: they are the raw
    // subscription-userinfo values, so they can be merged and persisted per key.
    // Everything else the panel says about the subscription — the announcement, the
    // support / website / premium links, the banner — is a column on the entity.
    private val _subscriptionUsage = MutableStateFlow(loadSubscriptionUsage())

    val subscriptions: StateFlow<List<SubscriptionUiModel>> =
        combine(subEntities, nodeEntities, _subscriptionPremium, _subscriptionUsage) { subs, allNodes, premium, usage ->
            val now = System.currentTimeMillis()
            subs.map { s ->
                val info = usage[s.id].orEmpty()
                SubscriptionUiModel(
                    id = s.id,
                    name = s.name,
                    url = s.url,
                    lastUpdated = s.lastUpdated,
                    nodeCount = allNodes.count { it.subscriptionId == s.id },
                    autoUpdateEnabled = s.autoUpdateEnabled,
                    premiumFeatureCount = premium[s.id]?.size ?: 0,
                    trafficSummary = info.takeIf { it.isNotEmpty() }?.let(SubscriptionUsage::summary),
                    expiryDaysLeft = SubscriptionUsage.expiryEpochSeconds(info)
                        ?.let { SubscriptionUsage.daysLeft(it, now) },
                    trafficRatio = SubscriptionUsage.ratio(info),
                    updateIntervalHours = s.updateIntervalHours.takeIf { it > 0 },
                    announce = s.announce.ifBlank { null },
                    announceUrl = s.announceUrl.ifBlank { null },
                    description = s.description.ifBlank { null },
                    telegramUrl = s.telegramUrl.ifBlank { null },
                    supportUrl = s.supportUrl.ifBlank { null },
                    supportEmail = s.supportEmail.ifBlank { null },
                    websiteUrl = s.websiteUrl.ifBlank { null },
                    premiumUrl = s.premiumUrl.ifBlank { null },
                    bannerText = s.bannerText.ifBlank { null },
                    bannerButtonText = s.bannerButtonText.ifBlank { null },
                    bannerButtonUrl = s.bannerButtonUrl.ifBlank { null },
                    bannerBgColor = s.bannerBgColor.ifBlank { null },
                    bannerButtonColor = s.bannerButtonColor.ifBlank { null },
                    hideUrl = s.hideUrl,
                    sortOrder = s.sortOrder.ifBlank { null }
                )
            }
        }.stateIn(viewModelScope, SharingStarted.Eagerly, emptyList())

    /**
     * The panel only reports usage while a refresh is running, and the figures used to
     * live in memory only: every process restart blanked the traffic and expiry rows
     * until the next successful update. They are kept in prefs instead, one line per
     * subscription, with an empty field for a value the panel has never sent.
     */
    private fun loadSubscriptionUsage(): Map<String, Map<String, Long>> =
        prefs.getString(KEY_SUBSCRIPTION_USAGE, "").orEmpty().lineSequence().mapNotNull { line ->
            val parts = line.split('|')
            if (parts.size != USAGE_KEYS.size + 1 || parts[0].isBlank()) return@mapNotNull null
            val info = linkedMapOf<String, Long>()
            USAGE_KEYS.forEachIndexed { index, key ->
                parts[index + 1].toLongOrNull()?.takeIf { it >= 0L }?.let { info[key] = it }
            }
            if (info.isEmpty()) null else parts[0] to info.toMap()
        }.toMap()

    private fun persistSubscriptionUsage(usage: Map<String, Map<String, Long>>) {
        val text = usage.entries.joinToString("\n") { (id, info) ->
            USAGE_KEYS.joinToString("|", prefix = "$id|") { key -> info[key]?.toString().orEmpty() }
        }
        prefs.edit().putString(KEY_SUBSCRIPTION_USAGE, text).apply()
    }

    /**
     * Merges one refresh into the stored figures. Only the keys the panel actually sent
     * are replaced: a response that omits `expire`, or that came back through a fallback
     * User-Agent whose answer carries no `subscription-userinfo` header at all, must not
     * reset a known good value to zero.
     */
    private fun mergeSubscriptionUsage(subscriptionId: String, fresh: Map<String, Long>) {
        if (fresh.isEmpty()) return
        val merged = SubscriptionUsage.merge(_subscriptionUsage.value[subscriptionId].orEmpty(), fresh)
        _subscriptionUsage.value = _subscriptionUsage.value + (subscriptionId to merged)
        persistSubscriptionUsage(_subscriptionUsage.value)
    }

    private fun forgetSubscriptionUsage(subscriptionId: String) {
        if (subscriptionId !in _subscriptionUsage.value) return
        _subscriptionUsage.value = _subscriptionUsage.value - subscriptionId
        persistSubscriptionUsage(_subscriptionUsage.value)
    }

    private val _refreshingIds = MutableStateFlow<Set<String>>(emptySet())
    val refreshingIds: StateFlow<Set<String>> = _refreshingIds

    // lastUpdated only advances on a successful refresh, so a failing or empty
    // subscription would stay due forever and be retried on every 60 s tick.
    private val subscriptionFailures = java.util.concurrent.ConcurrentHashMap<String, Int>()
    private val subscriptionRetryAfter = java.util.concurrent.ConcurrentHashMap<String, Long>()

    // Declared here (not in the top init block) so every field the loop touches exists.
    init { startSubscriptionAutoUpdate() }

    fun addSubscription(name: String, url: String) {
        viewModelScope.launch(Dispatchers.IO) {
            val sub = SubscriptionEntity(
                name = name.ifBlank { url.substringAfter("://").take(40) },
                url = url
            )
            subscriptionDao.insertSubscription(sub)
            log("Added subscription ${sub.name}")
            if (refreshSubscriptionInternal(sub, adoptProfileTitle = name.isBlank()) > 0) {
                focusServerGroup(sub.id)
                emitEvent(LumenEvent.ServerAdded)
            }
        }
    }

    /**
     * Updates only user-owned subscription fields. Nodes and provider metadata stay intact
     * until the user refreshes the subscription from its new URL.
     *
     * Validation is synchronous so the edit dialog can stay open and mark invalid input.
     */
    fun updateSubscription(model: SubscriptionUiModel, name: String, url: String): Boolean {
        val edit = validateSubscriptionEdit(
            existingUrl = model.url,
            name = name,
            url = url,
            allowHttp = _settings.value.subscriptionAllowHttp
        ) ?: return false
        viewModelScope.launch(Dispatchers.IO) {
            val current = subEntities.value.firstOrNull { it.id == model.id } ?: return@launch
            subscriptionDao.updateSubscription(
                current.copy(name = edit.name, url = edit.url)
            )
            log("Updated subscription ${edit.name}")
        }
        return true
    }

    fun refreshSubscription(model: SubscriptionUiModel) {
        viewModelScope.launch(Dispatchers.IO) {
            subEntities.value.firstOrNull { it.id == model.id }?.let {
                refreshSubscriptionInternal(it)
            }
        }
    }

    fun refreshSubscription(subscriptionId: String) {
        val model = subscriptions.value.firstOrNull { it.id == subscriptionId } ?: return
        refreshSubscription(model)
    }

    private suspend fun refreshSubscriptionInternal(
        sub: SubscriptionEntity,
        rethrow: Boolean = false,
        adoptProfileTitle: Boolean = false
    ): Int {
        _refreshingIds.value = _refreshingIds.value + sub.id
        var importedCount = 0
        try {
            val subscriptionSettings = _settings.value
            val payload = SubscriptionClient.fetch(
                rawUrl = sub.url,
                hwid = subscriptionSettings.subscriptionHwid.trim()
                    .takeIf { subscriptionSettings.subscriptionSendHwid && it.isNotBlank() },
                customUserAgent = subscriptionSettings.subscriptionUserAgent.trim().ifBlank { null },
                direct = subscriptionSettings.subscriptionDirect,
                allowHttp = subscriptionSettings.subscriptionAllowHttp,
                // Lumen itself is deliberately excluded from VpnService to avoid
                // feeding the core's sockets back into its own TUN. The setting can
                // therefore only mean an explicit request through the core's local
                // SOCKS inbound; a header alone never changed the Android route.
                proxyPort = subscriptionSettings.localSocksPort.takeIf {
                    subscriptionSettings.subscriptionUseProxyTun && LumenVpnService.isRunning.value
                }
            )
            val (parsed, errors) = LinkParser.parseLinksText(payload.body)
            errors.take(3).forEach { log("Subscription warning: $it") }
            val valid = parsed.filter {
                it.name.length <= 512 && it.server.length <= 512 &&
                    (it.scheme == "auto" || it.server.isNotBlank()) &&
                    (it.scheme == "auto" || it.port in 1..65535) && it.link.length <= 65_536
            }.take(LinkParser.MAX_IMPORT_NODES)
            if (valid.isNotEmpty()) {
                // Diff before the delete+insert transaction: afterwards the previous rows
                // are gone, and the user has no way to tell what the refresh actually did.
                val previous = nodeEntities.value.filter { it.subscriptionId == sub.id }
                val previousByKey = previous.associateBy {
                    subscriptionNodeKey(it.server, it.port, it.protocol, it.name)
                }
                val incomingByKey = valid.associateBy {
                    subscriptionNodeKey(it.server, it.port, it.scheme, it.name)
                }
                val added = incomingByKey.keys.count { it !in previousByKey }
                val removed = previousByKey.keys.count { it !in incomingByKey }
                // "Updated" means the same endpoint came back with a different link or
                // display name: a re-keyed server or a renamed location.
                val updated = incomingByKey.count { (key, node) ->
                    val old = previousByKey[key]
                    old != null && (old.link != node.link || old.name != node.name)
                }
                db.withTransaction {
                    nodeDao.deleteNodesBySubscription(sub.id)
                    nodeDao.insertNodes(valid.map { parsedNode ->
                        val previousNode = previousByKey[
                            subscriptionNodeKey(
                                parsedNode.server,
                                parsedNode.port,
                                parsedNode.scheme,
                                parsedNode.name
                            )
                        ]
                        parsedNode.toEntity(sub.id).let { refreshed ->
                            if (previousNode == null) refreshed else refreshed.copy(
                                id = previousNode.id,
                                pingMs = previousNode.pingMs
                            )
                        }
                    })
                }
                _subscriptionSummaries.tryEmit(
                    SubscriptionUpdateSummary(
                        subscriptionName = sub.name,
                        added = added,
                        updated = updated,
                        removed = removed,
                        total = valid.size
                    )
                )
                importedCount = valid.size
                _subscriptionPremium.value = _subscriptionPremium.value + (sub.id to payload.premiumFeatures)
                mergeSubscriptionUsage(sub.id, payload.userInfo)
                val premiumApplied = applyCompatiblePremiumFeatures(payload.premiumFeatures)
                // The subscription URL is a bearer credential: never let a provider
                // response move an https subscription to plaintext http.
                val replacementUrl = (payload.effectiveUrl
                    ?: SubscriptionClient.replaceDomain(sub.url, payload.premiumFeatures["new-domain"]))
                    ?.takeIf { candidate ->
                        subscriptionSettings.subscriptionAllowHttp ||
                            !sub.url.startsWith("https://", true) ||
                            candidate.startsWith("https://", true)
                    }
                val autoUpdate = payload.premiumFeatures["subscription-auto-update-enable"]
                    ?.let(::premiumEnabled) ?: sub.autoUpdateEnabled
                subscriptionDao.updateSubscription(
                    mergeSubscriptionMetadata(
                        sub,
                        payload.metadata,
                        payload.updateIntervalHours?.takeIf { it in 1..8760 }
                    ).copy(
                        // A provider title is a useful default on first import, but it must
                        // not undo a name the user deliberately set in the group editor.
                        name = refreshedSubscriptionName(
                            currentName = sub.name,
                            providerTitle = payload.profileTitle,
                            adoptProviderTitle = adoptProfileTitle
                        ),
                        url = replacementUrl ?: sub.url,
                        lastUpdated = System.currentTimeMillis(),
                        autoUpdateEnabled = autoUpdate
                    )
                )
                subscriptionFailures.remove(sub.id)
                subscriptionRetryAfter.remove(sub.id)
                log("Subscription ${sub.name}: ${parsed.size} node(s), profile ${payload.clientProfile}")
                if (premiumApplied.isNotEmpty()) log("Applied premium settings: ${premiumApplied.joinToString()}")
            } else {
                noteSubscriptionFailure(sub.id)
                log("Subscription ${sub.name}: no nodes found")
            }
        } catch (e: Exception) {
            noteSubscriptionFailure(sub.id)
            log("Subscription refresh failed: ${e.message}")
            if (rethrow) throw e
        } finally {
            _refreshingIds.value = _refreshingIds.value - sub.id
        }
        return importedCount
    }

    fun deleteSubscription(model: SubscriptionUiModel) {
        viewModelScope.launch(Dispatchers.IO) {
            val keys = nodeEntities.value.filter { it.subscriptionId == model.id }.map { it.groupKey() }
            nodeDao.deleteNodesBySubscription(model.id)
            subscriptionDao.deleteSubscriptionById(model.id)
            if (keys.isNotEmpty()) serverGroupDao.assignNodes(keys, null)
            forgetSubscriptionUsage(model.id)
            log("Deleted subscription ${model.name}")
        }
    }

    fun deleteSubscription(subscriptionId: String) {
        val model = subscriptions.value.firstOrNull { it.id == subscriptionId } ?: return
        deleteSubscription(model)
    }

    // Subscriptions always auto-update; there is no per-subscription switch anymore.
    // Cadence priority: interval requested by the provider (profile-update-interval),
    // otherwise the interval configured in app settings.
    private fun startSubscriptionAutoUpdate() {
        viewModelScope.launch(Dispatchers.IO) {
            while (true) {
                kotlinx.coroutines.delay(60_000L)
                if (!hasNetworkConnection()) continue
                val configuredMinutes = _settings.value.subscriptionAutoUpdateMinutes
                    .takeIf { it > 0 } ?: 240
                val now = System.currentTimeMillis()
                subEntities.value.forEach { sub ->
                    val providerMinutes = sub.updateIntervalHours.takeIf { it in 1..8760 }?.times(60)
                    val intervalMinutes = providerMinutes ?: configuredMinutes
                    val due = now - sub.lastUpdated >= intervalMinutes * 60_000L
                    val backedOff = now < (subscriptionRetryAfter[sub.id] ?: 0L)
                    if (due && !backedOff && sub.id !in _refreshingIds.value) {
                        runCatching { refreshSubscriptionInternal(sub) }
                    }
                }
            }
        }
    }

    /** Exponential backoff so an expired or offline subscription is not retried every minute. */
    private fun noteSubscriptionFailure(subscriptionId: String) {
        val failures = (subscriptionFailures[subscriptionId] ?: 0) + 1
        subscriptionFailures[subscriptionId] = failures
        val backoffMinutes = (5L shl (failures - 1).coerceAtMost(6)).coerceAtMost(360L)
        subscriptionRetryAfter[subscriptionId] =
            System.currentTimeMillis() + backoffMinutes * 60_000L
    }

    private fun hasNetworkConnection(): Boolean = runCatching {
        val manager = getApplication<Application>()
            .getSystemService(Context.CONNECTIVITY_SERVICE) as android.net.ConnectivityManager
        val network = manager.activeNetwork ?: return@runCatching false
        val capabilities = manager.getNetworkCapabilities(network) ?: return@runCatching false
        capabilities.hasCapability(android.net.NetworkCapabilities.NET_CAPABILITY_INTERNET)
    }.getOrDefault(true)

    /**
     * Resolvers of the currently active physical network. Only ever called while the
     * VPN is down, so `activeNetwork` is the underlay; the scope suffix of a
     * link-local address is stripped because nothing downstream can carry it.
     */
    private fun currentNetworkDnsServers(): List<String> = runCatching {
        val manager = getApplication<Application>()
            .getSystemService(Context.CONNECTIVITY_SERVICE) as android.net.ConnectivityManager
        val network = manager.activeNetwork ?: return@runCatching emptyList()
        manager.getLinkProperties(network)?.dnsServers
            ?.mapNotNull { it.hostAddress?.substringBefore('%') }
            ?.distinct()
            .orEmpty()
    }.getOrDefault(emptyList())

    private fun premiumEnabled(value: String): Boolean =
        value.trim().lowercase(Locale.US) in setOf("1", "true", "yes", "on", "enabled")

    private fun applyCompatiblePremiumFeatures(premium: Map<String, String>): List<String> {
        if (premium.isEmpty() || !_settings.value.allowSubscriptionOverrides) return emptyList()
        val applied = mutableListOf<String>()
        var next = _settings.value

        premium["subscription-autoconnect"]?.let {
            next = next.copy(autoConnectOnBoot = premiumEnabled(it))
            applied += "subscription-autoconnect"
        }
        premium["fragmentation-enable"]?.let {
            next = next.copy(fragmentEnabled = premiumEnabled(it))
            applied += "fragmentation-enable"
        }
        premium["fragmentation-packets"]?.takeIf { it.isNotBlank() }?.let {
            next = next.copy(fragmentPackets = it.take(64)); applied += "fragmentation-packets"
        }
        premium["fragmentation-length"]?.takeIf { it.isNotBlank() }?.let {
            next = next.copy(fragmentLength = it.take(32)); applied += "fragmentation-length"
        }
        premium["fragmentation-interval"]?.takeIf { it.isNotBlank() }?.let {
            next = next.copy(fragmentDelay = it.take(32)); applied += "fragmentation-interval"
        }
        premium["mux-enable"]?.let {
            next = next.copy(muxEnabled = premiumEnabled(it)); applied += "mux-enable"
        }
        premium["mux-tcp-connections"]?.toIntOrNull()?.coerceIn(-1, 1024)?.let {
            next = next.copy(muxConcurrency = it); applied += "mux-tcp-connections"
        }
        // Both of these used to write prefs directly, so _settings kept the stale
        // value and the next settings save overwrote the provider's override.
        premium["change-user-agent"]?.trim()?.takeIf {
            it.isNotBlank() && it.length <= 256 && '\r' !in it && '\n' !in it
        }?.let {
            next = next.copy(subscriptionUserAgent = it)
            applied += "change-user-agent"
        }
        premium["ping-type"]?.trim()?.takeIf { it.isNotBlank() }?.let {
            next = next.copy(pingType = normalizedPingType(it))
            applied += "ping-type"
        }
        if (next != _settings.value) updateSettings(next)

        premium["per-app-proxy-mode"]?.trim()?.lowercase(Locale.US)?.let { mode ->
            val mapped = when (mode) {
                "allow", "allow-list", "include", "whitelist", "1" -> SplitModeUi.ALLOW_LIST
                "disallow", "disallow-list", "exclude", "blacklist", "2" -> SplitModeUi.DISALLOW_LIST
                "off", "disabled", "0" -> SplitModeUi.DISABLED
                else -> null
            }
            if (mapped != null) {
                setSplitMode(mapped)
                applied += "per-app-proxy-mode"
            }
        }
        premium["per-app-proxy-list"]?.let { raw ->
            val packages = raw.split(Regex("[\\s,;]+"))
                .map { it.trim() }
                .filter { it.matches(Regex("[A-Za-z0-9_.]+")) }
                .take(500)
                .toSet()
            if (packages.isNotEmpty()) {
                _splitPackages.value = packages
                prefs.edit().putStringSet("split_packages", packages).apply()
                applied += "per-app-proxy-list"
            }
        }
        return applied
    }

    // ---------- Ping ----------
    private val _isPinging = MutableStateFlow(false)
    val isPinging: StateFlow<Boolean> = _isPinging
    private val _testingNodeId = MutableStateFlow<String?>(null)
    val testingNodeId: StateFlow<String?> = _testingNodeId
    private val _serverTestResults = MutableStateFlow<Map<String, String>>(emptyMap())
    val serverTestResults: StateFlow<Map<String, String>> = _serverTestResults
    private val _pingingNodeIds = MutableStateFlow<Set<String>>(emptySet())
    val pingingNodeIds: StateFlow<Set<String>> = _pingingNodeIds
    private var bulkPingJob: kotlinx.coroutines.Job? = null
    private var bulkPingGeneration = 0L

    // ICMP fallback wakes the radio; keep it far below the ping concurrency.
    private val icmpSemaphore = kotlinx.coroutines.sync.Semaphore(4)
    // AUTO pools can contain hundreds of endpoints. Probe them concurrently, but keep one
    // shared ceiling across all AUTO nodes so large subscriptions cannot exhaust sockets.
    private val autoMemberPingSemaphore =
        kotlinx.coroutines.sync.Semaphore(PingBudget.AUTO_MEMBER_CONCURRENCY)
    // A real HTTP test starts an isolated sing-box proxy for the target node.
    // Keep those heavier probes bounded independently from cheap endpoint pings.
    private val realPingSemaphore = kotlinx.coroutines.sync.Semaphore(4)
    private val coreBinaryMissingLogged = java.util.concurrent.atomic.AtomicBoolean(false)

    fun pingAll() {
        pingNodeListInternal(nodeEntities.value)
    }

    fun pingGroup(subscriptionId: String?) {
        val targets = nodeEntities.value.filter { it.subscriptionId == subscriptionId }
        pingNodeListInternal(targets)
    }

    fun pingNodes(nodes: List<NodeUiModel>) {
        val nodeIds = nodes.map { it.id }.toSet()
        val targets = nodeEntities.value.filter { it.id in nodeIds }
        pingNodeListInternal(targets)
    }

    fun stopPing() {
        val wasRunning = bulkPingJob?.isActive == true || _isPinging.value
        bulkPingGeneration += 1
        bulkPingJob?.cancel()
        bulkPingJob = null
        _pingingNodeIds.value = emptySet()
        _testingNodeId.value = null
        _isPinging.value = false
        if (wasRunning) log("Ping stopped")
    }

    private fun pingNodeListInternal(targets: List<NodeEntity>) {
        if (targets.isEmpty()) return
        val cfg = _settings.value
        val mode = cfg.pingType
        // A mixed list can still redirect individual UDP-only nodes to the core path;
        // realPingSemaphore keeps those bounded without slowing the whole run down.
        val limit = if (cfg.pingType in CORE_PING_TYPES) {
            cfg.pingConcurrency.coerceIn(1, 4)
        } else {
            cfg.pingConcurrency.coerceIn(1, 32)
        }
        // A new request always supersedes the old one. This makes every run start from a
        // clean slate even if the user changes a group or starts another check mid-flight.
        val generation = ++bulkPingGeneration
        bulkPingJob?.cancel()
        val job = viewModelScope.launch(
            Dispatchers.IO,
            start = kotlinx.coroutines.CoroutineStart.LAZY
        ) {
            _isPinging.value = true
            log("Pinging ${targets.size} node(s), $limit at a time ($mode)…")
            try {
                // Drop stale values first: the row must show "measuring", not the previous ping.
                val targetIds = targets.map { it.id }
                _serverTestResults.value = _serverTestResults.value - targetIds.toSet()
                _pingingNodeIds.value = targetIds.toSet()
                nodeDao.updatePingsBatch(targetIds.map { Pair(it, null as Int?) })
                val pending = java.util.Collections.synchronizedSet(targetIds.toMutableSet())
                val completedPings = java.util.Collections.synchronizedMap(mutableMapOf<String, Int>())
                val semaphore = kotlinx.coroutines.sync.Semaphore(limit)
                val jobs = targets.map { node ->
                    async {
                        try {
                            semaphore.withPermit {
                                // Repeats the probe and aggregates it per the ping settings.
                                val ping = measureNodePing(node)
                                val persistedPing = ping.coerceAtLeast(0)
                                nodeDao.updatePing(node.id, persistedPing)
                                completedPings[node.id] = persistedPing
                            }
                        } catch (e: kotlinx.coroutines.CancellationException) {
                            throw e
                        } catch (e: Exception) {
                            // One failing node must not abort the run for all the others.
                            runCatching {
                                nodeDao.updatePing(node.id, 0)
                                completedPings[node.id] = 0
                            }
                            log("Ping failed for ${node.name}: ${e.message}")
                        } finally {
                            // Runs on the cancellation path too, so no row stays measuring.
                            synchronized(pending) {
                                pending.remove(node.id)
                                if (bulkPingGeneration == generation) {
                                    _pingingNodeIds.value = pending.toSet()
                                }
                            }
                        }
                    }
                }
                // Every node already carries its own deadline; this is the backstop that
                // keeps the run finite when a straggler is stuck in a blocking probe.
                val finished = withTimeoutOrNull(PingBudget.batchMs(targets.size, limit)) {
                    jobs.awaitAll()
                } != null
                if (!finished) {
                    jobs.forEach { it.cancel() }
                    val leftovers = synchronized(pending) { pending.toList() }
                    runCatching { nodeDao.updatePingsBatch(leftovers.map { Pair(it, 0 as Int?) }) }
                    log("Ping deadline reached: ${leftovers.size} node(s) marked unreachable")
                }
                if (finished && cfg.pingAutoDeleteUnreachable) {
                    val removed = removeUnhealthyNodesAfterPing(
                        completedPings = completedPings.toMap(),
                        thresholdMs = cfg.pingAutoDeleteThresholdMs
                    )
                    if (removed > 0) log("Auto-removed $removed node(s) after the ping test")
                }
                log("Ping finished for ${targets.size} node(s)")
            } finally {
                // A canceled predecessor must not reset state owned by its replacement.
                if (bulkPingGeneration == generation) {
                    bulkPingJob = null
                    _pingingNodeIds.value = emptySet()
                    _isPinging.value = false
                }
            }
        }
        bulkPingJob = job
        job.start()
    }

    fun pingNode(node: NodeUiModel) {
        if (node.id in _pingingNodeIds.value) return
        viewModelScope.launch(Dispatchers.IO) {
            _testingNodeId.value = node.id
            // update{} instead of read-modify-write: parallel pings share these sets.
            _pingingNodeIds.update { it + node.id }
            // Old value is dropped before measuring so the row never shows a stale ping.
            _serverTestResults.update { it - node.id }
            try {
                nodeDao.updatePing(node.id, null)
                // Same repeat/aggregate rules as the bulk check.
                val entity = nodeEntities.value.firstOrNull { it.id == node.id }
                val ping = entity?.let { measureNodePing(it) } ?: -1
                val persistedPing = ping.coerceAtLeast(0)
                nodeDao.updatePing(node.id, persistedPing)
                val result = if (ping > 0) "$ping ms" else "0"
                _serverTestResults.update { it + (node.id to result) }
                log("Ping ${node.name}: $result")
                if (
                    _settings.value.pingAutoDeleteUnreachable &&
                    isPingRemovalCandidate(persistedPing, _settings.value.pingAutoDeleteThresholdMs)
                ) {
                    val removed = removeUnhealthyNodesAfterPing(
                        completedPings = mapOf(node.id to persistedPing),
                        thresholdMs = _settings.value.pingAutoDeleteThresholdMs
                    )
                    if (removed > 0) log("Auto-removed ${node.name} after the ping test")
                }
            } finally {
                // A thrown or cancelled measurement must not leave the row spinning.
                _pingingNodeIds.update { it - node.id }
                if (_testingNodeId.value == node.id) _testingNodeId.value = null
            }
        }
    }

    /**
     * "Check" button on the dashboards: measures the server that is selected/connected
     * right now with the ping method chosen in settings and reports it as a Toast.
     * The value is kept in [_connectedPing] so it can also be shown next to the button.
     */
    fun checkConnectedPing(unreachableLabel: String, noServerLabel: String) {
        val node = activeNode.value
        if (node == null) {
            emitToast(noServerLabel)
            return
        }
        if (_checkingConnectedPing.value) return
        val generation = ++connectedPingGeneration
        connectedPingJob = viewModelScope.launch(Dispatchers.IO) {
            _checkingConnectedPing.value = true
            _connectedPing.value = null
            try {
                val entity = nodeEntities.value.firstOrNull { it.id == node.id }
                val ping = entity?.let { measureNodePing(it) } ?: -1
                if (entity != null) nodeDao.updatePing(entity.id, ping.coerceAtLeast(0))
                val label = if (ping > 0) "$ping ms" else unreachableLabel
                if (generation != connectedPingGeneration || _selectedNodeId.value != node.id) {
                    return@launch
                }
                _connectedPing.value = label
                _serverTestResults.update { it + (node.id to label) }
                emitToast("${node.name}: $label")
                log("Check ping ${node.name}: $label")
            } finally {
                if (generation == connectedPingGeneration) {
                    _checkingConnectedPing.value = false
                    connectedPingJob = null
                }
            }
        }
    }

    private val _connectedPing = MutableStateFlow<String?>(null)
    val connectedPing: StateFlow<String?> = _connectedPing

    private val _checkingConnectedPing = MutableStateFlow(false)
    val checkingConnectedPing: StateFlow<Boolean> = _checkingConnectedPing
    private var connectedPingJob: Job? = null
    private var connectedPingGeneration = 0L

    private fun resetConnectedPing() {
        connectedPingGeneration += 1
        connectedPingJob?.cancel()
        connectedPingJob = null
        _connectedPing.value = null
        _checkingConnectedPing.value = false
    }

    fun exportNodesText(nodeIds: Set<String>): String {
        val allEntities = nodeEntities.value.associateBy { it.id }
        return nodeIds.mapNotNull { id -> allEntities[id]?.link?.takeIf { it.isNotBlank() } }
            .joinToString("\n")
    }

    fun exportSubscriptionText(subscriptionId: String?): String {
        val targets = nodeEntities.value.filter { it.subscriptionId == subscriptionId }
        return targets.mapNotNull { it.link.takeIf { l -> l.isNotBlank() } }.joinToString("\n")
    }

    private fun pingTimeout(): Int = _settings.value.pingTimeoutMs.coerceIn(500, 20_000)

    /**
     * Overall wall-clock ceiling for one node, derived from the configured timeout,
     * retry count and retry delay so it always tracks the user's ping settings.
     * [pingWithin] turns an expired budget into "unreachable" instead of a row that
     * keeps measuring: the user asked for it to go to 0 rather than spin.
     */
    private suspend fun pingWithin(
        entity: NodeEntity,
        memberCount: Int,
        realCheck: Boolean,
        block: suspend kotlinx.coroutines.CoroutineScope.() -> Int
    ): Int {
        val cfg = _settings.value
        val budget = PingBudget.nodeMs(
            PingBudget.attemptsMs(
                timeoutMs = cfg.pingTimeoutMs,
                attempts = cfg.pingAttempts,
                retryDelayMs = cfg.pingRetryDelayMs,
                realCheck = realCheck
            ),
            memberCount
        )
        val measured = withTimeoutOrNull(budget, block)
        if (measured == null) log("Ping deadline reached for ${entity.name}: unreachable")
        return measured ?: -1
    }

    private suspend fun measureAttempts(probe: suspend () -> Int): Int {
        val cfg = _settings.value
        val attempts = cfg.pingAttempts.coerceIn(1, 10)
        val retryDelay = cfg.pingRetryDelayMs.coerceIn(0, 5_000).toLong()
        val samples = ArrayList<Int>(attempts)
        repeat(attempts) { index ->
            if (index > 0 && retryDelay > 0) kotlinx.coroutines.delay(retryDelay)
            val value = probe()
            if (value >= 0) samples.add(value)
        }
        if (samples.isEmpty()) return -1
        return when (cfg.pingAggregate) {
            "avg" -> samples.average().toInt()
            "median" -> samples.sorted()[samples.size / 2]
            else -> samples.min()
        }
    }

    /**
     * The method a given node is actually probed with.
     *
     * WireGuard/AmneziaWG (and WARP, which is WireGuard underneath) endpoints only
     * listen on UDP, so the TCP connect behind TCPing can never complete and every one
     * of those rows read 0 ms. They are redirected to the core backed check, which
     * measures an HTTP request through the node and is protocol agnostic. ICMP is left
     * alone: it probes the host address and works for a UDP endpoint as it is.
     */
    private fun effectivePingType(protocol: String): String {
        val method = _settings.value.pingType
        if (method != "tcping") return method
        return if (protocol.trim().lowercase(Locale.US) in UDP_ONLY_SCHEMES) "real" else method
    }

    /**
     * One node's repeats. [node] is only resolved for the checks that need a full
     * config, so a TCPing run over a large subscription still parses nothing.
     */
    private suspend fun measureNodeAttempts(
        protocol: String,
        host: String,
        port: Int,
        node: () -> ParsedNode
    ): Int {
        val method = effectivePingType(protocol)
        if (method in CORE_PING_TYPES) {
            val parsed = node()
            return measureAttempts { proxyPingOnce(parsed, httpGet = method == "http") }
        }
        return measureAttempts { if (method == "icmp") icmpPing(host) else tcpPing(host, port) }
    }

    /**
     * AUTO nodes have no endpoint of their own. Desktop Lumen resolves their
     * selector/urltest members before probing; do the same here and keep the
     * best reachable member as the AUTO latency.
     */
    private suspend fun measureNodePing(entity: NodeEntity): Int {
        val isAuto = entity.isAutoNode || entity.protocol.equals("auto", true)
        if (!isAuto) {
            val realCheck = effectivePingType(entity.protocol) in CORE_PING_TYPES
            return pingWithin(entity, memberCount = 1, realCheck = realCheck) {
                measureNodeAttempts(entity.protocol, entity.server, entity.port) { parseEntity(entity) }
            }
        }

        val members = runCatching { LinkParser.autoMembers(parseEntity(entity).outbound) }
            .getOrDefault(emptyList())
            .filter { it.server.isNotBlank() && it.port in 1..65535 }
        if (members.isEmpty()) return -1

        // The old sequential loop multiplied the full timeout by every member (hundreds for
        // Auto WiFi). A shared semaphore keeps this bounded while still checking the full pool.
        val realCheck = members.any { effectivePingType(it.scheme) in CORE_PING_TYPES }
        return pingWithin(entity, memberCount = members.size, realCheck = realCheck) {
            members.map { member ->
                async {
                    autoMemberPingSemaphore.withPermit {
                        measureNodeAttempts(member.scheme, member.server, member.port) { member }
                    }
                }
            }.awaitAll()
                .filter { it >= 0 }
                .minOrNull()
                ?: -1
        }
    }

    /**
     * Deletes only rows whose just-completed result is still present in Room. A timed-out
     * batch never calls this method, and a result that changed during the test is retained.
     * The selected live tunnel is protected so cleanup cannot interrupt a connection.
     */
    private suspend fun removeUnhealthyNodesAfterPing(
        completedPings: Map<String, Int>,
        thresholdMs: Int
    ): Int {
        val candidateIds = completedPings
            .filter { (id, _) ->
                id != _selectedNodeId.value ||
                    (!LumenVpnService.isRunning.value && !LumenVpnService.isStarting.value)
            }
            .filter { (_, ping) -> isPingRemovalCandidate(ping, thresholdMs) }
            .keys
            .toList()
        if (candidateIds.isEmpty()) return 0

        val confirmed = nodeDao.getNodesByIds(candidateIds).filter { node ->
            completedPings[node.id] == node.pingMs &&
                isPingRemovalCandidate(node.pingMs, thresholdMs)
        }
        if (confirmed.isEmpty()) return 0

        val keys = confirmed.map { it.groupKey() }
        confirmed.forEach { nodeDao.deleteNodeById(it.id) }
        if (keys.isNotEmpty()) serverGroupDao.assignNodes(keys, null)

        if (_selectedNodeId.value in confirmed.map { it.id }) {
            _selectedNodeId.value = null
            prefs.edit()
                .remove("selected_node_id")
                .remove("selected_node_name")
                .remove("selected_node_name_b64")
                .apply()
            com.lumen.app.widget.LumenWidgetProvider.sendUpdateBroadcast(getApplication())
        }
        return confirmed.size
    }

    /**
     * A hijacking carrier does not answer a blocked hostname with NXDOMAIN, it
     * answers with the address of its own block page - Iran's 10.10.34.0/24 being
     * the widespread case - and that box accepts TCP on every port within a few
     * milliseconds. The probe would therefore report a healthy latency for a
     * server that cannot pass a single byte, which is exactly the "ping shows
     * numbers that are not real" report. Anything that is not routable unicast is
     * treated the same way.
     */
    private fun isSinkholeAddress(address: java.net.InetAddress): Boolean {
        if (address.isAnyLocalAddress || address.isLoopbackAddress ||
            address.isLinkLocalAddress || address.isMulticastAddress
        ) {
            return true
        }
        val octets = address.address
        return octets.size == 4 &&
            (octets[0].toInt() and 0xFF) == 10 &&
            (octets[1].toInt() and 0xFF) == 10 &&
            (octets[2].toInt() and 0xFF) == 34
    }

    /**
     * Resolves the endpoint here instead of letting connect() do it, so a poisoned
     * answer is discarded before anything is timed. An empty list means every
     * address the resolver returned was a sinkhole: unreachable, not fast.
     */
    private fun resolveProbeAddresses(host: String): List<java.net.InetAddress> =
        runCatching { java.net.InetAddress.getAllByName(host).toList() }
            .getOrDefault(emptyList())
            .filterNot(::isSinkholeAddress)

    private fun tcpPing(host: String, port: Int, timeoutMs: Int = pingTimeout()): Int {
        val addresses = resolveProbeAddresses(host)
        if (addresses.isEmpty()) return -1
        // A dual-stack endpoint can advertise an unusable AAAA on an IPv4-only
        // carrier, so a failing address falls through to the next one instead of
        // condemning the whole node.
        for (address in addresses) {
            val measured = runCatching {
                val start = System.nanoTime()
                Socket().use { it.connect(InetSocketAddress(address, port), timeoutMs) }
                ((System.nanoTime() - start) / 1_000_000).toInt()
            }.getOrNull()
            if (measured != null) return measured
        }
        return -1
    }

    private suspend fun icmpPing(host: String, timeoutMs: Int = pingTimeout()): Int = try {
        icmpSemaphore.withPermit {
            val address = resolveProbeAddresses(host).firstOrNull()
            if (address == null) {
                -1
            } else {
                val start = System.nanoTime()
                if (address.isReachable(timeoutMs)) {
                    ((System.nanoTime() - start) / 1_000_000).toInt()
                } else {
                    -1
                }
            }
        }
    } catch (e: Exception) {
        -1
    }

    /**
     * Desktop Lumen's "Real HTTP" check starts a temporary proxy for the node
     * and measures an HTTP request through it. The old Android URL check was a
     * direct request and therefore returned nearly the same result for every
     * server without proving that any node could pass traffic.
     *
     * The proxy is the node's own outbound, so this works for every protocol the core
     * speaks — including WireGuard/AmneziaWG, which has no TCP port to connect to.
     * [httpGet] switches to the "HTTP GET" method: the same request, timed from the
     * moment it is sent instead of from the connect, so it reports the node's
     * request/response latency without the SOCKS and TLS setup.
     */
    private suspend fun proxyPingOnce(node: ParsedNode, httpGet: Boolean): Int = realPingSemaphore.withPermit {
        val app = getApplication<Application>()
        val binary = File(app.applicationInfo.nativeLibraryDir, "libsingbox.so")
        if (!binary.isFile) {
            // Otherwise every row just shows an unexplained -1.
            if (coreBinaryMissingLogged.compareAndSet(false, true)) {
                log("VPN core missing for this CPU architecture: real ping unavailable")
            }
            return@withPermit -1
        }
        val bridge = obfsBridgeOf(node)
        val socksPort = runCatching { ServerSocket(0).use { it.localPort } }.getOrElse {
            return@withPermit -1
        }
        val obfsPort = if (bridge != null) {
            availableTcpPort(setOf(socksPort)).takeIf { it > 0 } ?: return@withPermit -1
        } else {
            SingboxConfigBuilder.OBFS_LOCAL_PORT
        }
        val workDir = File(app.cacheDir, "ping-tests/${UUID.randomUUID()}").apply { mkdirs() }
        val configFile = File(workDir, "config.json")
        var process: Process? = null
        var relay: ObfsRelay? = null
        try {
            if (bridge != null) {
                relay = ObfsRelay(
                    localPort = obfsPort,
                    type = bridge.first,
                    bridgeHost = bridge.second,
                    bridgePort = bridge.third,
                    // Lumen's UID is excluded from its own VpnService; the temporary
                    // relay therefore already dials the physical network.
                    protect = { true }
                ).also { it.start() }
            }
            configFile.writeText(
                SingboxConfigBuilder.buildConfig(
                    node,
                    pingSingboxOptions(socksPort, obfsPort, workDir)
                ),
                Charsets.UTF_8
            )
            process = ProcessBuilder(binary.absolutePath, "run", "-c", configFile.absolutePath)
                .directory(workDir)
                .redirectErrorStream(true)
                .start()
            val startedProcess = process
            Thread({
                runCatching { startedProcess.inputStream.bufferedReader().use { it.readText() } }
            }, "lumen-real-ping-log").apply {
                isDaemon = true
                start()
            }

            val readyDeadline = System.nanoTime() +
                pingTimeout().coerceAtLeast(2_000).toLong() * 1_000_000L
            var ready = false
            while (System.nanoTime() < readyDeadline && startedProcess.isAlive) {
                ready = runCatching {
                    Socket().use { socket ->
                        socket.connect(InetSocketAddress("127.0.0.1", socksPort), 100)
                    }
                    true
                }.getOrDefault(false)
                if (ready) break
                delay(50)
            }
            if (!ready || !startedProcess.isAlive) return@withPermit -1
            httpDelayThroughSocks(socksPort, _settings.value.pingUrl, pingTimeout(), httpGet)
        } catch (_: Exception) {
            -1
        } finally {
            process?.let {
                runCatching { it.destroy() }
                if (it.isAlive) runCatching { it.waitFor(300, TimeUnit.MILLISECONDS) }
                if (it.isAlive) runCatching { it.destroyForcibly() }
            }
            runCatching { relay?.stop() }
            runCatching { workDir.deleteRecursively() }
        }
    }

    private fun availableTcpPort(excluded: Set<Int>): Int {
        repeat(8) {
            val candidate = runCatching { ServerSocket(0).use { socket -> socket.localPort } }
                .getOrDefault(0)
            if (candidate > 0 && candidate !in excluded) return candidate
        }
        return 0
    }

    /**
     * A real/HTTP ping must exercise the same core features as a connection. Keeping
     * DNS, route, MUX, fragmentation and dial options here avoids a false green result
     * from a stripped-down config that the actual tunnel would never use.
     */
    private fun pingSingboxOptions(
        socksPort: Int,
        obfsPort: Int,
        workDir: File
    ): SingboxConfigOptions {
        val s = _settings.value
        return SingboxConfigOptions(
            tunMode = false,
            tunMtu = s.mtu.coerceIn(1280, 9000),
            localSocksPort = socksPort,
            localHttpPort = 0,
            allowLanConnections = false,
            obfsLocalPort = obfsPort,
            multiplexEnabled = s.muxEnabled,
            multiplexConcurrency = s.muxConcurrency,
            multiplexProtocol = s.multiplexProtocol,
            multiplexMinStreams = s.multiplexMinStreams,
            multiplexPadding = s.multiplexPadding,
            multiplexBrutalEnabled = s.multiplexBrutalEnabled,
            multiplexBrutalUpMbps = s.multiplexBrutalUpMbps,
            multiplexBrutalDownMbps = s.multiplexBrutalDownMbps,
            outboundTcpFastOpen = s.outboundTcpFastOpen,
            outboundTcpMultiPath = s.outboundTcpMultiPath,
            outboundUdpFragment = s.outboundUdpFragment,
            outboundConnectTimeoutSeconds = s.outboundConnectTimeoutSeconds,
            udpOverTcp = s.udpOverTcp,
            enableFinalFragment = s.fragmentEnabled,
            preferIpv6 = s.preferIpv6,
            blockQuic = s.blockQuic,
            proxyDnsServer = s.dnsProxyServers.lineSequence().firstOrNull()?.trim()
                .orEmpty().ifBlank { "cloudflare-dns.com" },
            directDnsServer = s.dnsDirectServers.lineSequence().firstOrNull()?.trim()
                .orEmpty().ifBlank { "1.1.1.1" },
            dnsMode = s.dnsMode,
            dnsCustomJson = s.dnsCustomJson,
            dnsDirectServers = s.dnsDirectServers.split(Regex("[\\n,;]+"))
                .map(String::trim).filter(String::isNotEmpty),
            systemDnsServers = currentNetworkDnsServers(),
            dnsProxyServers = s.dnsProxyServers.split(Regex("[\\n,;]+"))
                .map(String::trim).filter(String::isNotEmpty),
            dnsDirectType = s.dnsDirectType,
            dnsProxyType = s.dnsProxyType,
            dnsDirectStrategy = s.dnsDirectStrategy,
            dnsProxyStrategy = s.dnsProxyStrategy,
            dnsHijackEnabled = s.dnsHijackEnabled,
            dnsFakeIpEnabled = s.dnsFakeIpEnabled,
            dnsParallelQuery = s.dnsParallelQuery,
            dnsOptimisticCache = s.dnsOptimisticCache,
            dnsGeoCheck = s.dnsGeoCheck,
            dnsProxyIpv4Only = s.dnsProxyIpv4Only,
            dnsHosts = s.dnsHosts.lineSequence().mapNotNull { line ->
                val host = line.substringBefore('=').trim().trimEnd('.').lowercase()
                val addresses = line.substringAfter('=', "").split(',')
                    .map(String::trim).filter(String::isNotEmpty)
                if (host.isNotBlank() && addresses.isNotEmpty()) host to addresses else null
            }.toMap(),
            dnsOverrideEnabled = s.dnsOverrideEnabled,
            dnsOverrideHostname = s.dnsOverrideHostname,
            dnsOverrideIpv4 = s.dnsOverrideIpv4,
            logLevel = "error",
            urlTestUrl = s.urlTestUrl.ifBlank { "https://www.gstatic.com/generate_204" },
            urlTestIntervalMinutes = s.urlTestIntervalMinutes.coerceIn(1, 1440),
            urlTestToleranceMs = s.urlTestToleranceMs.coerceIn(0, 5000),
            urlTestIdleTimeoutMinutes = s.urlTestIdleTimeoutMinutes,
            urlTestInterruptExistConnections = s.urlTestInterruptExistConnections,
            // A reachability check must never inherit user bypass rules. Otherwise the
            // target URL can go out through DIRECT and make a dead node look healthy.
            bypassLan = false,
            cacheFileEnabled = true,
            cacheFilePath = File(workDir, "cache.db").absolutePath,
            geoResourceSource = s.geoResourceSource,
            directDomains = emptyList(),
            directIpCidrs = emptyList(),
            dnsFakeIpRangeIPv4 = prefs.getString("dns_fake_ip_range_v4", null)
                ?.takeIf { it.isNotBlank() } ?: "198.18.0.0/15",
            dnsFakeIpRangeIPv6 = prefs.getString("dns_fake_ip_range_v6", null)
                ?.takeIf { it.isNotBlank() } ?: "fc00::/18",
            dnsIndependentCache = prefs.getBoolean("dns_independent_cache", true),
            dnsDisableCache = prefs.getBoolean("dns_disable_cache", false),
            dnsClientSubnet = prefs.getString("dns_client_subnet", "").orEmpty().trim(),
            domainResolverStrategy = prefs.getString("domain_resolver_strategy", "")
                .orEmpty().trim().lowercase(Locale.US),
            sniffTimeoutMs = prefs.getInt("sniff_timeout_ms", 0),
            sniffers = prefs.getString("sniffers", "").orEmpty()
                .split(Regex("[\\n,;]+"))
                .map { it.trim().lowercase(Locale.US) }
                .filter(String::isNotEmpty)
        )
    }

    private fun httpDelayThroughSocks(
        socksPort: Int,
        rawUrl: String,
        timeoutMs: Int,
        httpGet: Boolean
    ): Int {
        val url = URL(rawUrl.trim().ifBlank { "https://www.gstatic.com/generate_204" })
        val protocol = url.protocol.lowercase(Locale.US)
        if (protocol != "http" && protocol != "https") return -1
        val targetPort = if (url.port > 0) url.port else if (protocol == "https") 443 else 80
        val hostBytes = url.host.toByteArray(Charsets.UTF_8)
        if (hostBytes.isEmpty() || hostBytes.size > 255) return -1
        val startedAt = System.nanoTime()
        // Failures are the expected case here, so the socket must close on every
        // exit path — a handshake exception used to leak one fd per probe.
        return Socket().use { socket ->
            socket.soTimeout = timeoutMs
            socket.connect(InetSocketAddress("127.0.0.1", socksPort), timeoutMs)
            val input = socket.getInputStream()
            val output = socket.getOutputStream()
            output.write(byteArrayOf(0x05, 0x01, 0x00))
            output.flush()
            val greeting = readExactly(input, 2)
            if (greeting[0].toInt() != 0x05 || greeting[1].toInt() != 0x00) return -1
            output.write(
                byteArrayOf(0x05, 0x01, 0x00, 0x03, hostBytes.size.toByte()) +
                    hostBytes +
                    byteArrayOf((targetPort ushr 8).toByte(), targetPort.toByte())
            )
            output.flush()
            val reply = readExactly(input, 4)
            if (reply[1].toInt() != 0x00) return -1
            when (reply[3].toInt() and 0xFF) {
                0x01 -> readExactly(input, 4)
                0x03 -> readExactly(input, readExactly(input, 1)[0].toInt() and 0xFF)
                0x04 -> readExactly(input, 16)
                else -> return -1
            }
            readExactly(input, 2)

            val requestSocket: Socket = if (protocol == "https") {
                ((SSLSocketFactory.getDefault() as SSLSocketFactory)
                    .createSocket(socket, url.host, targetPort, true) as SSLSocket).apply {
                    soTimeout = timeoutMs
                    // A successful handshake alone is not enough: without hostname
                    // verification a captive portal can answer and create a false result.
                    sslParameters = sslParameters.apply {
                        endpointIdentificationAlgorithm = "HTTPS"
                    }
                    startHandshake()
                }
            } else {
                socket
            }
            // Everything above is setup. "HTTP GET" reports the round trip from here on;
            // "real" keeps reporting the whole connect, which is the desktop behaviour.
            val requestStartedAt = System.nanoTime()
            requestSocket.use { active ->
                val activeOut = active.getOutputStream()
                val path = url.file.takeIf { it.isNotBlank() } ?: "/"
                activeOut.write(
                    (
                        "GET $path HTTP/1.1\r\n" +
                            "Host: ${url.host}\r\n" +
                            "User-Agent: Lumen-Ping/Android\r\n" +
                            // A plain GET asks for the whole body; "real" only needs the
                            // first byte, so it keeps trimming the response to one.
                            (if (httpGet) "" else "Range: bytes=0-0\r\n") +
                            "Connection: close\r\n\r\n"
                        ).toByteArray(Charsets.US_ASCII)
                )
                activeOut.flush()
                if (httpGet) {
                    // A complete status line proves the node carried an HTTP exchange,
                    // not just some bytes back from whatever answered.
                    val status = readStatusLine(active.getInputStream())
                    if (!isSuccessfulHttpPingStatusLine(status)) return -1
                } else {
                    if (active.getInputStream().read() < 0) return -1
                }
            }
            val measuredFrom = if (httpGet) requestStartedAt else startedAt
            ((System.nanoTime() - measuredFrom) / 1_000_000L).toInt()
        }
    }

    /** Response status line, length bounded so a hostile endpoint cannot stream forever. */
    private fun readStatusLine(input: java.io.InputStream): String? {
        val line = StringBuilder()
        while (line.length < 256) {
            val byte = input.read()
            if (byte < 0) break
            if (byte == '\n'.code) break
            if (byte != '\r'.code) line.append(Char(byte))
        }
        return line.takeIf { it.isNotEmpty() }?.toString()
    }

    private fun readExactly(input: java.io.InputStream, count: Int): ByteArray {
        val result = ByteArray(count)
        var offset = 0
        while (offset < count) {
            val read = input.read(result, offset, count - offset)
            if (read < 0) throw java.io.EOFException("SOCKS proxy closed the connection")
            offset += read
        }
        return result
    }

    // ---------- Connection ----------
    private val _connectionState = MutableStateFlow(ConnectionState.Disconnected)
    val connectionState: StateFlow<ConnectionState> = _connectionState

    private val _uploadHistory = MutableStateFlow<List<Float>>(emptyList())
    val uploadHistory: StateFlow<List<Float>> = _uploadHistory
    private val _downloadHistory = MutableStateFlow<List<Float>>(emptyList())
    val downloadHistory: StateFlow<List<Float>> = _downloadHistory

    // Declared before the collector below, which reads it: viewModelScope dispatches
    // on Main.immediate, so that lambda can already run while this object is built.
    private val _connectError = MutableStateFlow<String?>(null)

    /**
     * One-shot notifications for things the user should feel rather than read. The UI
     * collects [events] and plays a haptic tick; nothing here vibrates by itself, so the
     * hapticsEnabled setting stays the single gate (rememberHapticTick honours it).
     *
     * replay = 0 and a small buffer with DROP_OLDEST: an event that nobody is collecting
     * (app in the background) is meant to be lost, not replayed on the next resume.
     */
    private val _events = kotlinx.coroutines.flow.MutableSharedFlow<LumenEvent>(
        replay = 0,
        extraBufferCapacity = 8,
        onBufferOverflow = kotlinx.coroutines.channels.BufferOverflow.DROP_OLDEST
    )
    val events: kotlinx.coroutines.flow.SharedFlow<LumenEvent> = _events

    private fun emitEvent(event: LumenEvent) {
        _events.tryEmit(event)
    }

    /**
     * Short user-facing messages the UI shows as a Toast at the bottom of the screen
     * (ping checks, subscription update summaries). Same one-shot semantics as [events]:
     * a message nobody is collecting is dropped instead of replayed on the next resume.
     */
    private val _toasts = kotlinx.coroutines.flow.MutableSharedFlow<String>(
        replay = 0,
        extraBufferCapacity = 8,
        onBufferOverflow = kotlinx.coroutines.channels.BufferOverflow.DROP_OLDEST
    )
    val toasts: kotlinx.coroutines.flow.SharedFlow<String> = _toasts

    fun emitToast(message: String) {
        if (message.isNotBlank()) _toasts.tryEmit(message)
    }

    /**
     * Result of one subscription refresh. Emitted raw (numbers, not a sentence) so the
     * UI layer can format it with the user's language strings.
     */
    private val _subscriptionSummaries = kotlinx.coroutines.flow.MutableSharedFlow<SubscriptionUpdateSummary>(
        replay = 0,
        extraBufferCapacity = 8,
        onBufferOverflow = kotlinx.coroutines.channels.BufferOverflow.DROP_OLDEST
    )
    val subscriptionSummaries: kotlinx.coroutines.flow.SharedFlow<SubscriptionUpdateSummary> = _subscriptionSummaries

    init {
        // The tunnel can already be up when the app is opened; that first emission is
        // the current state, not a transition, so it must not fire "connected".
        var sawFirstConnectionState = false
        viewModelScope.launch {
            combine(
                LumenVpnService.isRunning,
                LumenVpnService.isStarting,
                VpnLogBus.lastError
            ) { running, starting, error ->
                when {
                    running -> ConnectionState.Connected
                    starting -> ConnectionState.Connecting
                    error != null -> ConnectionState.Error
                    else -> ConnectionState.Disconnected
                }
            }.collect { state ->
                val previous = _connectionState.value
                _connectionState.value = state
                // A start that failed has a specific reason - the core's own FATAL
                // line - and it is the only thing worth showing the user. Only a
                // failed connection attempt raises it; a tunnel that drops later
                // must not open a dialog on top of whatever the user is doing.
                if (state == ConnectionState.Error && previous == ConnectionState.Connecting) {
                    VpnLogBus.lastError.value?.let { _connectError.value = it }
                }
                if (sawFirstConnectionState && state != previous) {
                    when {
                        state == ConnectionState.Connected -> emitEvent(LumenEvent.Connected)
                        previous == ConnectionState.Connected -> emitEvent(LumenEvent.Disconnected)
                    }
                }
                sawFirstConnectionState = true
            }
        }
    }

    private var connectTimeoutJob: kotlinx.coroutines.Job? = null

    /**
     * Why the last start attempt produced no tunnel. The navigator shows it: a config
     * that cannot be built for a 300 member AUTO pool has to say so, not fail silently.
     */
    val connectError: StateFlow<String?> = _connectError

    fun reportConnectError(message: String) {
        log(message)
        _connectError.value = message
    }

    fun dismissConnectError() {
        _connectError.value = null
    }

    fun markConnecting() {
        VpnLogBus.clearLastError()
        _connectionState.value = ConnectionState.Connecting
        // Repeated taps must not stack watchdogs racing to flip the state to Error.
        connectTimeoutJob?.cancel()
        connectTimeoutJob = viewModelScope.launch {
            delay(45_000)
            if (!LumenVpnService.isRunning.value &&
                _connectionState.value == ConnectionState.Connecting
            ) {
                _connectionState.value = ConnectionState.Error
                _connectError.value = VpnLogBus.lastError.value ?: "Connection attempt timed out"
                log("Connection attempt timed out")
            }
        }
    }

    /**
     * The quick-settings tile and widget start from the private active config file.
     * Mark it stale as soon as a node, DNS/routing option or split-tunnel selection
     * changes, then rebuild only from the latest state. The old file remains available
     * to the running service, while the tile and widget refuse to start from it.
     */
    private fun scheduleStoredVpnConfigRefresh() {
        storedVpnConfigRefreshJob?.cancel()
        val application = getApplication<Application>()
        storedVpnConfigRefreshJob = viewModelScope.launch(Dispatchers.IO) {
            VpnStartIntentFactory.markConfigDirty(application)
            com.lumen.app.widget.LumenWidgetProvider.sendUpdateBroadcast(application)
            delay(STORED_CONFIG_REFRESH_DEBOUNCE_MS)
            while (LumenVpnService.isRunning.value || LumenVpnService.isStarting.value) {
                delay(STORED_CONFIG_RUNNING_RETRY_MS)
            }
            buildStartIntent(application, reportErrors = false)
            com.lumen.app.widget.LumenWidgetProvider.sendUpdateBroadcast(application)
        }
    }

    /**
     * Parsing every stored node and serialising the config is measurable work with a
     * large subscription, so the whole build runs on IO; only the service start is
     * left to the caller on the main thread.
     */
    suspend fun buildStartIntent(
        context: Context,
        reportErrors: Boolean = true
    ): Intent? = withContext(Dispatchers.IO) {
        if (reportErrors) {
            storedVpnConfigRefreshJob?.cancel()
            _connectError.value = null
        }
        if (nodes.value.isEmpty() || activeNode.value == null) {
            if (reportErrors) reportConnectError("No active servers available to connect")
            return@withContext null
        }
        val entities = nodeEntities.value
        if (entities.isEmpty()) {
            if (reportErrors) reportConnectError("No servers configured in database")
            return@withContext null
        }
        val selected = entities.firstOrNull { it.id == _selectedNodeId.value } ?: entities.first()
        if (selected.id != _selectedNodeId.value) {
            // A deleted or disabled selection must not leave the tile/widget pointing
            // at a server different from the config they are about to start.
            persistSelectedNodeIdentity(selected.id, selected.name)
        }
        val parsedSelected = parseEntity(selected)
        val obfsBridges = obfsBridgesOf(parsedSelected)
        if (obfsBridges.size > 1) {
            if (reportErrors) {
                reportConnectError(
                    "Config build failed: AUTO contains multiple OpenVPN obfs bridges; " +
                        "select one OpenVPN server"
                )
            }
            return@withContext null
        }
        val s = _settings.value.copy(engine = "SINGBOX")
        val configJson = try {
            run {
                val pool = entities.map { parseEntity(it) }
                // Carriers that answer a lookup with a block page (Iran's 10.10.34.x)
                // cannot be defeated inside the core: a hijacked reply is a valid
                // answer, so no fallback advances past it. Resolved here instead,
                // before the tunnel exists, and only kept when the reply the core
                // would have used is provably bogus. Costs one UDP query otherwise.
                val pinnedServers = runCatching {
                    ServerAddressPinner.pinnedAddressesForPool(
                        probeHost = parsedSelected.server,
                        hostnames = pool.map { it.server },
                        foreignResolver = s.dnsDirectServers.lineSequence()
                            .firstOrNull()?.trim().orEmpty().ifBlank { "1.1.1.1" }
                    )
                }.getOrDefault(emptyMap())
                SingboxConfigBuilder.buildConfig(
                    pool,
                    parsedSelected,
                    SingboxConfigOptions(
                        tunMode = false,
                        tunMtu = tunMtuFor(parsedSelected, s.mtu),
                        pinnedServerIps = pinnedServers,
                        localSocksPort = s.localSocksPort.coerceIn(1024, 65535),
                        localHttpPort = if (s.localInboundEnabled) s.localHttpPort.coerceIn(1024, 65535) else 0,
                        allowLanConnections = s.lanSharingEnabled,
                        bypassLan = s.lanSharingEnabled,
                        // Socks5 authorization: with it on, the builder also drops the
                        // HTTP inbound, which cannot carry these credentials.
                        socksAuthEnabled = s.socks5AuthEnabled,
                        socksUsername = s.socks5Username,
                        socksPassword = s.socks5Password,
                        // Geo rule sets are loaded from disk. A remote set is fetched
                        // while the core starts and a failed fetch kills the start.
                        geoRuleSetDir = geoResourcesDir.absolutePath,
                        requireLocalRuleSets = true,
                        multiplexEnabled = s.muxEnabled,
                        multiplexConcurrency = s.muxConcurrency,
                        // sniffRouteOnly and the three fragment sub-fields are gone: the
                        // builder no longer reads them, this core has no counterpart.
                        enableFinalFragment = s.fragmentEnabled,
                        preferIpv6 = s.preferIpv6,
                        blockQuic = s.blockQuic,
                        proxyDnsServer = s.dnsProxyServers.lineSequence().firstOrNull()?.trim().orEmpty().ifBlank { "cloudflare-dns.com" },
                        directDnsServer = s.dnsDirectServers.lineSequence().firstOrNull()?.trim().orEmpty().ifBlank { "1.1.1.1" },
                        dnsMode = s.dnsMode,
                        dnsCustomJson = s.dnsCustomJson,
                        dnsDirectServers = s.dnsDirectServers.split(Regex("[\\n,;]+")).map(String::trim).filter(String::isNotEmpty),
                        // Desktop parity: the physical adapter's own resolvers bootstrap
                        // the DNS chain. Read here, before the tunnel exists, so this is
                        // the underlay network's list and never the TUN's own address.
                        systemDnsServers = currentNetworkDnsServers(),
                        dnsProxyServers = s.dnsProxyServers.split(Regex("[\\n,;]+")).map(String::trim).filter(String::isNotEmpty),
                        dnsDirectType = s.dnsDirectType,
                        dnsProxyType = s.dnsProxyType,
                        dnsDirectStrategy = s.dnsDirectStrategy,
                        dnsProxyStrategy = s.dnsProxyStrategy,
                        dnsHijackEnabled = s.dnsHijackEnabled,
                        dnsFakeIpEnabled = s.dnsFakeIpEnabled,
                        dnsParallelQuery = s.dnsParallelQuery,
                        dnsOptimisticCache = s.dnsOptimisticCache,
                        dnsGeoCheck = s.dnsGeoCheck,
                        dnsProxyIpv4Only = s.dnsProxyIpv4Only,
                        dnsHosts = s.dnsHosts.lineSequence().mapNotNull { line ->
                            val host = line.substringBefore('=').trim().trimEnd('.').lowercase()
                            val addresses = line.substringAfter('=', "").split(',').map(String::trim).filter(String::isNotEmpty)
                            if (host.isNotBlank() && addresses.isNotEmpty()) host to addresses else null
                        }.toMap(),
                        dnsOverrideEnabled = s.dnsOverrideEnabled,
                        dnsOverrideHostname = s.dnsOverrideHostname,
                        dnsOverrideIpv4 = s.dnsOverrideIpv4,
                        // Core verbosity follows the master switch. "none" is not a
                        // valid level for this core, so silence is "error" - the level
                        // the core itself only uses for a fatal it is about to die on.
                        logLevel = if (s.loggingEnabled) CORE_LOG_LEVEL else "error",
                        urlTestUrl = s.urlTestUrl.ifBlank { "https://www.gstatic.com/generate_204" },
                        urlTestIntervalMinutes = s.urlTestIntervalMinutes.coerceIn(1, 1440),
                        urlTestToleranceMs = s.urlTestToleranceMs.coerceIn(0, 5000),
                        geoResourceSource = s.geoResourceSource,
                        directDomains = s.directDomains.split(Regex("[\\n,;]+")).map { it.trim() }.filter { it.isNotEmpty() },
                        directIpCidrs = s.directIpCidrs.split(Regex("[\\n,;]+")).map { it.trim() }.filter { it.isNotEmpty() },
                        // Remote .srs sets and urltest selections must survive a
                        // reconnect. Without this, every start re-downloads GitHub
                        // resources and a temporary 404/network block aborts the core.
                        cacheFileEnabled = true,
                        cacheFilePath = File(context.filesDir, "singbox/cache.db").also {
                            it.parentFile?.mkdirs()
                        }.absolutePath,
                        // Core knobs the builder gained that SettingsUiState has no row for
                        // yet. They come from the same preference store the settings screens
                        // use, so adding a row later is a one-line change; every default
                        // below matches SingboxConfigOptions, so today's output is unchanged.
                        multiplexProtocol = prefs.getString("mux_protocol", "smux") ?: "smux",
                        multiplexMinStreams = prefs.getInt("mux_min_streams", 4),
                        multiplexPadding = prefs.getBoolean("mux_padding", true),
                        multiplexBrutalEnabled = prefs.getBoolean("mux_brutal_enabled", false),
                        multiplexBrutalUpMbps = prefs.getInt("mux_brutal_up_mbps", 0),
                        multiplexBrutalDownMbps = prefs.getInt("mux_brutal_down_mbps", 0),
                        outboundTcpFastOpen = prefs.getBoolean("outbound_tcp_fast_open", false),
                        outboundTcpMultiPath = prefs.getBoolean("outbound_tcp_multi_path", false),
                        outboundUdpFragment = prefs.getBoolean("outbound_udp_fragment", false),
                        outboundConnectTimeoutSeconds = prefs.getInt("outbound_connect_timeout_s", 0),
                        udpOverTcp = prefs.getBoolean("udp_over_tcp", false),
                        dnsFakeIpRangeIPv4 = prefs.getString("dns_fake_ip_range_v4", null)
                            ?.takeIf { it.isNotBlank() } ?: "198.18.0.0/15",
                        dnsFakeIpRangeIPv6 = prefs.getString("dns_fake_ip_range_v6", null)
                            ?.takeIf { it.isNotBlank() } ?: "fc00::/18",
                        dnsIndependentCache = prefs.getBoolean("dns_independent_cache", true),
                        dnsDisableCache = prefs.getBoolean("dns_disable_cache", false),
                        dnsClientSubnet = prefs.getString("dns_client_subnet", "").orEmpty().trim(),
                        domainResolverStrategy = prefs.getString("domain_resolver_strategy", "")
                            .orEmpty().trim().lowercase(Locale.US),
                        sniffTimeoutMs = prefs.getInt("sniff_timeout_ms", 0),
                        // String backed like directDomains, so the same separators apply.
                        sniffers = prefs.getString("sniffers", "").orEmpty()
                            .split(Regex("[\\n,;]+"))
                            .map { it.trim().lowercase(Locale.US) }
                            .filter { it.isNotEmpty() },
                        urlTestIdleTimeoutMinutes = prefs.getInt("url_test_idle_timeout_minutes", 0),
                        urlTestInterruptExistConnections =
                            prefs.getBoolean("url_test_interrupt_exist", true)
                    )
                )
            }
        } catch (cancelled: CancellationException) {
            throw cancelled
        } catch (e: Exception) {
            if (reportErrors) reportConnectError("Config build failed: ${e.message}")
            return@withContext null
        }
        // OpenVPN "Use proxy" with obfs2/obfs3 needs the in-app transport relay;
        // plain http/socks proxies are handled by the core itself.
        val bridge = obfsBridges.singleOrNull()
        // One shared builder for the app, the widget and the tile: the two latter
        // read these prefs back, so every start parameter must be mirrored here.
        val params = VpnStartParams(
            configJson = configJson,
            engineType = s.engine,
            splitMode = _splitMode.value.name,
            splitPackages = _splitPackages.value,
            // The tun device itself must respect the same OpenVPN ceiling as the config.
            mtu = tunMtuFor(parsedSelected, s.mtu),
            localSocksPort = s.localSocksPort,
            proxyOnly = s.proxyOnly,
            dnsMode = s.dnsMode,
            reconnectOnNetworkChange = s.reconnectOnNetworkChange,
            obfsType = bridge?.first.orEmpty(),
            obfsHost = bridge?.second.orEmpty(),
            obfsPort = bridge?.third ?: 0
        )
        // Writes the config to its own private file; the start intent only carries the
        // path, which is what keeps a 300 member AUTO pool out of the Binder transaction.
        currentCoroutineContext().ensureActive()
        val stored = storedVpnConfigWriteMutex.withLock {
            // A foreground connect cancels any stale background build before waiting
            // for this lock, so it is always the last writer of active-config.json.
            currentCoroutineContext().ensureActive()
            runCatching { VpnStartIntentFactory.persistStartParams(context, params) }
        }
        if (stored.isFailure) {
            if (reportErrors) {
                reportConnectError(
                    "Could not store the generated config: ${stored.exceptionOrNull()?.message}"
                )
            }
            return@withContext null
        }
        if (reportErrors) {
            VpnLogBus.clearLastError()
            log("Starting sing-box extended \u2192 ${selected.name}")
        }
        VpnStartIntentFactory.buildStartIntent(context, params)
    }

    /** Returns every distinct obfs bridge used by a node or an imported AUTO pool. */
    private fun obfsBridgesOf(node: ParsedNode): List<Triple<String, String, Int>> {
        val candidates = if (node.scheme.equals("auto", true)) {
            LinkParser.autoMembers(node.outbound)
        } else {
            listOf(node)
        }
        return candidates.mapNotNull(::obfsBridgeOf).distinct()
    }

    private fun obfsBridgeOf(node: ParsedNode): Triple<String, String, Int>? {
        val proxy = node.outbound["lumen_proxy"] as? Map<*, *> ?: return null
        val type = (proxy["type"] as? String)?.trim()?.lowercase().orEmpty()
        if (type !in setOf("obfs2", "obfs2-legacy", "obfs3")) return null
        val host = (proxy["server"] as? String)?.trim().orEmpty()
        val port = when (val raw = proxy["server_port"]) {
            is Number -> raw.toInt()
            is String -> raw.trim().toIntOrNull() ?: 0
            else -> 0
        }
        if (host.isBlank() || port !in 1..65535) return null
        return Triple(type, host, port)
    }

    /**
     * Largest local TUN MTU that still fits inside one OpenVPN datagram on an
     * ordinary 1500-byte path: 1500 minus IP, UDP/TCP, the OpenVPN header and the
     * data-channel HMAC/GCM tag leaves roughly 1400 usable bytes.
     */
    private val openVpnMaxTunMtu = 1400

    /** True when this node, or any member of an imported AUTO pool, is OpenVPN. */
    private fun usesOpenVpn(node: ParsedNode): Boolean {
        val candidates = if (node.scheme.equals("auto", true)) {
            LinkParser.autoMembers(node.outbound)
        } else {
            listOf(node)
        }
        return candidates.any { member ->
            member.scheme.equals("openvpn", true) ||
                (member.outbound["type"] as? String)?.equals("openvpn", true) == true
        }
    }

    /**
     * The MTU setting goes up to 9000, which is fine for the TCP-based protocols but
     * hands OpenVPN packets it cannot carry: everything the far side has to fragment
     * or drop stalls, which is why small requests survive while QUIC and other
     * full-size traffic (Google, YouTube) hangs on an otherwise connected tunnel.
     */
    private fun tunMtuFor(node: ParsedNode, requested: Int): Int {
        val bounded = requested.coerceIn(1280, 9000)
        return if (usesOpenVpn(node)) bounded.coerceAtMost(openVpnMaxTunMtu) else bounded
    }

    fun buildStopIntent(context: Context): Intent =
        VpnStartIntentFactory.buildStopIntent(context)

    private fun parseEntity(entity: NodeEntity): ParsedNode {
        try {
            if (entity.isAutoNode || entity.protocol.equals("auto", true) || entity.link.trim().equals("auto", true)) {
                // An imported AUTO group stores its server pool in outboundJson.
                val storedAuto = entity.outboundJson.trim()
                val autoOutbound = if (storedAuto.startsWith("{")) {
                    runCatching { LinkParser.jsonToMap(JSONObject(storedAuto)) }.getOrDefault(emptyMap())
                } else emptyMap()
                return ParsedNode(
                    name = entity.name,
                    scheme = "auto",
                    server = "",
                    port = 0,
                    link = entity.link,
                    outbound = autoOutbound
                )
            }

            var parsed: ParsedNode? = null

            val linkText = entity.link.trim()

            // The stored normalized outbound is authoritative for every protocol.
            // Re-parsing a share link drops Clash-only fields, native sing-box
            // dependencies, plugins and protocol options that have no URI spelling.
            val storedJson = entity.outboundJson.trim()
            if (storedJson.startsWith("{")) {
                try {
                    val json = JSONObject(storedJson)
                    val outboundMap = LinkParser.jsonToMap(json)
                    val isNormalizedWrapper = outboundMap.keys.any {
                        it in setOf(
                            "protocol", "singbox", "settings", "streamSettings",
                            "clash", "_singbox_dependencies"
                        )
                    }
                    parsed = if (isNormalizedWrapper) {
                        ParsedNode(
                            name = entity.name.ifBlank { entity.server },
                            scheme = entity.protocol,
                            server = entity.server,
                            port = entity.port,
                            link = entity.link,
                            outbound = outboundMap
                        )
                    } else {
                        LinkParser.parseJsonObjectOutbound(json)
                    }
                } catch (_: Exception) {}
            }

            if (parsed == null && linkText.isNotBlank() && !linkText.startsWith("{") && !linkText.startsWith("[")) {
                try {
                    val (nodes, _) = LinkParser.parseLinksText(linkText)
                    parsed = nodes.firstOrNull()
                } catch (_: Exception) {}
            }

            if (parsed == null) {
                val jsonCandidate = when {
                    linkText.startsWith("{") -> linkText
                    else -> ""
                }
                if (jsonCandidate.isNotEmpty()) {
                    try {
                        val json = JSONObject(jsonCandidate)
                        parsed = LinkParser.parseJsonObjectOutbound(json)
                    } catch (_: Exception) {}
                }
            }

            if (parsed == null) {
                var outboundMap: Map<String, Any?> = emptyMap()
                if (entity.outboundJson.trim().startsWith("{")) {
                    try {
                        outboundMap = LinkParser.jsonToMap(JSONObject(entity.outboundJson.trim()))
                    } catch (_: Exception) {}
                }
                parsed = ParsedNode(
                    name = entity.name.ifBlank { entity.server },
                    scheme = entity.protocol.ifBlank { "unknown" },
                    server = entity.server,
                    port = entity.port,
                    link = entity.link,
                    outbound = outboundMap
                )
            }

            if (parsed.name.isBlank()) parsed.name = entity.name
            if (parsed.server.isBlank()) parsed.server = entity.server
            if (parsed.port <= 0) parsed.port = entity.port

            return parsed
        } catch (e: Exception) {
            log("Parse error for ${entity.name}: ${e.message}")
            return ParsedNode(
                name = entity.name.ifBlank { "Node" },
                scheme = entity.protocol.ifBlank { "unknown" },
                server = entity.server,
                port = entity.port,
                link = entity.link,
                outbound = emptyMap()
            )
        }
    }

    private fun extractDisplayProtocol(rawProtocol: String, outboundJson: String?, link: String?): String {
        val outboundObject = outboundJson?.takeIf { it.isNotBlank() }?.let { json ->
            runCatching { JSONObject(json) }.getOrNull()
        }
        val preferred = outboundObject?.optString("display_protocol").orEmpty().trim()
        if (preferred.isNotEmpty()) return preferred

        val jsonUpper = outboundJson?.uppercase() ?: ""
        val linkUpper = link?.uppercase() ?: ""
        val rootWarp = outboundObject?.optBoolean("warp", false) == true
        val isAutoPool = rawProtocol.equals("auto", ignoreCase = true)

        val isWarp = rootWarp || rawProtocol.equals("warp", ignoreCase = true) ||
            (!isAutoPool && (
                jsonUpper.contains("\"TYPE\":\"WARP\"") ||
                    jsonUpper.contains("\"TYPE\": \"WARP\"") ||
                    jsonUpper.contains("\"WARP\":TRUE") ||
                    jsonUpper.contains("\"WARP\": TRUE") ||
                    jsonUpper.contains("CLOUDFLARECLIENT.COM") ||
                    jsonUpper.contains("162.159.192.") ||
                    jsonUpper.contains("162.159.193.") ||
                    jsonUpper.contains("162.159.198.") ||
                    jsonUpper.contains("188.114.") ||
                    jsonUpper.contains("2606:4700:110:") ||
                    jsonUpper.contains("2606:4700:D0:") ||
                    jsonUpper.contains("2606:4700:D1:") ||
                    linkUpper.startsWith("WARP://") ||
                    linkUpper.contains("CLOUDFLARECLIENT.COM")
                ))
        if (isWarp) {
            val isMasque = rawProtocol.equals("masque", ignoreCase = true) ||
                jsonUpper.contains("\"TYPE\":\"MASQUE\"") ||
                jsonUpper.contains("\"TYPE\": \"MASQUE\"") ||
                linkUpper.startsWith("MASQUE://")
            return if (isMasque) "MASQUE/WARP" else "AWG/WARP"
        }

        val isAwg = rawProtocol.equals("awg", ignoreCase = true) ||
                rawProtocol.equals("amneziawg", ignoreCase = true) ||
                jsonUpper.contains("\"AMNEZIA\"") ||
                jsonUpper.contains("\"JC\"") ||
                jsonUpper.contains("\"JMIN\"") ||
                jsonUpper.contains("\"H1\"") ||
                jsonUpper.contains("\"S1\"") ||
                linkUpper.contains("AWG://") ||
                linkUpper.contains("AMNEZIA-WG") ||
                linkUpper.contains("JC=") ||
                linkUpper.contains("H1=") ||
                linkUpper.contains("S1=")

        val proto = when {
            isAwg -> "AWG"
            rawProtocol.equals("wireguard", ignoreCase = true) || rawProtocol.equals("wg", ignoreCase = true) -> "WireGuard"
            rawProtocol.equals("openvpn", ignoreCase = true) -> "OpenVPN"
            rawProtocol.equals("hysteria2", ignoreCase = true) || rawProtocol.equals("hy2", ignoreCase = true) -> "Hysteria2"
            rawProtocol.equals("tuic", ignoreCase = true) -> "TUIC"
            rawProtocol.equals("shadowsocks", ignoreCase = true) || rawProtocol.equals("ss", ignoreCase = true) -> "Shadowsocks"
            else -> rawProtocol.trim().uppercase()
        }

        if (proto == "AWG" || proto == "WireGuard" || proto == "OpenVPN" || proto == "Hysteria2" || proto == "TUIC" || proto == "Shadowsocks") {
            return proto
        }

        val security = when {
            jsonUpper.contains("\"REALITY\"") || linkUpper.contains("SECURITY=REALITY") || linkUpper.contains("PBK=") -> "REALITY"
            jsonUpper.contains("\"TLS\"") || linkUpper.contains("SECURITY=TLS") -> "TLS"
            else -> ""
        }

        val network = when {
            jsonUpper.contains("\"XHTTP\"") || linkUpper.contains("TYPE=XHTTP") || linkUpper.contains("HEADER=XHTTP") -> "XHTTP"
            jsonUpper.contains("\"HTTPUPGRADE\"") || linkUpper.contains("TYPE=HTTPUPGRADE") -> "HTTPUpgrade"
            jsonUpper.contains("\"GRPC\"") || linkUpper.contains("TYPE=GRPC") -> "gRPC"
            jsonUpper.contains("\"WS\"") || linkUpper.contains("TYPE=WS") -> "WS"
            jsonUpper.contains("\"H2\"") || linkUpper.contains("TYPE=H2") -> "H2"
            else -> ""
        }

        val subType = when {
            security == "REALITY" -> "REALITY"
            network.isNotEmpty() && security.isNotEmpty() -> "$security/$network"
            network.isNotEmpty() -> network
            security.isNotEmpty() -> security
            else -> ""
        }

        return if (subType.isNotEmpty()) "$proto/$subType" else proto
    }

    // AWG/WireGuard imports have no human readable name, so the parser generates one from
    // the endpoint ("AmneziaWG-1.2.3.4"). Those are recognised here and replaced with the
    // detected location, so the list and the connection status area show "Germany" for AWG
    // exactly like they already do for VLESS.
    private val technicalNodeNameRegex = Regex(
        "^(amnezia\\s*-?wg|amneziawg|awg|wireguard|wg)\\b[-_ :]*",
        RegexOption.IGNORE_CASE
    )

    private fun locationNameOrNull(name: String, server: String, countryCode: String): String? {
        val trimmed = name.trim()
        if (trimmed.isEmpty()) return null
        val technical = technicalNodeNameRegex.containsMatchIn(trimmed) ||
            trimmed.equals(server, ignoreCase = true) ||
            trimmed.removePrefix("[").removeSuffix("]").equals(server, ignoreCase = true)
        if (!technical) return null
        val location = runCatching {
            CountryFlagHelper.countryDisplayName(countryCode)
        }.getOrDefault("")
        return location.ifBlank { null }
    }

    private fun shouldResolveWireGuardCountry(entity: NodeEntity): Boolean {
        val protocol = entity.protocol.trim().lowercase(Locale.US)
        if (protocol !in setOf("awg", "amneziawg", "wireguard", "wg")) return false
        if (CountryFlagHelper.detectCountryStrict(entity.name, entity.server).isNotEmpty()) return false
        val outbound = entity.outboundJson.orEmpty()
        val isWarp = runCatching { JSONObject(outbound).optBoolean("warp", false) }.getOrDefault(false) ||
            entity.name.contains("warp", true) ||
            outbound.contains("cloudflare", true) ||
            outbound.contains("2606:4700:110:", true)
        return !isWarp
    }

    private fun normalizedEndpointHost(server: String): String =
        server.trim().removePrefix("[").removeSuffix("]").substringBefore('%').lowercase(Locale.US)

    private fun resolveCountryCode(host: String): String {
        val address = runCatching { InetAddress.getByName(host) }.getOrNull() ?: return ""
        if (
            address.isAnyLocalAddress ||
            address.isLoopbackAddress ||
            address.isLinkLocalAddress ||
            address.isSiteLocalAddress ||
            address.isMulticastAddress
        ) return ""
        val queryAddress = address.hostAddress?.substringBefore('%').orEmpty()
        if (queryAddress.isEmpty()) return ""
        return runCatching {
            val connection = (URL("https://ipwho.is/$queryAddress").openConnection() as HttpURLConnection).apply {
                requestMethod = "GET"
                connectTimeout = 3_000
                readTimeout = 3_000
                setRequestProperty("Accept", "application/json")
                setRequestProperty("User-Agent", "Lumen-Android")
            }
            try {
                if (connection.responseCode !in 200..299) return@runCatching ""
                val json = connection.inputStream.bufferedReader().use { JSONObject(it.readText()) }
                if (!json.optBoolean("success", true)) return@runCatching ""
                json.optString("country_code")
                    .trim()
                    .uppercase(Locale.US)
                    .takeIf { it.length == 2 && it.all { ch -> ch in 'A'..'Z' } }
                    .orEmpty()
            } finally {
                connection.disconnect()
            }
        }.getOrDefault("")
    }

    private fun stripFlagEmoji(value: String): String {
        val result = StringBuilder()
        value.codePoints().forEach { codePoint ->
            if (codePoint !in 0x1F1E6..0x1F1FF && codePoint != 0xFE0F) {
                result.appendCodePoint(codePoint)
            }
        }
        return result.toString()
            .replace(Regex("^[\\s|•·:—–-]+|[\\s|•·:—–-]+$"), "")
            .replace(Regex("\\s{2,}"), " ")
            .trim()
    }

    companion object {
        const val PREFS_NAME = "lumen_prefs"

        /**
         * Launcher icon the user pinned. Read before [_settings] exists (startup
         * reconcile) and written by [updateSettings], hence a named constant.
         */
        const val PREF_LAUNCHER_ICON = "launcher_icon"
        /** Preference ServerListScreen and the dashboard read their group from. */
        const val KEY_SERVERS_LAST_GROUP = "servers_last_group"
        /** Must match ServerListScreen's GROUP_MANUAL: the default / manual bucket. */
        const val SERVER_GROUP_MANUAL = "manual"
        // Core verbosity while logging is on. Debug is the single biggest CPU and
        // battery drain here — every line crosses the log bus — so stay at warning.
        const val CORE_LOG_LEVEL = "warning"
        private const val STORED_CONFIG_REFRESH_DEBOUNCE_MS = 400L
        private const val STORED_CONFIG_RUNNING_RETRY_MS = 250L
        private const val GEO_RESOURCE_MAX_BYTES = 256L * 1024 * 1024
        private const val PREF_LAST_ANDROID_UPDATE_CHECK = "last_android_update_check_ms"
        /** Last known subscription-userinfo figures, one `id|upload|download|total|expire` line each. */
        private const val KEY_SUBSCRIPTION_USAGE = "subscription_usage"
        private val USAGE_KEYS = listOf("upload", "download", "total", "expire")
        /** Ping methods that start a temporary core for the node instead of probing its endpoint. */
        private val CORE_PING_TYPES = setOf("real", "http")
        /** Protocols whose endpoint only listens on UDP, so a TCP connect can never succeed. */
        private val UDP_ONLY_SCHEMES = setOf(
            "wireguard", "amneziawg", "awg", "wg", "warp",
            // Hysteria/Hysteria2 and TUIC listen on QUIC/UDP. TCPing their port
            // measures a service that does not exist, so use the actual outbound
            // and HTTP relay-delay check instead.
            "hysteria", "hysteria2", "hy", "hy2", "tuic",
            // OpenVPN profiles are commonly UDP and the database protocol does not
            // carry the parsed transport. A real through-core check is valid for both
            // UDP and TCP profiles and proves that the tunnel passes traffic.
            "openvpn", "ovpn"
        )
    }
}

/** Longest provider text kept per field; the spec caps announcements at 200 characters. */
private const val SUBSCRIPTION_TEXT_MAX = 400

/**
 * Folds one refresh's headers into the stored provider metadata.
 *
 * Same rule the traffic figures already follow: a field this response did not carry keeps
 * the value the panel sent last time. A refresh that answers through a fallback
 * User-Agent, or that simply drops `announce`, must not blank the card.
 */
internal fun mergeSubscriptionMetadata(
    stored: SubscriptionEntity,
    fresh: SubscriptionMetadata,
    intervalHours: Int?
): SubscriptionEntity = stored.copy(
    description = fresh.description?.take(SUBSCRIPTION_TEXT_MAX) ?: stored.description,
    announce = fresh.announce?.take(SUBSCRIPTION_TEXT_MAX) ?: stored.announce,
    announceUrl = fresh.announceUrl ?: stored.announceUrl,
    telegramUrl = fresh.telegramUrl ?: stored.telegramUrl,
    supportUrl = fresh.supportUrl ?: stored.supportUrl,
    supportEmail = fresh.supportEmail ?: stored.supportEmail,
    websiteUrl = fresh.websiteUrl ?: stored.websiteUrl,
    premiumUrl = fresh.premiumUrl ?: stored.premiumUrl,
    bannerText = fresh.bannerText?.take(SUBSCRIPTION_TEXT_MAX) ?: stored.bannerText,
    bannerButtonText = fresh.bannerButtonText?.take(80) ?: stored.bannerButtonText,
    bannerButtonUrl = fresh.bannerButtonUrl ?: stored.bannerButtonUrl,
    bannerBgColor = fresh.bannerBgColor ?: stored.bannerBgColor,
    bannerButtonColor = fresh.bannerButtonColor ?: stored.bannerButtonColor,
    hideUrl = fresh.hideUrl ?: stored.hideUrl,
    sortOrder = fresh.sortOrder ?: stored.sortOrder,
    updateIntervalHours = intervalHours ?: stored.updateIntervalHours
)

/**
 * Accounting for the `subscription-userinfo` figures. Pure, and kept out of the view
 * model so the rules that used to be wrong here — a zero `total` meaning "unlimited"
 * rather than "nothing left", upload counting towards the quota, an expiry that is
 * absent rather than elapsed — are covered by unit tests.
 */
internal object SubscriptionUsage {
    /** 9999-12-31T23:59:59Z, the same ceiling SubscriptionClient normalises expiry to. */
    private const val MAX_EXPIRE_SECONDS = 253_402_300_799L
    private const val DAY_MS = 86_400_000L

    /**
     * Folds one refresh into the stored figures. Only the keys the panel actually sent
     * are replaced: a response that omits a field, or a fallback User-Agent whose answer
     * carries no `subscription-userinfo` header at all, must not reset a known good
     * value to zero.
     */
    fun merge(stored: Map<String, Long>, fresh: Map<String, Long>): Map<String, Long> =
        if (fresh.isEmpty()) stored else stored + fresh

    /** Both directions count against the quota, which is what the panels themselves report. */
    fun used(info: Map<String, Long>): Long =
        (info["upload"] ?: 0L).coerceAtLeast(0L) + (info["download"] ?: 0L).coerceAtLeast(0L)

    /** null = unlimited: a missing or zero `total` is how panels spell an uncapped plan. */
    fun totalOrUnlimited(info: Map<String, Long>): Long? = info["total"]?.takeIf { it > 0L }

    fun remaining(info: Map<String, Long>): Long? =
        totalOrUnlimited(info)?.let { (it - used(info)).coerceAtLeast(0L) }

    fun ratio(info: Map<String, Long>): Float? =
        totalOrUnlimited(info)?.let { (used(info).toDouble() / it).coerceIn(0.0, 1.0).toFloat() }

    /** null = never expires; the value is a UNIX timestamp in seconds. */
    fun expiryEpochSeconds(info: Map<String, Long>): Long? = info["expire"]?.takeIf { it > 0L }

    /** Rounded up, so a plan with 18 hours left reads "1 day" instead of "0 days". */
    fun daysLeft(expireEpochSec: Long, nowMs: Long): Int {
        val remainingMs = expireEpochSec.coerceIn(0L, MAX_EXPIRE_SECONDS) * 1000L - nowMs
        if (remainingMs <= 0L) return 0
        return ((remainingMs + DAY_MS - 1) / DAY_MS).toInt()
    }

    fun summary(info: Map<String, Long>): String {
        val total = totalOrUnlimited(info)
        return "${formatBytes(used(info))} / ${total?.let(::formatBytes) ?: "∞"}"
    }

    fun formatBytes(bytes: Long): String {
        if (bytes < 1024) return "$bytes B"
        val units = arrayOf("KB", "MB", "GB", "TB")
        var value = bytes.toDouble()
        var index = -1
        while (value >= 1024 && index < units.lastIndex) {
            value /= 1024.0
            index++
        }
        return String.format(Locale.US, "%.1f %s", value, units[index.coerceAtLeast(0)])
    }
}

/**
 * Ping deadlines. Pure arithmetic, kept out of the view model so it can be unit
 * tested: every value follows from the user's timeout / attempts / retry settings,
 * so raising the timeout raises the deadline instead of contradicting it.
 */
internal object PingBudget {
    /** Members of one AUTO pool probed at a time; mirrors autoMemberPingSemaphore. */
    const val AUTO_MEMBER_CONCURRENCY = 32

    /** Nothing may hold a single row in "measuring" longer than this. */
    const val MAX_NODE_MS = 180_000L

    /** Nor a whole "ping all" run longer than this. */
    const val MAX_BATCH_MS = 900_000L

    /**
     * Every attempt plus the delays between them, with slack for name resolution
     * and, for the real HTTP check, for starting the temporary core.
     */
    fun attemptsMs(timeoutMs: Int, attempts: Int, retryDelayMs: Int, realCheck: Boolean): Long {
        val timeout = timeoutMs.coerceIn(500, 20_000).toLong()
        val tries = attempts.coerceIn(1, 10).toLong()
        val retryDelay = retryDelayMs.coerceIn(0, 5_000).toLong()
        // A core-backed attempt has two separately bounded phases: starting the
        // temporary sing-box-extended process and performing the HTTP exchange.
        val perAttempt = if (realCheck) timeout * 2L + 500L else timeout
        return tries * perAttempt + (tries - 1) * retryDelay + 2_000L
    }

    /**
     * AUTO pools probe their members in waves of [AUTO_MEMBER_CONCURRENCY], so their
     * budget grows with the number of waves rather than with the member count: a 307
     * member pool gets ten attempt budgets, not 307.
     */
    fun nodeMs(attemptsMs: Long, memberCount: Int): Long =
        (attemptsMs * waves(memberCount, AUTO_MEMBER_CONCURRENCY)).coerceAtMost(MAX_NODE_MS)

    /** Backstop for a whole run: the per-node ceiling times the number of waves. */
    fun batchMs(nodeCount: Int, concurrency: Int): Long =
        (MAX_NODE_MS * waves(nodeCount, concurrency.coerceIn(1, 32)))
            .coerceIn(MAX_NODE_MS, MAX_BATCH_MS)

    private fun waves(count: Int, perWave: Int): Long {
        val total = count.coerceAtLeast(1).toLong()
        return ((total + perWave - 1) / perWave).coerceAtLeast(1L)
    }
}

/** Only a successful HTTP response is latency; errors and proxy block pages are not. */
internal fun isSuccessfulHttpPingStatusLine(status: String?): Boolean {
    val value = status?.trim().orEmpty()
    val firstSpace = value.indexOf(' ')
    if (firstSpace <= 0 || !value.substring(0, firstSpace).startsWith("HTTP/", true)) return false
    val code = value.substring(firstSpace + 1)
        .trimStart()
        .takeWhile(Char::isDigit)
        .takeIf { it.length == 3 }
        ?.toIntOrNull()
        ?: return false
    return code in 200..399
}

internal data class SubscriptionEdit(val name: String, val url: String)

internal fun refreshedSubscriptionName(
    currentName: String,
    providerTitle: String?,
    adoptProviderTitle: Boolean
): String = if (adoptProviderTitle) {
    providerTitle?.trim()?.take(160)?.ifBlank { currentName } ?: currentName
} else {
    currentName
}

/**
 * HTTPS is always accepted. Plain HTTP follows the App Settings switch, except that an
 * already saved HTTP URL may be kept while the user changes only the subscription name.
 */
internal fun validateSubscriptionEdit(
    existingUrl: String,
    name: String,
    url: String,
    allowHttp: Boolean
): SubscriptionEdit? {
    val cleanName = name.trim().take(160)
    val cleanUrl = url.trim()
    if (cleanName.isEmpty() || cleanUrl.isEmpty() || cleanUrl.length > 8_192) return null
    if ('\r' in cleanUrl || '\n' in cleanUrl) return null
    val parsed = runCatching { URL(cleanUrl) }.getOrNull() ?: return null
    if (parsed.host.isBlank()) return null
    val scheme = parsed.protocol.lowercase(Locale.US)
    val keepsExistingHttp = scheme == "http" && cleanUrl == existingUrl.trim()
    if (scheme != "https" && !(scheme == "http" && (allowHttp || keepsExistingHttp))) return null
    return SubscriptionEdit(cleanName, cleanUrl)
}
