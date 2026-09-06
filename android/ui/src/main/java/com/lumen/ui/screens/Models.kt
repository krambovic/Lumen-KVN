package com.lumen.ui.screens

import androidx.compose.runtime.Immutable
import androidx.compose.ui.graphics.ImageBitmap

/**
 * UI-facing models shared by all screens. The :ui module is intentionally
 * decoupled from :core:database — the app layer maps entities to these models.
 */

@Immutable
data class NodeUiModel(
    val id: String,
    val name: String,
    val protocol: String,
    val server: String,
    val port: Int,
    val pingMs: Int? = null,
    val countryCode: String = "",
    val isAutoNode: Boolean = false,
    val isSelected: Boolean = false,
    val subscriptionId: String? = null,
    // Custom group the user put this server in, null when it is in none. Independent
    // of [subscriptionId]: a subscription server can also sit in a custom group.
    val groupId: String? = null,
    val displayProtocol: String = protocol.uppercase()
)

@Immutable
data class SubscriptionUiModel(
    val id: String,
    val name: String,
    val url: String,
    val lastUpdated: Long = 0L,
    val nodeCount: Int = 0,
    val autoUpdateEnabled: Boolean = true,
    val premiumFeatureCount: Int = 0,
    val trafficSummary: String? = null,
    val expiryDaysLeft: Int? = null,
    // Premium API extras shown on the dashboard card.
    val trafficRatio: Float? = null,
    val updateIntervalHours: Int? = null,
    // Provider metadata, already base64-decoded by the app layer. A null field means the
    // panel has never sent it; the row it belongs to is simply not rendered.
    val announce: String? = null,
    val announceUrl: String? = null,
    val description: String? = null,
    /** Happ's "Channel / Bot" link (telegram-url). */
    val telegramUrl: String? = null,
    val supportUrl: String? = null,
    val supportEmail: String? = null,
    val websiteUrl: String? = null,
    val premiumUrl: String? = null,
    val bannerText: String? = null,
    val bannerButtonText: String? = null,
    val bannerButtonUrl: String? = null,
    /** `#RRGGBB`, uppercase, validated by the app layer. */
    val bannerBgColor: String? = null,
    val bannerButtonColor: String? = null,
    /** The provider asked for the subscription URL not to be shown. */
    val hideUrl: Boolean = false,
    /** "ping", "name" or "none" — the order the provider wants its servers listed in. */
    val sortOrder: String? = null
)

/**
 * Server group ids shared by the dashboard and the server list: everything else
 * is a subscription id. Both screens persist the choice under "servers_last_group".
 */
internal const val GROUP_ALL = "all"
internal const val GROUP_MANUAL = "manual"

/** A group the user made by hand, listed next to Default and the subscriptions. */
@Immutable
data class ServerGroupUiModel(
    val id: String,
    val name: String,
    val nodeCount: Int = 0
)

@Immutable
data class HomeServerGroup(
    val id: String,
    val title: String,
    val nodes: List<NodeUiModel>,
    val isSubscription: Boolean = false,
    val subscription: SubscriptionUiModel? = null,
    /** True for a user-made group; drives the rename / delete actions. */
    val isCustom: Boolean = false
)

/**
 * The group selector's ids, in display order: All, Default, the custom groups the user
 * made, then one entry per subscription.
 */
fun serverGroupIds(
    customGroups: List<ServerGroupUiModel>,
    subscriptions: List<SubscriptionUiModel>
): List<String> = buildList {
    add(GROUP_ALL)
    // Default is a real destination for manual imports and must stay selectable
    // before its first node is added.
    add(GROUP_MANUAL)
    customGroups.forEach { add(it.id) }
    subscriptions.forEach { add(it.id) }
}

/**
 * Membership rule of the whole screen, in one place.
 *
 * A custom group wins over the subscription: once a server is assigned to one, that is
 * the only group the selector lists it under, so moving servers around actually moves
 * them. Subscription membership itself is untouched — the server keeps refreshing with
 * its subscription and still exports with it — and "All servers" keeps showing
 * everything.
 */
fun nodeInGroup(node: NodeUiModel, groupId: String): Boolean = when (groupId) {
    GROUP_ALL -> true
    GROUP_MANUAL -> node.subscriptionId == null && node.groupId == null
    else -> if (node.groupId != null) node.groupId == groupId else node.subscriptionId == groupId
}

/** Nodes of one group, unsorted and unfiltered. */
fun nodesInGroup(nodes: List<NodeUiModel>, groupId: String): List<NodeUiModel> =
    nodes.filter { nodeInGroup(it, groupId) }

data class AppEntryUiModel(
    val packageName: String,
    val label: String,
    val icon: ImageBitmap? = null,
    val isSelected: Boolean = false,
    val isSystem: Boolean = false
)

data class GeoResourceUiModel(
    val name: String,
    val sizeBytes: Long = 0L,
    val modifiedAt: Long = 0L
)

/**
 * One line of the app's own log store. The level is a lowercase name rather than the
 * :core:vpn enum so the :ui module stays independent of it, like every other model here.
 */
@Immutable
data class LogEntryUi(
    val timestamp: Long,
    val time: String,
    val level: String,
    val component: String,
    val message: String
) {
    /** Rendered form used by copy, export and the plain-text fallback. */
    fun formatted(): String = "$time ${level.uppercase()} [$component] $message"
}

/** Severities the app's log store records, least to most severe. */
val LOG_STORE_LEVELS: List<String> = listOf("debug", "info", "warning", "error")

/** Extra option of the log level filter: keep every severity. */
const val LOG_FILTER_ALL: String = "all"

/** Rank of a log level, used to filter by minimum severity. Unknown levels sort lowest. */
fun logLevelRank(level: String): Int = LOG_STORE_LEVELS.indexOf(level.trim().lowercase())

enum class SplitModeUi { DISABLED, ALLOW_LIST, DISALLOW_LIST }

enum class ThemeMode { SYSTEM, LIGHT, DARK }

enum class ThemePreset {
    LIGHT,
    DARK,
    DRACULA,
    CATPPUCCIN,
    NORD,
    GITHUB,
    GRUVBOX,
    TOKYO_NIGHT,
    MONOKAI,
    MATERIAL,
    SOLARIZED,
    ROSE_PINE
}

enum class ImportKindUi { SUBSCRIPTION, CONFIG }

enum class ImportPhaseUi { HIDDEN, AWAITING, IMPORTING, SUCCESS, ERROR }

data class ImportUiState(
    val phase: ImportPhaseUi = ImportPhaseUi.HIDDEN,
    val kind: ImportKindUi? = null,
    val raw: String = "",
    val title: String = "",
    val message: String = ""
)

/**
 * Socks5 credentials for the local inbound. The login keeps the `lu_` prefix so
 * it is recognisable, and both values are generated from a cryptographic source
 * because they are the only thing protecting the local proxy on a shared LAN.
 */
fun generateSocks5Username(): String {
    val random = java.security.SecureRandom()
    return "lu_" + (1..9).joinToString("") { random.nextInt(10).toString() }
}

fun generateSocks5Password(): String {
    // No look-alike characters: these values are read off the screen and retyped.
    val alphabet = "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    val random = java.security.SecureRandom()
    return (1..16).joinToString("") { alphabet[random.nextInt(alphabet.length)].toString() }
}

val DEFAULT_DIRECT_DOMAINS: String = """
direct:10.0.0.0/8
direct:172.16.0.0/12
direct:192.168.0.0/16
direct:127.0.0.0/8
direct:fc00::/7
direct:geosite:category-ru
direct:geoip:ru
""".trimIndent()

data class SettingsUiState(
    val engine: String = "SINGBOX",
    val muxEnabled: Boolean = false,
    val muxConcurrency: Int = 8,
    val multiplexProtocol: String = "smux",
    val multiplexMinStreams: Int = 4,
    val multiplexPadding: Boolean = true,
    val multiplexBrutalEnabled: Boolean = false,
    val multiplexBrutalUpMbps: Int = 0,
    val multiplexBrutalDownMbps: Int = 0,
    val fragmentEnabled: Boolean = false,
    val fragmentPackets: String = "tlshello",
    val fragmentLength: String = "50-100",
    val fragmentDelay: String = "10-20",
    val outboundTcpFastOpen: Boolean = false,
    val outboundTcpMultiPath: Boolean = false,
    val outboundUdpFragment: Boolean = false,
    val udpOverTcp: Boolean = false,
    val outboundConnectTimeoutSeconds: Int = 0,
    val localInboundEnabled: Boolean = true,
    val localSocksPort: Int = 10808,
    val localHttpPort: Int = 10809,
    val lanSharingEnabled: Boolean = false,
    val socks5AuthEnabled: Boolean = true,
    val socks5Username: String = "",
    val socks5Password: String = "",
    val proxyOnly: Boolean = false,
    val autoConnectOnBoot: Boolean = false,
    val enableSpeedStats: Boolean = true,
    val preferIpv6: Boolean = false,
    val blockQuic: Boolean = false,
    val sniffRouteOnly: Boolean = false,
    val mtu: Int = 1500,
    val directDomains: String = DEFAULT_DIRECT_DOMAINS,
    val directIpCidrs: String = "",
    val geoResourceSource: String = "https://github.com/runetfreedom/russia-v2ray-rules-dat/",
    val proxyDnsServer: String = "cloudflare-dns.com",
    val directDnsServer: String = "1.1.1.1",
    val dnsMode: String = "automatic",
    val dnsCustomJson: String = "",
    val dnsDirectServers: String = "1.1.1.1\n8.8.8.8",
    val dnsProxyServers: String = "cloudflare-dns.com\ndns.google",
    val dnsDirectType: String = "udp",
    val dnsProxyType: String = "https",
    val dnsDirectStrategy: String = "ipv4_only",
    val dnsProxyStrategy: String = "ipv4_only",
    val dnsHijackEnabled: Boolean = true,
    val dnsFakeIpEnabled: Boolean = false,
    val dnsParallelQuery: Boolean = false,
    val dnsOptimisticCache: Boolean = false,
    val dnsGeoCheck: Boolean = true,
    val dnsProxyIpv4Only: Boolean = true,
    val dnsHosts: String = "",
    val dnsOverrideEnabled: Boolean = false,
    val dnsOverrideHostname: String = "",
    val dnsOverrideIpv4: String = "",
    val urlTestUrl: String = "https://www.gstatic.com/generate_204",
    val urlTestIntervalMinutes: Int = 3,
    val urlTestToleranceMs: Int = 50,
    val urlTestIdleTimeoutMinutes: Int = 0,
    val urlTestInterruptExistConnections: Boolean = true,
    val subscriptionUserAgent: String = "Happ/2.18.3/Windows/2606241603601",
    val subscriptionHwid: String = "",
    val subscriptionSendHwid: Boolean = true,
    val subscriptionDirect: Boolean = true,
    val allowSubscriptionOverrides: Boolean = true,
    val subscriptionAutoUpdateMinutes: Int = 240,
    val subscriptionIncludeRegex: String = "",
    val subscriptionExcludeRegex: String = "",
    val subscriptionUseProxyTun: Boolean = false,
    val subscriptionAllowHttp: Boolean = false,
    val subscriptionConverterEnabled: Boolean = false,
    val subscriptionConverterUrl: String = "",
    val loggingEnabled: Boolean = true,
    val language: String = "en",
    val themeMode: ThemeMode = ThemeMode.DARK,
    val themePreset: ThemePreset = ThemePreset.DARK,
    val useMaterialYou: Boolean = false,
    val useAmoledBlack: Boolean = false,
    val hapticsEnabled: Boolean = true,
    val telemetryEnabled: Boolean = true,
    val reconnectOnNetworkChange: Boolean = true,
    val validateProxyDataPath: Boolean = false,
    val showNotification: Boolean = true,
    val showNotificationSpeed: Boolean = true,
    val pingType: String = "http",
    val pingTimeoutMs: Int = 2000,
    val pingConcurrency: Int = 16,
    val pingUrl: String = "https://www.google.com/generate_204",
    val pingAttempts: Int = 1,
    val pingAggregate: String = "min",
    val pingRetryDelayMs: Int = 200,
    val pingGoodMs: Int = 150,
    val pingFairMs: Int = 300,
    val pingAutoOnOpen: Boolean = false,
    /** Remove completed ping results at or below [pingAutoDeleteThresholdMs]. */
    val pingAutoDeleteUnreachable: Boolean = false,
    /** Defaults to the requested 0/1 ms cleanup, but 0 keeps a valid 1 ms result. */
    val pingAutoDeleteThresholdMs: Int = 1,
    /** Check GitHub for a newer Android APK when the app is opened, at most daily. */
    val autoCheckUpdates: Boolean = true,
    val dashboardStyle: DashboardStyle = DashboardStyle.DEFAULT,
    val launcherIcon: LauncherIconOption = LauncherIconOption.SYSTEM
)

/** Dashboard layouts offered in Customization. */
enum class DashboardStyle { DEFAULT, SLIDER, CENTERED }

/**
 * Launcher icon the user pinned in Customization.
 *
 * [SYSTEM] is the default and the state the user can always come back to: it keeps
 * the shipped `ic_launcher`, which follows the system light/dark theme through the
 * res/drawable-night qualifier. [LIGHT] and [DARK] pin one of the two variants and
 * stop it re-theming itself.
 *
 * The app layer maps each entry to an <activity-alias>; the names are persisted, so
 * renaming an entry silently resets everyone's choice.
 */
enum class LauncherIconOption { SYSTEM, LIGHT, DARK }

/**
 * Editable node draft used by [NodeEditorModal]. [secret] holds the
 * UUID / password / WireGuard private key depending on the protocol.
 */
data class NodeDraft(
    val id: String? = null,
    val name: String = "",
    val protocol: String = "vless",
    val server: String = "",
    val port: String = "443",
    val secret: String = "",
    val flow: String = "",
    val network: String = "tcp",
    val security: String = "none",
    val path: String = "",
    val host: String = "",
    val serviceName: String = "",
    val sni: String = "",
    val alpn: String = "",
    val fingerprint: String = "",
    /** Base64 SHA-256 digest of the server certificate's SPKI public key. */
    val certificateSha256: String = "",
    val publicKey: String = "",
    val shortId: String = "",
    val method: String = "aes-256-gcm",
    val address: String = "",
    val presharedKey: String = "",
    val allowedIps: String = "0.0.0.0/0, ::/0",
    val reserved: String = "",
    val mtu: String = "",
    val dns: String = "",
    val persistentKeepalive: String = "",
    val jc: String = "",
    val jmin: String = "",
    val jmax: String = "",
    val s1: String = "",
    val s2: String = "",
    val s3: String = "",
    val s4: String = "",
    // AmneziaWG magic headers and the 2.0 junk-packet parameters; the server
    // matches on them, so the editor must round-trip them untouched.
    val h1: String = "",
    val h2: String = "",
    val h3: String = "",
    val h4: String = "",
    val i1: String = "",
    val i2: String = "",
    val i3: String = "",
    val i4: String = "",
    val i5: String = "",
    val j1: String = "",
    val j2: String = "",
    val j3: String = "",
    val itime: String = "",
    val obfs: String = "",
    val obfsPassword: String = "",
    val congestionControl: String = "bbr",
    val insecure: Boolean = false,
    val rawConfig: String = "",
    // OpenVPN editor fields (parity with desktop Lumen node editor).
    val ovpnProto: String = "udp",
    val ovpnCipher: String = "",
    val ovpnAuth: String = "",
    val ovpnUsername: String = "",
    val ovpnPassword: String = "",
    val ovpnCa: String = "",
    val ovpnCert: String = "",
    val ovpnKey: String = "",
    // Passphrase of an encrypted private key (OpenVPN's askpass).
    val ovpnKeyPassword: String = "",
    val ovpnTlsCrypt: String = "",
    val ovpnTlsCryptV2: Boolean = false,
    val ovpnTlsAuth: String = "",
    val ovpnKeyDirection: String = "",
    val ovpnTlsCipherSuites: String = "",
    val ovpnVerifyX509Name: String = "",
    val ovpnVerifyX509Mode: String = "",
    val ovpnExtraRemotes: String = "",
    val ovpnReconnectDelay: String = "",
    val ovpnPingInterval: String = "",
    val ovpnPingRestart: String = "",
    val ovpnDns: String = "",
    // "Use proxy" for OpenVPN: "" (none), "http", "socks", "obfs3", "obfs2", "obfs2-legacy".
    val ovpnProxyType: String = "",
    val ovpnProxyServer: String = "",
    val ovpnProxyPort: String = "",
    val ovpnProxyUsername: String = "",
    val ovpnProxyPassword: String = ""
)

val SUPPORTED_PROTOCOLS: List<String> = listOf(
    "vless", "vmess", "trojan", "ss", "hysteria", "hysteria2", "tuic",
    "wireguard", "awg", "masque", "openvpn", "socks", "http"
)

val NETWORK_TRANSPORTS: List<String> = listOf("tcp", "ws", "grpc", "xhttp", "http", "quic")

val SECURITY_OPTIONS: List<String> = listOf("none", "tls", "reality")

val SS_METHODS: List<String> = listOf(
    "aes-256-gcm", "aes-128-gcm", "chacha20-ietf-poly1305",
    "2022-blake3-aes-256-gcm", "2022-blake3-aes-128-gcm", "2022-blake3-chacha20-poly1305"
)

val CONGESTION_OPTIONS: List<String> = listOf("bbr", "cubic", "new_reno")

/** Multiplex protocols the core accepts; anything else is coerced back to smux. */
val MULTIPLEX_PROTOCOLS: List<String> = listOf("smux", "yamux", "h2mux")

/**
 * Log levels the core parses. "none" is deliberately absent: the core rejects it
 * with "unknown log level: none" and refuses to start.
 */
val LOG_LEVELS: List<String> = listOf("trace", "debug", "info", "warning", "error")

/**
 * Ping methods shared with desktop Lumen. "real" times the whole connect through a
 * temporary core, "http" times a plain GET through the same node once it is up.
 */
val PING_TYPES: List<String> = listOf("tcping", "icmp", "real", "http")

/** How several probes of one server are reduced to a single latency value. */
val PING_AGGREGATES: List<String> = listOf("min", "avg", "median")

/** Connectivity endpoints used by desktop Lumen and its Android fallback list. */
val PING_URL_PRESETS: List<String> = listOf(
    "https://www.google.com/generate_204",
    "https://www.gstatic.com/generate_204",
    "https://cp.cloudflare.com/generate_204",
    "https://connectivitycheck.platform.hicloud.com/generate_204"
)

/** Global haptics switch so any screen can respect the vibration setting. */
val LocalHapticsEnabled = androidx.compose.runtime.staticCompositionLocalOf { true }

/** Single source of version strings; the app layer fills [appVersion] from BuildConfig. */
object LumenVersion {
    var appVersion: String = "0.7.0"
    const val ENGINE: String = "1.13.14-extended-2.5.2"
}
