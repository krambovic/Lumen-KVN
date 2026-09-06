from __future__ import annotations

from pathlib import Path
import sys

from .data_paths import resolve_data_dir, seed_user_data


APP_NAME = "Lumen"
APP_VERSION = "1.9.10"
STATE_SCHEMA_VERSION = 1
# Bump when parsing/reconciliation semantics change; cached validators remain
# useful, while the value lets future migrations force one clean reconcile.
SUBSCRIPTION_PARSER_REVISION = 2
SUBSCRIPTION_FETCHER_EXE_NAME = "lumen-subscription-fetcher.exe"

DIAGNOSTICS_UPLOAD_URL = "https://diagnostics.lumen-kvn.eu.cc/api/ingest"
# NOISE FILTER
DIAGNOSTICS_SECRET = "07f7d005166286e354645dcbce892998987bd8d8d20f296026dbb01ff05a9b8a"

PROXY_HOST = "127.0.0.1"
DEFAULT_SOCKS_PORT = 10808
DEFAULT_HTTP_PORT = 10809
DEFAULT_DISCORD_SOCKS_PORT = 10818
DEFAULT_XRAY_STATS_API_PORT = 19085
XRAY_GITHUB_RELEASES_API = "https://api.github.com/repos/XTLS/Xray-core/releases"

ROUTING_GLOBAL = "global"
ROUTING_RULE = "rule"
ROUTING_DIRECT = "direct"
ROUTING_MODES = (ROUTING_GLOBAL, ROUTING_RULE, ROUTING_DIRECT)


BASE_DIR = (
    Path(sys.executable).resolve().parent
    if getattr(sys, "frozen", False)
    else Path(__file__).resolve().parents[1]
)


INSTALL_DATA_DIR = BASE_DIR / "data"
DATA_DIR = resolve_data_dir(BASE_DIR, INSTALL_DATA_DIR, APP_NAME)
if DATA_DIR != INSTALL_DATA_DIR:
    seed_user_data(INSTALL_DATA_DIR, DATA_DIR)

ASSETS_DIR = BASE_DIR / "assets"
APP_ICON_PATH = ASSETS_DIR / "Lumen.ico"
TEMPLATES_DIR = DATA_DIR / "templates"
CONFIGS_DIR = DATA_DIR / "configs"
SINGBOX_TEMPLATES_DIR = TEMPLATES_DIR / "sing-box"
XRAY_TEMPLATES_DIR = TEMPLATES_DIR / "xray"
SINGBOX_CONFIGS_DIR = CONFIGS_DIR / "sing-box"
XRAY_CONFIGS_DIR = CONFIGS_DIR / "xray"
RUNTIME_DIR = DATA_DIR / "runtime"
LOG_DIR = DATA_DIR / "logs"
STATE_FILE = DATA_DIR / "state.enc"
XRAY_CONFIG_FILE = RUNTIME_DIR / "xray_config.json"
XRAY_DEFAULT_CONFIG_NAME = "default.json"
XRAY_PATH_DEFAULT = BASE_DIR / "core" / "xray.exe"

SINGBOX_CONFIG_FILE = RUNTIME_DIR / "singbox_config.json"
SINGBOX_DEFAULT_CONFIG_NAME = "default.json"
SINGBOX_PATH_DEFAULT = BASE_DIR / "core" / "sing-box.exe"
SINGBOX_CLASH_API_PORT = 19090
SINGBOX_CLASH_API_SELECTOR = "proxy"
SINGBOX_XRAY_RELAY_PORT = 11808
SINGBOX_TUN_INTERFACE_NAME = "tun0"
SINGBOX_LEGACY_TUN_INTERFACE_NAMES = ("singbox_tun", "xftun*")

SPEED_TEST_DEFAULT_URL = "https://cachefly.cachefly.net/50mb.test"
SPEED_TEST_PING_URL = "https://www.google.com/generate_204"
SPEED_TEST_TIMEOUT = 10
SPEED_TEST_MIXED_CONCURRENCY = 10
SPEED_TEST_STARTUP_TIMEOUT = 5.0
SPEED_TEST_PING_TIMEOUT = 3.0
SPEED_TEST_MAX_PING_MS = 3500
SPEED_TEST_DOWNLOAD_IDLE_TIMEOUT = 3.0
SPEED_TEST_SLOW_GRACE_SECONDS = 2.5
SPEED_TEST_MIN_BYTES_AFTER_GRACE = 128 * 1024
SPEED_TEST_MIN_MBPS_AFTER_GRACE = 0.2

PING_METHODS = ("tcping", "icmp", "http", "real")
ICMP_PING_TIMEOUT_MS = 1500
SPEED_TEST_MAX_CONCURRENCY = 32

SS_PROTECT_PORT_START = 19200
SS_PROTECT_PORT_END = 19300
