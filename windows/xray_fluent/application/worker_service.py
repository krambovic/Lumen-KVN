from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING

from ..connectivity_test import ConnectivityTestWorker
from ..constants import DEFAULT_HTTP_PORT, XRAY_PATH_DEFAULT
from ..i18n import tr
from ..path_utils import resolve_configured_path
from ..ping_worker import PingWorker
from ..qthread_utils import bind_thread_reference, retain_thread_until_finished
from ..speed_test_worker import SpeedTestWorker
from .node_runtime_service import is_native_singbox_only_node

if TYPE_CHECKING:
    from ..app_controller import AppController
    from ..models import Node


_ENDPOINT_PING_UNSUPPORTED = {
    "auto",
    "awg",
    "masque",
    "openvpn",
    "singbox_config",
    "warp",
    "wireguard",
    "xray_config",
}
_XRAY_TEST_UNSUPPORTED = {"auto", "singbox_config", "xray_config"}
_AUTO_CONFIG_PROTOCOLS = {"singbox_config", "xray_config"}
_IGNORED_AUTO_OUTBOUNDS = {
    "block",
    "blackhole",
    "direct",
    "dns",
    "freedom",
    "selector",
    "url-test",
    "urltest",
}


def _node_protocol(node: Node) -> str:
    outbound = node.outbound if isinstance(node.outbound, dict) else {}
    return str(outbound.get("protocol") or outbound.get("type") or node.scheme or "").strip().lower()


def _outbound_protocol(outbound: dict) -> str:
    return str(outbound.get("protocol") or outbound.get("type") or "").strip().lower()


def _port_number(value: object) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def _outbound_endpoint(outbound: dict) -> tuple[str, int]:
    server = str(outbound.get("server") or outbound.get("address") or "").strip()
    port = _port_number(outbound.get("server_port") or outbound.get("port"))
    settings = outbound.get("settings") if isinstance(outbound.get("settings"), dict) else {}
    for key in ("vnext", "servers"):
        entries = settings.get(key)
        if not isinstance(entries, list) or not entries or not isinstance(entries[0], dict):
            continue
        server = str(entries[0].get("address") or entries[0].get("server") or server).strip()
        port = _port_number(entries[0].get("port") or entries[0].get("server_port") or port)
        break
    if not server:
        server = str(settings.get("address") or settings.get("server") or "").strip()
    if port <= 0:
        port = _port_number(settings.get("port") or settings.get("server_port"))
    return server, port


def _auto_candidate_outbounds(node: Node) -> list[dict]:
    outbound = node.outbound if isinstance(node.outbound, dict) else {}
    protocol = _node_protocol(node)
    config_key = "xray_config" if protocol == "xray_config" else "singbox_config"
    config = outbound.get(config_key)
    if protocol not in _AUTO_CONFIG_PROTOCOLS or not isinstance(config, dict):
        return []
    outbounds = [item for item in config.get("outbounds", []) if isinstance(item, dict)]
    if not outbounds:
        return []

    selectors: list[str] = []
    if protocol == "xray_config":
        routing = config.get("routing") if isinstance(config.get("routing"), dict) else {}
        for balancer in routing.get("balancers", []):
            if not isinstance(balancer, dict):
                continue
            raw = balancer.get("selector")
            if isinstance(raw, list):
                selectors.extend(str(value).strip() for value in raw if str(value).strip())
        for observer_key in ("observatory", "burstObservatory"):
            observer = config.get(observer_key)
            raw = observer.get("subjectSelector") if isinstance(observer, dict) else None
            if isinstance(raw, list):
                selectors.extend(str(value).strip() for value in raw if str(value).strip())
    else:
        tag_map = {
            str(item.get("tag") or "").strip(): item
            for item in outbounds
            if str(item.get("tag") or "").strip()
        }
        for selector in outbounds:
            if _outbound_protocol(selector) not in {"selector", "url-test", "urltest"}:
                continue
            refs = selector.get("outbounds")
            if isinstance(refs, list):
                selectors.extend(str(value).strip() for value in refs if str(value).strip())
        selected = [tag_map[tag] for tag in selectors if tag in tag_map]
        if selected:
            outbounds = selected
            selectors = []

    candidates = [
        item for item in outbounds
        if _outbound_protocol(item) not in _IGNORED_AUTO_OUTBOUNDS
    ]
    if selectors:
        selected = [
            item for item in candidates
            if any(str(item.get("tag") or "").strip().startswith(prefix) for prefix in selectors)
        ]
        if selected:
            candidates = selected
    return candidates


def _auto_candidate_supports(candidate: dict, test: str, *, ping_method: str) -> bool:
    protocol = _outbound_protocol(candidate)
    server, port = _outbound_endpoint(candidate)
    if not server or port <= 0:
        return False
    if test == "speed":
        return protocol not in _XRAY_TEST_UNSUPPORTED and protocol not in {
            "awg", "hysteria", "hysteria2", "hy", "hy2", "masque", "mieru",
            "openvpn", "naive", "tuic", "warp", "wireguard",
        }
    return protocol not in _ENDPOINT_PING_UNSUPPORTED


def _node_supports_test(node: Node, test: str, *, ping_method: str = "tcping") -> bool:
    protocol = _node_protocol(node)
    if protocol in _AUTO_CONFIG_PROTOCOLS:
        if protocol == "singbox_config" and (test == "speed" or ping_method in {"http", "real"}):
            return False
        return any(
            _auto_candidate_supports(candidate, test, ping_method=ping_method)
            for candidate in _auto_candidate_outbounds(node)
        )
    if test == "speed":
        return not is_native_singbox_only_node(node) and protocol not in _XRAY_TEST_UNSUPPORTED
    if protocol in _ENDPOINT_PING_UNSUPPORTED:
        server, port = _outbound_endpoint(node.outbound if isinstance(node.outbound, dict) else {})
        if not server:
            server = str(node.server or "").strip()
        if port <= 0:
            port = _port_number(node.port)
        return bool(server and port > 0)
    return bool(node.server and _port_number(node.port) > 0)


def _node_for_test(node: Node, test: str, *, ping_method: str) -> Node:
    protocol = _node_protocol(node)
    if protocol not in _AUTO_CONFIG_PROTOCOLS or test == "speed":
        return node
    for candidate in _auto_candidate_outbounds(node):
        if not _auto_candidate_supports(candidate, test, ping_method=ping_method):
            continue
        server, port = _outbound_endpoint(candidate)
        prepared = deepcopy(node)
        prepared.server = server
        prepared.port = port
        candidate_protocol = _outbound_protocol(candidate)
        if candidate_protocol:
            prepared.scheme = candidate_protocol
            prepared.outbound = {"protocol": candidate_protocol, "singbox": deepcopy(candidate)}
        return prepared
    return node


def _filter_testable_nodes(
    controller: AppController,
    nodes: list[Node],
    test: str,
    *,
    ping_method: str = "tcping",
) -> list[Node]:
    supported: list[Node] = []
    unsupported: list[Node] = []
    for node in nodes:
        if _node_supports_test(node, test, ping_method=ping_method):
            supported.append(_node_for_test(node, test, ping_method=ping_method))
        else:
            unsupported.append(node)
    if not unsupported:
        return supported

    test_name = tr("Тест скорости") if test == "speed" else (
        tr("HTTP GET ping") if ping_method == "http" else (
            tr("Реальный пинг") if ping_method == "real" else tr("Пинг")
        )
    )
    names = [str(node.name or node.server or node.scheme or "—") for node in unsupported[:3]]
    if len(unsupported) > 3:
        names.append(tr("и ещё {count}", count=len(unsupported) - 3))
    controller.status.emit(
        "warning",
        tr(
            "{test} не поддерживается для выбранных серверов: {servers}",
            test=test_name,
            servers=", ".join(names),
        ),
    )
    return supported


def _clear_ping_measurements(controller: AppController, nodes: list[Node]) -> None:
    changed = False
    for node in nodes:
        if node.ping_ms is None and node.is_alive is None:
            continue
        node.ping_ms = None
        node.is_alive = None
        controller.ping_updated.emit(node.id, None)
        changed = True
    if changed:
        controller.schedule_save()


def _clear_speed_measurements(controller: AppController, nodes: list[Node]) -> None:
    changed = False
    for node in nodes:
        if node.speed_mbps is None and node.is_alive is None:
            continue
        node.speed_mbps = None
        node.is_alive = None
        controller.speed_updated.emit(node.id, None, False)
        controller.speed_progress_updated.emit(node.id, 0)
        changed = True
    if changed:
        controller.schedule_save()


def _resolve_xray_test_executable(controller: AppController) -> Path | None:
    resolved = resolve_configured_path(
        controller.state.settings.xray_path,
        default_path=XRAY_PATH_DEFAULT,
        use_default_if_empty=True,
        migrate_default_location=True,
    )
    if resolved is not None and resolved.is_file():
        return resolved
    missing_path = resolved or XRAY_PATH_DEFAULT
    controller.status.emit(
        "error",
        tr("xray.exe не найден: ") + str(missing_path),
    )
    return None


def ping_nodes(
    controller: AppController,
    node_ids: set[str] | None = None,
    method: str | None = None,
) -> None:
    nodes = controller.state.nodes
    if node_ids:
        nodes = [node for node in nodes if node.id in node_ids]
    if not nodes:
        return

    resolved_method = (method or controller.state.settings.ping_method or "tcping").strip().lower()
    if resolved_method not in ("tcping", "icmp", "http", "real"):
        resolved_method = "tcping"
    nodes = _filter_testable_nodes(controller, nodes, "ping", ping_method=resolved_method)
    if not nodes:
        return

    xray_test_executable = None
    if resolved_method in {"http", "real"}:
        if any(not SpeedTestWorker._uses_direct_ping_fallback(node) for node in nodes):
            xray_test_executable = _resolve_xray_test_executable(controller)
            if xray_test_executable is None:
                return

    if controller._ping_worker and controller._ping_worker.isRunning():
        previous = controller._ping_worker
        previous.cancel()
        retain_thread_until_finished(
            controller,
            controller._retired_workers,
            previous,
            delete_worker=False,
        )
        controller._ping_worker = None

    controller._ping_total = len(nodes)
    controller._ping_completed = 0
    state_node_map = {node.id: node for node in controller.state.nodes}
    controller._ping_node_map = {node.id: state_node_map.get(node.id, node) for node in nodes}
    _clear_ping_measurements(controller, list(controller._ping_node_map.values()))
    controller.bulk_task_progress.emit("ping", 0, controller._ping_total, False)

    if resolved_method in {"http", "real"}:
        # Реальная задержка измеряется через временный xray-прокси (как в v2rayN).
        xray_path = str(xray_test_executable)
        controller._log("[ping] Измеряю реальную задержку через временные прокси")
        real_active_session = controller._active_session
        real_bypass_tun = bool(
            controller.connected
            and real_active_session is not None
            and real_active_session.tun_mode
        )
        worker = SpeedTestWorker(
            nodes,
            xray_path=xray_path,
            routing=controller.state.routing,
            mode="ping",
            concurrency=controller.state.settings.speed_test_concurrency,
            bypass_tun=real_bypass_tun,
        )
        controller._ping_worker = worker
        bind_thread_reference(controller, "_ping_worker", worker)
        worker.ping_result.connect(controller._on_ping_result)
        worker.progress.connect(controller._on_ping_progress)
        worker.completed.connect(controller._on_ping_complete)
        worker.start()
        return

    active_session = controller._active_session
    bypass_tun = bool(controller.connected and active_session is not None and active_session.tun_mode)
    if bypass_tun:
        controller._log("[ping] TUN включен: проверяю серверы через временные прямые маршруты")
    controller._ping_worker = PingWorker(nodes, bypass_tun=bypass_tun, method=resolved_method)
    bind_thread_reference(controller, "_ping_worker", controller._ping_worker)
    controller._ping_worker.result.connect(controller._on_ping_result)
    controller._ping_worker.progress.connect(controller._on_ping_progress)
    controller._ping_worker.completed.connect(controller._on_ping_complete)
    controller._ping_worker.start()


def speed_test_nodes(controller: AppController, node_ids: set[str] | None = None) -> bool:
    nodes = controller.state.nodes
    if node_ids:
        nodes = [node for node in nodes if node.id in node_ids]
    if not nodes:
        return False

    if controller._speed_worker and controller._speed_worker.isRunning():
        controller.status.emit("info", "Тест скорости уже выполняется. Остановите его перед новым запуском.")
        return False

    nodes = _filter_testable_nodes(controller, nodes, "speed")
    if not nodes:
        return False

    xray_test_executable = _resolve_xray_test_executable(controller)
    if xray_test_executable is None:
        return False
    xray_path = str(xray_test_executable)

    controller._speed_total = len(nodes)
    controller._speed_completed = 0
    state_node_map = {node.id: node for node in controller.state.nodes}
    controller._speed_node_map = {node.id: state_node_map.get(node.id, node) for node in nodes}
    _clear_speed_measurements(controller, list(controller._speed_node_map.values()))
    controller.bulk_task_progress.emit("speed", 0, controller._speed_total, False)
    active_session = controller._active_session
    bypass_tun = bool(controller.connected and active_session is not None and active_session.tun_mode)
    if bypass_tun:
        controller._log("[speed] TUN включен: тестирую через временные прямые маршруты")
    controller._speed_worker = SpeedTestWorker(
        nodes,
        xray_path=xray_path,
        routing=controller.state.routing,
        test_url=controller.state.settings.speed_test_url,
        concurrency=controller.state.settings.speed_test_concurrency,
        bypass_tun=bypass_tun,
    )
    bind_thread_reference(controller, "_speed_worker", controller._speed_worker)
    controller._speed_worker.result.connect(controller._on_speed_result)
    controller._speed_worker.progress.connect(controller._on_speed_progress)
    controller._speed_worker.node_progress.connect(controller._on_speed_node_progress)
    controller._speed_worker.completed.connect(controller._on_speed_complete)
    controller._speed_worker.start()
    return True


def cancel_speed_test(controller: AppController) -> bool:
    worker = controller._speed_worker
    if worker is None or not worker.isRunning():
        controller.status.emit("info", "Тест скорости сейчас не выполняется")
        return False
    worker.cancel()
    controller.status.emit("info", "Останавливаю тест скорости...")
    return True


def test_connectivity(controller: AppController, url: str | None = None) -> None:
    target = (url or "https://www.gstatic.com/generate_204").strip()
    if not target:
        target = "https://www.gstatic.com/generate_204"

    if controller._connectivity_worker and controller._connectivity_worker.isRunning():
        controller.status.emit("info", "Тест подключения уже выполняется")
        return

    http_port = controller.get_effective_http_proxy_port() or int(controller.state.settings.local_http_port)
    controller._connectivity_worker = ConnectivityTestWorker(
        http_port,
        target,
        tun_mode=controller.state.settings.tun_mode,
        proxy_url=controller.get_effective_http_proxy_url() or "",
    )
    bind_thread_reference(controller, "_connectivity_worker", controller._connectivity_worker)
    controller._connectivity_worker.result.connect(controller._on_connectivity_result)
    controller._connectivity_worker.start()


def on_ping_result(controller: AppController, node_id: str, ping_ms: int | None) -> None:
    if controller.sender() is not controller._ping_worker:
        return
    node = getattr(controller, "_ping_node_map", {}).get(node_id)
    if node is not None:
        node.ping_ms = ping_ms
        node.is_alive = ping_ms is not None
        ts = datetime.now(timezone.utc).isoformat()
        node.ping_history.append((ts, ping_ms))
        if len(node.ping_history) > 50:
            node.ping_history = node.ping_history[-50:]
    controller.ping_updated.emit(node_id, ping_ms)


def on_ping_progress(controller: AppController, current: int, total: int) -> None:
    if controller.sender() is not controller._ping_worker:
        return
    controller._ping_completed = current
    controller.bulk_task_progress.emit("ping", current, total, False)


def on_ping_complete(controller: AppController) -> None:
    if controller.sender() is not controller._ping_worker:
        return
    controller.bulk_task_progress.emit("ping", controller._ping_completed, controller._ping_total, True)
    controller._ping_node_map = {}
    controller.save()


def on_speed_result(controller: AppController, node_id: str, speed_mbps: float | None, is_alive: bool) -> None:
    if controller.sender() is not controller._speed_worker:
        return
    node = getattr(controller, "_speed_node_map", {}).get(node_id)
    if node is not None:
        node.speed_mbps = speed_mbps
        node.is_alive = is_alive
        ts = datetime.now(timezone.utc).isoformat()
        node.speed_history.append((ts, speed_mbps))
        if len(node.speed_history) > 50:
            node.speed_history = node.speed_history[-50:]
        controller.schedule_save()
    controller.speed_updated.emit(node_id, speed_mbps, is_alive)


def on_speed_progress(controller: AppController, current: int, total: int) -> None:
    if controller.sender() is not controller._speed_worker:
        return
    controller._speed_completed = current
    controller.bulk_task_progress.emit("speed", current, total, False)


def on_speed_node_progress(controller: AppController, node_id: str, percent: int) -> None:
    if controller.sender() is not controller._speed_worker:
        return
    controller.speed_progress_updated.emit(node_id, max(0, min(100, int(percent))))


def on_speed_complete(controller: AppController) -> None:
    if controller.sender() is not controller._speed_worker:
        return
    worker = controller._speed_worker
    cancelled = bool(worker.was_cancelled) if worker is not None else False
    completed = worker.completed_nodes if worker is not None else controller._speed_completed
    controller._speed_completed = completed
    if cancelled:
        controller.speed_test_cancelled.emit(completed, controller._speed_total)
    controller.bulk_task_progress.emit("speed", completed, controller._speed_total, True)
    controller._speed_node_map = {}
    controller.save()
    if cancelled:
        controller.status.emit("info", f"Тест скорости остановлен ({completed}/{controller._speed_total})")
    else:
        controller.status.emit("success", "Тест скорости завершён")


def on_connectivity_result(controller: AppController, ok: bool, message: str, elapsed_ms: int | None) -> None:
    if controller.sender() is not controller._connectivity_worker:
        return
    if ok and elapsed_ms is not None:
        text = f"Подключение в порядке: {elapsed_ms} мс"
        controller.status.emit("success", text)
        controller._log(f"[test] {message} ({elapsed_ms} ms)")
    else:
        controller.status.emit("warning", "Тест подключения не пройден")
        controller._log(f"[test] {message}")
    controller.connectivity_test_done.emit(ok, message, elapsed_ms)
