from __future__ import annotations

from types import SimpleNamespace

from xray_fluent.application.worker_service import (
    _clear_ping_measurements,
    _clear_speed_measurements,
    _filter_testable_nodes,
    _node_supports_test,
    ping_nodes,
    speed_test_nodes,
)
from xray_fluent.models import Node
from xray_fluent import ping_worker


class _Signal:
    def __init__(self) -> None:
        self.calls: list[tuple] = []

    def emit(self, *args) -> None:
        self.calls.append(args)


class _Controller:
    def __init__(self) -> None:
        self.ping_updated = _Signal()
        self.speed_updated = _Signal()
        self.speed_progress_updated = _Signal()
        self.save_count = 0

    def schedule_save(self) -> None:
        self.save_count += 1


class _CompatibilityController(_Controller):
    def __init__(self, nodes: list[Node]) -> None:
        super().__init__()
        self.state = SimpleNamespace(
            nodes=nodes,
            settings=SimpleNamespace(ping_method="tcping"),
        )
        self.status = _Signal()
        self._ping_worker = None
        self._speed_worker = None


def test_clear_ping_measurements_resets_saved_values_before_worker_starts() -> None:
    node = Node(id="node-1", ping_ms=123, speed_mbps=45.0, is_alive=True)
    controller = _Controller()

    _clear_ping_measurements(controller, [node])

    assert node.ping_ms is None
    assert node.speed_mbps == 45.0
    assert node.is_alive is None
    assert controller.ping_updated.calls == [("node-1", None)]
    assert controller.save_count == 1


def test_clear_speed_measurements_resets_saved_values_before_worker_starts() -> None:
    node = Node(id="node-1", ping_ms=123, speed_mbps=45.0, is_alive=True)
    controller = _Controller()

    _clear_speed_measurements(controller, [node])

    assert node.ping_ms == 123
    assert node.speed_mbps is None
    assert node.is_alive is None
    assert controller.speed_updated.calls == [("node-1", None, False)]
    assert controller.speed_progress_updated.calls == [("node-1", 0)]
    assert controller.save_count == 1


def _native_node(node_id: str, protocol: str) -> Node:
    return Node(
        id=node_id,
        name=node_id.upper(),
        scheme=protocol,
        server="203.0.113.10",
        port=443,
        outbound={"protocol": protocol, "singbox": {"type": protocol}},
    )


def test_awg_and_masque_endpoint_ping_are_supported() -> None:
    nodes = [_native_node("awg", "awg"), _native_node("masque", "masque")]

    assert all(_node_supports_test(node, "ping", ping_method="tcping") for node in nodes)


def test_native_speed_warning_is_emitted_once_for_bulk_selection() -> None:
    nodes = [_native_node("awg", "awg"), _native_node("masque", "masque")]
    controller = _CompatibilityController(nodes)

    assert speed_test_nodes(controller, {node.id for node in nodes}) is False

    assert len(controller.status.calls) == 1
    assert controller.status.calls[0][0] == "warning"
    assert controller._speed_worker is None
    assert controller.speed_updated.calls == []
    assert all(node.is_alive is None and node.speed_mbps is None for node in nodes)


def test_hysteria2_and_tuic_real_ping_are_supported_by_endpoint_fallback() -> None:
    nodes = [_native_node("hy2", "hysteria2"), _native_node("tuic", "tuic")]

    assert all(_node_supports_test(node, "ping", ping_method="real") for node in nodes)


def test_hysteria_protocol_ping_uses_udp_probe_with_icmp_fallback(monkeypatch) -> None:
    calls: list[tuple[str, int, float]] = []

    monkeypatch.setattr(ping_worker, "udp_ping", lambda host, port, timeout: calls.append((host, port, timeout)) or None)
    monkeypatch.setattr(ping_worker, "icmp_ping", lambda host, timeout_ms: 37)

    node = _native_node("hy2", "hysteria2")
    worker = ping_worker.PingWorker([node], timeout=1.5, method="tcping")

    assert worker._measure(node) == 37
    assert calls == [("203.0.113.10", 443, 1.5)]


def _xray_auto_node(*outbounds: dict) -> Node:
    return Node(
        id="auto",
        name="AUTO",
        scheme="auto",
        server="first.invalid",
        port=443,
        outbound={
            "protocol": "xray_config",
            "xray_config": {
                "outbounds": list(outbounds),
                "routing": {
                    "balancers": [{"tag": "auto", "selector": ["proxy"]}],
                    "rules": [{"type": "field", "balancerTag": "auto"}],
                },
                "observatory": {"subjectSelector": ["proxy"]},
            },
        },
    )


def test_xray_auto_is_testable_when_its_candidates_support_the_test() -> None:
    auto = _xray_auto_node(
        {
            "tag": "proxy-1",
            "protocol": "vless",
            "settings": {"vnext": [{"address": "one.example", "port": 443}]},
        },
        {"tag": "direct", "protocol": "freedom"},
    )

    assert _node_supports_test(auto, "ping", ping_method="tcping") is True
    assert _node_supports_test(auto, "ping", ping_method="http") is True
    assert _node_supports_test(auto, "ping", ping_method="real") is True
    assert _node_supports_test(auto, "speed") is True


def test_xray_auto_endpoint_ping_uses_a_supported_inner_server() -> None:
    auto = _xray_auto_node(
        {
            "tag": "proxy-awg",
            "protocol": "awg",
            "settings": {"address": "awg.example", "port": 443},
        },
        {
            "tag": "proxy-vless",
            "protocol": "vless",
            "settings": {"vnext": [{"address": "vless.example", "port": 8443}]},
        },
    )
    controller = _CompatibilityController([auto])

    prepared = _filter_testable_nodes(controller, [auto], "ping", ping_method="tcping")

    assert len(prepared) == 1
    assert prepared[0].id == auto.id
    assert (prepared[0].server, prepared[0].port) == ("vless.example", 8443)


def test_auto_with_only_unsupported_candidates_stays_untested() -> None:
    auto = _xray_auto_node(
        {
            "tag": "proxy-awg",
            "protocol": "awg",
            "settings": {"address": "awg.example", "port": 443},
        }
    )

    assert _node_supports_test(auto, "ping", ping_method="tcping") is False
    assert _node_supports_test(auto, "speed") is False
