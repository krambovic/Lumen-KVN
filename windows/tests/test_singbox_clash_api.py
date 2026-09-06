from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

import xray_fluent.app_controller as app_controller_module
import xray_fluent.engines.singbox.clash_api as clash_api
from xray_fluent.app_controller import AppController
from xray_fluent.engines.singbox.clash_api import ClashApiError, SelectorSwitchResult, SingboxClashApiClient
from xray_fluent.engines.singbox import operations
from xray_fluent.engines.singbox.runtime_planner import singbox_node_source_signature, singbox_node_tag
from xray_fluent.models import Node


class _Response:
    def __init__(self, payload: object = None) -> None:
        self._payload = payload

    def __enter__(self):
        return self

    def __exit__(self, *_args) -> None:
        return None

    def read(self, _limit: int = -1) -> bytes:
        if self._payload is None:
            return b""
        if isinstance(self._payload, bytes):
            return self._payload
        return json.dumps(self._payload).encode("utf-8")


def test_selector_switch_uses_bearer_put_and_verifies_target(monkeypatch) -> None:
    requests: list[tuple[str, str, bytes | None]] = []
    state = {"now": "old", "all": ["old", "new"]}

    def fake_urlopen(request, timeout: float):
        requests.append((request.get_method(), request.full_url, request.data))
        assert timeout == 1.25
        assert request.get_header("Authorization") == "Bearer test-secret"
        if request.get_method() == "PUT":
            assert json.loads(request.data) == {"name": "new"}
            state["now"] = "new"
            return _Response()
        return _Response(dict(state))

    monkeypatch.setattr(clash_api, "urlopen", fake_urlopen)
    result = SingboxClashApiClient(secret="test-secret", timeout=1.25).switch_selector("proxy", "new")

    assert result.previous == "old"
    assert result.current == "new"
    assert result.changed is True
    assert [(method, url.rsplit("/", 1)[-1]) for method, url, _ in requests] == [
        ("GET", "proxy"),
        ("PUT", "proxy"),
        ("GET", "proxy"),
    ]


def test_selector_switch_rolls_back_when_verification_does_not_confirm_target(monkeypatch) -> None:
    requests: list[tuple[str, bytes | None]] = []
    get_count = 0

    def fake_urlopen(request, timeout: float):
        nonlocal get_count
        requests.append((request.get_method(), request.data))
        if request.get_method() == "PUT":
            return _Response()
        get_count += 1
        if get_count == 1:
            return _Response({"now": "old", "all": ["old", "new"]})
        return _Response({"now": "old", "all": ["old", "new"]})

    monkeypatch.setattr(clash_api, "urlopen", fake_urlopen)
    with pytest.raises(ClashApiError, match="did not confirm target"):
        SingboxClashApiClient(secret="test-secret").switch_selector("proxy", "new")

    put_bodies = [json.loads(data) for method, data in requests if method == "PUT" and data]
    assert put_bodies == [{"name": "new"}, {"name": "old"}]


def test_selector_switch_rejects_target_not_in_running_selector(monkeypatch) -> None:
    monkeypatch.setattr(
        clash_api,
        "urlopen",
        lambda _request, **_kwargs: _Response({"now": "old", "all": ["old"]}),
    )

    with pytest.raises(ClashApiError, match="does not contain target"):
        SingboxClashApiClient(secret="test-secret").switch_selector("proxy", "missing")


def test_tun_hot_switch_falls_back_to_restart_when_api_is_unavailable(monkeypatch) -> None:
    node = Node(id="new-node", name="New", server="example.com", port=443)
    controller = SimpleNamespace(
        _active_session=SimpleNamespace(
            active_core="singbox",
            tun_mode=True,
            hybrid=False,
            clash_api_selector="proxy",
            clash_api_secret="secret",
            clash_api_node_signatures=((node.id, singbox_node_source_signature(node)),),
        ),
        selected_node=node,
        _log=lambda _message: None,
    )

    class _UnavailableClient:
        def __init__(self, **_kwargs) -> None:
            pass

        def switch_selector(self, _selector: str, _target: str):
            raise ClashApiError("connection refused")

    monkeypatch.setattr(operations, "SingboxClashApiClient", _UnavailableClient)
    assert operations.try_hot_switch_selector(controller, "node switched") is False


def test_controller_uses_restart_fallback_after_selector_attempt_fails(monkeypatch) -> None:
    node = Node(id="new-node", name="New", server="example.com", port=443)
    calls: list[str] = []
    controller = SimpleNamespace(
        _active_session=SimpleNamespace(api_port=0, protect_ss_port=0, protect_ss_password=""),
        selected_node=node,
        _active_core="singbox",
        _xray_api_port=0,
        _protect_ss_port=0,
        _protect_ss_password="",
        _auto_switch_transitioning=True,
        _restart_singbox_runtime=lambda reason: calls.append(reason) or True,
    )
    monkeypatch.setattr(app_controller_module, "try_singbox_hot_switch_selector_operation", lambda *_args: False)

    assert AppController._hot_swap_node(controller, "selector unavailable") is True
    assert calls == ["selector unavailable"]
    assert controller._auto_switch_transitioning is False


def test_hot_switch_skips_a_node_whose_runtime_mapping_is_stale(monkeypatch) -> None:
    node = Node(id="new-node", name="New", server="old.example.com", port=443)
    expected_signature = singbox_node_source_signature(node)
    node.server = "updated.example.com"
    calls: list[tuple[str, str]] = []
    controller = SimpleNamespace(
        _active_session=SimpleNamespace(
            active_core="singbox",
            tun_mode=True,
            hybrid=False,
            clash_api_selector="proxy",
            clash_api_secret="secret",
            clash_api_node_signatures=(("new-node", expected_signature),),
        ),
        selected_node=node,
        _log=lambda _message: None,
    )

    class _UnexpectedClient:
        def __init__(self, **_kwargs) -> None:
            pass

        def switch_selector(self, selector: str, target: str):
            calls.append((selector, target))
            raise AssertionError("stale mapping must not reach the Clash API")

    monkeypatch.setattr(operations, "SingboxClashApiClient", _UnexpectedClient)

    assert operations.try_hot_switch_selector(controller, "node switched") is False
    assert calls == []


@pytest.mark.parametrize(
    ("tun_mode", "mode_label"),
    [(True, "TUN"), (False, "прокси")],
)
def test_hot_switch_updates_the_active_session_without_restart(
    monkeypatch,
    tun_mode: bool,
    mode_label: str,
) -> None:
    node = Node(id="new-node", name="New", server="new.example.com", port=443)
    mapping = ((node.id, singbox_node_source_signature(node)),)
    captured: dict[str, object] = {}
    metrics: list[bool] = []
    statuses: list[tuple[str, str]] = []
    controller = SimpleNamespace(
        _active_session=SimpleNamespace(
            active_core="singbox",
            tun_mode=tun_mode,
            hybrid=False,
            clash_api_selector="proxy",
            clash_api_secret="secret",
            clash_api_node_signatures=mapping,
            api_port=0,
            socks_port=10808,
            http_port=10809,
            xray_inbound_tags=(),
        ),
        selected_node=node,
        _log=lambda _message: None,
        _metrics_request=SimpleNamespace(emit=metrics.append),
        _infer_singbox_ping_target=lambda _config, selected: (selected.server, selected.port),
        _capture_active_session=lambda selected, **kwargs: captured.update(node=selected, **kwargs),
        _set_connection_status=lambda status, message, **_kwargs: statuses.append((status, message)),
        save=lambda: None,
    )

    class _SuccessfulClient:
        def __init__(self, *, secret: str) -> None:
            assert secret == "secret"

        def switch_selector(self, selector: str, target: str) -> SelectorSwitchResult:
            assert selector == "proxy"
            assert target == singbox_node_tag(node.id)
            return SelectorSwitchResult(selector, "old-tag", target, changed=True)

    monkeypatch.setattr(operations, "SingboxClashApiClient", _SuccessfulClient)

    assert operations.try_hot_switch_selector(controller, "node switched") is True
    assert captured["node"] is node
    assert captured["tun"] is tun_mode
    assert captured["clash_api_selector"] == "proxy"
    assert captured["clash_api_node_signatures"] == mapping
    assert statuses == [("running", f"Переключено: New ({mode_label})")]
    assert metrics == [False, True]


def test_hot_switch_rejects_the_already_active_node(monkeypatch) -> None:
    node = Node(id="active-node", name="Active", server="active.example.com", port=443)
    controller = SimpleNamespace(
        _active_session=SimpleNamespace(
            node_id=node.id,
            active_core="singbox",
            tun_mode=True,
            hybrid=False,
            clash_api_selector="proxy",
            clash_api_secret="secret",
            clash_api_node_signatures=((node.id, singbox_node_source_signature(node)),),
        ),
        selected_node=node,
        _log=lambda _message: None,
    )

    class _UnexpectedClient:
        def __init__(self, **_kwargs) -> None:
            pass

        def switch_selector(self, *_args):
            raise AssertionError("the active node must not be switched")

    monkeypatch.setattr(operations, "SingboxClashApiClient", _UnexpectedClient)

    assert operations.try_hot_switch_selector(controller, "same node") is False
