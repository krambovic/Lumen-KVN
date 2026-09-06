from __future__ import annotations

from dataclasses import dataclass
import json
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen

from ...constants import PROXY_HOST, SINGBOX_CLASH_API_PORT


class ClashApiError(RuntimeError):
    """Raised when the local sing-box Clash API cannot complete an operation."""


@dataclass(frozen=True, slots=True)
class SelectorSwitchResult:
    selector: str
    previous: str
    current: str
    changed: bool


class SingboxClashApiClient:
    """Small authenticated client for sing-box's local Clash-compatible API."""

    def __init__(
        self,
        *,
        port: int = SINGBOX_CLASH_API_PORT,
        secret: str,
        timeout: float = 2.0,
        host: str = PROXY_HOST,
    ) -> None:
        self._base_url = f"http://{host}:{int(port)}"
        self._secret = str(secret or "")
        self._timeout = max(0.1, float(timeout))

    def get_proxy(self, name: str) -> dict[str, Any]:
        payload = self._request("GET", f"/proxies/{name}")
        if not isinstance(payload, dict):
            raise ClashApiError("sing-box Clash API returned a non-object proxy response")
        return payload

    def put_proxy(self, name: str, target: str) -> None:
        self._request(
            "PUT",
            f"/proxies/{name}",
            body={"name": str(target)},
            expect_json=False,
        )

    def switch_selector(self, selector: str, target: str) -> SelectorSwitchResult:
        selector = str(selector or "").strip()
        target = str(target or "").strip()
        if not selector or not target:
            raise ClashApiError("selector and target are required")

        before = self.get_proxy(selector)
        previous = self._selector_now(before, selector)
        available = self._selector_members(before, selector)
        if target not in available:
            raise ClashApiError(f"selector `{selector}` does not contain target `{target}`")
        if previous not in available:
            raise ClashApiError(f"selector `{selector}` has invalid current target `{previous}`")
        if previous == target:
            return SelectorSwitchResult(selector, previous, previous, changed=False)

        try:
            self.put_proxy(selector, target)
            after = self.get_proxy(selector)
            current = self._selector_now(after, selector)
            if current != target:
                raise ClashApiError(
                    f"selector `{selector}` did not confirm target `{target}` (current `{current or 'unknown'}`)"
                )
        except ClashApiError as exc:
            rollback_error = self._rollback(selector, previous)
            if rollback_error:
                raise ClashApiError(f"{exc}; rollback failed: {rollback_error}") from exc
            raise

        return SelectorSwitchResult(selector, previous, target, changed=True)

    def _rollback(self, selector: str, previous: str) -> str:
        try:
            self.put_proxy(selector, previous)
            restored = self._selector_now(self.get_proxy(selector), selector)
            if restored != previous:
                return f"current target is `{restored or 'unknown'}`"
        except ClashApiError as exc:
            return str(exc)
        return ""

    @staticmethod
    def _selector_now(payload: dict[str, Any], selector: str) -> str:
        current = str(payload.get("now") or "").strip()
        if not current:
            raise ClashApiError(f"Clash API proxy `{selector}` has no current target")
        return current

    @staticmethod
    def _selector_members(payload: dict[str, Any], selector: str) -> set[str]:
        raw_members = payload.get("all")
        if not isinstance(raw_members, list):
            raise ClashApiError(f"Clash API proxy `{selector}` is not a selector")
        members = {str(item or "").strip() for item in raw_members if str(item or "").strip()}
        if not members:
            raise ClashApiError(f"Clash API selector `{selector}` has no members")
        return members

    def _request(
        self,
        method: str,
        path: str,
        *,
        body: dict[str, Any] | None = None,
        expect_json: bool = True,
    ) -> Any:
        if not self._secret:
            raise ClashApiError("sing-box Clash API secret is not configured")
        path_without_query = path.split("?", 1)[0]
        prefix, separator, leaf = path_without_query.rpartition("/")
        if not separator or not leaf:
            raise ClashApiError(f"invalid Clash API path `{path}`")
        url = f"{self._base_url}{prefix}/{quote(leaf, safe='')}"
        data = json.dumps(body, ensure_ascii=True, separators=(",", ":")).encode("utf-8") if body is not None else None
        headers = {
            "Authorization": f"Bearer {self._secret}",
            "Accept": "application/json",
        }
        if data is not None:
            headers["Content-Type"] = "application/json"
        request = Request(url, data=data, headers=headers, method=method)
        try:
            with urlopen(request, timeout=self._timeout) as response:
                raw = response.read(64 * 1024)
        except HTTPError as exc:
            try:
                detail = exc.read(4096).decode("utf-8", errors="replace").strip()
            except Exception:
                detail = ""
            suffix = f": {detail[:300]}" if detail else ""
            raise ClashApiError(f"Clash API {method} {path} failed with HTTP {exc.code}{suffix}") from exc
        except (URLError, OSError, TimeoutError) as exc:
            raise ClashApiError(f"Clash API {method} {path} failed: {exc}") from exc

        if not expect_json:
            return None
        if not raw:
            raise ClashApiError(f"Clash API {method} {path} returned an empty response")
        try:
            return json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ClashApiError(f"Clash API {method} {path} returned invalid JSON") from exc
