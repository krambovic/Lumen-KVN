from __future__ import annotations

import base64
from dataclasses import dataclass
import json
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Callable

from .constants import BASE_DIR, SUBSCRIPTION_FETCHER_EXE_NAME
from .direct_http import DirectNetworkUnavailable, DirectUrlOpener
from .http_utils import get_ssl_context
from .subprocess_utils import CREATE_NO_WINDOW


_MAX_IPC_REQUEST_BYTES = 64 * 1024
_MAX_HELPER_STDERR_BYTES = 64 * 1024


@dataclass(frozen=True, slots=True)
class SubscriptionHttpPayload:
    body: bytes
    headers: dict[str, str]
    status: int = 0
    transport: str = "direct-route"


class SubscriptionFetcherUnavailable(RuntimeError):
    pass


class SubscriptionFetcherCancelled(RuntimeError):
    pass


class _FetcherProcessHandle:
    def __init__(self, process: subprocess.Popen[bytes]) -> None:
        self._process = process

    def close(self) -> None:
        process = self._process
        if process.poll() is not None:
            return
        try:
            process.terminate()
            process.wait(timeout=1.0)
        except (OSError, subprocess.TimeoutExpired):
            try:
                process.kill()
            except OSError:
                pass


def _read_http_response(response: object, max_bytes: int) -> tuple[bytes, dict[str, str], int]:
    try:
        declared_size = int(response.headers.get("Content-Length", 0) or 0)
    except (AttributeError, TypeError, ValueError):
        declared_size = 0
    if declared_size > max_bytes:
        raise RuntimeError(f"подписка слишком большая: {declared_size} байт, максимум {max_bytes}")

    payload = bytearray()
    while True:
        chunk = response.read(min(64 * 1024, max_bytes + 1 - len(payload)))
        if not chunk:
            break
        payload.extend(chunk)
        if len(payload) > max_bytes:
            raise RuntimeError(f"подписка превышает допустимый размер {max_bytes} байт")

    raw_headers: dict[str, str] = {}
    try:
        for key, value in response.headers.items():
            normalized = str(key or "").strip().lower()
            if normalized:
                raw_headers[normalized] = str(value or "").strip()
    except (AttributeError, TypeError):
        pass
    try:
        effective_url = str(response.geturl() or "").strip()
    except (AttributeError, TypeError, ValueError):
        effective_url = ""
    if effective_url:
        # Internal-only metadata used to reject HTTPS -> HTTP redirect downgrades.
        raw_headers["x-lumen-effective-url"] = effective_url
    try:
        status = int(getattr(response, "status", 0) or 0)
    except (TypeError, ValueError):
        status = 0
    if not status:
        try:
            status = int(response.getcode() or 0)
        except (AttributeError, TypeError, ValueError):
            status = 0
    return bytes(payload), raw_headers, status


def _not_modified_http_error(exc: urllib.error.HTTPError, transport: str) -> SubscriptionHttpPayload:
    """Convert urllib's optional HTTPError(304) path into a normal payload."""
    if int(getattr(exc, "code", 0) or 0) != 304:
        raise exc
    headers: dict[str, str] = {}
    try:
        for key, value in exc.headers.items():
            normalized = str(key or "").strip().lower()
            if normalized:
                headers[normalized] = str(value or "").strip()
    except (AttributeError, TypeError):
        pass
    try:
        effective_url = str(exc.geturl() or "").strip()
    except (AttributeError, TypeError, ValueError):
        effective_url = ""
    if effective_url:
        headers["x-lumen-effective-url"] = effective_url
    return SubscriptionHttpPayload(b"", headers, 304, transport)


def _download_in_current_process(
    url: str,
    headers: dict[str, str],
    *,
    timeout: float,
    max_bytes: int,
    allow_process_direct_fallback: bool = False,
    response_opened=None,
    response_closed=None,
) -> SubscriptionHttpPayload:
    request = urllib.request.Request(url, headers=dict(headers))
    try:
        with DirectUrlOpener() as opener:
            try:
                with opener.open(request, timeout=timeout) as response:
                    if response_opened is not None:
                        response_opened(response)
                    try:
                        body, response_headers, status = _read_http_response(response, max_bytes)
                    finally:
                        if response_closed is not None:
                            response_closed(response)
            except urllib.error.HTTPError as exc:
                return _not_modified_http_error(exc, "direct-route")
        return SubscriptionHttpPayload(body, response_headers, status, "direct-route")
    except DirectNetworkUnavailable:
        if not allow_process_direct_fallback:
            raise
        # In the packaged helper, sing-box permanently routes this process to
        # the direct outbound.  This fallback also remains direct when TUN is
        # disabled and avoids failing just because a host route could not be
        # prepared at that exact moment.
        opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}),
            urllib.request.HTTPSHandler(context=get_ssl_context()),
        )
        try:
            with opener.open(request, timeout=timeout) as response:
                if response_opened is not None:
                    response_opened(response)
                try:
                    body, response_headers, status = _read_http_response(response, max_bytes)
                finally:
                    if response_closed is not None:
                        response_closed(response)
        except urllib.error.HTTPError as exc:
            return _not_modified_http_error(exc, "process-direct")
        return SubscriptionHttpPayload(body, response_headers, status, "process-direct")


def _download_via_proxy_or_tun(
    url: str,
    headers: dict[str, str],
    *,
    timeout: float,
    max_bytes: int,
    proxy_url: str = "",
    response_opened=None,
    response_closed=None,
) -> SubscriptionHttpPayload:
    """Use the active Lumen proxy/TUN path instead of the direct helper."""
    request = urllib.request.Request(url, headers=dict(headers))
    handlers: list[object] = []
    normalized_proxy = str(proxy_url or "").strip()
    if normalized_proxy:
        handlers.append(
            urllib.request.ProxyHandler(
                {"http": normalized_proxy, "https": normalized_proxy}
            )
        )
    handlers.append(urllib.request.HTTPSHandler(context=get_ssl_context()))
    transport = "lumen-proxy" if normalized_proxy else "system-proxy-tun"
    opener = urllib.request.build_opener(*handlers)
    try:
        try:
            with opener.open(request, timeout=timeout) as response:
                if response_opened is not None:
                    response_opened(response)
                try:
                    body, response_headers, status = _read_http_response(response, max_bytes)
                finally:
                    if response_closed is not None:
                        response_closed(response)
        except urllib.error.HTTPError as exc:
            return _not_modified_http_error(exc, transport)
    finally:
        opener.close()
    return SubscriptionHttpPayload(body, response_headers, status, transport)


def _fetcher_command() -> list[str]:
    if not getattr(sys, "frozen", False):
        return []
    executable = BASE_DIR / SUBSCRIPTION_FETCHER_EXE_NAME
    if not executable.is_file():
        return []
    try:
        if executable.resolve() == Path(sys.executable).resolve():
            return []
    except OSError:
        return []
    return [str(executable), "--subscription-fetcher"]


def _run_fetcher_process(
    command: list[str],
    url: str,
    headers: dict[str, str],
    *,
    timeout: float,
    max_bytes: int,
    cancelled: Callable[[], bool] | None,
    response_opened=None,
    response_closed=None,
) -> SubscriptionHttpPayload:
    request_data = json.dumps(
        {
            "url": url,
            "headers": dict(headers),
            "timeout": timeout,
            "max_bytes": max_bytes,
        },
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")
    if len(request_data) > _MAX_IPC_REQUEST_BYTES:
        raise ValueError("параметры подписки слишком большие")
    try:
        process = subprocess.Popen(
            command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            creationflags=CREATE_NO_WINDOW,
        )
    except OSError as exc:
        raise SubscriptionFetcherUnavailable(str(exc)) from exc

    handle = _FetcherProcessHandle(process)
    if response_opened is not None:
        response_opened(handle)
    deadline = time.monotonic() + max(15.0, float(timeout) + 45.0)
    first_call = True
    try:
        while True:
            if cancelled is not None and cancelled():
                handle.close()
                raise SubscriptionFetcherCancelled("загрузка подписки отменена")
            if time.monotonic() >= deadline:
                handle.close()
                raise TimeoutError("превышено время ожидания загрузчика подписки")
            try:
                stdout, stderr = process.communicate(
                    input=request_data if first_call else None,
                    timeout=0.2,
                )
                break
            except subprocess.TimeoutExpired:
                first_call = False
                continue
    finally:
        if response_closed is not None:
            response_closed(handle)

    stderr_text = stderr[-_MAX_HELPER_STDERR_BYTES:].decode("utf-8", errors="replace").strip()
    try:
        result = json.loads(stdout.decode("utf-8", errors="strict"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        detail = stderr_text or "загрузчик вернул некорректный ответ"
        raise SubscriptionFetcherUnavailable(detail) from exc
    if not isinstance(result, dict):
        raise SubscriptionFetcherUnavailable("загрузчик вернул некорректный ответ")
    if not result.get("ok"):
        raise RuntimeError(str(result.get("error") or stderr_text or "не удалось загрузить подписку"))
    try:
        body = base64.b64decode(str(result.get("body") or ""), validate=True)
    except (ValueError, TypeError) as exc:
        raise SubscriptionFetcherUnavailable("загрузчик вернул повреждённые данные") from exc
    if len(body) > max_bytes:
        raise RuntimeError(f"подписка превышает допустимый размер {max_bytes} байт")
    response_headers = result.get("headers") if isinstance(result.get("headers"), dict) else {}
    return SubscriptionHttpPayload(
        body=body,
        headers={str(key).lower(): str(value) for key, value in response_headers.items()},
        status=int(result.get("status") or 0),
        transport=str(result.get("transport") or "process-direct"),
    )


def fetch_subscription_http(
    url: str,
    headers: dict[str, str],
    *,
    timeout: float,
    max_bytes: int,
    use_proxy_tun: bool = False,
    proxy_url: str = "",
    cancelled: Callable[[], bool] | None = None,
    response_opened=None,
    response_closed=None,
) -> SubscriptionHttpPayload:
    if use_proxy_tun:
        if cancelled is not None and cancelled():
            raise SubscriptionFetcherCancelled("загрузка подписки отменена")
        return _download_via_proxy_or_tun(
            url,
            headers,
            timeout=timeout,
            max_bytes=max_bytes,
            proxy_url=proxy_url,
            response_opened=response_opened,
            response_closed=response_closed,
        )
    command = _fetcher_command()
    if command:
        try:
            return _run_fetcher_process(
                command,
                url,
                headers,
                timeout=timeout,
                max_bytes=max_bytes,
                cancelled=cancelled,
                response_opened=response_opened,
                response_closed=response_closed,
            )
        except SubscriptionFetcherUnavailable:
            # A missing/quarantined helper must not break existing installs.
            pass
    if cancelled is not None and cancelled():
        raise SubscriptionFetcherCancelled("загрузка подписки отменена")
    return _download_in_current_process(
        url,
        headers,
        timeout=timeout,
        max_bytes=max_bytes,
        allow_process_direct_fallback=False,
        response_opened=response_opened,
        response_closed=response_closed,
    )


def _cli_request() -> dict:
    raw = sys.stdin.buffer.read(_MAX_IPC_REQUEST_BYTES + 1)
    if len(raw) > _MAX_IPC_REQUEST_BYTES:
        raise ValueError("запрос к загрузчику слишком большой")
    payload = json.loads(raw.decode("utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("некорректный запрос к загрузчику")
    return payload


def cli_main() -> int:
    try:
        request = _cli_request()
        url = str(request.get("url") or "").strip()
        if not url.lower().startswith(("http://", "https://")):
            raise ValueError("URL подписки должен начинаться с http:// или https://")
        headers_raw = request.get("headers") if isinstance(request.get("headers"), dict) else {}
        headers = {str(key): str(value) for key, value in headers_raw.items()}
        timeout = max(1.0, min(60.0, float(request.get("timeout") or 20.0)))
        max_bytes = max(1, min(8 * 1024 * 1024, int(request.get("max_bytes") or 0)))
        result = _download_in_current_process(
            url,
            headers,
            timeout=timeout,
            max_bytes=max_bytes,
            allow_process_direct_fallback=True,
        )
        response = {
            "ok": True,
            "body": base64.b64encode(result.body).decode("ascii"),
            "headers": result.headers,
            "status": result.status,
            "transport": result.transport,
        }
        exit_code = 0
    except Exception as exc:  # noqa: BLE001 - IPC boundary returns a safe message
        response = {"ok": False, "error": str(exc) or type(exc).__name__}
        exit_code = 1
    sys.stdout.buffer.write(json.dumps(response, ensure_ascii=False, separators=(",", ":")).encode("utf-8"))
    sys.stdout.buffer.flush()
    return exit_code
