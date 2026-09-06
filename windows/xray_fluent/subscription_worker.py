"""Фоновая загрузка подписок, чтобы UI-поток не фризил на сетевых запросах.

Сеть идёт в отдельном QThread; применение результата к state делается в GUI-потоке.
"""
from __future__ import annotations

from dataclasses import dataclass
import threading

from PyQt6.QtCore import QObject, pyqtSignal

from .application.node_service import (
    SubscriptionFetchCancelled,
    fetch_subscription_payload_result,
)
from .http_utils import abort_http_response


@dataclass
class SubscriptionJob:
    """Одна задача загрузки подписки."""

    url: str
    kind: str  # "import" | "update"
    name: str = ""
    user_agent: str = ""
    hwid: str = ""
    use_real_hwid: bool = True
    use_proxy_tun: bool = False
    proxy_url: str = ""
    converter_url: str = ""
    etag: str = ""
    last_modified: str = ""


class SubscriptionFetchWorker(QObject):
    """Грузит подписки по сети в фоновом потоке."""

    # batch_id, job, text, userinfo, errors, response metadata
    fetched = pyqtSignal(int, object, str, object, object, object)
    # batch_id, total
    completed = pyqtSignal(int, int)

    def __init__(self) -> None:
        super().__init__()
        self._stopped = threading.Event()
        self._responses: list[object] = []
        self._response_lock = threading.Lock()

    def stop(self) -> None:
        self._stopped.set()
        with self._response_lock:
            responses = list(self._responses)
        for response in responses:
            abort_http_response(response)

    def _register_response(self, response: object) -> None:
        with self._response_lock:
            self._responses.append(response)

    def _unregister_response(self, response: object) -> None:
        with self._response_lock:
            self._responses = [item for item in self._responses if item is not response]

    def run_batch(self, jobs: object, batch_id: int) -> None:
        total = 0
        for job in list(jobs or []):
            if self._stopped.is_set():
                return
            try:
                result = fetch_subscription_payload_result(
                    job.url,
                    user_agent=job.user_agent,
                    hwid=job.hwid,
                    use_real_hwid=job.use_real_hwid,
                    use_proxy_tun=job.use_proxy_tun,
                    proxy_url=job.proxy_url,
                    converter_url=job.converter_url,
                    cache_etag=job.etag,
                    cache_last_modified=job.last_modified,
                    cancelled=self._stopped.is_set,
                    response_opened=self._register_response,
                    response_closed=self._unregister_response,
                )
                text, userinfo, errors = result.text, result.userinfo, result.errors
                metadata = {
                    "headers": dict(result.headers),
                    "status": result.status,
                    "not_modified": result.not_modified,
                }
            except SubscriptionFetchCancelled:
                return
            except Exception as exc:  # никогда не роняем рабочий поток
                text, userinfo, errors = "", {}, [str(exc)]
                metadata = {"headers": {}, "status": 0, "not_modified": False}
            if self._stopped.is_set():
                return
            self.fetched.emit(batch_id, job, text, userinfo, list(errors), metadata)
            total += 1
        if not self._stopped.is_set():
            self.completed.emit(batch_id, total)
