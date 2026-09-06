"""Show a Qt Quick window only after its first frame is ready."""
from __future__ import annotations

from collections.abc import Callable
from typing import Any


class WindowReveal:
    """Avoid exposing the native window surface before Qt Quick has painted."""

    def __init__(
        self,
        window: Any,
        schedule: Callable[[Callable[[], None]], None],
    ) -> None:
        self._window = window
        self._schedule = schedule
        self._pending = False
        self._frame_seen = False

    def request(self, *, activate: bool = False) -> None:
        self._pending = True
        try:
            self._window.setOpacity(0.0)
        except Exception:
            pass

        try:
            if activate:
                self._window.show()
                self._window.raise_()
                self._window.requestActivate()
            else:
                self._window.setVisible(True)
        except Exception:
            pass

        if self._frame_seen:
            self.frame_swapped()

    def frame_swapped(self) -> None:
        self._frame_seen = True
        if not self._pending:
            return
        self._pending = False
        self._schedule(self._finish)

    def reveal_if_pending(self) -> None:
        """Fallback for unusual render backends that do not emit frameSwapped."""
        if self._pending:
            self.frame_swapped()

    def _finish(self) -> None:
        try:
            self._window.setOpacity(1.0)
        except Exception:
            pass
