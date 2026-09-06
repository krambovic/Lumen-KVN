from __future__ import annotations

from xray_fluent.qml_app.window_reveal import WindowReveal


class _Window:
    def __init__(self) -> None:
        self.calls: list[object] = []

    def setOpacity(self, value: float) -> None:
        self.calls.append(("setOpacity", value))

    def setVisible(self, value: bool) -> None:
        self.calls.append(("setVisible", value))


def test_reveal_waits_for_a_presented_frame_before_becoming_opaque() -> None:
    window = _Window()
    scheduled: list[object] = []
    reveal = WindowReveal(window, scheduled.append)

    reveal.request()

    assert window.calls == [("setOpacity", 0.0), ("setVisible", True)]
    assert scheduled == []

    reveal.frame_swapped()

    assert len(scheduled) == 1
    scheduled[0]()
    assert window.calls[-1] == ("setOpacity", 1.0)

