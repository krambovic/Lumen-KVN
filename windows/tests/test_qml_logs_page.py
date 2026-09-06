from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).parents[1]
QML_DIR = ROOT / "xray_fluent" / "qml_app" / "qml"


def test_log_list_uses_the_legacy_table_rows_and_keeps_event_stream() -> None:
    logs_qml = (QML_DIR / "LogsPage.qml").read_text(encoding="utf-8")

    assert "hoverable: false" in logs_qml
    assert "id: logList" in logs_qml
    assert "delegate: Rectangle" in logs_qml
    assert "radius: Theme.radiusSmall" in logs_qml
    assert "component SelectableLogText: FluentTextEdit" in logs_qml
    assert "selectByMouse: true" in logs_qml
    assert "persistentSelection: false" in logs_qml
    assert "text: page.formattedLog(time, source, level, line, details)" in logs_qml
    assert "model: App.logModel" in logs_qml
    assert "onCountChanged:" in logs_qml
    assert "positionViewAtEnd()" in logs_qml
    assert "id: logStreamCard" not in logs_qml
    assert "id: logLevelBadge" not in logs_qml
    assert "В реальном времени" not in logs_qml
    assert "searchDebounce.restart()" in logs_qml
    assert "font.family: Theme.fontFamily" in logs_qml


def test_log_auto_scroll_can_be_disabled_and_reenabled() -> None:
    logs_qml = (QML_DIR / "LogsPage.qml").read_text(encoding="utf-8")

    assert "property bool autoScrollEnabled: true" in logs_qml
    assert 'text: I18n.t("Логи работы")' not in logs_qml
    assert 'text: I18n.t("Автопрокрутка")' in logs_qml
    assert "onToggled: page.setAutoScrollEnabled(checked)" in logs_qml
    assert "if (enabled)" in logs_qml
    assert "logList.stickToBottom" not in logs_qml
    assert "if (page.autoScrollEnabled)" in logs_qml
    assert "&& stickToBottom" not in logs_qml
    assert "onVisibleChanged: if (visible && autoScrollEnabled)" in logs_qml
