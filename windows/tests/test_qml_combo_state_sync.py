from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys
import textwrap


ROOT = Path(__file__).parents[1]
QML_DIR = ROOT / "xray_fluent" / "qml_app" / "qml"


def test_fluent_combo_reapplies_bound_index_after_model_population() -> None:
    script = textwrap.dedent(
        f"""
        import sys
        from PyQt6.QtCore import QObject, QUrl, pyqtProperty
        from PyQt6.QtGui import QGuiApplication
        from PyQt6.QtQml import QQmlComponent, QQmlEngine, qmlRegisterSingletonInstance

        class StubApp(QObject):
            @pyqtProperty(str, constant=True)
            def language(self):
                return "ru"

            @pyqtProperty("QVariantMap", constant=True)
            def translations(self):
                return {{}}

        app = QGuiApplication([])
        stub = StubApp()
        qmlRegisterSingletonInstance("App", 1, 0, "App", stub)
        engine = QQmlEngine()
        component = QQmlComponent(engine)
        component.setData(
            b'''import QtQuick
        import "{QML_DIR.as_uri()}" as Lumen
        Lumen.FluentCombo {{
            boundIndex: 1
            model: ["direct", "proxy"]
        }}
        ''',
            QUrl(),
        )
        if component.isError():
            raise RuntimeError("\\n".join(error.toString() for error in component.errors()))
        combo = component.create()
        if combo is None:
            raise RuntimeError("\\n".join(error.toString() for error in component.errors()))
        for _ in range(5):
            app.processEvents()
        assert combo.property("count") == 2
        assert combo.property("currentIndex") == 1
        """
    )
    env = os.environ.copy()
    env.setdefault("QT_QPA_PLATFORM", "offscreen")
    result = subprocess.run(
        [sys.executable, "-c", script],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr


def test_dns_and_routing_state_use_model_safe_combo_selection() -> None:
    settings_qml = (QML_DIR / "SettingsPage.qml").read_text(encoding="utf-8")
    routing_qml = (QML_DIR / "RoutingPage.qml").read_text(encoding="utf-8")

    assert "boundIndex: Math.max(0, values.indexOf(App.dnsMode))" in settings_qml
    assert "boundIndex: page.idxIn(page.svcActionKeys, modelData.action)" in routing_qml
    assert "boundIndex: page.idxIn(page.procActionKeys, modelData.action)" in routing_qml
    assert routing_qml.count("boundIndex: 1") >= 3


def test_settings_tabs_switch_directly_without_swiping_intermediate_pages() -> None:
    settings_qml = (QML_DIR / "SettingsPage.qml").read_text(encoding="utf-8")

    assert "SwipeView {" not in settings_qml
    assert "StackLayout {" in settings_qml
    assert "currentIndex: page.displayedTab" in settings_qml
    assert "onClicked: page.activateTab(modelData.pageIndex)" in settings_qml
    assert "page.displayedTab = page.pendingTab" in settings_qml
    assert "tabTransitionDirection = targetIndex >= sourceIndex ? 1 : -1" in settings_qml
    assert "transform: Translate { id: tabTranslate }" in settings_qml
    assert "readonly property real tabTransitionOpacity: 0.86" in settings_qml
    assert "tabStack.opacity = 0.0" not in settings_qml
    assert settings_qml.count("ParallelAnimation {") >= 2


def test_startup_settings_expose_always_run_as_admin() -> None:
    settings_qml = (QML_DIR / "SettingsPage.qml").read_text(encoding="utf-8")

    assert 'title: I18n.t("Всегда запускать от администратора")' in settings_qml
    assert 'checked: App.alwaysRunAsAdmin' in settings_qml
    assert 'onToggled: App.setAlwaysRunAsAdmin(checked)' in settings_qml


def test_compact_settings_mode_hides_advanced_controls_not_data_tools() -> None:
    settings_qml = (QML_DIR / "SettingsPage.qml").read_text(encoding="utf-8")

    assert "readonly property bool showAdvancedSettings: !App.compactMode" in settings_qml
    assert "compactHidden: true" not in settings_qml
    assert "Скрыть сложные и профессиональные настройки" in settings_qml
    assert settings_qml.count("visible: page.showAdvancedSettings") >= 12
    assert "visible: page.showAdvancedSettings && App.uiWallpaper" in settings_qml
    assert "visible: page.showAdvancedSettings && App.fragmentationEnabled" in settings_qml
    assert "visible: page.showAdvancedSettings && App.multiplexingEnabled" in settings_qml


def test_resource_update_setting_and_reset_are_in_expected_sections() -> None:
    settings_qml = (QML_DIR / "SettingsPage.qml").read_text(encoding="utf-8")

    resource_title = 'title: I18n.t("Проверять обновления ядра и geoip/geosite")'
    resource_index = settings_qml.index(resource_title)
    updates_index = settings_qml.index('Text { text: I18n.t("Обновления")')
    data_index = settings_qml.index('Text { text: I18n.t("Данные")')
    assert settings_qml.count(resource_title) == 1
    assert updates_index < resource_index < data_index

    reset_index = settings_qml.index('title: I18n.t("Сброс настроек")')
    paths_index = settings_qml.index('Text { text: I18n.t("Пути к ядрам")')
    version_index = settings_qml.index('text: App.appName + " · v" + App.appVersion')
    assert reset_index > paths_index
    assert version_index > reset_index


def test_routing_page_has_no_user_control_for_tun_default_outbound() -> None:
    routing_qml = (QML_DIR / "RoutingPage.qml").read_text(encoding="utf-8")

    assert "По умолчанию (TUN)" not in routing_qml
    assert "tunDefaultOutbound" not in routing_qml
    assert "setTunDefaultOutbound" not in routing_qml


def test_updates_page_hides_internal_lumen_singbox_revision() -> None:
    updates_qml = (QML_DIR / "UpdatesPage.qml").read_text(encoding="utf-8")

    assert "function publicSingboxVersion(value)" in updates_qml
    assert "-lumen(?:\\.[0-9A-Za-z.-]+)?$" in updates_qml
    assert "singboxVersion = publicSingboxVersion(s.singboxVersion)" in updates_qml
