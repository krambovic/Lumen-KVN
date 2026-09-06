"""System tray icon for the QML frontend."""
from __future__ import annotations

from PyQt6.QtGui import QAction, QCursor, QIcon
from PyQt6.QtWidgets import QMenu, QSystemTrayIcon
from PyQt6.QtCore import QObject, QPoint, QRect, Qt, QTimer

from ..constants import APP_ICON_PATH, APP_NAME
from ..i18n import tr
from .toast import show_toast


class QmlTray(QObject):
    """Owns the QSystemTrayIcon and bridges it to the window + AppBridge."""

    def __init__(self, app, window, bridge, show_window=None) -> None:
        super().__init__(window)
        self._app = app
        self._window = window
        self._bridge = bridge
        self._show_window_callback = show_window
        self._notified = False
        self._routing_actions: list[QAction] = []

        self._tray = QSystemTrayIcon(self)
        if APP_ICON_PATH.is_file():
            self._tray.setIcon(QIcon(str(APP_ICON_PATH)))
        else:
            self._tray.setIcon(app.windowIcon())
        self._tray.setToolTip(APP_NAME)

        self._menu = QMenu()
        self._routing_menu = QMenu()
        self._refresh_menu_style()
        self._routing_hover_timer = QTimer(self)
        self._routing_hover_timer.setInterval(120)
        self._routing_hover_timer.timeout.connect(self._sync_routing_hover)

        self._action_show = QAction(tr("Скрыть"), self._menu)
        self._action_show.triggered.connect(self._toggle_window)
        self._action_connect = QAction(tr("Подключить"), self._menu)
        self._action_connect.triggered.connect(self._toggle_connection)
        self._action_next = QAction(tr("Следующий сервер"), self._menu)
        self._action_next.triggered.connect(self._switch_next)
        self._action_routing = QAction(tr("Маршрутизация") + "  ›", self._menu)
        self._action_routing.hovered.connect(self._show_routing_menu)
        self._action_routing.triggered.connect(self._show_routing_menu)
        self._action_admin = QAction(tr("Перезапустить от администратора"), self._menu)
        self._action_admin.triggered.connect(self._restart_admin)
        self._action_quit = QAction(tr("Выход"), self._menu)
        self._action_quit.triggered.connect(self._quit)

        self._menu.addAction(self._action_show)
        self._menu.addAction(self._action_connect)
        self._menu.addAction(self._action_next)
        self._menu.addAction(self._action_routing)
        self._menu.addSeparator()
        self._menu.addAction(self._action_admin)
        self._menu.addSeparator()
        self._menu.addAction(self._action_quit)
        self._menu.aboutToHide.connect(self._hide_routing_menu)
        self._menu.aboutToShow.connect(self._refresh_actions)
        for action in (
            self._action_show,
            self._action_connect,
            self._action_next,
            self._action_admin,
            self._action_quit,
        ):
            action.hovered.connect(self._hide_routing_menu)

        self._tray.activated.connect(self._on_activated)
        self._tray.messageClicked.connect(self._show_window)
        try:
            self._bridge.connectedChanged.connect(self._refresh_actions)
        except Exception:
            pass
        try:
            self._bridge.settingsChanged.connect(self._refresh_actions)
        except Exception:
            pass
        try:
            self._bridge.languageChanged.connect(self._refresh_actions)
        except Exception:
            pass
        try:
            self._bridge.trayMessageRequested.connect(self.notify_hidden)
        except Exception:
            pass
        try:
            self._app.styleHints().colorSchemeChanged.connect(lambda _scheme: self._refresh_actions())
        except Exception:
            pass

        self._refresh_actions()
        self._tray.show()

    def _window_visible(self) -> bool:
        try:
            return bool(self._window.isVisible())
        except Exception:
            return True

    def _show_window(self) -> None:
        try:
            if self._show_window_callback is not None:
                self._show_window_callback()
            else:
                self._window.show()
                self._window.raise_()
                self._window.requestActivate()
        except Exception:
            pass
        self._refresh_actions()

    def _hide_window(self) -> None:
        try:
            self._window.hide()
        except Exception:
            pass
        self._refresh_actions()

    def _toggle_window(self) -> None:
        if self._window_visible():
            self._hide_window()
        else:
            self._show_window()

    def _on_activated(self, reason) -> None:
        if reason == QSystemTrayIcon.ActivationReason.Context:
            self._show_context_menu()
            return
        if reason in (
            QSystemTrayIcon.ActivationReason.Trigger,
            QSystemTrayIcon.ActivationReason.DoubleClick,
        ):
            self._toggle_window()

    def _show_context_menu(self) -> None:
        try:
            self._refresh_actions()
            self._hide_routing_menu()
            self._menu.popup(QCursor.pos())
        except Exception:
            pass

    def _toggle_connection(self) -> None:
        try:
            self._bridge.toggleConnection()
        except Exception:
            pass

    def _switch_next(self) -> None:
        try:
            self._bridge.switchNext()
        except Exception:
            pass

    def _apply_default_routing(self, preset_id: str) -> None:
        try:
            self._bridge.applyRoutingPreset(preset_id)
        except Exception:
            pass
        self._hide_menus()

    def _apply_custom_routing(self, preset_id: str) -> None:
        try:
            self._bridge.applyCustomRoutingPreset(preset_id)
        except Exception:
            pass
        self._hide_menus()

    def _restart_admin(self) -> None:
        try:
            self._bridge._on_admin_relaunch()
        except Exception as exc:
            import logging
            logging.getLogger("xray_fluent.app").error("[tray] Exception in _restart_admin", exc_info=exc)

    def _quit(self) -> None:
        try:
            self._bridge.prepareQuit()
        except Exception:
            pass
        try:
            self._tray.hide()
        except Exception:
            pass
        QTimer.singleShot(0, self._app.quit)

    def _connected(self) -> bool:
        try:
            return bool(self._bridge.controller.connected)
        except Exception:
            return False

    def _refresh_actions(self) -> None:
        try:
            self._refresh_menu_style()
            self._action_show.setText(tr("Показать") if not self._window_visible() else tr("Скрыть"))
            self._action_connect.setText(tr("Отключить") if self._connected() else tr("Подключить"))
            self._action_next.setText(tr("Следующий сервер"))
            
            from ..startup import is_process_elevated
            if is_process_elevated():
                self._action_admin.setText(tr("Запущено от администратора"))
                self._action_admin.setEnabled(False)
            else:
                self._action_admin.setText(tr("Перезапустить от администратора"))
                self._action_admin.setEnabled(True)
                
            self._action_quit.setText(tr("Выход"))
            self._action_routing.setText(tr("Маршрутизация") + "  ›")
        except Exception:
            pass

    def _dark_theme(self) -> bool:
        try:
            theme = str(self._bridge.themeName or "").strip().lower()
        except Exception:
            theme = "system"
        if theme == "dark":
            return True
        if theme == "light":
            return False
        try:
            return self._app.styleHints().colorScheme() == Qt.ColorScheme.Dark
        except Exception:
            return True

    def _refresh_menu_style(self) -> None:
        dark = self._dark_theme()
        self._apply_menu_style(self._menu, dark=dark)
        self._apply_menu_style(self._routing_menu, dark=dark)

    def _refresh_routing_actions(self) -> None:
        self._routing_menu.clear()
        self._routing_actions.clear()

        presets = getattr(self._bridge, "regionalRoutingPresets", []) or []
        for item in presets:
            if not isinstance(item, dict):
                continue
            preset_id = str(item.get("id") or "")
            if not preset_id:
                continue
            label = str(item.get("name") or "") or tr("Пресет")
            action = QAction(label, self._routing_menu)
            action.triggered.connect(lambda _checked=False, pid=preset_id: self._apply_default_routing(pid))
            self._insert_routing_action(action)

        custom = getattr(self._bridge, "customRoutingPresets", []) or []
        if custom:
            sep = QAction(self._routing_menu)
            sep.setSeparator(True)
            self._insert_routing_action(sep)
        for item in custom:
            if not isinstance(item, dict):
                continue
            preset_id = str(item.get("id") or "")
            if not preset_id:
                continue
            name = str(item.get("name") or "") or tr("Пресет")
            action = QAction(name, self._routing_menu)
            action.triggered.connect(lambda _checked=False, pid=preset_id: self._apply_custom_routing(pid))
            self._insert_routing_action(action)

    def _insert_routing_action(self, action: QAction) -> None:
        self._routing_menu.addAction(action)
        self._routing_actions.append(action)

    def _show_routing_menu(self) -> None:
        try:
            self._refresh_routing_actions()
            geometry = self._menu.actionGeometry(self._action_routing)
            pos = self._menu.mapToGlobal(geometry.topRight() + QPoint(6, 0))
            self._routing_menu.popup(pos)
            self._routing_hover_timer.start()
        except Exception:
            pass

    def _hide_routing_menu(self) -> None:
        try:
            self._routing_hover_timer.stop()
        except Exception:
            pass
        try:
            self._routing_menu.hide()
        except Exception:
            pass

    def _sync_routing_hover(self) -> None:
        try:
            if not self._menu.isVisible() or not self._routing_menu.isVisible():
                self._hide_routing_menu()
                return

            cursor = QCursor.pos()
            action_geometry = self._menu.actionGeometry(self._action_routing)
            action_top_left = self._menu.mapToGlobal(action_geometry.topLeft())
            action_rect = QRect(
                action_top_left.x(),
                action_top_left.y(),
                action_geometry.width(),
                action_geometry.height(),
            ).adjusted(-8, -6, 12, 6)
            routing_rect = self._routing_menu.frameGeometry().adjusted(-8, -8, 8, 8)
            if not action_rect.contains(cursor) and not routing_rect.contains(cursor):
                self._hide_routing_menu()
        except Exception:
            self._hide_routing_menu()

    def _hide_menus(self) -> None:
        try:
            self._hide_routing_menu()
            self._menu.hide()
        except Exception:
            pass

    @staticmethod
    def _apply_menu_style(menu: QMenu, *, dark: bool) -> None:
        try:
            if dark:
                background = "#242424"
                text = "#FFFFFF"
                border = "#3B3B3B"
                selected = "#343434"
                disabled = "#9A9A9A"
                separator = "#3D3D3D"
            else:
                background = "#FFFFFF"
                text = "#1A1A1A"
                border = "#D6D6D6"
                selected = "#F0F0F0"
                disabled = "#757575"
                separator = "#E5E5E5"
            menu.setStyleSheet(
                f"""
                QMenu {{
                    background: {background};
                    color: {text};
                    border: 1px solid {border};
                    border-radius: 4px;
                    padding: 6px;
                    min-width: 210px;
                }}
                QMenu::item {{
                    min-height: 24px;
                    padding: 5px 28px 5px 12px;
                    background: transparent;
                }}
                QMenu::item:selected {{
                    background: {selected};
                    color: {text};
                }}
                QMenu::item:disabled {{
                    color: {disabled};
                    background-color: transparent;
                }}
                QMenu::separator {{
                    height: 1px;
                    background: {separator};
                    margin: 6px 2px;
                }}
                """
            )
        except Exception:
            pass

    def notify_hidden(self) -> None:
        if self._notified:
            return
        self._notified = True
        message = tr("Приложение свернуто в системный трей")
        # show_toast() only reports that PowerShell was spawned — the WinRT script can
        # still die on execution policy or missing assemblies without telling us, so the
        # in-process balloon goes first and the toast stays as the fallback.
        try:
            if self._tray.isVisible() and QSystemTrayIcon.supportsMessages():
                self._tray.showMessage(APP_NAME, message, QSystemTrayIcon.MessageIcon.Information, 2000)
                return
        except Exception:
            pass
        show_toast(APP_NAME, message)
