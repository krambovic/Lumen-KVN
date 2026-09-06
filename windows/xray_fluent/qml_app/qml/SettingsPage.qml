import QtQuick
import QtQuick.Controls.Universal
import QtQuick.Layouts
import QtQuick.Effects
import QtQuick.Dialogs
import App 1.0
import "."
Item {
    id: page
    readonly property var themeKeys: ["system", "light", "dark"]
    readonly property var languageKeys: App.availableLanguages
    readonly property var presetKeys: ["default", "absolutely", "ayu", "catppuccin", "codex", "dracula", "everforest", "github", "gruvbox", "linear", "lobster", "material", "matrix", "midnight", "monokai", "night-owl", "nord", "notion", "one", "oscurange", "raycast", "rose-pine", "sentry", "solarized", "temple", "tokyo-night", "vercel", "vscode-plus", "xcode"]
    readonly property var presetLabels: ["Default", "Absolutely", "Ayu", "Catppuccin", "Codex", "Dracula", "Everforest", "GitHub", "Gruvbox", "Linear", "Lobster", "Material", "Matrix", "Midnight", "Monokai", "Night Owl", "Nord", "Notion", "One", "Oscurange", "Raycast", "Rose Pine", "Sentry", "Solarized", "Temple", "Tokyo Night", "Vercel", "VS Code Plus", "Xcode"]
    property int currentTab: 0
    property int displayedTab: 0
    property int pendingTab: 0
    property int tabTransitionDirection: 1
    readonly property real tabEnterDistance: Math.round(Math.max(24, Math.min(40, width * 0.035)))
    readonly property real tabExitDistance: Math.round(tabEnterDistance * 0.35)
    readonly property real tabTransitionOpacity: 0.86
    readonly property bool showAdvancedSettings: !App.compactMode
    readonly property var tabModel: [
        { glyph: "\uE790", label: I18n.t("Внешний вид"),        pageIndex: 0, compactHidden: false },
        { glyph: "\uE774", label: I18n.t("Сеть"),               pageIndex: 3, compactHidden: false },
        { glyph: "\uE7E8", label: I18n.t(App.compactMode ? "Запуск" : "Запуск и тесты"), pageIndex: 4, compactHidden: false },
        { glyph: "\uE8C8", label: I18n.t("Подписки"),           pageIndex: 1, compactHidden: false },
        { glyph: "\uE774", label: I18n.t("DNS"),                pageIndex: 2, compactHidden: false },
        { glyph: "\uE895", label: I18n.t("Обновления"),         pageIndex: 5, compactHidden: false },
        { glyph: "\uE74E", label: I18n.t("Данные"),             pageIndex: 6, compactHidden: false }
    ]
    readonly property bool narrowTabs: width < 760
    readonly property bool showTabLabels: width >= 1220
    readonly property real tabScale: width < 760 ? 0.82 : 1.0
    readonly property var visibleTabs: tabModel.filter(function(t) { return !(t.compactHidden && App.compactMode); })
    readonly property int activeVisibleIndex: {
        for (var i = 0; i < visibleTabs.length; i++)
            if (visibleTabs[i].pageIndex === currentTab) return i;
        return 0;
    }
    onVisibleTabsChanged: {
        var ok = false;
        for (var i = 0; i < visibleTabs.length; i++)
            if (visibleTabs[i].pageIndex === currentTab) { ok = true; break; }
        if (!ok && visibleTabs.length > 0) activateTab(visibleTabs[0].pageIndex);
    }

    function visibleIndexForTab(tabIndex) {
        for (var i = 0; i < visibleTabs.length; i++)
            if (visibleTabs[i].pageIndex === tabIndex)
                return i
        return 0
    }

    function resetTabTransition() {
        tabExit.stop()
        tabEnter.stop()
        tabTranslate.x = 0
        tabStack.opacity = 1.0
    }

    function activateTab(tabIndex) {
        if (tabIndex < 0 || tabIndex >= tabModel.length)
            return

        var sourceIndex = visibleIndexForTab(displayedTab)
        var targetIndex = visibleIndexForTab(tabIndex)
        tabTransitionDirection = targetIndex >= sourceIndex ? 1 : -1
        currentTab = tabIndex
        pendingTab = tabIndex

        if (displayedTab === tabIndex) {
            if (tabExit.running)
                resetTabTransition()
            return
        }

        if (!Theme.animations) {
            resetTabTransition()
            displayedTab = tabIndex
            return
        }

        // A new click during the exit animation only changes the destination.
        // This prevents intermediate settings pages from ever becoming visible.
        if (tabExit.running)
            return

        if (tabEnter.running)
            tabEnter.stop()
        tabExit.restart()
    }

    ParallelAnimation {
        id: tabExit
        NumberAnimation {
            target: tabStack
            property: "opacity"
            to: page.tabTransitionOpacity
            duration: 70
            easing.type: Easing.InCubic
        }
        NumberAnimation {
            target: tabTranslate
            property: "x"
            to: -page.tabTransitionDirection * page.tabExitDistance
            duration: 90
            easing.type: Easing.InCubic
        }
        onFinished: {
            page.displayedTab = page.pendingTab
            tabStack.opacity = page.tabTransitionOpacity
            tabTranslate.x = page.tabTransitionDirection * page.tabEnterDistance
            tabEnter.restart()
        }
    }

    ParallelAnimation {
        id: tabEnter
        NumberAnimation {
            target: tabStack
            property: "opacity"
            to: 1.0
            duration: 120
            easing.type: Easing.OutCubic
        }
        NumberAnimation {
            target: tabTranslate
            property: "x"
            to: 0.0
            duration: 220
            easing.type: Theme.easeEmphasized
        }
    }

    function saveSubscriptionSettings() {
        App.setSubscriptionIncludeRegex(subscriptionIncludeRegex.text)
        App.setSubscriptionExcludeRegex(subscriptionExcludeRegex.text)
        App.setSubscriptionUserAgent(subscriptionUserAgent.text)
        App.setSubscriptionUseRealHwid(subscriptionUseRealHwid.checked)
        App.setSubscriptionHwid(subscriptionHwid.text)
        App.setSubscriptionConverterEnabled(subscriptionConverterEnabled.checked)
        App.setSubscriptionConverterUrl(subscriptionConverterUrl.text)
    }



    component StyledCombo: FluentCombo { Layout.preferredWidth: 210 }

    component StyledField: FluentTextField {
        implicitHeight: Theme.controlHeight
        color: Theme.text
        font.family: Theme.fontFamily
        font.pixelSize: Theme.fontNormal
        opacity: enabled ? 1.0 : 0.5
        selectByMouse: true
        leftPadding: 10; rightPadding: 10
        background: Rectangle {
            radius: Theme.radiusSmall
            color: Theme.card
            border.width: 1; border.color: Theme.borderSolid
        }
    }

    component StyledArea: FluentTextArea {
        Layout.fillWidth: true
        Layout.preferredHeight: 86
        color: Theme.text
        font.family: Theme.fontFamily
        font.pixelSize: Theme.fontNormal
        opacity: enabled ? 1.0 : 0.5
        selectByMouse: true
        wrapMode: TextEdit.WrapAnywhere
        leftPadding: 10; rightPadding: 10; topPadding: 8; bottomPadding: 8
        background: Rectangle {
            radius: Theme.radiusSmall
            color: Theme.card
            border.width: 1
            border.color: parent.activeFocus ? Theme.accent : Theme.borderSolid
        }
    }

    component InfoIcon: ToolButton {
        id: infoIconControl
        property string tip: ""
        Layout.preferredWidth: 28
        Layout.preferredHeight: 28
        text: "\uE946"
        font.family: "Segoe Fluent Icons"
        font.pixelSize: 14
        hoverEnabled: true
        FluentToolTip {
            visible: infoIconControl.hovered
            delay: 250
            text: infoIconControl.tip
        }
        contentItem: Text {
            text: parent.text
            font: parent.font
            color: parent.hovered ? Theme.text : Theme.textMuted
            horizontalAlignment: Text.AlignHCenter
            verticalAlignment: Text.AlignVCenter
        }
        background: Rectangle {
            radius: Theme.radiusSmall
            color: parent.hovered ? Theme.controlFillHover : "transparent"
            border.width: 0
        }
    }

    component SettingRow: RowLayout {
        id: sr
        property string glyph: ""
        property string title: ""
        property string subtitle: ""
        default property alias rightItems: rc.data
        Layout.fillWidth: true
        spacing: 12
        Text {
            text: sr.glyph
            visible: sr.glyph.length > 0
            font.family: "Segoe Fluent Icons"; font.pixelSize: 16
            color: Theme.textMuted
            Layout.preferredWidth: 22
            Layout.alignment: Qt.AlignVCenter
        }
        ColumnLayout {
            Layout.fillWidth: true
            spacing: 2
            Text { text: sr.title; color: Theme.text; font.family: Theme.fontFamily; font.pixelSize: Theme.fontNormal; font.hintingPreference: Font.PreferVerticalHinting; renderType: Text.QtRendering; Layout.fillWidth: true; wrapMode: Text.WordWrap }
            Text { text: sr.subtitle; visible: sr.subtitle.length > 0; color: Theme.textFaint; font.family: Theme.fontFamily; font.pixelSize: Theme.fontSmall; font.hintingPreference: Font.PreferVerticalHinting; renderType: Text.QtRendering; Layout.fillWidth: true; wrapMode: Text.WordWrap }
        }
        RowLayout { id: rc; spacing: 8; Layout.alignment: Qt.AlignVCenter }
    }

    component PercentSlider: RowLayout {
        id: ps
        property int value: 0
        signal valueEdited(int value)
        spacing: 8
        Slider {
            Layout.preferredWidth: 170
            from: 0
            to: 100
            stepSize: 5
            value: ps.value
            onMoved: ps.valueEdited(Math.round(value))
        }
        Text {
            text: ps.value + "%"
            color: Theme.textMuted
            font.family: Theme.fontFamily
            font.pixelSize: Theme.fontSmall
            Layout.preferredWidth: 42
            horizontalAlignment: Text.AlignRight
        }
    }

    // ---- accent colour picker ----
    component AccentPicker: Item {
        id: ap
        implicitWidth: 56
        implicitHeight: Theme.controlHeight
        Rectangle {
            id: swatch
            anchors.fill: parent
            radius: Theme.radiusSmall
            color: App.accentColor
            border.width: 1
            border.color: hover.hovered ? Theme.text : Theme.divider
            HoverHandler { id: hover }
            TapHandler { onTapped: accentDlg.openWith(App.accentColor) }
        }
        ColorPickerDialog {
            id: accentDlg
            showSystem: true
            showDarkness: true
            onAccepted: (hex) => App.setAccent(hex)
        }
    }

    component BaseTintPicker: Item {
        id: bt
        implicitWidth: 56
        implicitHeight: Theme.controlHeight
        Rectangle {
            id: btSwatch
            anchors.fill: parent
            radius: Theme.radiusSmall
            color: App.uiBaseTint !== "" ? App.uiBaseTint : "transparent"
            border.width: 1
            border.color: btHover.hovered ? Theme.text : Theme.divider
            Text {
                anchors.centerIn: parent
                visible: App.uiBaseTint === ""
                text: "\u2014"
                font.family: Theme.fontFamily; font.pixelSize: Theme.fontNormal
                color: Theme.textFaint
            }
            HoverHandler { id: btHover }
            TapHandler {
                onTapped: {
                    var src = App.uiBaseTintSrc
                    if (src && src.indexOf("|") > 0) {
                        var parts = src.split("|")
                        baseTintDlg.openWith(parts[0], parseFloat(parts[1]))
                    } else if (App.uiBaseTint !== "") {
                        baseTintDlg.openWith(App.uiBaseTint, 0)
                    } else {
                        baseTintDlg.openWith("#5B6B8C", 0.6)
                    }
                }
            }
        }
        ColorPickerDialog {
            id: baseTintDlg
            showDarkness: true
            heading: I18n.t("Свой базовый тон")
            onAccepted: (hex) => {
                App.setUiBaseTint(hex)
                App.setUiBaseTintSrc(baseTintDlg._baseHex() + "|" + baseTintDlg._mute)
            }
        }
    }


    FileDialog {
        id: wallpaperDlg
        title: I18n.t("Выберите изображение")
        nameFilters: [I18n.t("Изображения") + " (*.png *.jpg *.jpeg *.bmp *.webp)"]
        onAccepted: App.setUiWallpaper(selectedFile.toString())
    }

    FluentDialog {
        id: resetSettingsDialog
        width: 480
        title: I18n.t("Сбросить настройки?")
        okText: I18n.t("Сбросить")
        onAccepted: App.resetSettingsToDefaults()
        contentItem: Text {
            text: I18n.t("Настройки приложения и маршрутизации вернутся к значениям по умолчанию. Серверы и подписки не будут удалены.")
            color: Theme.textMuted
            font.family: Theme.fontFamily
            font.pixelSize: Theme.fontNormal
            wrapMode: Text.WordWrap
        }
    }

    ColumnLayout {
        anchors.fill: parent
        anchors.topMargin: 20
        anchors.bottomMargin: 8
        anchors.rightMargin: 12
        spacing: Theme.spacingLarge

        Text {
            text: I18n.t("Настройки")
            font.family: Theme.fontFamily; font.pixelSize: Theme.fontTitle
            font.weight: Font.DemiBold; color: Theme.text
        }

        // ===== Адаптивный таб-бар с анимированным индикатором =====
        Item {
            Layout.fillWidth: true
            implicitHeight: Math.round(40 * Theme.fontScale)

            RowLayout {
                id: tabRow
                anchors.fill: parent
                spacing: 4
                Repeater {
                    model: page.visibleTabs
                    delegate: Rectangle {
                        required property int index
                        required property var modelData
                        readonly property bool current: page.currentTab === modelData.pageIndex
                        Layout.fillWidth: true
                        Layout.preferredWidth: 1
                        Layout.fillHeight: true
                        radius: Theme.radiusSmall
                        color: "transparent"
                        Rectangle {
                            anchors.fill: parent
                            radius: parent.radius
                            color: current ? Theme.accentSoft : Theme.navHover
                            opacity: current || tabMouse.containsMouse ? 1 : 0
                            Behavior on opacity { NumberAnimation { duration: Theme.animations ? 140 : 0 } }
                        }
                        Row {
                            anchors.centerIn: parent
                            spacing: 8
                            Text {
                                anchors.verticalCenter: parent.verticalCenter
                                text: modelData.glyph
                                font.family: "Segoe Fluent Icons"
                                font.pixelSize: Math.round(Theme.fontNormal * page.tabScale)
                                color: current ? Theme.accent : Theme.textMuted
                                Behavior on color { ColorAnimation { duration: Theme.animations ? 140 : 0 } }
                            }
                            Text {
                                anchors.verticalCenter: parent.verticalCenter
                                visible: page.showTabLabels
                                text: modelData.label
                                font.family: Theme.fontFamily
                                font.pixelSize: Math.round(Theme.fontNormal * page.tabScale)
                                font.weight: current ? Font.DemiBold : Font.Normal
                                color: current ? Theme.text : Theme.textMuted
                                Behavior on color { ColorAnimation { duration: Theme.animations ? 140 : 0 } }
                            }
                        }
                        MouseArea {
                            id: tabMouse
                            anchors.fill: parent
                            hoverEnabled: true
                            onClicked: page.activateTab(modelData.pageIndex)
                        }
                    }
                }
            }

            // Скользящий индикатор активной вкладки
            Rectangle {
                id: tabIndicator
                readonly property int count: page.visibleTabs.length
                readonly property real tw: (tabRow.width - tabRow.spacing * (count - 1)) / count
                height: 2.5
                radius: 2
                color: Theme.accent
                y: tabRow.height - height
                width: tw * 0.5
                x: page.activeVisibleIndex * (tw + tabRow.spacing) + (tw - width) / 2
                Behavior on x { NumberAnimation { duration: Theme.animations ? 240 : 0; easing.type: Theme.easeEmphasized } }
                Behavior on width { NumberAnimation { duration: Theme.animations ? 240 : 0 } }
            }
        }

        Rectangle { Layout.fillWidth: true; height: 1; color: Theme.divider }

        StackLayout {
            id: tabStack
            Layout.fillWidth: true
            Layout.fillHeight: true
            clip: true
            currentIndex: page.displayedTab
            transform: Translate { id: tabTranslate }

        FluentScroll {
            roundedClip: false
            ColumnLayout {
                width: parent.width
                spacing: Theme.spacingLarge
        Card {
            Layout.fillWidth: true
            ColumnLayout {
                anchors.fill: parent
                spacing: 14
                Text { text: I18n.t("Тема"); color: Theme.text; font.family: Theme.fontFamily; font.pixelSize: Theme.fontStrong; font.weight: Font.DemiBold }

                SettingRow {
                    glyph: "\uE790"; title: I18n.t("Тема"); subtitle: I18n.t("Выберите светлую, тёмную или системную тему")
                    StyledCombo {
                        model: [I18n.t("Авто"), I18n.t("Светлая"), I18n.t("Тёмная")]
                        currentIndex: Math.max(0, page.themeKeys.indexOf(App.themeName))
                        onActivated: App.setTheme(page.themeKeys[currentIndex])
                    }
                }

                SettingRow {
                    glyph: "\uE771"; title: I18n.t("Палитра (пресет)"); subtitle: I18n.t("Готовая цветовая тема поверх светлой/тёмной")
                    StyledCombo {
                        model: page.presetLabels
                        currentIndex: Math.max(0, page.presetKeys.indexOf(App.uiThemePreset))
                        onActivated: App.setUiThemePreset(page.presetKeys[currentIndex])
                    }
                }

                SettingRow {
                    glyph: "\uE774"; title: I18n.t("Язык"); subtitle: I18n.t("При первом запуске выбирается по языку системы")
                    StyledCombo {
                        model: App.languageLabels
                        currentIndex: Math.max(0, page.languageKeys.indexOf(App.language))
                        onActivated: App.setLanguage(page.languageKeys[currentIndex])
                    }
                }

                SettingRow {
                    glyph: "\uE2B1"; title: I18n.t("Цвет акцента"); subtitle: I18n.t("Цвет акцента для элементов интерфейса")
                    AccentPicker {}
                }

                SettingRow {
                    visible: page.showAdvancedSettings
                    glyph: "\uE7E6"; title: I18n.t("Свой базовый тон"); subtitle: I18n.t("Кастомный цвет подложки окна (поверх пресета)")
                    AccentButton {
                        kind: "ghost"
                        text: I18n.t("Сбросить")
                        visible: App.uiBaseTint !== ""
                        onClicked: App.setUiBaseTint("")
                    }
                    BaseTintPicker {}
                }
            }
        }

        Card {
            Layout.fillWidth: true
            ColumnLayout {
                anchors.fill: parent
                spacing: 14
                Text { text: I18n.t("Обои"); color: Theme.text; font.family: Theme.fontFamily; font.pixelSize: Theme.fontStrong; font.weight: Font.DemiBold }

                SettingRow {
                    glyph: "\uEB9F"; title: I18n.t("Обои окна"); subtitle: I18n.t("Фоновое изображение под интерфейсом")
                    AccentButton {
                        kind: "ghost"
                        text: I18n.t("Сбросить")
                        visible: App.uiWallpaper !== ""
                        onClicked: App.setUiWallpaper("")
                    }
                    AccentButton {
                        text: I18n.t("Выбрать\u2026")
                        onClicked: wallpaperDlg.open()
                    }
                }

                SettingRow {
                    visible: page.showAdvancedSettings && App.uiWallpaper !== ""
                    glyph: "\uE890"; title: I18n.t("Непрозрачность обоев"); subtitle: I18n.t("Насколько ярко видно изображение, %")
                    PercentSlider { value: App.uiWallpaperOpacity; onValueEdited: (v) => App.setUiWallpaperOpacity(v) }
                }

                SettingRow {
                    visible: page.showAdvancedSettings && App.uiWallpaper !== ""
                    glyph: "\uE7B3"; title: I18n.t("Размытие обоев"); subtitle: I18n.t("Сила размытия фона, 0–100")
                    PercentSlider { value: App.uiWallpaperBlur; onValueEdited: (v) => App.setUiWallpaperBlur(v) }
                }

                SettingRow {
                    visible: page.showAdvancedSettings && App.uiWallpaper !== ""
                    glyph: "\uE706"; title: I18n.t("Яркость обоев"); subtitle: I18n.t("100 = оригинал, меньше = темнее")
                    PercentSlider { value: App.uiWallpaperBrightness; onValueEdited: (v) => App.setUiWallpaperBrightness(v) }
                }
            }
        }

        Card {
            Layout.fillWidth: true
            ColumnLayout {
                anchors.fill: parent
                spacing: 14
                Text { text: I18n.t("Интерфейс"); color: Theme.text; font.family: Theme.fontFamily; font.pixelSize: Theme.fontStrong; font.weight: Font.DemiBold }

                SettingRow {
                    glyph: "\uE799"; title: I18n.t("Плотность"); subtitle: I18n.t("Насколько компактно расположены элементы")
                    StyledCombo {
                        model: [I18n.t("Компактная"), I18n.t("Обычная"), I18n.t("Просторная")]
                        readonly property var keys: ["compact", "comfortable", "spacious"]
                        currentIndex: Math.max(0, keys.indexOf(App.uiDensity))
                        onActivated: App.setUiDensity(keys[currentIndex])
                    }
                }

                SettingRow {
                    glyph: "\uE8E9"; title: I18n.t("Масштаб интерфейса"); subtitle: I18n.t("Размер шрифта и всего интерфейса, % (80–140)")
                    FluentSpin { from: 80; to: 140; stepSize: 5; value: App.uiFontScale; onValueModified: App.setUiFontScale(value) }
                }

                SettingRow {
                    visible: page.showAdvancedSettings
                    glyph: "\uE8B3"; title: I18n.t("Скругление углов"); subtitle: I18n.t("Радиус скругления карточек и кнопок, px")
                    FluentSpin { from: 0; to: 20; value: App.uiCornerRadius; onValueModified: App.setUiCornerRadius(value) }
                }

                SettingRow {
                    glyph: "\uE945"; title: I18n.t("Анимации"); subtitle: I18n.t("Плавные переходы и движение интерфейса")
                    Switch { checked: App.uiAnimations; onToggled: App.setUiAnimations(checked) }
                }

                SettingRow {
                    glyph: "\uE890"; title: I18n.t("Компактный режим"); subtitle: I18n.t("Скрыть сложные и профессиональные настройки")
                    Switch { checked: App.compactMode; onToggled: App.setInterfaceMode(checked ? "compact" : "full") }
                }
            }
        }

        Card {
            Layout.fillWidth: true
            ColumnLayout {
                anchors.fill: parent
                spacing: 14
                Text { text: I18n.t("Прозрачность"); color: Theme.text; font.family: Theme.fontFamily; font.pixelSize: Theme.fontStrong; font.weight: Font.DemiBold }

                SettingRow {
                    glyph: "\uE790"; title: I18n.t("Прозрачность"); subtitle: I18n.t("Использовать системные эффекты фона Windows 11")
                    Switch {
                        checked: App.uiBackdrop !== "solid"
                        onToggled: App.setUiBackdrop(checked ? "mica" : "solid")
                    }
                }

                SettingRow {
                    enabled: App.uiBackdrop !== "solid"
                    visible: page.showAdvancedSettings
                    opacity: enabled ? 1.0 : 0.55
                    glyph: "\uE9E9"; title: I18n.t("Сила прозрачности"); subtitle: I18n.t("0: Mica почти выключена, 100: максимум Mica")
                    PercentSlider { value: App.uiTransparencyStrength; onValueEdited: (v) => App.setUiTransparencyStrength(v) }
                }
            }
        }
                Item { Layout.fillHeight: true; Layout.preferredHeight: 1 }
            }
        }

        FluentScroll {
            roundedClip: false
            ColumnLayout {
                width: parent.width
                spacing: Theme.spacingLarge
                Card {
                    Layout.fillWidth: true
                    ColumnLayout {
                        anchors.fill: parent
                        spacing: 14
                        Text { text: I18n.t("Подписки"); color: Theme.text; font.family: Theme.fontFamily; font.pixelSize: Theme.fontStrong; font.weight: Font.DemiBold }
                        SettingRow {
                            glyph: "\uE895"; title: I18n.t("Автообновление подписок"); subtitle: I18n.t("Как часто фоново обновлять подписки (прокси/VPN не отключается)")
                            StyledCombo {
                                Layout.preferredWidth: 200
                                readonly property var values: [0, 30, 60, 240, 720, 1440]
                                model: [I18n.t("Выкл"), I18n.t("30 мин"), I18n.t("1 час"), I18n.t("4 часа"), I18n.t("12 часов"), I18n.t("24 часа")]
                                currentIndex: Math.max(0, values.indexOf(App.subscriptionAutoUpdateMinutes))
                                onActivated: App.setSubscriptionAutoUpdateMinutes(values[currentIndex])
                            }
                        }
                        SettingRow {
                            glyph: "\uE8A7"; title: I18n.t("Загружать подписки через прокси/TUN"); subtitle: I18n.t("Импорт и обновление используют активное подключение Lumen; без подключения — системную сеть")
                            Switch { checked: App.subscriptionUseProxyTun; onToggled: App.setSubscriptionUseProxyTun(checked) }
                        }
                    }
                }

                Card {
                    Layout.fillWidth: true
                    visible: page.showAdvancedSettings
                    ColumnLayout {
                        anchors.fill: parent
                        spacing: 14
                        Text { text: I18n.t("Фильтры regex"); color: Theme.text; font.family: Theme.fontFamily; font.pixelSize: Theme.fontNormal; font.weight: Font.DemiBold }
                        Text { text: I18n.t("Каждая строка — отдельное выражение. Фильтр применяется к имени, адресу, протоколу и исходной ссылке сервера."); color: Theme.textFaint; font.family: Theme.fontFamily; font.pixelSize: Theme.fontSmall; Layout.fillWidth: true; wrapMode: Text.WordWrap }
                        GridLayout {
                            Layout.fillWidth: true
                            columns: page.width < 1000 ? 1 : 2
                            rowSpacing: 12
                            columnSpacing: 12
                            ColumnLayout {
                                Layout.fillWidth: true
                                Text { text: I18n.t("Включать"); color: Theme.textMuted; font.family: Theme.fontFamily; font.pixelSize: Theme.fontSmall }
                                StyledArea { id: subscriptionIncludeRegex; text: App.subscriptionIncludeRegex; placeholderText: "NL|DE|Reality" }
                            }
                            ColumnLayout {
                                Layout.fillWidth: true
                                Text { text: I18n.t("Исключать"); color: Theme.textMuted; font.family: Theme.fontFamily; font.pixelSize: Theme.fontSmall }
                                StyledArea { id: subscriptionExcludeRegex; text: App.subscriptionExcludeRegex; placeholderText: "expired|traffic limit" }
                            }
                        }
                    }
                }

                Card {
                    Layout.fillWidth: true
                    visible: page.showAdvancedSettings
                    ColumnLayout {
                        anchors.fill: parent
                        spacing: 14
                        Text { text: I18n.t("Параметры запроса"); color: Theme.text; font.family: Theme.fontFamily; font.pixelSize: Theme.fontNormal; font.weight: Font.DemiBold }
                        SettingRow {
                            glyph: "\uE8D4"; title: "User-Agent"; subtitle: I18n.t("Пустое поле использует полный профиль запросов Happ для Windows")
                            StyledField { id: subscriptionUserAgent; Layout.preferredWidth: 360; text: App.subscriptionUserAgent; placeholderText: "Happ/2.18.3/Windows/2606241603601" }
                        }
                        SettingRow {
                            glyph: "\uE72E"; title: I18n.t("Отправлять настоящий HWID"); subtitle: I18n.t("Использовать MachineGuid текущей установки Windows вместо указанного вручную")
                            Switch { id: subscriptionUseRealHwid; checked: App.subscriptionUseRealHwid }
                        }
                        SettingRow {
                            visible: !subscriptionUseRealHwid.checked
                            glyph: "\uE950"; title: "HWID"; subtitle: I18n.t("Идентификатор устройства для заголовка X-Hwid; пустое поле использует стандартное значение Happ")
                            StyledField {
                                id: subscriptionHwid
                                Layout.preferredWidth: 360
                                text: App.subscriptionHwid
                                placeholderText: "00000000-0000-4000-8000-000000000000"
                                maximumLength: 256
                            }
                        }
                        SettingRow {
                            glyph: "\uE8AB"; title: I18n.t("Конвертация подписки"); subtitle: I18n.t("Перед загрузкой передавать URL сервису-конвертеру")
                            Switch { id: subscriptionConverterEnabled; checked: App.subscriptionConverterEnabled }
                        }
                        StyledField {
                            id: subscriptionConverterUrl
                            Layout.fillWidth: true
                            enabled: subscriptionConverterEnabled.checked
                            text: App.subscriptionConverterUrl
                            placeholderText: "https://converter.example/sub?url={url}"
                        }
                        RowLayout {
                            Layout.fillWidth: true
                            Item { Layout.fillWidth: true }
                            AccentButton { glyph: "\uE74E"; text: I18n.t("Сохранить настройки подписок"); onClicked: page.saveSubscriptionSettings() }
                        }
                    }
                }
                Item { Layout.fillHeight: true; Layout.preferredHeight: 1 }
            }
        }

        FluentScroll {
            roundedClip: false
            ColumnLayout {
                width: parent.width
                spacing: Theme.spacingLarge
                Card {
                    Layout.fillWidth: true
                    ColumnLayout {
                        anchors.fill: parent
                        spacing: 14
                        Text { text: "DNS"; color: Theme.text; font.family: Theme.fontFamily; font.pixelSize: Theme.fontStrong; font.weight: Font.DemiBold }
                        SettingRow {
                            glyph: "\uE774"; title: I18n.t("Режим DNS"); subtitle: I18n.t("Системный DNS или встроенный DNS выбранного ядра")
                            StyledCombo {
                                readonly property var values: ["system", "builtin"]
                                model: [I18n.t("Системный"), I18n.t("Встроенный")]
                                boundIndex: Math.max(0, values.indexOf(App.dnsMode))
                                onActivated: App.setDnsMode(values[currentIndex])
                            }
                        }
                    }
                }

                Card {
                    Layout.fillWidth: true
                    visible: page.showAdvancedSettings
                    enabled: App.dnsMode === "builtin"
                    opacity: enabled ? 1.0 : 0.5
                    ColumnLayout {
                        anchors.fill: parent
                        spacing: 14
                        Text { text: I18n.t("DNS-серверы"); color: Theme.text; font.family: Theme.fontFamily; font.pixelSize: Theme.fontNormal; font.weight: Font.DemiBold }
                        ColumnLayout {
                            Layout.fillWidth: true
                            spacing: 14
                            GridLayout {
                                Layout.fillWidth: true
                                columns: page.width < 1000 ? 1 : 2
                                rowSpacing: 12
                                columnSpacing: 12
                                ColumnLayout {
                                    Layout.fillWidth: true
                                    Text { text: I18n.t("Прямые DNS-серверы"); color: Theme.text; font.family: Theme.fontFamily; font.pixelSize: Theme.fontNormal }
                                    Text { text: I18n.t("Необязательно; пусто — DNS только через прокси"); color: Theme.textFaint; font.family: Theme.fontFamily; font.pixelSize: Theme.fontSmall }
                                    StyledArea { id: dnsBootstrapServers; text: App.dnsBootstrapServersText; placeholderText: "1.1.1.1\n8.8.8.8" }
                                }
                                ColumnLayout {
                                    Layout.fillWidth: true
                                    Text { text: I18n.t("DNS через прокси"); color: Theme.text; font.family: Theme.fontFamily; font.pixelSize: Theme.fontNormal }
                                    Text { text: I18n.t("По одному адресу в строке"); color: Theme.textFaint; font.family: Theme.fontFamily; font.pixelSize: Theme.fontSmall }
                                    StyledArea { id: dnsProxyServers; text: App.dnsProxyServersText; placeholderText: "dns.google\ncloudflare-dns.com" }
                                }
                            }
                            GridLayout {
                                Layout.fillWidth: true
                                columns: page.width < 1000 ? 1 : 2
                                rowSpacing: 12
                                columnSpacing: 12
                                SettingRow {
                                    Layout.fillWidth: true; glyph: "\uE8A5"; title: I18n.t("Тип прямого DNS")
                                    StyledCombo { model: ["udp", "tcp", "tls", "https"]; boundIndex: Math.max(0, model.indexOf(App.dnsBootstrapType)); onActivated: App.setBootstrapDns("", currentText) }
                                }
                                SettingRow {
                                    Layout.fillWidth: true; glyph: "\uE8A5"; title: I18n.t("Тип proxy DNS")
                                    StyledCombo { model: ["udp", "tcp", "tls", "https"]; boundIndex: Math.max(0, model.indexOf(App.dnsProxyType)); onActivated: App.setProxyDns("", currentText) }
                                }
                            }
                            GridLayout {
                                Layout.fillWidth: true
                                columns: page.width < 1000 ? 1 : 2
                                rowSpacing: 12
                                columnSpacing: 12
                                SettingRow {
                                    Layout.fillWidth: true; glyph: "\uE8EF"; title: I18n.t("Стратегия прямого DNS")
                                    StyledCombo { readonly property var values: ["prefer_ipv4", "prefer_ipv6", "ipv4_only", "ipv6_only"]; model: values; boundIndex: Math.max(0, values.indexOf(App.dnsBootstrapStrategy)); onActivated: App.setDnsBootstrapStrategy(values[currentIndex]) }
                                }
                                SettingRow {
                                    Layout.fillWidth: true; glyph: "\uE8EF"; title: I18n.t("Стратегия proxy DNS")
                                    StyledCombo { readonly property var values: ["prefer_ipv4", "prefer_ipv6", "ipv4_only", "ipv6_only"]; model: values; boundIndex: Math.max(0, values.indexOf(App.dnsProxyStrategy)); onActivated: App.setDnsProxyStrategy(values[currentIndex]) }
                                }
                            }

                            SettingRow { glyph: "\uE8C9"; title: I18n.t("Параллельные DNS-запросы"); subtitle: I18n.t("Запрашивать несколько DNS одновременно, когда ядро это поддерживает"); Switch { checked: App.dnsParallelQuery; onToggled: App.setDnsParallelQuery(checked) } }
                            SettingRow { glyph: "\uE823"; title: I18n.t("Оптимистичный кэш"); subtitle: I18n.t("Отдавать устаревший ответ и обновлять его в фоне, когда ядро это поддерживает"); Switch { checked: App.dnsOptimisticCache; onToggled: App.setDnsOptimisticCache(checked) } }
                            SettingRow { glyph: "\uE81E"; title: I18n.t("Geo-проверка DNS"); subtitle: I18n.t("Выбирать прямой или proxy DNS по правилам GeoSite пресета"); Switch { checked: App.dnsGeoCheck; onToggled: App.setDnsGeoCheck(checked) } }
                            SettingRow { glyph: "\uE8D7"; title: I18n.t("Перехватывать DNS в TUN"); subtitle: I18n.t("Направлять DNS-запросы приложений во встроенный DNS"); Switch { checked: App.dnsHijackEnabled; onToggled: App.setDnsHijackEnabled(checked) } }
                            SettingRow { glyph: "\uE8F1"; title: I18n.t("Fake DNS"); subtitle: I18n.t("Использовать FakeIP для DNS в TUN"); Switch { checked: App.dnsFakeEnabled; onToggled: App.setDnsFakeEnabled(checked) } }
                        }
                    }
                }

                Card {
                    Layout.fillWidth: true
                    visible: page.showAdvancedSettings
                    enabled: App.dnsMode === "builtin"
                    opacity: enabled ? 1.0 : 0.5
                    ColumnLayout {
                        anchors.fill: parent
                        spacing: 14
                        Text { text: "Hosts"; color: Theme.text; font.family: Theme.fontFamily; font.pixelSize: Theme.fontNormal; font.weight: Font.DemiBold }
                        Text { text: I18n.t("Формат: domain=address. Несколько адресов разделяются запятыми."); color: Theme.textFaint; font.family: Theme.fontFamily; font.pixelSize: Theme.fontSmall; Layout.fillWidth: true; wrapMode: Text.WordWrap }
                        StyledArea { id: dnsHosts; Layout.preferredHeight: 110; text: App.dnsHostsText; placeholderText: "example.com=1.1.1.1\nlocal.test=127.0.0.1,::1" }
                        RowLayout {
                            Layout.fillWidth: true
                            Item { Layout.fillWidth: true }
                            AccentButton {
                                glyph: "\uE74E"; text: I18n.t("Применить DNS")
                                onClicked: App.applyDnsSettings(dnsBootstrapServers.text, dnsProxyServers.text, dnsHosts.text)
                            }
                        }
                    }
                }
                Item { Layout.fillHeight: true; Layout.preferredHeight: 1 }
            }
        }

        FluentScroll {
            roundedClip: false
            ColumnLayout {
                width: parent.width
                spacing: Theme.spacingLarge
        Card {
            Layout.fillWidth: true
            ColumnLayout {
                anchors.fill: parent
                spacing: 14
                Text { text: I18n.t("Сеть"); color: Theme.text; font.family: Theme.fontFamily; font.pixelSize: Theme.fontStrong; font.weight: Font.DemiBold }

                SettingRow {
                    glyph: "\uE909"; title: I18n.t("Региональный профиль"); subtitle: I18n.t("Меняет быстрые пресеты и источники GeoIP/GeoSite")
                    FluentCombo {
                        id: regionalPresetCombo
                        Layout.preferredWidth: 220
                        enabled: !App.regionalPresetBusy
                        textRole: "label"
                        valueRole: "key"
                        model: [
                            { key: "russia", label: I18n.t("Россия") },
                            { key: "china", label: I18n.t("Китай") },
                            { key: "iran", label: I18n.t("Иран") }
                        ]
                        boundIndex: App.regionalPreset === "china" ? 1 : (App.regionalPreset === "iran" ? 2 : 0)
                        onActivated: App.setRegionalPreset(currentValue)
                        Connections {
                            target: App
                            function onRegionalPresetBusyChanged() {
                                Qt.callLater(function() { regionalPresetCombo.syncBoundIndex() })
                            }
                        }
                    }
                }

                SettingRow {
                    glyph: "\uE80F"; title: I18n.t("Прокси в обход локальной сети"); subtitle: I18n.t("Не проксировать адреса локальной сети")
                    Switch { checked: App.proxyBypassLan; onToggled: App.setProxyBypassLan(checked) }
                }
                SettingRow {
                    glyph: "\uE774"; title: I18n.t("Настраивать прокси Firefox"); subtitle: I18n.t("Принудительно записывать прокси в профили браузеров Firefox")
                    InfoIcon { tip: I18n.t("Обычно Firefox использует системный прокси автоматически. Включайте эту настройку только если Firefox его игнорирует.") }
                    Switch { checked: App.firefoxProxyIntegration; onToggled: App.setFirefoxProxyIntegration(checked) }
                }
                SettingRow {
                    glyph: "\uE895"; title: I18n.t("Переподключение при смене сети"); subtitle: I18n.t("Автоматически переподключаться при изменении сети")
                    Switch { checked: App.reconnectOnNetworkChange; onToggled: App.setReconnectOnNetworkChange(checked) }
                }
                SettingRow {
                    glyph: "\uE7E8"; title: I18n.t("Восстанавливать VPN после сна"); subtitle: I18n.t("Автоматически переподключаться после выхода Windows из сна или гибернации")
                    Switch { checked: App.reconnectAfterSleep; onToggled: App.setReconnectAfterSleep(checked) }
                }
                SettingRow {
                    visible: page.showAdvancedSettings
                    glyph: "\uE968"; title: I18n.t("Предпочитать IPv6"); subtitle: I18n.t("Использовать IPv6-адреса раньше IPv4, если сервер и сеть это поддерживают")
                    Switch { checked: App.preferIpv6; onToggled: App.setPreferIpv6(checked) }
                }
                SettingRow {
                    glyph: "\uE72E"; title: I18n.t("Kill-switch"); subtitle: I18n.t("При обрыве VPN блокировать трафик вместо выхода напрямую")
                    Switch { checked: App.killSwitch; onToggled: App.setKillSwitch(checked) }
                }
                SettingRow {
                    visible: page.showAdvancedSettings
                    Layout.fillWidth: true
                    glyph: "\uE8A6"; title: I18n.t("Фрагментирование"); subtitle: I18n.t("TLS Fragment")
                    InfoIcon { tip: I18n.t("Фрагментирование делит TLS-рукопожатие на части. Может помочь обходу DPI, но иногда снижает стабильность.") }
                    Switch { checked: App.fragmentationEnabled; onToggled: App.setFragmentation(checked) }
                }
                SettingRow {
                    visible: page.showAdvancedSettings && App.fragmentationEnabled
                    Layout.fillWidth: true
                    glyph: "\uE9D9"; title: I18n.t("Настройки фрагментирования"); subtitle: I18n.t("Fragment Settings")
                    InfoIcon { tip: I18n.t("Packets выбирает часть трафика, Length размер фрагментов, Delay задержку между ними.") }
                    StyledField { id: fragPackets; Layout.preferredWidth: 100; text: App.fragmentPackets; placeholderText: "tlshello"; onEditingFinished: App.setFragmentSettings(text, fragLength.text, fragDelay.text) }
                    StyledField { id: fragLength; Layout.preferredWidth: 100; text: App.fragmentLength; placeholderText: "50-100"; onEditingFinished: App.setFragmentSettings(fragPackets.text, text, fragDelay.text) }
                    StyledField { id: fragDelay; Layout.preferredWidth: 100; text: App.fragmentDelay; placeholderText: "10-20"; onEditingFinished: App.setFragmentSettings(fragPackets.text, fragLength.text, text) }
                }
                SettingRow {
                    visible: page.showAdvancedSettings
                    Layout.fillWidth: true
                    glyph: "\uE7C3"; title: I18n.t("Мультиплексирование"); subtitle: I18n.t("Multiplex")
                    InfoIcon { tip: I18n.t("Мультиплексирование объединяет несколько запросов в один канал. Может ускорить много мелких соединений, но зависит от поддержки сервера.") }
                    Switch { checked: App.multiplexingEnabled; onToggled: App.setMultiplexing(checked) }
                }
                SettingRow {
                    visible: page.showAdvancedSettings && App.multiplexingEnabled
                    Layout.fillWidth: true
                    glyph: "\uE9D9"; title: I18n.t("Настройки мультиплексирования"); subtitle: I18n.t("Multiplex Settings")
                    InfoIcon { tip: I18n.t("Потоки задают, сколько запросов можно вести внутри одного мультиплексированного соединения.") }
                    FluentSpin { from: 1; to: 32; value: App.multiplexConcurrency; onValueModified: App.setMultiplexConcurrency(value) }
                }
            }
        }
        Card {
            Layout.fillWidth: true
            visible: page.showAdvancedSettings
            ColumnLayout {
                anchors.fill: parent
                spacing: 14
                Text { text: I18n.t("Авто-переключение"); color: Theme.text; font.family: Theme.fontFamily; font.pixelSize: Theme.fontStrong; font.weight: Font.DemiBold }

                SettingRow {
                    glyph: "\uE895"; title: I18n.t("Включить авто-переключение"); subtitle: I18n.t("Переключать сервер при падении скорости")
                    Switch { checked: App.autoSwitchEnabled; onToggled: App.setAutoSwitch(checked) }
                }
                SettingRow {
                    glyph: "\uEC4A"; title: I18n.t("Порог скорости"); subtitle: I18n.t("КБ/с, ниже которого срабатывает переключение")
                    FluentSpin { from: 1; to: 10000; value: App.autoSwitchThreshold; onValueModified: App.setAutoSwitchThreshold(value) }
                }
                SettingRow {
                    glyph: "\uE916"; title: I18n.t("Задержка"); subtitle: I18n.t("Секунд низкой скорости перед переключением")
                    FluentSpin { from: 5; to: 300; value: App.autoSwitchDelay; onValueModified: App.setAutoSwitchDelay(value) }
                }
                SettingRow {
                    glyph: "\uE81C"; title: I18n.t("Пауза"); subtitle: I18n.t("Секунд между переключениями")
                    FluentSpin { from: 10; to: 600; value: App.autoSwitchCooldown; onValueModified: App.setAutoSwitchCooldown(value) }
                }
            }
        }
        Card {
            Layout.fillWidth: true
            visible: page.showAdvancedSettings
            ColumnLayout {
                anchors.fill: parent
                spacing: 14
                Text { text: I18n.t("Прокси"); color: Theme.text; font.family: Theme.fontFamily; font.pixelSize: Theme.fontStrong; font.weight: Font.DemiBold }

                SettingRow {
                    glyph: "\uE8A6"; title: I18n.t("SOCKS-порт"); subtitle: I18n.t("Локальный порт SOCKS/mixed прокси (рекомендуется 10808)")
                    InfoIcon { tip: I18n.t("Локальный порт для SOCKS и mixed прокси. Порт 10818 зарезервирован под Discord Voice и будет сброшен на рекомендованный. Применяется с переподключением.") }
                    FluentSpin { from: 1025; to: 65535; value: App.localSocksPort; onValueModified: App.setLocalSocksPort(value) }
                }
                SettingRow {
                    glyph: "\uE8A6"; title: I18n.t("HTTP-порт"); subtitle: I18n.t("Локальный порт HTTP прокси (рекомендуется 10809)")
                    InfoIcon { tip: I18n.t("Локальный порт для HTTP прокси. Должен отличаться от SOCKS-порта; порт 10818 зарезервирован под Discord Voice. Применяется с переподключением.") }
                    FluentSpin { from: 1025; to: 65535; value: App.localHttpPort; onValueModified: App.setLocalHttpPort(value) }
                }
                SettingRow {
                    glyph: "\uE72E"; title: I18n.t("Авторизация прокси"); subtitle: I18n.t("Требовать логин и пароль для SOCKS/mixed и HTTP прокси")
                    InfoIcon { tip: I18n.t("По умолчанию выключено. После изменения активное подключение переподключится. Клиенты системного прокси должны поддерживать HTTP-аутентификацию.") }
                    Switch {
                        checked: App.proxyAuthEnabled
                        enabled: proxyAuthUsername.text.trim().length > 0 && proxyAuthPassword.text.length > 0
                        onToggled: App.setProxyAuthEnabled(checked)
                    }
                }
                SettingRow {
                    glyph: "\uE77B"; title: I18n.t("Логин прокси"); subtitle: I18n.t("Имя пользователя для локального прокси")
                    StyledField {
                        id: proxyAuthUsername
                        Layout.preferredWidth: 240
                        text: App.proxyAuthUsername
                        maximumLength: 256
                        placeholderText: I18n.t("Логин")
                        onEditingFinished: App.setProxyAuthCredentials(text, proxyAuthPassword.text)
                    }
                }
                SettingRow {
                    glyph: "\uE8D7"; title: I18n.t("Пароль прокси"); subtitle: I18n.t("Пароль не показывается в интерфейсе")
                    StyledField {
                        id: proxyAuthPassword
                        Layout.preferredWidth: 240
                        text: App.proxyAuthPassword
                        maximumLength: 256
                        echoMode: TextInput.Password
                        placeholderText: I18n.t("Пароль")
                        onEditingFinished: App.setProxyAuthCredentials(proxyAuthUsername.text, text)
                    }
                }
                SettingRow {
                    glyph: "\uE774"; title: I18n.t("Разрешить подключения из локальной сети"); subtitle: I18n.t("Открыть SOCKS/HTTP порты для других устройств вашей сети")
                    InfoIcon { tip: I18n.t("Другие устройства вашей сети смогут использовать этот ПК как прокси (адрес — IP этого ПК и указанные выше порты). Работает в режиме прокси. Windows может запросить разрешение брандмауэра.") }
                    Switch { checked: App.proxyAllowLan; onToggled: App.setProxyAllowLan(checked) }
                }
                SettingRow {
                    glyph: "\uE895"; title: I18n.t("Sniffing только для маршрутизации"); subtitle: I18n.t("Не подменять адрес назначения доменом из sniffing (рекомендуется: выключено)")
                    InfoIcon { tip: I18n.t("Домен из sniffing используется только для правил маршрутизации, а соединение идёт на исходный IP. Может помочь, если отдельные приложения некорректно работают с подменой адреса.") }
                    Switch { checked: App.sniffRouteOnly; onToggled: App.setSniffRouteOnly(checked) }
                }
            }
        }
        Card {
            Layout.fillWidth: true
            visible: page.showAdvancedSettings
            enabled: !App.limitedMode
            opacity: enabled ? 1.0 : 0.5
            ColumnLayout {
                anchors.fill: parent
                spacing: 14
                Text { text: I18n.t("TUN"); color: Theme.text; font.family: Theme.fontFamily; font.pixelSize: Theme.fontStrong; font.weight: Font.DemiBold }

                SettingRow {
                    glyph: "\uE72E"; title: I18n.t("Strict Route"); subtitle: I18n.t("Жёсткая маршрутизация: блокировать любой трафик мимо TUN (рекомендуется: выключено)")
                    InfoIcon { tip: I18n.t("Защищает от утечек, но ломает голосовые звонки Discord (ICE fallback) и инструменты на WinDivert. Применяется при следующем включении TUN.") }
                    Switch { checked: App.tunStrictRoute; onToggled: App.setTunStrictRoute(checked) }
                }
                SettingRow {
                    glyph: "\uE968"; title: I18n.t("Сетевой стек TUN"); subtitle: I18n.t("mixed — рекомендуется")
                    InfoIcon { tip: I18n.t("system — быстрее, gvisor — совместимее, mixed — system для TCP и gVisor для UDP.") }
                    StyledCombo {
                        model: ["mixed", "system", "gvisor"]
                        currentIndex: Math.max(0, ["mixed", "system", "gvisor"].indexOf(App.tunStack))
                        onActivated: App.setTunStack(["mixed", "system", "gvisor"][currentIndex])
                    }
                }
                SettingRow {
                    glyph: "\uE9D9"; title: I18n.t("MTU"); subtitle: I18n.t("Размер пакета TUN-адаптера (рекомендуется 9000)")
                    FluentSpin { from: 1280; to: 65535; value: App.tunMtu; onValueModified: App.setTunMtu(value) }
                }
                SettingRow {
                    glyph: "\uE72C"; title: I18n.t("Блокировать QUIC/HTTP3 в TUN"); subtitle: I18n.t("Браузеры переходят на HTTP/2 через прокси (рекомендуется: включено)")
                    InfoIcon { tip: I18n.t("QUIC/HTTP3 из TUN отклоняется, чтобы браузеры использовали TCP HTTP/2 — так стабильнее через прокси. Отключайте, только если нужен HTTP/3. Применяется при следующем включении TUN.") }
                    Switch { checked: App.tunBlockQuic; onToggled: App.setTunBlockQuic(checked) }
                }
                SettingRow {
                    glyph: "\uE774"; title: I18n.t("Endpoint-Independent NAT"); subtitle: I18n.t("Full-cone NAT для игр и P2P (рекомендуется: выключено)")
                    InfoIcon { tip: I18n.t("Улучшает совместимость с играми и P2P-приложениями, но потребляет больше памяти. Работает со стеками gvisor и mixed. Применяется при следующем включении TUN.") }
                    Switch { checked: App.tunEndpointIndependentNat; onToggled: App.setTunEndpointIndependentNat(checked) }
                }
            }
        }
                Item { Layout.fillHeight: true; Layout.preferredHeight: 1 }
            }
        }

        FluentScroll {
            roundedClip: false
            ColumnLayout {
                width: parent.width
                spacing: Theme.spacingLarge
        Card {
            Layout.fillWidth: true
            ColumnLayout {
                anchors.fill: parent
                spacing: 14
                Text { text: I18n.t("Запуск"); color: Theme.text; font.family: Theme.fontFamily; font.pixelSize: Theme.fontStrong; font.weight: Font.DemiBold }

                SettingRow {
                    glyph: "\uE7E8"; title: I18n.t("Запускать при входе"); subtitle: I18n.t("Автозапуск вместе с Windows")
                    Switch { checked: App.launchOnStartup; onToggled: App.setLaunchOnStartup(checked) }
                }
                SettingRow {
                    enabled: App.launchOnStartup
                    opacity: enabled ? 1.0 : 0.55
                    glyph: "\uE7E8"; title: I18n.t("Запускать автозапуск в трей"); subtitle: I18n.t("При входе в Windows не показывать окно, только иконку в трее")
                    Switch { checked: App.launchInTrayOnStartup; onToggled: App.setLaunchInTrayOnStartup(checked) }
                }
                SettingRow {
                    glyph: "\uE72E"; title: I18n.t("Всегда запускать от администратора"); subtitle: I18n.t("При каждом запуске Windows будет запрашивать права администратора")
                    Switch { checked: App.alwaysRunAsAdmin; onToggled: App.setAlwaysRunAsAdmin(checked) }
                }
                SettingRow {
                    glyph: "\uE768"; title: I18n.t("Автоподключение после запуска"); subtitle: I18n.t("Подключаться к последнему использованному серверу при старте")
                    Switch { checked: App.autoConnectLast; onToggled: App.setAutoConnectLast(checked) }
                }
                SettingRow {
                    glyph: "\uE72E"; title: I18n.t("Проверка VPN"); subtitle: I18n.t("Не запускать Lumen при работающем другом VPN или прокси")
                    Switch { checked: App.blockVpnConflicts; onToggled: App.setBlockVpnConflicts(checked) }
                }
                SettingRow {
                    glyph: "\uE896"; title: I18n.t("Автоподключение при импорте"); subtitle: I18n.t("Сразу подключаться к импортированному серверу")
                    Switch { checked: App.autoConnectOnImport; onToggled: App.setAutoConnectOnImport(checked) }
                }
                SettingRow {
                    visible: page.showAdvancedSettings
                    glyph: "\uE945"; title: I18n.t("Автозапуск Zapret"); subtitle: I18n.t("Запускать Zapret при старте приложения")
                    Switch { checked: App.zapretAutostart; onToggled: App.setZapretAutostart(checked) }
                }
            }
        }
        Card {
            Layout.fillWidth: true
            visible: page.showAdvancedSettings
            ColumnLayout {
                anchors.fill: parent
                spacing: 14
                Text { text: I18n.t("Тестирование серверов"); color: Theme.text; font.family: Theme.fontFamily; font.pixelSize: Theme.fontStrong; font.weight: Font.DemiBold }

                SettingRow {
                    glyph: "\uE724"; title: I18n.t("Способ измерения ping"); subtitle: I18n.t("TCP ping быстрее всего; ICMP — системный ping; реальная задержка — HTTP через сервер")
                    StyledCombo {
                        model: [I18n.t("TCP ping (быстро)"), I18n.t("ICMP (системный)"), I18n.t("HTTP GET"), I18n.t("Реальная задержка (HTTP)")]
                        readonly property var keys: ["tcping", "icmp", "http", "real"]
                        currentIndex: Math.max(0, keys.indexOf(App.pingMethod))
                        onActivated: App.setPingMethod(keys[currentIndex])
                    }
                }
                SettingRow {
                    glyph: "\uEC4A"; title: I18n.t("URL теста скорости"); subtitle: I18n.t("Пусто — стандартный (cachefly 50MB)")
                    StyledField {
                        id: speedUrlField
                        Layout.preferredWidth: 300
                        text: App.speedTestUrl
                        placeholderText: "https://cachefly.cachefly.net/50mb.test"
                        onEditingFinished: App.setSpeedTestUrl(text)
                    }
                    Button {
                        id: speedPresetBtn
                        implicitHeight: Theme.controlHeight
                        implicitWidth: 36
                        hoverEnabled: true
                        text: "\uE70D"
                        font.family: "Segoe Fluent Icons"; font.pixelSize: 12
                        background: Rectangle {
                            radius: Theme.radiusSmall
                            color: speedPresetBtn.down ? Theme.controlFillPressed
                                   : (speedPresetBtn.hovered ? Theme.controlFillHover : Theme.controlFill)
                            border.width: 1; border.color: Theme.borderSolid
                        }
                        contentItem: Text {
                            text: speedPresetBtn.text; font: speedPresetBtn.font
                            color: Theme.textMuted
                            horizontalAlignment: Text.AlignHCenter; verticalAlignment: Text.AlignVCenter
                        }
                        onClicked: speedPresetMenu.visible ? speedPresetMenu.close() : speedPresetMenu.open()
                        function pick(u) { App.setSpeedTestUrl(u); speedUrlField.text = u; }
                        Popup {
                            id: speedPresetMenu
                            y: speedPresetBtn.height + 4
                            x: speedPresetBtn.width - width
                            width: 230
                            padding: 4
                            modal: false
                            parent: speedPresetBtn
                            closePolicy: Popup.CloseOnEscape | Popup.CloseOnPressOutsideParent
                            readonly property var presets: [
                                { label: "Cachefly 100 MB",  url: "https://cachefly.cachefly.net/100mb.test" },
                                { label: "Cachefly 50 MB",   url: "https://cachefly.cachefly.net/50mb.test" },
                                { label: "Cachefly 10 MB",   url: "https://cachefly.cachefly.net/10mb.test" },
                                { label: "Cachefly 1 MB",    url: "https://cachefly.cachefly.net/1mb.test" },
                                { label: "Cloudflare 100 MB", url: "https://speed.cloudflare.com/__down?bytes=104857600" },
                                { label: "Cloudflare 50 MB",  url: "https://speed.cloudflare.com/__down?bytes=52428800" },
                                { label: "Cloudflare 10 MB",  url: "https://speed.cloudflare.com/__down?bytes=10485760" }
                            ]
                            background: Rectangle {
                                radius: 8
                                color: Theme.flyout
                                border.width: 1
                                border.color: Theme.flyoutBorder
                            }
                            contentItem: Column {
                                spacing: 0
                                Repeater {
                                    model: speedPresetMenu.presets
                                    delegate: ItemDelegate {
                                        id: presetItem
                                        width: speedPresetMenu.availableWidth
                                        height: 34
                                        padding: 0
                                        hoverEnabled: true
                                        contentItem: Text {
                                            leftPadding: 12
                                            rightPadding: 12
                                            text: modelData.label
                                            color: Theme.text
                                            font.family: Theme.fontFamily
                                            font.pixelSize: Theme.fontNormal
                                            verticalAlignment: Text.AlignVCenter
                                            elide: Text.ElideRight
                                        }
                                        background: Rectangle {
                                            anchors.fill: parent
                                            anchors.margins: 3
                                            radius: Theme.radiusSmall
                                            color: presetItem.hovered ? Theme.cardHover : "transparent"
                                            Rectangle {
                                                visible: App.speedTestUrl === modelData.url
                                                width: 3
                                                radius: 1.5
                                                height: parent.height * 0.5
                                                anchors.left: parent.left
                                                anchors.leftMargin: 1
                                                anchors.verticalCenter: parent.verticalCenter
                                                color: Theme.accent
                                            }
                                        }
                                        onClicked: { speedPresetBtn.pick(modelData.url); speedPresetMenu.close() }
                                    }
                                }
                            }
                            enter: Transition {
                                NumberAnimation { property: "opacity"; from: 0.0; to: 1.0; duration: 90 }
                            }
                        }
                    }
                }
                SettingRow {
                    glyph: "\uE8C9"; title: I18n.t("Параллельных проверок"); subtitle: I18n.t("Сколько серверов тестировать одновременно (0 — авто)")
                    FluentSpin { from: 0; to: 32; value: App.speedTestConcurrency; onValueModified: App.setSpeedTestConcurrency(value) }
                }
            }
        }
                Item { Layout.fillHeight: true; Layout.preferredHeight: 1 }
            }
        }

        FluentScroll {
            roundedClip: false
            ColumnLayout {
                width: parent.width
                spacing: Theme.spacingLarge
        Card {
            Layout.fillWidth: true
            ColumnLayout {
                anchors.fill: parent
                spacing: 14
                Text { text: I18n.t("Обновления"); color: Theme.text; font.family: Theme.fontFamily; font.pixelSize: Theme.fontStrong; font.weight: Font.DemiBold }

                SettingRow {
                    glyph: "\uE777"; title: I18n.t("Проверять обновления"); subtitle: I18n.t("Автоматически проверять наличие обновлений")
                    Switch { checked: App.checkUpdates; onToggled: App.setCheckUpdates(checked) }
                }

                SettingRow {
                    glyph: "\uE72C"; title: I18n.t("Проверять обновления ядра и geoip/geosite"); subtitle: I18n.t("При запуске проверять обновления и уведомлять")
                    Switch { checked: App.resourceUpdateCheck; onToggled: App.setResourceUpdateCheck(checked) }
                }

                SettingRow {
                    glyph: "\uE895"; title: I18n.t("Автообновление приложения"); subtitle: I18n.t("Автоматически скачивать и устанавливать новые версии")
                    Switch { checked: App.appAutoUpdate; onToggled: App.setAppAutoUpdate(checked) }
                }
            }
        }
                Item { Layout.fillHeight: true; Layout.preferredHeight: 1 }
            }
        }

        FluentScroll {
            roundedClip: false
            ColumnLayout {
                width: parent.width
                spacing: Theme.spacingLarge
        Card {
            Layout.fillWidth: true
            ColumnLayout {
                anchors.fill: parent
                spacing: 14
                Text { text: I18n.t("Данные"); color: Theme.text; font.family: Theme.fontFamily; font.pixelSize: Theme.fontStrong; font.weight: Font.DemiBold }

                SettingRow {
                    glyph: "\uE74E"; title: I18n.t("Резервная копия"); subtitle: I18n.t("Экспорт и импорт настроек и серверов")
                    AccentButton { kind: "ghost"; glyph: "\uE74E"; text: I18n.t("Экспорт"); onClicked: App.exportBackup() }
                    AccentButton { kind: "ghost"; glyph: "\uE8B7"; text: I18n.t("Импорт"); onClicked: App.importBackup() }
                }
                SettingRow {
                    glyph: "\uE9D9"; title: I18n.t("Телеметрия"); subtitle: I18n.t("Отправлять диагностические ошибки на сервер Lumen")
                    Switch { checked: App.diagnosticsUploadEnabled; onToggled: App.setDiagnosticsUpload(checked) }
                }
            }
        }
        Card {
            Layout.fillWidth: true
            visible: page.showAdvancedSettings
            ColumnLayout {
                anchors.fill: parent
                spacing: 14
                Text { text: I18n.t("Пути к ядрам"); color: Theme.text; font.family: Theme.fontFamily; font.pixelSize: Theme.fontStrong; font.weight: Font.DemiBold }

                SettingRow {
                    glyph: "\uE756"; title: I18n.t("Ядро Xray"); subtitle: I18n.t("Путь к исполняемому файлу xray")
                    StyledField { id: xrayField; Layout.preferredWidth: 240; text: App.xrayPath; placeholderText: "core\\xray.exe"; onEditingFinished: App.setXrayPath(text) }
                    AccentButton { kind: "ghost"; glyph: "\uE8B7"; text: I18n.t("Обзор"); onClicked: { var p = App.browseXrayPath(); if (p) xrayField.text = p } }
                }
                SettingRow {
                    glyph: "\uE756"; title: I18n.t("Ядро sing-box-extended"); subtitle: I18n.t("Путь к исполняемому файлу sing-box-extended")
                    StyledField { id: sbField; Layout.preferredWidth: 240; text: App.singboxPath; placeholderText: "core\\sing-box.exe"; onEditingFinished: App.setSingboxPath(text) }
                    AccentButton { kind: "ghost"; glyph: "\uE8B7"; text: I18n.t("Обзор"); onClicked: { var p = App.browseSingboxPath(); if (p) sbField.text = p } }
                }
            }
        }
        Card {
            Layout.fillWidth: true
            ColumnLayout {
                anchors.fill: parent
                spacing: 14
                SettingRow {
                    glyph: "\uE777"; title: I18n.t("Сброс настроек"); subtitle: I18n.t("Вернуть настройки приложения и маршрутизации по умолчанию. Серверы и подписки останутся.")
                    AccentButton {
                        kind: "danger"
                        glyph: "\uE777"
                        text: I18n.t("Сбросить настройки")
                        onClicked: resetSettingsDialog.open()
                    }
                }
            }
        }
        Text {
            Layout.topMargin: 4
            text: App.appName + " · v" + App.appVersion
            color: Theme.textFaint
            font.family: Theme.fontFamily; font.pixelSize: Theme.fontSmall
        }
                Item { Layout.fillHeight: true; Layout.preferredHeight: 1 }
            }
        }
        }
    }
}
