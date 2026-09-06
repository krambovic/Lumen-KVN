import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import QtQuick.Window
import QtQuick.Effects
import App 1.0
import "."

// Servers tab.
Item {
    id: page

    // ── selection state ──────────────────────────
    property var sel: ({})        // nodeId -> true
    property int selCount: 0
    property int selRev: 0        // bumped on every selection change so delegates re-evaluate
    property int anchorRow: -1
    property int menuRow: -1
    property bool compact: App.compactMode
    property bool selectionDragging: false
    property real selectionPointerX: -1
    property real selectionPointerY: -1
    property int hoverRow: -1
    property real savedListContentY: 0

    // ── filtering / sorting state ───────────────────
    property string filterText: ""
    property string filterGroup: App.nodeFilterGroup   // "" = all groups
    property string sortKey: App.nodeSortKey
    property bool sortAsc: App.nodeSortAscending

    readonly property var groupModel: [I18n.t("Все группы")].concat(App.groupOptions)
    readonly property var sortLabels: [I18n.t("Вручную"), I18n.t("Имя"), I18n.t("Группа"), I18n.t("Тип"), I18n.t("Транспорт"), I18n.t("Пинг"), I18n.t("Скорость"), I18n.t("Последнее использование")]
    readonly property var sortKeys: ["manual", "name", "group", "scheme", "transport", "ping", "speed", "last"]
    readonly property bool hasSubscriptionMeta: page.subscriptionMeta(page.selectedSub()) !== null

    // ── sizing ───────────────────────────────
    // Closer to the original compact rows (was 36/44).
    readonly property int rowH: compact ? 30 : 34
    readonly property int cellFont: 13

    // Columns start in automatic mode. The first divider drag freezes the
    // current layout, after which every boundary can be adjusted independently.
    readonly property var savedTableLayout: App.nodeTableLayout || ({})
    property bool manualColumnWidths: savedTableLayout.manual === true
    property real manualColName: savedTableLayout.name !== undefined ? Number(savedTableLayout.name) : 160
    property real manualColType: savedTableLayout.type !== undefined ? Number(savedTableLayout.type) : 78
    property real manualColTransport: savedTableLayout.transport !== undefined ? Number(savedTableLayout.transport) : 92
    property real manualColAddr: savedTableLayout.address !== undefined ? Number(savedTableLayout.address) : 150
    property real manualColPort: savedTableLayout.port !== undefined ? Number(savedTableLayout.port) : 60
    property real manualColGroup: savedTableLayout.group !== undefined ? Number(savedTableLayout.group) : 120
    property real manualColPing: savedTableLayout.ping !== undefined ? Number(savedTableLayout.ping) : 80
    property real manualColSpeed: savedTableLayout.speed !== undefined ? Number(savedTableLayout.speed) : 108
    property real manualColStatus: savedTableLayout.status !== undefined ? Number(savedTableLayout.status) : 72
    property real manualColLast: savedTableLayout.last !== undefined ? Number(savedTableLayout.last) : 140

    readonly property int colType: Math.round(manualColType)
    readonly property int colTransport: Math.round(manualColTransport)
    readonly property int colPort: Math.round(manualColPort)
    readonly property int colGroup: Math.round(manualColGroup)
    readonly property int colPing: Math.round(manualColPing)
    readonly property int colSpeed: Math.round(manualColSpeed)
    readonly property int colStatus: Math.round(manualColStatus)
    readonly property int colLast: Math.round(manualColLast)
    readonly property int leftPad: 12
    readonly property int trailPad: 12

    // Flexible columns (minimums).
    readonly property int colNameMin: 160
    readonly property int colAddrMin: 150

    readonly property int fixedCols: colType + colTransport + colPort + colGroup
        + colPing + colSpeed + colStatus + colLast
    readonly property int minTableWidth: fixedCols + colNameMin + colAddrMin + leftPad + trailPad

    // Fill the viewport when wider than the minimum; scroll when narrower.
    readonly property int autoTableWidth: Math.max(minTableWidth, Math.floor(hflick.width))
    readonly property int flexExtra: Math.max(0, autoTableWidth - minTableWidth)
    readonly property int colName: Math.round(manualColumnWidths ? manualColName : colNameMin + Math.floor(flexExtra / 2))
    readonly property int colAddr: Math.round(manualColumnWidths ? manualColAddr : colAddrMin + (flexExtra - Math.floor(flexExtra / 2)))
    readonly property int tableWidth: manualColumnWidths
        ? leftPad + trailPad + colName + colType + colTransport + colAddr + colPort
          + colGroup + colPing + colSpeed + colStatus + colLast
        : autoTableWidth

    function freezeColumnWidths() {
        if (manualColumnWidths)
            return;
        manualColName = colName;
        manualColType = colType;
        manualColTransport = colTransport;
        manualColAddr = colAddr;
        manualColPort = colPort;
        manualColGroup = colGroup;
        manualColPing = colPing;
        manualColSpeed = colSpeed;
        manualColStatus = colStatus;
        manualColLast = colLast;
        manualColumnWidths = true;
    }

    function resizeColumn(index, width) {
        freezeColumnWidths();
        var value = Math.max(index === 0 || index === 3 ? 90 : 48, Math.round(width));
        if (index === 0) manualColName = value;
        else if (index === 1) manualColType = value;
        else if (index === 2) manualColTransport = value;
        else if (index === 3) manualColAddr = value;
        else if (index === 4) manualColPort = value;
        else if (index === 5) manualColGroup = value;
        else if (index === 6) manualColPing = value;
        else if (index === 7) manualColSpeed = value;
        else if (index === 8) manualColStatus = value;
        else if (index === 9) manualColLast = value;
        persistTableLayout();
    }

    function persistTableLayout() {
        App.setNodeTableLayout({
            "manual": manualColumnWidths,
            "name": manualColName,
            "type": manualColType,
            "transport": manualColTransport,
            "address": manualColAddr,
            "port": manualColPort,
            "group": manualColGroup,
            "ping": manualColPing,
            "speed": manualColSpeed,
            "status": manualColStatus,
            "last": manualColLast
        });
    }

    // ── selection helpers ─────────────────────
    function _commit(obj, count) {
        sel = obj;
        selCount = count;
        selRev++;
    }
    function isSelected(id) { return sel[id] === true; }
    function selectedIds() { return Object.keys(sel); }
    function firstSelected() { var k = Object.keys(sel); return k.length ? k[0] : ""; }
    function testTargets() { return page.selCount > 0 ? page.selectedIds() : []; }
    function selectedSub() {
        var subs = App.subscriptions;
        if (!subs || subs.length === 0) return null;
        var i = subCombo.currentIndex - 1;
        if (i < 0 || i >= subs.length) return null;
        return subs[i];
    }
    // Подписка, выбранная в диалоге свойств (может отличаться от subCombo).
    function infoSub() {
        var subs = App.subscriptions;
        if (!subs || subs.length === 0) return null;
        var i = infoCombo.currentIndex;
        if (i < 0 || i >= subs.length) return null;
        return subs[i];
    }
    // Человекочитаемый размер: байты → КБ/МБ/ГБ/ТБ.
    function fmtBytes(n) {
        var b = Number(n);
        if (!isFinite(b) || b < 0) return String(n);
        var u = [I18n.t("Б"), I18n.t("КБ"), I18n.t("МБ"), I18n.t("ГБ"), I18n.t("ТБ"), I18n.t("ПБ")];
        var i = 0;
        while (b >= 1024 && i < u.length - 1) { b /= 1024; i++; }
        return (i === 0 ? String(Math.round(b)) : b.toFixed(2)) + " " + u[i];
    }
    // Время → локальный часовой пояс компьютера (из unix-секунд или ISO/UTC).
    function fmtTime(v) {
        if (v === undefined || v === null || v === "") return "";
        var d;
        if (typeof v === "number") d = new Date(v * 1000);
        else {
            var s = String(v).trim();
            if (/^\d{9,}$/.test(s)) d = new Date(parseInt(s, 10) * 1000);
            else d = new Date(s);
        }
        if (isNaN(d.getTime())) return String(v);
        return Qt.formatDateTime(d, "dd.MM.yyyy HH:mm");
    }
    // Строит список [метка, значение] из данных подписки.
    function infoRows(sub) {
        var rows = [];
        if (!sub) return rows;
        rows.push([I18n.t("Группа"), (sub.name && sub.name.length ? sub.name : "—")]);
        if (sub.url) rows.push(["URL", sub.url]);
        if (sub.updated_at) rows.push([I18n.t("Обновлено"), fmtTime(sub.updated_at)]);
        rows.push([I18n.t("Серверов"), String(sub.node_count || 0)]);
        var ui = sub.userinfo;
        if (ui && typeof ui === "object") {
            if (ui.username) rows.push([I18n.t("Пользователь"), String(ui.username)]);
            if (ui.userStatus) rows.push([I18n.t("Статус"), String(ui.userStatus)]);
            else if (ui.isActive !== undefined) rows.push([I18n.t("Статус"), ui.isActive ? I18n.t("Активна") : I18n.t("Неактивна")]);
            if (ui.daysLeft !== undefined) rows.push([I18n.t("Осталось дней"), String(ui.daysLeft)]);
            var usedB = (ui.trafficUsedBytes !== undefined) ? Number(ui.trafficUsedBytes)
                      : ((ui.total !== undefined) ? Number((ui.upload || 0) + (ui.download || 0)) : undefined);
            var limitB = (ui.trafficLimitBytes !== undefined) ? Number(ui.trafficLimitBytes)
                       : ((ui.total !== undefined) ? Number(ui.total) : undefined);
            if (usedB !== undefined || limitB !== undefined) {
                if (limitB !== undefined && isFinite(limitB) && limitB <= 0) {
                    rows.push([I18n.t("Трафик"), I18n.t("Безлимитный трафик")]);
                } else {
                    var uStr = (usedB !== undefined) ? fmtBytes(usedB)
                             : (ui.trafficUsed !== undefined ? String(ui.trafficUsed) : "?");
                    var lStr = (limitB !== undefined) ? fmtBytes(limitB)
                             : (ui.trafficLimit !== undefined ? String(ui.trafficLimit) : "∞");
                    rows.push([I18n.t("Трафик"), uStr + " / " + lStr]);
                }
            } else if (ui.trafficUsed !== undefined || ui.trafficLimit !== undefined) {
                var used = (ui.trafficUsed !== undefined ? String(ui.trafficUsed) : "?");
                var limit = (ui.trafficLimit !== undefined ? String(ui.trafficLimit) : "∞");
                rows.push([I18n.t("Трафик"), used + " / " + limit]);
            }
            if (ui.expiresAt) rows.push([I18n.t("Истекает"), fmtTime(ui.expiresAt)]);
            else if (ui.expire) rows.push([I18n.t("Истекает"), fmtTime(ui.expire)]);
            if (ui.trafficLimitStrategy) rows.push([I18n.t("Сброс трафика"), String(ui.trafficLimitStrategy)]);
            if (ui.profileTitle) rows.push([I18n.t("Название профиля"), String(ui.profileTitle)]);
            if (ui.providerId) rows.push(["Provider ID", String(ui.providerId)]);
            if (ui.announcement) rows.push([I18n.t("Объявление"), String(ui.announcement)]);
            if (ui.profileUpdateInterval) rows.push([I18n.t("Интервал обновления"), String(ui.profileUpdateInterval)]);
            var premium = ui.premiumFeatures;
            if (premium && typeof premium === "object") {
                var keys = Object.keys(premium).sort();
                for (var p = 0; p < keys.length; p++) {
                    rows.push([page.premiumFeatureLabel(keys[p]), String(premium[keys[p]])]);
                }
            }
        }
        return rows;
    }
    function premiumFeatureLabel(key) {
        var labels = {
            "new-url": I18n.t("Новый URL подписки"),
            "new-domain": I18n.t("Новый домен подписки"),
            "subscription-always-hwid-enable": I18n.t("Обязательный HWID"),
            "notification-subs-expire": I18n.t("Уведомлять об окончании"),
            "hide-settings": I18n.t("Скрыть настройки серверов"),
            "server-address-resolve-enable": I18n.t("Резолвинг адресов серверов"),
            "server-address-resolve-dns-domain": I18n.t("Домен DNS для резолвинга"),
            "server-address-resolve-dns-ip": I18n.t("IP DNS для резолвинга"),
            "subscription-autoconnect": I18n.t("Автоподключение"),
            "subscription-autoconnect-type": I18n.t("Режим автоподключения"),
            "subscription-ping-onopen-enabled": I18n.t("Автопинг при открытии"),
            "subscription-auto-update-enable": I18n.t("Автообновление подписок"),
            "fragmentation-enable": I18n.t("Фрагментация"),
            "fragmentation-packets": I18n.t("Пакеты фрагментации"),
            "fragmentation-length": I18n.t("Размер фрагментации"),
            "fragmentation-interval": I18n.t("Интервал фрагментации"),
            "ping-type": I18n.t("Тип пинга"),
            "check-url-via-proxy": I18n.t("URL проверки через прокси"),
            "change-user-agent": "User-Agent",
            "app-auto-start": I18n.t("Автозапуск приложения"),
            "subscription-auto-update-open-enable": I18n.t("Обновлять подписки при запуске"),
            "per-app-proxy-mode": I18n.t("Режим прокси приложений"),
            "per-app-proxy-list": I18n.t("Список приложений"),
            "sniffing-enable": "Sniffing",
            "subscriptions-collapse": I18n.t("Сворачивание подписки"),
            "ping-result": I18n.t("Отображение пинга"),
            "mux-enable": "Mux",
            "mux-tcp-connections": "Mux TCP",
            "mux-xudp-connections": "Mux XUDP",
            "mux-quic": "Mux QUIC",
            "exclude-routes": I18n.t("Исключённые маршруты")
        };
        return labels[key] || key;
    }
    function subscriptionMeta(sub) {
        if (!sub || !sub.userinfo || typeof sub.userinfo !== "object") return null;
        var ui = sub.userinfo;
        var premium = ui.premiumFeatures && typeof ui.premiumFeatures === "object"
            && Object.keys(ui.premiumFeatures).length > 0;
        if (!ui.profileTitle && !ui.supportUrl && !ui.profileUrl && !ui.telegramUrl
                && !ui.announcement && !ui.announcementUrl && !ui.providerId && !premium) return null;
        return ui;
    }
    function menuNodeId() { return App.nodeIdAt(page.menuRow); }

    function selectOnly(rowIndex) {
        var id = App.nodeIdAt(rowIndex);
        if (!id) return;
        var o = {}; o[id] = true;
        anchorRow = rowIndex;
        _commit(o, 1);
    }
    function toggle(rowIndex) {
        var id = App.nodeIdAt(rowIndex);
        if (!id) return;
        var o = Object.assign({}, sel);
        if (o[id]) delete o[id]; else o[id] = true;
        anchorRow = rowIndex;
        _commit(o, Object.keys(o).length);
    }
    function selectRange(a, b) {
        if (a < 0) a = b;
        var lo = Math.min(a, b), hi = Math.max(a, b);
        var o = {};
        for (var r = lo; r <= hi; r++) {
            var id = App.nodeIdAt(r);
            if (id) o[id] = true;
        }
        _commit(o, Object.keys(o).length);
    }
    function clearSel() { anchorRow = -1; _commit({}, 0); }
    function rowAtSelectionPoint(x, y) {
        if (!listSelectionArea || !list || list.count <= 0) return -1;
        var px = Math.max(0, Math.min(list.width - 1, x));
        var py = Math.max(0, Math.min(list.height - 1, y));
        var pt = listSelectionArea.mapToItem(list.contentItem, px, py);
        return list.indexAt(pt.x, pt.y);
    }
    function updateDragSelection() {
        if (!selectionDragging) return;
        var r = rowAtSelectionPoint(selectionPointerX, selectionPointerY);
        if (r >= 0) selectRange(anchorRow, r);
    }
    function scrollDragSelection() {
        if (!selectionDragging || !listVbarTrack.scrollable) return;
        var edge = Math.max(28, rowH);
        var delta = 0;
        if (selectionPointerY < edge) {
            delta = -Math.ceil(((edge - selectionPointerY) / edge) * rowH);
        } else if (selectionPointerY > list.height - edge) {
            delta = Math.ceil(((selectionPointerY - (list.height - edge)) / edge) * rowH);
        }
        if (delta === 0) return;
        listScrollAnim.stop();
        list.contentY = Math.max(0, Math.min(listVbarTrack.maxY, list.contentY + delta));
        listVbarTrack.flash();
        updateDragSelection();
    }
    function stopSelectionDrag() {
        selectionDragging = false;
        hoverRow = -1;
    }
    function selectAll() {
        var o = {};
        for (var i = 0; i < list.count; i++) {
            var id = App.nodeIdAt(i);
            if (id) o[id] = true;
        }
        anchorRow = 0;
        _commit(o, Object.keys(o).length);
    }

    function applyFilters() {
        App.setNodeFilter(page.filterGroup, page.filterText);
    }

    function revealImportedNode(nodeId) {
        if (!nodeId) return;
        page.filterText = "";
        searchInput.text = "";
        page.applyFilters();
        Qt.callLater(function() {
            var row = App.nodeIndexById(nodeId);
            if (row < 0) {
                page.filterGroup = "";
                groupCombo.currentIndex = 0;
                page.applyFilters();
                row = App.nodeIndexById(nodeId);
            }
            if (row < 0) return;
            page.selectOnly(row);
            list.positionViewAtIndex(row, ListView.Center);
        });
    }
    function selectGroupByName(groupName) {
        Qt.callLater(function() {
            var idx = page.groupModel.indexOf(groupName);
            if (idx <= 0) return;
            groupCombo.currentIndex = idx;
            page.filterGroup = groupName;
            page.applyFilters();
        });
    }
    function selectSubscriptionByGroup(groupName) {
        Qt.callLater(function() {
            var subs = App.subscriptions || [];
            for (var i = 0; i < subs.length; i++) {
                var group = String(subs[i].group || subs[i].name || "Default");
                if (group === groupName) {
                    subCombo.currentIndex = i + 1;
                    App.setSelectedSubscriptionId(String(subs[i].id || ""));
                    return;
                }
            }
            subCombo.currentIndex = 0;
            App.setSelectedSubscriptionId("");
        });
    }

    function restoreSubscriptionSelection() {
        var wanted = String(App.selectedSubscriptionId || "");
        var subs = App.subscriptions || [];
        for (var i = 0; i < subs.length; i++) {
            if (String(subs[i].id || "") === wanted) {
                subCombo.currentIndex = i + 1;
                return;
            }
        }
        subCombo.currentIndex = 0;
        if (wanted.length)
            App.setSelectedSubscriptionId("");
    }

    function restoreServerViewState() {
        var groupIndex = page.groupModel.indexOf(page.filterGroup);
        if (groupIndex < 0) {
            page.filterGroup = "";
            groupIndex = 0;
        }
        groupCombo.currentIndex = groupIndex;
        var sortIndex = page.sortKeys.indexOf(page.sortKey);
        if (sortIndex < 0) {
            page.sortKey = "manual";
            sortIndex = 0;
        }
        sortCombo.currentIndex = sortIndex;
        page.applyFilters();
        App.setNodeSort(page.sortKey, page.sortAsc);
        page.restoreSubscriptionSelection();
    }

    Component.onCompleted: Qt.callLater(page.restoreServerViewState)

    function applySort(key) {
        if (!key) return;
        if (page.sortKey === key) {
            if (page.sortAsc) {
                page.sortAsc = false;          // asc -> desc
            } else {
                page.sortKey = "manual";       // desc -> off (manual order)
                page.sortAsc = true;
            }
        } else {
            page.sortKey = key;
            page.sortAsc = true;
        }
        var idx = page.sortKeys.indexOf(page.sortKey);
        if (idx >= 0)
            sortCombo.currentIndex = idx;
        App.setNodeSort(page.sortKey, page.sortAsc);
    }

    // ── reusable cell / header text ───────────────────
    component CellText: Text {
        property int w: 80
        width: w
        height: parent ? parent.height : 0
        leftPadding: 4
        verticalAlignment: Text.AlignVCenter
        elide: Text.ElideRight
        color: Theme.textMuted
        font.family: Theme.fontFamily
        font.pixelSize: page.cellFont
    }
    component HeaderLabel: Text {
        id: hdr
        property int w: 80
        property int columnIndex: -1
        property string sortKey: ""
        readonly property bool sortable: sortKey !== ""
        readonly property bool activeSort: sortable && page.sortKey === sortKey
        width: w
        height: parent ? parent.height : 0
        leftPadding: 4
        rightPadding: activeSort ? 16 : 0
        verticalAlignment: Text.AlignVCenter
        elide: Text.ElideRight
        color: activeSort ? Theme.text : Theme.textFaint
        font.family: Theme.fontFamily
        font.pixelSize: Theme.fontSmall
        font.bold: true

        // Sort-direction chevron, shown only on the active sort column.
        Text {
            visible: hdr.activeSort
            anchors.right: parent.right
            anchors.rightMargin: 4
            anchors.verticalCenter: parent.verticalCenter
            text: page.sortAsc ? "\uE74A" : "\uE74B"
            font.family: "Segoe Fluent Icons"
            font.pixelSize: 10
            color: Theme.textMuted
        }

        // Click a sortable header to sort by it; click again to flip direction.
        MouseArea {
            anchors.fill: parent
            anchors.rightMargin: 5
            enabled: hdr.sortable
            cursorShape: Qt.PointingHandCursor
            onClicked: page.applySort(hdr.sortKey)
        }

        MouseArea {
            id: columnResizeHandle
            z: 2
            width: 10
            anchors.top: parent.top
            anchors.bottom: parent.bottom
            anchors.right: parent.right
            acceptedButtons: Qt.LeftButton
            cursorShape: Qt.SplitHCursor
            property real pressedX: 0
            property real pressedWidth: 0
            onPressed: (mouse) => {
                var point = mapToItem(page, mouse.x, mouse.y);
                pressedX = point.x;
                pressedWidth = hdr.width;
                mouse.accepted = true;
            }
            onPositionChanged: (mouse) => {
                if (!pressed)
                    return;
                var point = mapToItem(page, mouse.x, mouse.y);
                page.resizeColumn(hdr.columnIndex, pressedWidth + point.x - pressedX);
            }
        }
    }
    component FilterCombo: FluentCombo {
        Layout.preferredHeight: Theme.controlHeight
    }

    ColumnLayout {
        anchors.fill: parent
        anchors.margins: Theme.spacing
        spacing: Theme.spacing

        // ── title ────────────────────────────────
        RowLayout {
            Layout.fillWidth: true
            Layout.preferredHeight: Theme.controlHeight
            spacing: Theme.spacing

            Text {
                text: I18n.t("Серверы")
                color: Theme.text
                font.family: Theme.fontFamily
                font.pixelSize: Theme.fontTitle
                font.bold: true
            }
            Text {
                visible: page.selCount > 0
                text: I18n.t("· выбрано: ") + page.selCount
                color: Theme.textMuted
                font.family: Theme.fontFamily
                font.pixelSize: Theme.fontNormal
                Layout.alignment: Qt.AlignVCenter
            }
            Item { Layout.fillWidth: true }
        }

        // Filters and search always occupy the same stable row.  Subscription
        // metadata must never move either side vertically.
        Item {
            id: serverFiltersRow
            Layout.fillWidth: true
            Layout.preferredHeight: Theme.controlHeight
            Layout.minimumHeight: Theme.controlHeight
            Layout.maximumHeight: Theme.controlHeight

            Row {
                id: filterFlow
                anchors.left: parent.left
                anchors.top: parent.top
                height: Theme.controlHeight
                spacing: 8

                FilterCombo {
                    id: groupCombo
                    width: 160
                    height: Theme.controlHeight
                    model: page.groupModel
                    onActivated: { page.filterGroup = (currentIndex <= 0 ? "" : currentText); page.applyFilters() }
                }
                FilterCombo {
                    id: sortCombo
                    width: 210
                    height: Theme.controlHeight
                    model: page.sortLabels
                    currentIndex: 0
                    onActivated: {
                        page.sortKey = page.sortKeys[currentIndex];
                        App.setNodeSort(page.sortKey, page.sortAsc);
                    }
                }
                AccentButton {
                    kind: "ghost"
                    iconOnly: true
                    glyph: page.sortAsc ? "\uE74A" : "\uE74B"
                    tip: page.sortAsc ? I18n.t("По возрастанию") : I18n.t("По убыванию")
                    onClicked: {
                        page.sortAsc = !page.sortAsc;
                        App.setNodeSort(page.sortKey, page.sortAsc);
                    }
                }
                AccentButton {
                    kind: "danger"
                    iconOnly: true
                    glyph: "\uE74D"
                    tip: I18n.t("Удалить выбранную группу")
                    enabled: page.filterGroup.length > 0 && page.filterGroup.toLowerCase() !== "default"
                    onClicked: {
                        deleteGroupDialog.groupName = page.filterGroup;
                        deleteGroupDialog.open();
                    }
                }
            }

            // Visible, filled search field with a search glyph.
            Rectangle {
                id: searchBox
                anchors.right: parent.right
                y: page.hasSubscriptionMeta ? -(Theme.controlHeight + 8) : 0
                width: Math.min(300, Math.max(220, page.width * 0.28))
                height: Theme.controlHeight
                radius: Theme.radiusSmall
                color: Theme.controlFill
                border.width: 1
                border.color: searchInput.activeFocus ? Theme.accent : Theme.borderSolid

                Text {
                    id: searchGlyph
                    anchors.left: parent.left
                    anchors.leftMargin: 10
                    anchors.verticalCenter: parent.verticalCenter
                    text: "\uE721"
                    font.family: "Segoe Fluent Icons"
                    font.pixelSize: 14
                    color: Theme.textFaint
                }
                FluentTextField {
                    id: searchInput
                    anchors.left: searchGlyph.right
                    anchors.leftMargin: 8
                    anchors.right: parent.right
                    anchors.rightMargin: 10
                    anchors.verticalCenter: parent.verticalCenter
                    background: null
                    verticalAlignment: TextInput.AlignVCenter
                    placeholderText: I18n.t("Поиск серверов…")
                    placeholderTextColor: Theme.textFaint
                    color: Theme.text
                    font.family: Theme.fontFamily
                    font.pixelSize: page.cellFont
                    onTextChanged: { page.filterText = text; page.applyFilters() }
                }

                Behavior on y {
                    NumberAnimation {
                        duration: Theme.animations ? 140 : 0
                        easing.type: Easing.OutCubic
                    }
                }
            }

            // Premium controls replace the search field's normal position.
            // They are an overlay and therefore cannot resize or move the
            // filters and action toolbars on the left.
            RowLayout {
                id: subMetaRow
                anchors.right: parent.right
                anchors.top: parent.top
                width: Math.min(620, page.width * 0.58)
                height: Theme.controlHeight
                spacing: 6
                visible: page.hasSubscriptionMeta

                Item { Layout.fillWidth: true }
                Text {
                    Layout.maximumWidth: Math.max(120, subMetaRow.width - Theme.controlHeight * 4 - 30)
                    Layout.preferredHeight: 20
                    text: {
                        var meta = page.subscriptionMeta(page.selectedSub());
                        if (!meta) return "";
                        var title = meta.profileTitle || "";
                        if (!title.length && meta.providerId) title = "Happ Premium";
                        return title.length ? title : I18n.t("Профиль подписки");
                    }
                    color: Theme.textMuted
                    font.family: Theme.fontFamily
                    font.pixelSize: Theme.fontSmall
                    elide: Text.ElideRight
                    horizontalAlignment: Text.AlignRight
                    verticalAlignment: Text.AlignVCenter
                }
                AccentButton {
                    Layout.preferredWidth: Theme.controlHeight
                    Layout.preferredHeight: Theme.controlHeight
                    visible: { var meta = page.subscriptionMeta(page.selectedSub()); return !!(meta && meta.announcementUrl); }
                    kind: "ghost"
                    iconOnly: true
                    glyph: "\uE7F4"
                    text: I18n.t("Объявление подписки")
                    onClicked: {
                        var meta = page.subscriptionMeta(page.selectedSub());
                        if (meta && meta.announcementUrl) App.openUrl(meta.announcementUrl);
                    }
                }
                AccentButton {
                    Layout.preferredWidth: Theme.controlHeight
                    Layout.preferredHeight: Theme.controlHeight
                    visible: { var meta = page.subscriptionMeta(page.selectedSub()); return !!(meta && meta.supportUrl); }
                    kind: "ghost"
                    iconOnly: true
                    glyph: "\uE8F2"
                    text: I18n.t("Поддержка подписки")
                    onClicked: {
                        var meta = page.subscriptionMeta(page.selectedSub());
                        if (meta && meta.supportUrl) App.openUrl(meta.supportUrl);
                    }
                }
                AccentButton {
                    Layout.preferredWidth: Theme.controlHeight
                    Layout.preferredHeight: Theme.controlHeight
                    visible: { var meta = page.subscriptionMeta(page.selectedSub()); return !!(meta && meta.telegramUrl); }
                    kind: "ghost"
                    iconOnly: true
                    glyph: "\uE8BD"
                    text: "Telegram"
                    onClicked: {
                        var meta = page.subscriptionMeta(page.selectedSub());
                        if (meta && meta.telegramUrl) App.openUrl(meta.telegramUrl);
                    }
                }
                AccentButton {
                    Layout.preferredWidth: Theme.controlHeight
                    Layout.preferredHeight: Theme.controlHeight
                    visible: { var meta = page.subscriptionMeta(page.selectedSub()); return !!(meta && meta.profileUrl); }
                    kind: "ghost"
                    iconOnly: true
                    glyph: "\uE774"
                    text: I18n.t("Страница подписки")
                    onClicked: {
                        var meta = page.subscriptionMeta(page.selectedSub());
                        if (meta && meta.profileUrl) App.openUrl(meta.profileUrl);
                    }
                }
            }
        }

        // ── subscription metadata: does not push server/search toolbars ─────
        RowLayout {
            visible: false
            Layout.preferredHeight: 0
            Layout.fillWidth: true
            spacing: 8

            Item { Layout.fillWidth: true }
            Text {
                Layout.maximumWidth: Math.max(220, page.width * 0.42)
                text: {
                    var meta = page.subscriptionMeta(page.selectedSub());
                    if (!meta) return "";
                    var title = meta.profileTitle || "";
                    return title.length ? title : I18n.t("Профиль подписки");
                }
                color: Theme.textMuted
                font.family: Theme.fontFamily
                font.pixelSize: Theme.fontSmall
                elide: Text.ElideRight
                horizontalAlignment: Text.AlignRight
                verticalAlignment: Text.AlignVCenter
            }
            AccentButton {
                visible: { var meta = page.subscriptionMeta(page.selectedSub()); return !!(meta && meta.supportUrl); }
                kind: "ghost"
                iconOnly: true
                glyph: "\uE8F2"
                text: I18n.t("Поддержка подписки")
                onClicked: {
                    var meta = page.subscriptionMeta(page.selectedSub());
                    if (meta && meta.supportUrl) App.openUrl(meta.supportUrl);
                }
            }
            AccentButton {
                visible: { var meta = page.subscriptionMeta(page.selectedSub()); return !!(meta && meta.profileUrl); }
                kind: "ghost"
                iconOnly: true
                glyph: "\uE774"
                text: I18n.t("Страница подписки")
                onClicked: {
                    var meta = page.subscriptionMeta(page.selectedSub());
                    if (meta && meta.profileUrl) App.openUrl(meta.profileUrl);
                }
            }
        }

        // ── action toolbar ───────────────────────
        RowLayout {
            Layout.fillWidth: true
            spacing: 12

            // Действия над серверами (слева, переносятся при нехватке места)
            Flow {
                Layout.fillWidth: true
                Layout.alignment: Qt.AlignBottom
                spacing: 8

                AccentButton { kind: "ghost";  iconOnly: true; glyph: "\uE8B5"; text: I18n.t("Импорт из буфера"); onClicked: App.importClipboard() }
                AccentButton { kind: "ghost";  iconOnly: true; glyph: "\uE8E5"; text: I18n.t("Импорт файла конфигурации"); onClicked: App.importNodeFile() }
                AccentButton { kind: "ghost";  iconOnly: true; glyph: "\uECC8"; text: I18n.t("Добавить сервер вручную"); onClicked: editDialog.openNew(page.filterGroup || "Default") }
                AccentButton { kind: "ghost";  iconOnly: true; glyph: "\uE710"; text: I18n.t("Создать группу"); onClicked: groupDialog.openNew() }
                AccentButton { kind: "ghost";  iconOnly: true; glyph: "\uE8B3"; text: I18n.t("Выбрать все"); onClicked: page.selectAll() }
                // Пинг — две кнопки как в оригинале (FIF.SEND / FIF.SYNC), способ из настроек
                AccentButton { kind: "accent"; iconOnly: true; glyph: "\uE724"; text: I18n.t("Пинг выбранных"); enabled: page.selCount > 0; onClicked: App.pingNodes(page.selectedIds()) }
                // Тест скорости — две кнопки (выбранные / все)
                AccentButton { kind: "accent"; iconOnly: true; glyph: "\uEC4A"; text: I18n.t("Тест скорости выбранных"); enabled: page.selCount > 0; onClicked: App.speedTestNodes(page.selectedIds()) }
                AccentButton { kind: "ghost";  iconOnly: true; glyph: "\uE769"; text: I18n.t("Остановить тест"); onClicked: App.cancelSpeedTest() }
                AccentButton { kind: "ghost";  iconOnly: true; glyph: "\uE943"; text: I18n.t("Экспорт outbound JSON"); enabled: page.selCount === 1; onClicked: App.saveOutboundJson(page.firstSelected()) }
                AccentButton { kind: "ghost";  iconOnly: true; glyph: "\uE792"; text: I18n.t("Экспорт runtime JSON"); enabled: page.selCount === 1; onClicked: App.saveRuntimeJson(page.firstSelected()) }
                AccentButton { kind: "ghost";  iconOnly: true; glyph: "\uE72D"; text: I18n.t("Экспорт выбранных (ссылки)"); enabled: page.selCount > 0; onClicked: App.exportNodeLinks(page.selectedIds()) }
                AccentButton { kind: "ghost";  iconOnly: true; glyph: "\uE8C8"; text: I18n.t("Экспорт всех (ссылки)"); onClicked: App.exportNodeLinks([]) }
                AccentButton { kind: "ghost";  iconOnly: true; glyph: "\uED14"; text: I18n.t("QR выбранного"); enabled: page.selCount === 1; onClicked: App.showNodeQr(page.firstSelected()) }
                AccentButton { kind: "danger"; iconOnly: true; glyph: "\uE74D"; text: I18n.t("Удалить выбранные"); enabled: page.selCount > 0; onClicked: App.deleteNodes(page.selectedIds()) }
            }

            // Подписки (справа)
            Item {
                id: subToolbar
                Layout.alignment: Qt.AlignBottom | Qt.AlignRight
                Layout.maximumWidth: Math.min(620, page.width * 0.58)
                Layout.preferredWidth: Math.min(620, page.width * 0.58)
                Layout.preferredHeight: Theme.controlHeight
                Layout.minimumHeight: Theme.controlHeight
                Layout.maximumHeight: Theme.controlHeight

                RowLayout {
                    id: subControls
                    anchors.right: parent.right
                    anchors.bottom: parent.bottom
                    width: parent.width
                    height: Theme.controlHeight
                    spacing: 8

                    Item { Layout.fillWidth: true }
                    AccentButton { kind: "ghost"; iconOnly: true; glyph: "\uE946"; text: I18n.t("Свойства подписки"); enabled: page.selectedSub() !== null; onClicked: infoDialog.openInfo() }
                    AccentButton { kind: "accent"; iconOnly: true; glyph: "\uE8B5"; text: I18n.t("Импорт подписки"); onClicked: subDialog.openNew() }
                    FilterCombo {
                        id: subCombo
                        Layout.preferredWidth: Math.round(Math.max(150, Math.min(260, page.width * 0.20)))
                        model: [I18n.t("Нет подписки")].concat(
                            App.subscriptions.map(function(s) { return (s.name && s.name.length ? s.name : s.url) + " (" + (s.node_count || 0) + ")"; })
                        )
                        onActivated: {
                            var subs = App.subscriptions || [];
                            var i = currentIndex - 1;
                            App.setSelectedSubscriptionId(i >= 0 && i < subs.length ? String(subs[i].id || "") : "");
                        }
                    }
                    AccentButton { kind: "ghost"; iconOnly: true; glyph: "\uE72C"; text: I18n.t("Обновить подписку"); enabled: page.selectedSub() !== null; onClicked: { var s = page.selectedSub(); if (s) App.updateSubscription(s.url) } }
                    AccentButton { kind: "ghost"; iconOnly: true; glyph: "\uE895"; text: I18n.t("Обновить все подписки"); enabled: App.subscriptions.length > 0; onClicked: App.updateAllSubscriptions() }
                    AccentButton { kind: "danger"; iconOnly: true; glyph: "\uE74D"; text: I18n.t("Удалить подписку (с серверами)"); enabled: page.selectedSub() !== null; onClicked: { var s = page.selectedSub(); if (s) App.removeSubscription(s.url, true) } }
                }
            }
        }

        // ── table ────────────────────────────
        Card {
            Layout.fillWidth: true
            Layout.fillHeight: true

            Flickable {
                id: hflick
                anchors.fill: parent
                contentWidth: page.tableWidth
                contentHeight: height
                flickableDirection: Flickable.HorizontalFlick
                interactive: false
                clip: true
                boundsBehavior: Flickable.StopAtBounds
                ScrollBar.horizontal: FluentScrollBar {
                    id: hbar
                    parent: hflick
                    anchors.left: parent.left
                    anchors.right: parent.right
                    anchors.bottom: parent.bottom
                    interactive: true
                    policy: page.tableWidth > hflick.width ? ScrollBar.AlwaysOn : ScrollBar.AlwaysOff
                }

                Column {
                    width: page.tableWidth
                    height: hflick.height

                    // header
                    Rectangle {
                        id: headerRow
                        width: page.tableWidth
                        height: 30
                        color: Theme.micaBase
                        Row {
                            anchors.fill: parent
                            anchors.leftMargin: page.leftPad
                            HeaderLabel { columnIndex: 0; w: page.colName; text: I18n.t("Сервер"); sortKey: "name" }
                            HeaderLabel { columnIndex: 1; w: page.colType; text: I18n.t("Тип"); sortKey: "scheme" }
                            HeaderLabel { columnIndex: 2; w: page.colTransport; text: I18n.t("Транспорт"); sortKey: "transport" }
                            HeaderLabel { columnIndex: 3; w: page.colAddr; text: I18n.t("Адрес") }
                            HeaderLabel { columnIndex: 4; w: page.colPort; text: I18n.t("Порт") }
                            HeaderLabel { columnIndex: 5; w: page.colGroup; text: I18n.t("Группа"); sortKey: "group" }
                            HeaderLabel { columnIndex: 6; w: page.colPing; text: I18n.t("Пинг"); sortKey: "ping" }
                            HeaderLabel { columnIndex: 7; w: page.colSpeed; text: I18n.t("Скорость"); sortKey: "speed" }
                            HeaderLabel { columnIndex: 8; w: page.colStatus; text: I18n.t("Статус") }
                            HeaderLabel { columnIndex: 9; w: page.colLast; text: I18n.t("Последнее"); sortKey: "last" }
                        }
                        Rectangle { anchors.bottom: parent.bottom; width: parent.width; height: 1; color: Theme.divider }
                    }

                    ListView {
                        id: list
                        width: page.tableWidth
                        height: parent.height - headerRow.height
                        model: App.nodeModel
                        onCountChanged: {
                            if (page.selCount === 0)
                                return;
                            var o = {};
                            var n = 0;
                            for (var i = 0; i < count; i++) {
                                var id = App.nodeIdAt(i);
                                if (id && page.sel[id] === true) { o[id] = true; n++; }
                            }
                            if (n !== page.selCount) {
                                page.anchorRow = -1;
                                page._commit(o, n);
                            }
                        }
                        clip: true
                        interactive: false  // wheel/scrollbar only; no drag-to-scroll list movement
                        boundsBehavior: Flickable.StopAtBounds
                        onContentYChanged: page.updateDragSelection()

                        Connections {
                            target: App.nodeModel
                            function onModelAboutToBeReset() {
                                page.savedListContentY = list.contentY;
                            }
                            function onModelReset() {
                                Qt.callLater(function() {
                                    var maxY = Math.max(0, list.contentHeight - list.height);
                                    list.contentY = Math.max(0, Math.min(maxY, page.savedListContentY));
                                });
                            }
                        }

                        NumberAnimation {
                            id: listScrollAnim
                            target: list
                            property: "contentY"
                            duration: 420
                            easing.type: Easing.OutQuint
                        }
                        WheelHandler {
                            acceptedDevices: PointerDevice.Mouse
                            onWheel: (ev) => {
                                var maxY = Math.max(0, list.contentHeight - list.height)
                                if (maxY <= 0) { ev.accepted = true; return }
                                var step = Math.max(60, page.rowH * 3)
                                var base = listScrollAnim.running ? listScrollAnim.to : list.contentY
                                var target = Math.max(0, Math.min(maxY, base - (ev.angleDelta.y / 120) * step))
                                listScrollAnim.to = target
                                listScrollAnim.restart()
                                listVbarTrack.flash()
                                ev.accepted = true
                            }
                        }

                        delegate: Rectangle {
                            id: nodeRow
                            required property int index
                            required property string nodeId
                            required property string name
                            required property string scheme
                            required property string description
                            required property string transport
                            required property string server
                            required property int port
                            required property string group
                            required property int ping
                            required property bool pinging
                            required property real speed
                            required property bool isAlive
                            required property bool tested
                            required property bool selected
                            required property bool runtimeSupported
                            required property int speedProgress
                            required property string flagSource
                            required property string flagEmoji
                            required property string flagOrient
                            required property var flagColors
                            required property string lastUsed

                            readonly property bool picked: (page.selRev >= 0) && (page.sel[nodeId] === true)

                            width: page.tableWidth
                            height: page.rowH
                            opacity: runtimeSupported ? 1.0 : 0.45
                            color: picked ? Theme.accentSoft : (page.hoverRow === nodeRow.index && runtimeSupported ? Theme.cardHover : "transparent")

                            // active-node accent bar
                            Rectangle {
                                visible: nodeRow.selected
                                width: 3
                                height: parent.height
                                color: Theme.accent
                            }
                            // bottom divider
                            Rectangle {
                                anchors.bottom: parent.bottom
                                width: parent.width
                                height: 1
                                color: Theme.divider
                                opacity: 0.5
                            }

                            Row {
                                anchors.fill: parent
                                anchors.leftMargin: page.leftPad

                                // name + flag
                                Item {
                                    width: page.colName
                                    height: parent.height
                                    Row {
                                        anchors.left: parent.left
                                        anchors.leftMargin: 4
                                        anchors.verticalCenter: parent.verticalCenter
                                        height: parent.height
                                        spacing: 8
                                        Item {
                                            id: flagBox
                                            readonly property bool imageReady: !!nodeRow.flagSource && flagImg.status === Image.Ready
                                            readonly property bool hasShapeFallback: !imageReady
                                                && nodeRow.flagColors && nodeRow.flagColors.length > 0
                                                && !!nodeRow.flagOrient
                                            readonly property bool showEmojiFallback: !imageReady
                                                && !hasShapeFallback && !!nodeRow.flagEmoji
                                            width: (nodeRow.flagSource || nodeRow.flagEmoji || (nodeRow.flagColors && nodeRow.flagColors.length > 0)) ? 24 : 0
                                            height: 18
                                            anchors.verticalCenter: parent.verticalCenter
                                            visible: width > 0
                                            clip: true
                                            Image {
                                                id: flagImg
                                                anchors.fill: parent
                                                visible: false
                                                source: nodeRow.flagSource
                                                fillMode: Image.PreserveAspectFit
                                                sourceSize.width: Math.round(flagBox.width * Screen.devicePixelRatio)
                                                sourceSize.height: Math.round(flagBox.height * Screen.devicePixelRatio)
                                                smooth: true
                                                mipmap: true
                                                asynchronous: true
                                                cache: true
                                            }
                                            Rectangle {
                                                id: flagMask
                                                anchors.fill: parent
                                                radius: 3
                                                visible: false
                                                antialiasing: true
                                                layer.enabled: true
                                                layer.smooth: true
                                                layer.samples: 4
                                                layer.textureSize: Qt.size(Math.round(flagBox.width * 3), Math.round(flagBox.height * 3))
                                            }
                                            MultiEffect {
                                                anchors.fill: parent
                                                visible: flagBox.imageReady
                                                source: flagImg
                                                maskEnabled: true
                                                maskSource: flagMask
                                                maskThresholdMin: 0.5
                                                maskSpreadAtMin: 0.5
                                                antialiasing: true
                                                layer.enabled: true
                                                layer.smooth: true
                                                layer.samples: 4
                                                layer.textureSize: Qt.size(Math.round(flagBox.width * 3), Math.round(flagBox.height * 3))
                                            }
                                            Text {
                                                anchors.centerIn: parent
                                                visible: flagBox.showEmojiFallback
                                                text: nodeRow.flagEmoji
                                                font.pixelSize: 18
                                                font.family: "Segoe UI Emoji"
                                                renderType: Text.NativeRendering
                                            }
                                            Column {
                                                anchors.fill: parent
                                                visible: flagBox.hasShapeFallback && nodeRow.flagOrient === "h"
                                                Repeater {
                                                    model: (flagBox.hasShapeFallback && nodeRow.flagOrient === "h") ? nodeRow.flagColors : []
                                                    delegate: Rectangle {
                                                        required property string modelData
                                                        width: flagBox.width
                                                        height: flagBox.height / Math.max(1, nodeRow.flagColors.length)
                                                        color: modelData
                                                    }
                                                }
                                            }
                                            Row {
                                                anchors.fill: parent
                                                visible: flagBox.hasShapeFallback && nodeRow.flagOrient === "v"
                                                Repeater {
                                                    model: (flagBox.hasShapeFallback && nodeRow.flagOrient === "v") ? nodeRow.flagColors : []
                                                    delegate: Rectangle {
                                                        required property string modelData
                                                        width: flagBox.width / Math.max(1, nodeRow.flagColors.length)
                                                        height: flagBox.height
                                                        color: modelData
                                                    }
                                                }
                                            }
                                            Item {
                                                anchors.fill: parent
                                                visible: flagBox.hasShapeFallback && nodeRow.flagOrient === "nordic"
                                                Rectangle { anchors.fill: parent; color: (nodeRow.flagColors && nodeRow.flagColors.length > 0) ? nodeRow.flagColors[0] : "transparent" }
                                                Rectangle {
                                                    x: 0; y: Math.round(flagBox.height * 0.36)
                                                    width: flagBox.width; height: Math.max(2, Math.round(flagBox.height * 0.28))
                                                    color: (nodeRow.flagColors && nodeRow.flagColors.length > 1) ? nodeRow.flagColors[1] : "transparent"
                                                }
                                                Rectangle {
                                                    x: Math.round(flagBox.width * 0.30); y: 0
                                                    width: Math.max(3, Math.round(flagBox.width * 0.18)); height: flagBox.height
                                                    color: (nodeRow.flagColors && nodeRow.flagColors.length > 1) ? nodeRow.flagColors[1] : "transparent"
                                                }
                                                Rectangle {
                                                    visible: nodeRow.flagColors && nodeRow.flagColors.length > 2
                                                    x: 0; y: Math.round(flagBox.height * 0.43)
                                                    width: flagBox.width; height: Math.max(1, Math.round(flagBox.height * 0.14))
                                                    color: (nodeRow.flagColors && nodeRow.flagColors.length > 2) ? nodeRow.flagColors[2] : "transparent"
                                                }
                                                Rectangle {
                                                    visible: nodeRow.flagColors && nodeRow.flagColors.length > 2
                                                    x: Math.round(flagBox.width * 0.36); y: 0
                                                    width: Math.max(1, Math.round(flagBox.width * 0.09)); height: flagBox.height
                                                    color: (nodeRow.flagColors && nodeRow.flagColors.length > 2) ? nodeRow.flagColors[2] : "transparent"
                                                }
                                            }
                                            Item {
                                                anchors.fill: parent
                                                visible: flagBox.hasShapeFallback && nodeRow.flagOrient === "cross"
                                                Rectangle { anchors.fill: parent; color: (nodeRow.flagColors && nodeRow.flagColors.length > 0) ? nodeRow.flagColors[0] : "transparent" }
                                                Rectangle {
                                                    anchors.verticalCenter: parent.verticalCenter
                                                    width: flagBox.width; height: Math.max(3, Math.round(flagBox.height * 0.30))
                                                    color: (nodeRow.flagColors && nodeRow.flagColors.length > 1) ? nodeRow.flagColors[1] : "transparent"
                                                }
                                                Rectangle {
                                                    anchors.horizontalCenter: parent.horizontalCenter
                                                    width: Math.max(3, Math.round(flagBox.width * 0.20)); height: flagBox.height
                                                    color: (nodeRow.flagColors && nodeRow.flagColors.length > 1) ? nodeRow.flagColors[1] : "transparent"
                                                }
                                            }
                                            Rectangle {
                                                anchors.fill: parent
                                                visible: flagBox.width > 0
                                                color: "transparent"
                                                radius: 3
                                                antialiasing: true
                                                border.width: 1
                                                border.color: Qt.rgba(0, 0, 0, 0.2)
                                            }
                                        }
                                        Column {
                                            width: page.colName - 24 - flagBox.width
                                            anchors.verticalCenter: parent.verticalCenter
                                            spacing: 0
                                            Text {
                                                width: parent.width
                                                text: nodeRow.name
                                                color: Theme.text
                                                font.family: Theme.fontFamily
                                                font.pixelSize: page.cellFont
                                                elide: Text.ElideRight
                                            }
                                            Text {
                                                visible: nodeRow.description.length > 0
                                                width: parent.width
                                                text: nodeRow.description
                                                color: Theme.textMuted
                                                font.family: Theme.fontFamily
                                                font.pixelSize: Math.max(9, page.cellFont - 3)
                                                elide: Text.ElideRight
                                            }
                                        }
                                    }
                                }

                                CellText { w: page.colType; text: nodeRow.scheme }
                                CellText { w: page.colTransport; text: nodeRow.transport }
                                CellText { w: page.colAddr; text: nodeRow.server; color: Theme.text }
                                CellText { w: page.colPort; text: nodeRow.port > 0 ? ("" + nodeRow.port) : "—" }
                                CellText { w: page.colGroup; text: nodeRow.group || "—" }

                                // ping
                                Item {
                                    width: page.colPing
                                    height: parent.height
                                    Text {
                                        visible: !nodeRow.pinging
                                        anchors.verticalCenter: parent.verticalCenter
                                        leftPadding: 4
                                        text: nodeRow.ping < 0 ? "—" : (nodeRow.ping + " ms")
                                        color: nodeRow.ping < 0 ? Theme.textFaint : Theme.pingColor(nodeRow.ping)
                                        font.family: Theme.fontFamily
                                        font.pixelSize: page.cellFont
                                    }
                                    Text {
                                        id: pingSpinner
                                        visible: nodeRow.pinging
                                        anchors.left: parent.left
                                        anchors.leftMargin: 5
                                        anchors.verticalCenter: parent.verticalCenter
                                        text: "\uE895"
                                        color: Theme.accent
                                        font.family: "Segoe Fluent Icons"
                                        font.pixelSize: 15
                                        transformOrigin: Item.Center
                                        RotationAnimator on rotation {
                                            from: 0
                                            to: 360
                                            duration: 850
                                            loops: Animation.Infinite
                                            running: nodeRow.pinging
                                        }
                                    }
                                }
                                // speed
                                Item {
                                    width: page.colSpeed
                                    height: parent.height
                                    Text {
                                        anchors.verticalCenter: parent.verticalCenter
                                        leftPadding: 4
                                        text: nodeRow.speedProgress >= 0
                                            ? (nodeRow.speedProgress + "%")
                                            : (nodeRow.speed < 0 ? "—" : (nodeRow.speed.toFixed(1) + " MB/s"))
                                        color: nodeRow.speedProgress >= 0
                                            ? Theme.accent
                                            : (nodeRow.speed < 0 ? Theme.textFaint : Theme.text)
                                        font.family: Theme.fontFamily
                                        font.pixelSize: page.cellFont
                                    }
                                }
                                // status
                                Item {
                                    width: page.colStatus
                                    height: parent.height
                                    Text {
                                        anchors.verticalCenter: parent.verticalCenter
                                        leftPadding: 4
                                        text: nodeRow.isAlive ? "OK" : (nodeRow.tested ? "✕" : "—")
                                        color: nodeRow.isAlive ? Theme.success : (nodeRow.tested ? Theme.danger : Theme.textFaint)
                                        font.family: Theme.fontFamily
                                        font.pixelSize: page.cellFont
                                        font.bold: true
                                    }
                                }
                                CellText { w: page.colLast; text: nodeRow.lastUsed }
                            }
                        }

                        MouseArea {
                            id: listSelectionArea
                            anchors.fill: parent
                            z: 100
                            acceptedButtons: Qt.LeftButton | Qt.RightButton
                            hoverEnabled: true
                            preventStealing: true
                            propagateComposedEvents: false

                            onPositionChanged: (mouse) => {
                                page.selectionPointerX = mouse.x;
                                page.selectionPointerY = mouse.y;
                                page.hoverRow = page.rowAtSelectionPoint(mouse.x, mouse.y);
                                page.updateDragSelection();
                            }
                            onExited: {
                                if (!page.selectionDragging)
                                    page.hoverRow = -1;
                            }
                            onPressed: (mouse) => {
                                list.forceActiveFocus();
                                page.selectionPointerX = mouse.x;
                                page.selectionPointerY = mouse.y;
                                var row = page.rowAtSelectionPoint(mouse.x, mouse.y);
                                if (row < 0)
                                    return;
                                page.hoverRow = row;
                                if (mouse.button === Qt.RightButton) {
                                    if (!page.isSelected(App.nodeIdAt(row)))
                                        page.selectOnly(row);
                                    page.menuRow = row;
                                    ctxMenu.popup();
                                    return;
                                }
                                if (mouse.modifiers & Qt.ControlModifier) {
                                    page.toggle(row);
                                    return;
                                }
                                if (mouse.modifiers & Qt.ShiftModifier) {
                                    page.selectRange(page.anchorRow < 0 ? row : page.anchorRow, row);
                                    return;
                                }
                                page.selectOnly(row);
                                page.selectionDragging = true;
                                selectionDragScroll.restart();
                            }
                            onDoubleClicked: (mouse) => {
                                var row = page.rowAtSelectionPoint(mouse.x, mouse.y);
                                var id = App.nodeIdAt(row);
                                if (id)
                                    App.selectNode(id);
                            }
                            onReleased: page.stopSelectionDrag()
                            onCanceled: page.stopSelectionDrag()
                        }

                        Timer {
                            id: selectionDragScroll
                            interval: 30
                            repeat: true
                            running: page.selectionDragging
                            onTriggered: page.scrollDragSelection()
                        }
                    }

                    Item {
                        id: listVbarTrack
                        parent: hflick
                        z: 50
                        width: 12
                        x: hflick.width - width - 2
                        y: headerRow.height
                        height: Math.max(0, hflick.height - headerRow.height - (hbar.visible ? 10 : 0))
                        property bool forcedVisible: false
                        readonly property real maxY: Math.max(0, list.contentHeight - list.height)
                        readonly property bool scrollable: maxY > 1
                        readonly property bool shown: scrollable

                        function flash() {
                            if (!scrollable)
                                return
                            forcedVisible = true
                            listBarHide.restart()
                        }

                        Timer {
                            id: listBarHide
                            interval: 720
                            repeat: false
                            onTriggered: listVbarTrack.forcedVisible = false
                        }

                        visible: scrollable
                        opacity: shown ? 1 : 0
                        Behavior on opacity { NumberAnimation { duration: Theme.animations ? 160 : 0; easing.type: Theme.easeStandard } }
                        HoverHandler { id: listBarHover }

                        Rectangle {
                            id: listThumb
                            readonly property real ratio: list.contentHeight <= 0 ? 1 : Math.min(1, list.height / list.contentHeight)
                            width: listThumbMouse.drag.active || listBarHover.hovered ? 8 : 4
                            height: Math.max(36, listVbarTrack.height * ratio)
                            x: Math.round((listVbarTrack.width - width) / 2)
                            y: listVbarTrack.maxY <= 0 ? 0 : (listVbarTrack.height - height) * (list.contentY / listVbarTrack.maxY)
                            radius: width / 2
                            color: listThumbMouse.drag.active ? Theme.textMuted : Theme.textFaint
                            opacity: listThumbMouse.drag.active ? 0.9 : (listBarHover.hovered ? 0.68 : 0.38)
                            Behavior on width { NumberAnimation { duration: Theme.animations ? 120 : 0; easing.type: Easing.OutCubic } }

                            MouseArea {
                                id: listThumbMouse
                                anchors.fill: parent
                                hoverEnabled: true
                                drag.target: parent
                                drag.axis: Drag.YAxis
                                drag.minimumY: 0
                                drag.maximumY: Math.max(0, listVbarTrack.height - listThumb.height)
                                preventStealing: true
                                onPressed: {
                                    listScrollAnim.stop()
                                    listVbarTrack.flash()
                                }
                                onPositionChanged: {
                                    if (!drag.active)
                                        return
                                    var denom = Math.max(1, listVbarTrack.height - listThumb.height)
                                    list.contentY = Math.max(0, Math.min(listVbarTrack.maxY, (listThumb.y / denom) * listVbarTrack.maxY))
                                    listVbarTrack.flash()
                                }
                                onReleased: listVbarTrack.flash()
                                onCanceled: listVbarTrack.flash()
                            }
                        }
                    }
                }
            }

            // empty state
            ColumnLayout {
                anchors.centerIn: parent
                visible: list.count === 0
                spacing: 6
                Text {
                    Layout.alignment: Qt.AlignHCenter
                    text: "\uE9D9"
                    font.family: "Segoe Fluent Icons"
                    font.pixelSize: 40
                    color: Theme.textFaint
                }
                Text {
                    Layout.alignment: Qt.AlignHCenter
                    text: I18n.t("Список серверов пуст")
                    color: Theme.textFaint
                    font.family: Theme.fontFamily
                    font.pixelSize: Theme.fontNormal
                }
                Text {
                    Layout.alignment: Qt.AlignHCenter
                    text: I18n.t("Скопируйте ссылки и нажмите «Импорт»")
                    color: Theme.textFaint
                    font.family: Theme.fontFamily
                    font.pixelSize: Theme.fontSmall
                }
            }
        }
    }

    // ── context menu (opaque, sized close to the original RoundMenu) ────
    FluentMenu {
        id: ctxMenu
        width: 230

        component Ctx: FluentMenuItem {}
        component Sep: FluentMenuSeparator {}

        Ctx {
            text: I18n.t("Установить как активный")
            enabled: page.selCount === 1
            onTriggered: App.selectNode(page.menuNodeId())
        }
        Sep {}
        Ctx {
            text: I18n.t("Редактировать")
            enabled: page.selCount === 1
            onTriggered: editDialog.openFor(page.firstSelected())
        }
        Ctx {
            text: I18n.t("Копировать ссылку")
            enabled: page.selCount === 1
            onTriggered: App.copyNodeLink(page.firstSelected())
        }
        Ctx {
            text: I18n.t("Массовое редактирование ({count})", { count: page.selCount })
            enabled: page.selCount > 0
            onTriggered: bulkDialog.openFor(page.selectedIds())
        }
        Ctx {
            text: I18n.t("Экспорт выбранных — ссылки ({count})", { count: page.selCount })
            enabled: page.selCount > 0
            onTriggered: App.exportNodeLinks(page.selectedIds())
        }
        Ctx {
            text: I18n.t("Экспорт в QR-код")
            enabled: page.selCount === 1
            onTriggered: App.showNodeQr(page.firstSelected())
        }
        Sep {}
        Ctx {
            text: I18n.t("Пинг — способ из настроек ({count})", { count: page.selCount })
            enabled: page.selCount > 0
            onTriggered: App.pingNodes(page.selectedIds())
        }
        Ctx {
            text: I18n.t("Тест TCP ping ({count})", { count: page.selCount })
            enabled: page.selCount > 0
            onTriggered: App.tcpingNodes(page.selectedIds())
        }
        Ctx {
            text: I18n.t("Тест HTTP GET ({count})", { count: page.selCount })
            enabled: page.selCount > 0
            onTriggered: App.httpGetNodes(page.selectedIds())
        }
        Ctx {
            text: I18n.t("Тест реальной задержки ({count})", { count: page.selCount })
            enabled: page.selCount > 0
            onTriggered: App.realDelayNodes(page.selectedIds())
        }
        Ctx {
            text: I18n.t("Тест скорости загрузки ({count})", { count: page.selCount })
            enabled: page.selCount > 0
            onTriggered: App.downloadSpeedNodes(page.selectedIds())
        }
        Sep {}
        Ctx {
            text: I18n.t("В начало списка")
            enabled: page.selCount === 1
            onTriggered: App.reorderNode(page.menuNodeId(), "top")
        }
        Ctx {
            text: I18n.t("В конец списка")
            enabled: page.selCount === 1
            onTriggered: App.reorderNode(page.menuNodeId(), "bottom")
        }
        Sep {}
        Ctx {
            text: I18n.t("Удалить ({count})", { count: page.selCount })
            enabled: page.selCount > 0
            onTriggered: App.deleteNodes(page.selectedIds())
        }
    }

    // ── keyboard shortcuts ───────────────────────
    readonly property bool _kbReady: page.visible
        && !searchInput.activeFocus
        && !editDialog.opened
        && !bulkDialog.opened
        && !groupDialog.opened
        && !ctxMenu.opened

    Shortcut {                              // Ctrl+V → импорт из буфера
        sequences: [ StandardKey.Paste ]
        enabled: page._kbReady
        autoRepeat: false
        onActivated: App.importClipboard()
    }
    Shortcut {                              // Ctrl+A → выбрать все
        sequences: [ StandardKey.SelectAll ]
        enabled: page._kbReady && list.count > 0
        autoRepeat: false
        onActivated: page.selectAll()
    }
    Shortcut {                              // Ctrl+C → копировать ссылку
        sequences: [ StandardKey.Copy ]
        enabled: page._kbReady && page.selCount === 1
        autoRepeat: false
        onActivated: App.copyNodeLink(page.firstSelected())
    }
    Shortcut {                              // Delete → удалить выбранные
        sequences: [ StandardKey.Delete ]
        enabled: page._kbReady && page.selCount > 0
        autoRepeat: false
        onActivated: App.deleteNodes(page.selectedIds())
    }
    Shortcut {                              // Esc → снять выбор
        sequences: [ StandardKey.Cancel ]
        enabled: page._kbReady && page.selCount > 0
        autoRepeat: false
        onActivated: page.clearSel()
    }

    // Диалоги редактирования (одиночного и массового) — порт ui/node_edit_dialog.py и ui/bulk_edit_dialog.py.
    NodeEditDialog {
        id: editDialog
        onNodeCreated: function(nodeId) { page.revealImportedNode(nodeId) }
    }
    BulkEditDialog { id: bulkDialog }

    // ── диалог создания ручной группы без подписки ──────────────
    Dialog {
        id: groupDialog
        modal: true
        dim: true
        parent: Overlay.overlay
        anchors.centerIn: parent
        Overlay.modal: Rectangle { color: Qt.rgba(0, 0, 0, 0.45) }
        width: 420
        padding: 18
        closePolicy: Popup.CloseOnEscape | Popup.CloseOnPressOutside

        function openNew() {
            groupNameField.text = "";
            groupDialog.open();
            groupNameField.forceActiveFocus();
        }

        background: Rectangle {
            color: Theme.flyout
            radius: 10
            border.width: 1
            border.color: Theme.flyoutBorder
        }

        contentItem: ColumnLayout {
            spacing: 12

            Text {
                text: I18n.t("Новая группа")
                color: Theme.text
                font.family: Theme.fontFamily
                font.pixelSize: Theme.fontStrong
                font.bold: true
            }
            Text {
                text: I18n.t("Группа будет создана отдельно от подписок. В неё можно переносить серверы через редактирование или массовое редактирование.")
                color: Theme.textFaint
                font.family: Theme.fontFamily
                font.pixelSize: Theme.fontSmall
                wrapMode: Text.WordWrap
                Layout.fillWidth: true
            }

            Text { text: I18n.t("Имя группы"); color: Theme.textMuted; font.family: Theme.fontFamily; font.pixelSize: Theme.fontSmall }
            FluentTextField {
                id: groupNameField
                Layout.fillWidth: true
                implicitHeight: Theme.controlHeight
                color: Theme.text
                font.family: Theme.fontFamily
                font.pixelSize: Theme.fontNormal
                selectByMouse: true
                leftPadding: 10; rightPadding: 10
                placeholderText: I18n.t("Например: Мои серверы")
                placeholderTextColor: Theme.textFaint
                background: Rectangle { radius: Theme.radiusSmall; color: Theme.card; border.width: 1; border.color: groupNameField.activeFocus ? Theme.accent : Theme.borderSolid }
                Keys.onReturnPressed: createGroupButton.clicked()
                Keys.onEnterPressed: createGroupButton.clicked()
            }

            RowLayout {
                Layout.fillWidth: true
                Layout.topMargin: 6
                Item { Layout.fillWidth: true }
                AccentButton { kind: "ghost"; text: I18n.t("Отмена"); onClicked: groupDialog.close() }
                AccentButton {
                    id: createGroupButton
                    kind: "accent"; text: I18n.t("Создать")
                    enabled: groupNameField.text.trim().length > 0
                    onClicked: {
                        var name = groupNameField.text.trim();
                        if (App.createManualGroup(name)) {
                            groupDialog.close();
                            page.selectGroupByName(name);
                        }
                    }
                }
            }
        }
    }

    // ── диалог импорта подписки (URL + имя группы) ──────────────
    Dialog {
        id: subDialog
        modal: true
        dim: true
        parent: Overlay.overlay
        anchors.centerIn: parent
        Overlay.modal: Rectangle { color: Qt.rgba(0, 0, 0, 0.45) }
        width: 480
        padding: 18
        closePolicy: Popup.CloseOnEscape | Popup.CloseOnPressOutside

        function openNew() {
            subUrlField.text = "";
            subNameField.text = "";
            subDialog.open();
            subUrlField.forceActiveFocus();
        }

        background: Rectangle {
            color: Theme.flyout
            radius: 10
            border.width: 1
            border.color: Theme.flyoutBorder
        }

        contentItem: ColumnLayout {
            spacing: 12

            Text {
                text: I18n.t("Импорт подписки")
                color: Theme.text
                font.family: Theme.fontFamily
                font.pixelSize: Theme.fontStrong
                font.bold: true
            }
            Text {
                text: I18n.t("Вставьте ссылку на подписку. Серверы автоматически попадут в новую группу.")
                color: Theme.textFaint
                font.family: Theme.fontFamily
                font.pixelSize: Theme.fontSmall
                wrapMode: Text.WordWrap
                Layout.fillWidth: true
            }

            Text { text: I18n.t("URL подписки"); color: Theme.textMuted; font.family: Theme.fontFamily; font.pixelSize: Theme.fontSmall }
            FluentTextField {
                id: subUrlField
                Layout.fillWidth: true
                implicitHeight: Theme.controlHeight
                color: Theme.text
                font.family: Theme.fontFamily
                font.pixelSize: Theme.fontNormal
                selectByMouse: true
                leftPadding: 10; rightPadding: 10
                placeholderText: "https://…"
                placeholderTextColor: Theme.textFaint
                background: Rectangle { radius: Theme.radiusSmall; color: Theme.card; border.width: 1; border.color: subUrlField.activeFocus ? Theme.accent : Theme.borderSolid }
            }

            Text { text: I18n.t("Имя группы (необязательно)"); color: Theme.textMuted; font.family: Theme.fontFamily; font.pixelSize: Theme.fontSmall }
            FluentTextField {
                id: subNameField
                Layout.fillWidth: true
                implicitHeight: Theme.controlHeight
                color: Theme.text
                font.family: Theme.fontFamily
                font.pixelSize: Theme.fontNormal
                selectByMouse: true
                leftPadding: 10; rightPadding: 10
                placeholderText: I18n.t("Пусто — имя будет создано автоматически")
                placeholderTextColor: Theme.textFaint
                background: Rectangle { radius: Theme.radiusSmall; color: Theme.card; border.width: 1; border.color: subNameField.activeFocus ? Theme.accent : Theme.borderSolid }
            }

            RowLayout {
                Layout.fillWidth: true
                Layout.topMargin: 6
                Item { Layout.fillWidth: true }
                AccentButton { kind: "ghost"; text: I18n.t("Отмена"); onClicked: subDialog.close() }
                AccentButton {
                    kind: "accent"; text: I18n.t("Импортировать")
                    enabled: subUrlField.text.trim().length > 0
                    onClicked: {
                        App.importSubscription(subUrlField.text.trim(), subNameField.text.trim());
                        subDialog.close();
                    }
                }
            }
        }
    }

    // ── диалог свойств подписки (инфо из ссылки, если есть) ──────
    Dialog {
        id: infoDialog
        modal: true
        dim: true
        parent: Overlay.overlay
        anchors.centerIn: parent
        Overlay.modal: Rectangle { color: Qt.rgba(0, 0, 0, 0.45) }
        width: 520
        padding: 18
        closePolicy: Popup.CloseOnEscape | Popup.CloseOnPressOutside

        function openInfo() {
            if (page.selectedSub() === null) return;
            var i = subCombo.currentIndex - 1;
            if (i < 0 || i >= App.subscriptions.length) i = 0;
            infoCombo.currentIndex = i;
            infoDialog.open();
        }

        background: Rectangle {
            color: Theme.flyout
            radius: 10
            border.width: 1
            border.color: Theme.flyoutBorder
        }

        contentItem: ColumnLayout {
            spacing: 12

            Text {
                text: I18n.t("Свойства подписки")
                color: Theme.text
                font.family: Theme.fontFamily
                font.pixelSize: Theme.fontStrong
                font.bold: true
            }

            // Переключатель подписки
            FilterCombo {
                id: infoCombo
                Layout.fillWidth: true
                enabled: App.subscriptions.length > 0
                model: App.subscriptions.length > 0
                    ? App.subscriptions.map(function(s) { return (s.name && s.name.length ? s.name : s.url) + " (" + (s.node_count || 0) + ")"; })
                    : [I18n.t("Нет подписок")]
            }

            // Premium-подписка может передать несколько десятков параметров;
            // свойства остаются доступны в компактном прокручиваемом блоке.
            FluentScroll {
                Layout.fillWidth: true
                Layout.preferredHeight: Math.min(420, Math.max(90, infoProperties.implicitHeight))
                roundedClip: false

            Column {
                id: infoProperties
                width: parent ? Math.max(0, parent.width - 4) : 0
                spacing: 6
                Repeater {
                    model: page.infoRows(page.infoSub())
                    delegate: RowLayout {
                        id: infoRow
                        width: infoProperties.width
                        spacing: 12
                        readonly property bool isUrlRow: String(modelData[0]).toLowerCase() === "url"
                        Text {
                            text: modelData[0]
                            color: Theme.textMuted
                            font.family: Theme.fontFamily
                            font.pixelSize: Theme.fontSmall
                            Layout.preferredWidth: 140
                            Layout.alignment: Qt.AlignTop
                        }
                        Text {
                            visible: !infoRow.isUrlRow
                            text: modelData[1]
                            color: Theme.text
                            font.family: Theme.fontFamily
                            font.pixelSize: Theme.fontSmall
                            wrapMode: Text.WrapAtWordBoundaryOrAnywhere
                            Layout.fillWidth: true
                            Layout.minimumWidth: 0
                            Layout.preferredWidth: 1
                            Layout.alignment: Qt.AlignTop
                        }
                        FluentTextEdit {
                            visible: infoRow.isUrlRow
                            text: modelData[1]
                            color: urlMouse.containsMouse ? Theme.accent : Theme.text
                            selectedTextColor: Theme.text
                            selectionColor: Theme.accentSoft
                            font.family: Theme.fontFamily
                            font.pixelSize: Theme.fontSmall
                            wrapMode: TextEdit.WrapAnywhere
                            readOnly: true
                            selectByMouse: true
                            textFormat: TextEdit.PlainText
                            Layout.fillWidth: true
                            Layout.minimumWidth: 0
                            Layout.preferredWidth: 1

                            MouseArea {
                                id: urlMouse
                                anchors.fill: parent
                                acceptedButtons: Qt.LeftButton | Qt.RightButton
                                cursorShape: Qt.PointingHandCursor
                                hoverEnabled: true
                                onClicked: function(mouse) {
                                    if (mouse.button === Qt.RightButton) {
                                        subUrlMenu.url = modelData[1];
                                        subUrlMenu.popup();
                                    } else {
                                        App.openUrl(modelData[1]);
                                    }
                                }
                            }
                        }
                    }
                }
            }
            }

            Text {
                visible: { var s = page.infoSub(); return s ? !(s.userinfo && typeof s.userinfo === "object" && Object.keys(s.userinfo).length > 0) : false; }
                text: I18n.t("В ссылке этой подписки нет доп. информации о пользователе.")
                color: Theme.textFaint
                font.family: Theme.fontFamily
                font.pixelSize: Theme.fontSmall
                wrapMode: Text.WordWrap
                Layout.fillWidth: true
            }

            RowLayout {
                Layout.fillWidth: true
                Layout.topMargin: 6
                Layout.rightMargin: 4
                Layout.bottomMargin: 4
                Item { Layout.fillWidth: true }
                AccentButton { kind: "accent"; text: I18n.t("Закрыть"); onClicked: infoDialog.close() }
            }
        }
    }

    FluentMenu {
        id: subUrlMenu
        property string url: ""
        width: 210
        FluentMenuItem {
            text: I18n.t("Копировать ссылку")
            onTriggered: App.copyText(subUrlMenu.url)
        }
    }

    FluentDialog {
        id: deleteGroupDialog
        property string groupName: ""
        title: I18n.t("Удалить группу")
        okText: I18n.t("Удалить")
        cancelText: I18n.t("Отмена")
        width: 440
        onAccepted: {
            var removed = App.deleteGroup(groupName);
            if (removed)
                page.selectGroupByName("Default");
        }
        contentItem: Text {
            text: I18n.t("Группа «{name}», все её серверы и связанная подписка будут удалены.").replace("{name}", deleteGroupDialog.groupName)
            color: Theme.textMuted
            font.family: Theme.fontFamily
            font.pixelSize: Theme.fontNormal
            wrapMode: Text.WordWrap
        }
    }

    // ---- QR dialog ---------------------------------------------------
    FluentDialog {
        id: qrDialog
        property string qrSource: ""
        property string qrName: ""
        title: qrName.length ? I18n.t("QR-код: ") + qrName : I18n.t("QR-код сервера")
        okText: I18n.t("Закрыть")
        showCancelButton: false
        width: 360
        contentItem: ColumnLayout {
            spacing: 12
            Image {
                source: qrDialog.qrSource
                Layout.alignment: Qt.AlignHCenter
                Layout.preferredWidth: 280
                Layout.preferredHeight: 280
                fillMode: Image.PreserveAspectFit
                smooth: false
            }
            Text {
                text: I18n.t("Отсканируйте код в клиенте, чтобы импортировать сервер.")
                color: Theme.textMuted; font.family: Theme.fontFamily; font.pixelSize: Theme.fontSmall
                wrapMode: Text.WordWrap; horizontalAlignment: Text.AlignHCenter; Layout.fillWidth: true
            }
        }
    }

    // ── диалог прогресса импорта подписки ──────────────────────────
    Dialog {
        id: importProgressDialog
        modal: true
        dim: true
        parent: Overlay.overlay
        anchors.centerIn: parent
        Overlay.modal: Rectangle { color: Qt.rgba(0, 0, 0, 0.45) }
        width: 320
        padding: 20
        closePolicy: Popup.NoAutoClose
        visible: App.subscriptionImporting

        background: Rectangle {
            color: Theme.flyout
            radius: 10
            border.width: 1
            border.color: Theme.flyoutBorder
        }

        contentItem: ColumnLayout {
            spacing: 16
            Text {
                text: I18n.t("Импорт подписки")
                color: Theme.text
                font.family: Theme.fontFamily
                font.pixelSize: Theme.fontStrong
                font.bold: true
                Layout.alignment: Qt.AlignHCenter
            }
            ProgressBar {
                indeterminate: true
                Layout.fillWidth: true
            }
            Text {
                text: App.subscriptionImportStatus || I18n.t("Загрузка подписки...")
                color: Theme.textMuted
                font.family: Theme.fontFamily
                font.pixelSize: Theme.fontNormal
                Layout.alignment: Qt.AlignHCenter
                wrapMode: Text.WordWrap
                horizontalAlignment: Text.AlignHCenter
                Layout.fillWidth: true
            }
            RowLayout {
                Layout.fillWidth: true
                Item { Layout.fillWidth: true }
                AccentButton {
                    kind: "ghost"
                    text: I18n.t("Отмена")
                    onClicked: App.cancelSubscriptionImport()
                }
                Item { Layout.fillWidth: true }
            }
        }
    }

    Connections {
        target: App
        function onNodeImported(nodeId) {
            page.revealImportedNode(nodeId);
        }
        function onSubscriptionImported(groupName) {
            page.selectGroupByName(groupName);
            page.selectSubscriptionByGroup(groupName);
        }
        function onSubscriptionsChanged() {
            Qt.callLater(page.restoreSubscriptionSelection);
        }
        function onNodeQrReady(dataUri, name) {
            qrDialog.qrSource = dataUri;
            qrDialog.qrName = name;
            qrDialog.open();
        }
    }
}
