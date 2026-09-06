# HANDOFF: Lumen KVN

## Цель проекта

Lumen — мультиплатформенный VPN/прокси-клиент. Windows-версия должна стабильно запускать Xray и sing-box в proxy/TUN режимах, применять региональные пресеты маршрутизации, корректно обрабатывать DNS, подписки и серверы, а также работать в ограниченном режиме без повышения прав. Android-версия является источником части уже реализованных идей по импорту, подпискам, OpenVPN и AmneziaWG.

Главные требования к продолжению работы: не ломать существующую маршрутизацию и UI, не допускать DNS-утечек, не путать собственные процессы Lumen с внешними VPN, не завершать процессы пользователя неожиданно и не запускать проверки, которые останавливают Xray/sing-box.

## Текущая архитектура

### Windows

- `windows/run_qml.py` — основной launcher.
- `windows/xray_fluent/qml_app/main_qml.py` — создание Qt/QML-приложения, single-instance/startup/admin relaunch и завершение.
- `windows/xray_fluent/app_controller.py` — фасад состояния, QML-сигналы и команды подключения, выбора сервера, тестов и настроек.
- `windows/xray_fluent/application/` — сервисы приложения:
  - `connection_service.py` — connect/disconnect/reconnect и переключение сервера;
  - `transition_engine.py` — выбор действия при изменении настроек/режима;
  - `runtime_services.py`, `xray_runtime_service.py`, `session_state.py` — жизненный цикл runtime, метрики и активная сессия;
  - `worker_service.py` — фоновые ping/speed/connectivity workers.
- `windows/xray_fluent/engines/xray/` — построение конфигов, запуск, остановка и диагностика Xray.
- `windows/xray_fluent/engines/singbox/` — построение и запуск sing-box:
  - `runtime_planner.py` нормализует импортированный конфиг и добавляет runtime-контракты;
  - `operations.py` выполняет start/restart runtime;
  - `manager.py` управляет процессом, TUN-адаптером и ожиданием освобождения портов.
- `windows/xray_fluent/link_parser.py` — ссылки/JSON-конфиги, автоматические группы и нормализация протоколов.
- `windows/xray_fluent/subscription_fetcher.py` и `subscription_worker.py` — загрузка подписок, HTTP-кэширование и фоновые задачи.
- `windows/xray_fluent/ping_worker.py`, `speed_test_worker.py` — тесты серверов; тесты выполняют временный Xray-процесс, поэтому их нельзя запускать в режиме, который завершает рабочий core.
- QML-страницы и bridge находятся в `windows/xray_fluent/qml_app/qml/` и `windows/xray_fluent/qml_app/bridge/`.

### Android

`android/` — Jetpack Compose-клиент. Существенные аналоги находятся в `android/core/config`, `android/core/engine`, `android/core/vpn`, `android/app` и используются как reference для parser/import/OpenVPN/AWG-поведения.

## Что уже реализовано

Ниже перечислены изменения, присутствующие в текущем рабочем коде после предыдущих итераций. Перед выпуском нужно сверить их фактический diff, так как часть работ могла попасть в разные коммиты.

### Runtime, TUN и процессы

- Имя Windows TUN-интерфейса sing-box стандартизировано на `tun0` вместо проблемного `singbox_tun`.
- Добавлены очистка осиротевших Wintun-адаптеров, повторные попытки запуска и ожидание освобождения TUN/Clash API-портов.
- Процессные окна core запускаются скрыто; фоновые worker'ы должны корректно останавливаться при закрытии приложения/выключении Windows.
- Есть отдельный конфликт-сканер внешних VPN/Xray/sing-box с диалогом «закрыть» или «закрыть процессы и продолжить».
- В проверки конфликтов добавлялись исключения для собственных процессов Lumen и временных тестовых процессов, чтобы Lumen не принимал свой Xray за внешний.
- Реализован ограниченный запуск без администратора: доступные без elevation функции продолжают работать, а действия, требующие прав (TUN/system proxy), должны показывать понятное предложение перезапустить Lumen от администратора.

### Sing-box planner и DNS

- `SingboxRuntimePlan` разделяет native sing-box и hybrid `sing-box + xray sidecar` режимы.
- Planner нормализует импортированные sing-box JSON-конфиги, OpenVPN и WireGuard/AmneziaWG endpoints, удаляет устаревшие AWG 1.5 поля и добавляет Windows-совместимые AWG 3 workaround'ы.
- Добавляется локальный Clash API на `127.0.0.1:19090` с секретом активной сессии. Сейчас он используется для метрик/статистики соединений.
- В runtime добавляются DNS/TUN/routing-контракты, fake DNS/fake-IP cache, bootstrap loop protection и правила перехвата DNS.
- Были исправления для пресетов «только заблокированное», «всё кроме РФ» и других региональных режимов: при старте правила должны сразу соответствовать выбранному пресету, а UI не должен повторно показывать сервер как Direct после изменения маршрута.
- Разбирался лог `qclass overflow`: это отдельная проблема подачи не-DNS/повреждённого UDP-пакета в DNS parser при широком `hijack-dns`, а не обычная DNS-утечка.

### Переключение серверов

- Выбор сервера проходит через planner и сохраняет активную сессию/выбранный node.
- Для обычного переключения сейчас используется `restart_runtime()`: он валидирует новый конфиг, останавливает sing-box и возможный Xray sidecar, затем запускает новый runtime.
- В коде уже есть инфраструктура Clash API и selector alias `proxy`, но полноценный hot-switch без перезапуска core ещё не реализован.

### Подписки и импорт

- Улучшен разбор подписок с группами/автовыбором/резервным и ручным выбором для поддерживаемых форматов.
- Добавлена логика HTTP `ETag`/`If-None-Match`, ответа `304 Not Modified`, backoff при ошибках и reconcile существующих узлов вместо безусловного дублирования.
- Переносились Android-фиксы парсинга OpenVPN, AmneziaWG/AWG 3 и профильных конфигов на Windows.
- Экспорт должен нормализовать протоколы: импортированный JSON VLESS/Trojan/VMess и другие поддерживаемые узлы экспортируются в канонический URI-формат соответствующего протокола, где это возможно.

### Тесты серверов и UI

- Реальный ping и speed test переведены на фоновые workers с отменой, ограничением параллельности, HTTP GET и контролем зависших временных процессов.
- Добавлена поддержка метода HTTP GET для измерения задержки.
- Учитывается обход активного TUN при прямой проверке endpoint'ов.
- В UI добавлялась ручная настройка ширины столбцов на вкладке серверов.
- Исправлялись диалог конфликтов, расположение кнопок, single-instance окно, стартовый экран, предупреждение Mica на Windows 10 и проблема чрезмерно длинной верхней рамки без изменения дизайна.
- Добавлялась/исправлялась регистрация автозапуска Windows, включая отображение включённого Lumen в диспетчере задач Windows 10.

## Важные решения этой сессии

1. Не запускать тесты, которые завершают рабочий Xray/sing-box. Разрешены статические проверки и unit-тесты, не трогающие активные процессы.
2. Для TUN использовать имя `tun0`; старое `singbox_tun` не возвращать.
3. Системный proxy и TUN без прав администратора не скрывать полностью: кнопки остаются доступными, но показывают причину отказа и предложение relaunch as administrator.
4. Прокси-авторизация — отдельная настройка, по умолчанию выключена; логин и пароль задаются пользователем.
5. При конфликте с другим VPN сначала показывать выбор: закрыть диалог или завершить найденные внешние процессы и продолжить. Собственные процессы Lumen/Xray не считать конфликтом.
6. Дизайн QML не менять при исправлении геометрии/рамок и диалогов.
7. Для hot-switch выбран подход через sing-box Clash API selector. Перезапуск остаётся fallback для hybrid/Xray, смены структуры конфига, TUN/DNS и иных изменений, которые API не умеет применять.
8. EDE `REFUSED/Network Error/No Reachable Authority` в логе DNS — это ответ/диагностика upstream, а не автоматически DNS leak; единичный домен не считать неисправностью маршрутизации без проверки других доменов.
9. Коммиты и release должны следовать существующему Conventional Commit/CHANGELOG формату проекта; перед bump/release сначала провести аудит diff.

## Ключевые файлы, затронутые работой

- `windows/xray_fluent/engines/singbox/runtime_planner.py` — TUN `tun0`, DNS/routing-контракты, fake DNS, Clash API, AWG3/OpenVPN normalization, selector alias.
- `windows/xray_fluent/engines/singbox/operations.py` — запуск/перезапуск sing-box runtime и текущая реализация server switch.
- `windows/xray_fluent/engines/singbox/manager.py` — жизненный цикл процесса, Wintun cleanup, ожидание портов и retry.
- `windows/xray_fluent/engines/xray/manager.py`, `windows/xray_fluent/engines/xray/operations.py` — запуск/остановка Xray, диагностика и sidecar.
- `windows/xray_fluent/application/connection_service.py` — connect/disconnect/reconnect, права, конфликты и выбор сервера.
- `windows/xray_fluent/application/transition_engine.py` — правила переходов и допустимые hot-swap действия.
- `windows/xray_fluent/application/runtime_services.py`, `xray_runtime_service.py`, `session_state.py` — active session, metrics и shutdown.
- `windows/xray_fluent/application/worker_service.py` — запуск ping/speed/connectivity workers и их завершение.
- `windows/xray_fluent/app_controller.py` — QML bridge, состояние подключения, admin relaunch, routing/server actions.
- `windows/xray_fluent/live_metrics_worker.py`, `process_traffic_collector.py` — Clash API `/connections` и статистика процессов/трафика.
- `windows/xray_fluent/link_parser.py` — parser подписок, selector/url-test groups, URI/JSON normalization.
- `windows/xray_fluent/subscription_fetcher.py`, `subscription_worker.py` — ETag/304/backoff/reconcile и фоновые обновления.
- `windows/xray_fluent/ping_worker.py`, `speed_test_worker.py` — HTTP GET, реальный ping/speed, cancellation и temporary core lifecycle.
- `windows/xray_fluent/qml_app/main_qml.py`, `qml_app/bridge/app_bridge.py` — запуск приложения, single instance, Mica/startup/admin UI и QML-сигналы.
- `windows/xray_fluent/qml_app/qml/` — диалоги конфликтов, настройки proxy auth, таблица серверов и исправления геометрии.
- `windows/xray_fluent/proxy_manager.py`, `process_conflicts.py`, `startup.py` — system proxy, внешние конфликты и elevation/startup.
- `windows/tests/` — существующие unit-тесты planner, subscriptions, workers, OpenVPN/AWG и lifecycle; перед изменениями проверить, какие из них безопасны для запуска.

## Найденные баги и причины

- Настоящий hot-switch отсутствует: функция с логом `[tun-hot-swap]` фактически вызывает `singbox.stop()` и повторный запуск. Это создаёт короткий разрыв TUN и может вызывать задержки.
- В planner путь выбранного node заменяет outbound `proxy` одним конкретным outbound. Для API-переключения нужно заранее собрать все совместимые node outbounds и selector, а не только добавить alias к одному outbound.
- Hybrid-ноды требуют Xray sidecar; для них selector sing-box не меняет сам Xray-конфиг.
- `bad question qclass/overflow` возникает, когда широкое DNS hijack получает невалидный или не-DNS UDP payload. Это не то же самое, что upstream `EDE 22/23`.
- `REFUSED`/EDE 22/23 для одного случайного домена обычно означает отказ/недоступность authoritative DNS. Массовые такие ответы требуют отдельного аудита активного DNS detour, `dns.final`, fake-DNS правил и reachability upstream.
- Ранее наблюдались редкие ложные срабатывания на Xray самого Lumen во время переключения/завершения временного speed-test процесса. Проверять, что PID/command line исключаются только после подтверждения принадлежности Lumen.
- На отдельных ноутбуках после перезагрузки появлялось окно «Lumen уже запущен, но не отвечает». Вероятная зона риска — stale single-instance marker/mutex или слишком ранняя проверка startup-процесса; проверять cleanup и PID liveness после cold boot.
- Portable launcher ранее мог исчезать после старта при проблемах с путями core/ресурсами. Проверять переносимые пути `core/xray.exe`, `core/sing-box.exe`, cwd и отсутствие скрытого исключения до создания UI.
- Для Windows 10 отдельно проверить фактическое отображение startup entry в Task Manager, а не только наличие записи запуска.

## Что сейчас не завершено / требует проверки

1. Реализовать native sing-box hot-switch через Clash API `PUT /proxies/{selector}` без остановки sing-box и TUN.
2. Сохранить fallback на полный restart для Xray/hybrid, OpenVPN/AWG-конфигураций, отсутствующего selector и изменений DNS/routing/inbound.
3. Добавить безопасные unit-тесты для selector mapping, API auth/HTTP PUT, fallback и rollback при отказе API. Тесты не должны запускать или убивать рабочий Xray/sing-box.
4. Провести DNS-аудит для трёх региональных пресетов в режимах default DNS, direct DNS off и fake DNS on; проверить отсутствие реальных DNS-запросов мимо TUN.
5. Проверить подписки с `ETag`, `304`, backoff и reconcile на повторном обновлении, ошибке сети и изменении состава узлов.
6. Проверить AWG 3.0 на реальном конфиге `awg3_uhorem-awg3_slot1.conf` и строгой версии sing-box, включая Windows bind workaround.
7. Проверить реальный ping/speed test на нескольких node без завершения пользовательского core и без мгновенного ложного `completed`.
8. Проверить single-instance после cold reboot, portable запуск, admin relaunch без консольного окна, shutdown Windows и внешний VPN conflict dialog.
9. Перед релизом выполнить полный read-only `git diff`/`git status`, сверить `APP_VERSION`, `CHANGELOG.md`, installer/portable артефакты и только затем commit/push/release.

## Команды запуска, сборки и тестов

### Windows

```powershell
cd D:\Lumen-KVN-release\windows
pip install -r requirements.txt
python run_qml.py
pytest
python build_qml.py
```

Безопасные проверки перед изменениями:

```powershell
cd D:\Lumen-KVN-release\windows
python -m compileall xray_fluent run_qml.py
pytest tests/test_singbox_runtime_planner.py tests/test_singbox_extended_imports.py
pytest tests/test_subscription_import_cancel.py tests/test_thread_lifecycle.py
```

Конкретный набор нужно уточнить по текущему `git diff`. Не запускать тестовые сценарии, которые вызывают `stop/kill` рабочего Xray/sing-box или меняют системный TUN/proxy.

### Android

```powershell
cd D:\Lumen-KVN-release\android
./gradlew assembleDebug
```

## Важные ограничения

- Проект Windows рассчитан на Windows 10/11; TUN, system proxy, Wintun, registry startup и elevation зависят от ОС.
- Не считать наличие `experimental.clash_api` доказательством hot-switch: сейчас API гарантированно нужен для метрик, а selector должен быть явно подготовлен.
- Не завершать процессы по одному имени (`xray.exe`, `sing-box.exe`): сначала проверять PID, путь, командную строку и принадлежность текущей сессии Lumen.
- Не менять внешний вид QML при исправлении layout; ограничиваться anchors/layout/implicit size и общим стилем диалогов.
- Не удалять широкие каталоги и не использовать destructive git-команды для «очистки» рабочей копии.
- Сохранять совместимость с импортированными JSON, URI, OpenVPN, WireGuard/AmneziaWG и существующими Android-поведенческими контрактами.
- При изменениях библиотек/API сначала использовать Context7 для актуальной документации; для sing-box проверять совместимость с реально поставляемой версией core.

## Следующий рекомендуемый шаг

Сначала выполнить read-only аудит текущего diff и определить точный контракт selector'а в поставляемой версии sing-box. Затем добавить отдельный модуль Clash API-клиента с таймаутом, bearer-secret, проверкой текущего selector и rollback. В `runtime_planner.py` формировать selector только для native-совместимых серверов, в `connection_service.py` переключать его без restart, а для hybrid/неподдерживаемых конфигов оставлять проверенный restart fallback. После этого добавить безопасные mock/unit-тесты и только потом проводить ручную проверку DNS, TUN и UI на Windows 10/11.
