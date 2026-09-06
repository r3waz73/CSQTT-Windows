# Разработка CSQTT for Windows 3.13.1: подробное учебное руководство

Это руководство описывает полный путь создания Windows-клиента: от анализа Android-приложения до сборки, отладки сетевого адаптера и выпуска готового архива. Оно рассчитано на студента, знакомого с основами C#, Rust, TCP/IP и Git, но ещё не разрабатывавшего VPN-клиенты.

> Проект основан на CSQTT и распространяется по PolyForm Noncommercial 1.0.0. Коммерческое использование требует отдельного разрешения правообладателя.

## 1. Цель и ограничения

Требование проекта: Android- и Windows-клиенты должны работать с одной конфигурацией сервера без редеплоя. Следовательно, Windows-клиент не должен придумывать новый серверный API или менять формат пакетов.

Из этого следуют архитектурные решения:

1. Протокольное Rust-ядро берётся из Android-проекта.
2. Windows-часть отвечает только за UI, настройки, виртуальный адаптер и маршруты.
3. Между Wintun и Rust-ядром используется уже существующий локальный UDP-режим ядра.
4. Сервер продолжает выдавать адрес и DNS сообщением `TUNCONF`.

Текущая версия синхронизирована с CSQTT 2.1.9 и протоколом
`CSQTT-WIRE-3`. При обновлении upstream копировать следует весь набор модулей
`rust-client` и `shared`, потому что частичное обновление сетевого ядра нарушает
совместимость даже при успешной компиляции.

## 2. Архитектура

```text
Приложения Windows
       │ IPv4-пакеты
       ▼
Виртуальный адаптер Wintun «CSQTT»
       │
       │ TunnelController.TunToCore()
       ▼
Локальный UDP 127.0.0.1:<ephemeral-port>
       │
       ▼
client.exe — оригинальное Rust-ядро CSQTT
       │ TURN/RTP + WRAP + obfs + FEC
       ▼
Тот же CSQTT-сервер, что используется Android-клиентом
```

Обратный трафик проходит в противоположном порядке через `CoreToTun()`.

### Почему не переписывать протокол на C#

Протокол включает авторизацию VK Calls, TURN, шифрование WRAP, обфускацию и FEC. Повторная реализация создала бы риск несовместимости и потребовала бы дублировать тестирование криптографии. Повторное использование Rust-ядра сохраняет поведение Android-клиента.

### Почему Wintun

Wintun — компактный layer-3 адаптер для Windows. Он передаёт готовые IP-пакеты без Ethernet-заголовков, что соответствует Android `VpnService`/TUN и формату, ожидаемому Rust-диспетчером.

## 3. Структура проекта

| Файл | Назначение |
|---|---|
| `Program.cs` | Точка входа WinForms |
| `MainForm.cs` | UI, навигация, ввод и отображение журнала |
| `ClientConfig.cs` | JSON-конфигурация пользователя |
| `ProtectedStore.cs` | Защита ссылки и пароля через Windows DPAPI |
| `CsqttLink.cs` | Разбор v2 и legacy `csqtt://` ссылок |
| `TunnelController.cs` | Жизненный цикл Rust-процесса, Wintun и пакетного моста |
| `Wintun.cs` | P/Invoke-сигнатуры `wintun.dll` |
| `RouteManager.cs` | IP, DNS, MTU, default route и bypass routes |
| `LogText.cs` | Исправление повреждённой кодировки журнала |
| `Core/rust-client` | Протокольное Rust-ядро из upstream CSQTT |
| `Core/shared` | Общие FEC/scheduler-модули Rust |
| `Assets/deploy.sh` | Upstream-установщик сервера CSQTT 2.1.9 |
| `Assets/csqtt` | Серверный Linux x86_64-musl бинарник той же ревизии протокола |
| `build.ps1` | Загрузка Wintun, сборка Rust и публикация .NET |
| `app.manifest` | Запрос прав администратора |

## 4. Необходимая среда

Минимальный набор:

- Windows 10/11 x64;
- .NET 10 SDK;
- Rust 1.97.1 MSVC через rustup;
- Visual Studio Build Tools с workload C++ Desktop Development;
- PowerShell 7 или Windows PowerShell 5.1;
- Git;
- доступ к интернету при первой сборке.

Проверка:

```powershell
dotnet --version
rustc --version
cargo --version
git --version
```

Если Cargo установлен, но не виден в текущем терминале:

```powershell
$env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"
```

## 5. Рекомендуемый порядок разработки

### Этап 1. Исследование Android-клиента

Нужно определить границу между переносимой и платформенной логикой.

Изучаются:

- `TunnelManager.kt`: аргументы запуска `client.exe`;
- `TunVpnService.kt`: создание TUN, адрес, DNS, MTU и routes;
- `UiUtils.kt`: формат `csqtt://`;
- `ConnectionSource.kt`: приоритет ссылки, пароля и хешей;
- `rust-client/main.rs`: CLI и `TUNCONF`;
- `dispatcher.rs`: режим TUN FD и локальный UDP-режим.

Результатом должен стать контракт:

```text
Windows UI -> параметры CLI -> client.exe
client.exe -> TUNCONF:IP:DNS:PORT -> Windows network setup
Wintun packet <-> UDP datagram <-> client.exe
```

### Этап 2. Сборка Rust-ядра на Windows

Сначала ядро собирается независимо от GUI:

```powershell
cd Core\rust-client
cargo build --release
```

Результат:

```text
Core\rust-client\target\release\client.exe
```

Smoke test парсера CLI:

```powershell
.\target\release\client.exe `
  --validate-vk-hashes `
  -peer 127.0.0.1:1 `
  -password smoke-test `
  -vk invalid-test-hash
```

Ожидается структурированный `HASH_CHECK`; сетевое подключение при таком тесте не требуется.

### Этап 3. Минимальная Wintun-обёртка

В `Wintun.cs` описываются только используемые функции. Важно точно соблюдать:

- calling convention экспортов DLL;
- UTF-16 для имени адаптера;
- `SetLastError = true` там, где API сообщает Win32 error;
- парные операции `StartSession/EndSession` и `Create/OpenAdapter/CloseAdapter`;
- `ReceivePacket/ReleaseReceivePacket`.

Нельзя хранить указатель пакета после `ReleaseReceivePacket` или `SendPacket`.

### Этап 4. Пакетный мост

`TunnelController` создаёт два независимых цикла:

1. `TunToCore`: Wintun → managed `byte[]` → UDP → Rust.
2. `CoreToTun`: UDP → память Wintun → сетевой стек Windows.

Для первого прототипа копирование через `Marshal.Copy` предпочтительнее unsafe zero-copy: оно проще, безопаснее и достаточно для проверки архитектуры. Оптимизацию выполняют только после измерения производительности.

### Этап 5. Настройка сети

Порядок критичен:

1. Найти физический IPv4-интерфейс и его gateway.
2. Разрешить peer/VK/OK/TURN имена в IP.
3. Добавить `/32` маршруты этих адресов через физический gateway.
4. Назначить Wintun адрес из `TUNCONF`.
5. Установить MTU 1300.
6. Назначить DNS.
7. Последним добавить `0.0.0.0/0` через CSQTT.

Если default route добавить раньше bypass routes, управляющий TURN-трафик попадёт внутрь собственного туннеля.

### Этап 6. Парсер `TUNCONF`

Формат текущего сервера:

```text
TUNCONF:<client-ip>:<dns1,dns2>:<local-port>
```

Пример:

```text
TUNCONF:10.66.67.4:1.1.1.1,1.0.0.1:64787
```

Нельзя интерпретировать `:64787` как часть второго DNS. После разбора каждый DNS дополнительно проверяется через `IPAddress.TryParse`.

### Этап 7. Ссылки подключения

Современный формат:

```text
csqtt://connect?v=2&host=203.0.113.7&peer=46000&password=secret&hashes=HASH1+HASH2
```

Legacy:

```text
csqtt://secret@203.0.113.7:46000
```

Тестировать нужно URL decoding, `%2B`, IPv6, пустые поля, порты вне диапазона, повторы и более шести хешей.

### Этап 8. Хранение настроек

Не секретные значения сериализуются `System.Text.Json` в:

```text
%LOCALAPPDATA%\CSQTT\config.json
```

Пароль и полная ссылка могут содержать секреты. `ProtectedStore` вызывает Windows DPAPI, привязанный к профилю пользователя. При изменении схемы конфигурации новые свойства должны иметь безопасные значения по умолчанию, чтобы старый JSON продолжал загружаться.

### Этап 9. UI

UI не должен напрямую:

- запускать `netsh`;
- читать пакеты Wintun;
- формировать TURN handshake;
- управлять нативными handle.

Форма вызывает `TunnelController.StartAsync/StopAsync` и подписывается на события `Log` и `StateChanged`. Это принцип разделения ответственности.

## 6. Полная сборка

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\build.ps1
```

Скрипт:

1. Загружает официальный Wintun 0.14.1, если DLL отсутствует.
2. Выполняет `cargo build --release`.
3. Выполняет `dotnet publish` для `win-x64`.
4. Копирует `client.exe`, `wintun.dll` и лицензию.
5. Проверяет наличие обязательных файлов.

Запускается весь каталог `publish`, а не отдельно скопированный основной EXE.

## 7. Отладка

### Отладка GUI

Открыть `CSQTT.Windows.csproj` в Visual Studio, выбрать Debug/x64 и запустить. Из-за манифеста Visual Studio или приложение запросит elevation.

Полезные breakpoint:

- `MainForm.ApplyLink` — импорт ссылки;
- `MainForm.Save` — сохранение;
- `TunnelController.StartAsync` — последовательность запуска;
- `TunnelController.PumpLogs` — `TUNCONF` и TURN IP;
- `RouteManager.ConfigureAsync` — системная сеть;
- `TunnelController.StopAsync` — очистка.

### Отладка Rust

```powershell
$env:RUST_BACKTRACE = "1"
cargo build
cargo test
```

Debug-версия находится в `target\debug\client.exe`. Для GUI release-путь нужно временно заменить или скопировать debug binary рядом с приложением.

### Диагностика маршрутов

```powershell
route print -4
Get-NetRoute -AddressFamily IPv4 | Sort-Object DestinationPrefix
Get-NetIPConfiguration
Get-DnsClientServerAddress -AddressFamily IPv4
Get-NetAdapter -Name CSQTT
```

Нужно увидеть:

- адрес `10.66.x.x/32` на CSQTT;
- default route через CSQTT;
- `/32` маршруты peer и TURN через физический gateway;
- DNS из `TUNCONF`.

### Wireshark

Снимать трафик следует одновременно на физическом интерфейсе и CSQTT:

- на физическом — TURN/RTP транспорт;
- на CSQTT — обычные IP-пакеты приложений.

Если TURN появляется на CSQTT, отсутствует bypass route.

### WinDbg/Process Explorer

Проверить:

- дочерний `client.exe` существует только в одном экземпляре;
- при отключении он завершается;
- handle Wintun закрывается;
- после закрытия приложения не остаётся default route CSQTT.

## 8. Стратегия тестирования

### 8.1. Unit tests

Рекомендуется создать `CSQTT.Windows.Tests` и покрыть:

#### CsqttLinkParser

- v2 без хешей;
- v2 с 1–6 хешами;
- `%2B` внутри хеша;
- concatenated parameters;
- legacy;
- IPv6;
- неверная версия/порт/пустой пароль;
- дубли и более шести хешей.

#### LogText

- ASCII без изменений;
- правильный UTF-8 без изменений;
- одинарный mojibake;
- двойной mojibake;
- строка с emoji и символом ✓.

#### TUNCONF

Парсер желательно вынести в отдельный класс и тестировать примерами:

```text
TUNCONF:10.66.67.4:1.1.1.1,1.0.0.1:64787
TUNCONF:10.66.66.2:8.8.8.8:60340
```

#### Worker calculation

- UI хранит общее, а не «помноженное на число хешей» количество потоков;
- ползунок предлагает значения от 9 до 108 с шагом 9;
- Rust-ядро дополнительно нормализует число до полной группы из 9 потоков;
- в ручном режиме ядро ограничивает доступный максимум числом валидных хешей;
- в Auto JS разрешено перераспределение потоков между созданными хешами.

### 8.2. Integration tests без реального сервера

Заменить `client.exe` тестовым процессом, который:

1. Печатает TURN IP.
2. Печатает `TUNCONF`.
3. Принимает UDP-пакеты.
4. Возвращает тестовый IPv4-пакет.

Системные команды рекомендуется абстрагировать интерфейсом `ICommandRunner`, чтобы тест не менял реальные routes.

### 8.3. Integration tests с тестовым сервером

Матрица:

| Сценарий | Ожидание |
|---|---|
| Правильная ссылка | READY и доступ в интернет |
| Неверный пароль | понятная ошибка, routes очищены |
| Неверный хеш | ошибка auth, Wintun закрыт |
| Отключение сети | нет зависшего UI |
| Повторное подключение | один client.exe |
| Закрытие окна | маршруты удалены |
| Два DNS | оба назначены без UDP-порта |
| Смена Wi-Fi | либо восстановление, либо контролируемый stop |

### 8.4. Ручной acceptance test

1. Сделать `route print -4` до запуска.
2. Запустить от администратора.
3. Вставить Android-ссылку.
4. Нажать «Применить» и перезапустить приложение — поля должны восстановиться.
5. Подключиться, дождаться READY.
6. Открыть несколько HTTPS-сайтов и проверить DNS.
7. Проверить внешний IP.
8. Отключиться.
9. Сравнить route table с исходной.
10. Убедиться, что `client.exe` завершён.

## 9. Типичные ошибки

### `wintun.dll` не найден

Запускался только EXE вместо полного каталога. Повторить `build.ps1` и переносить весь `publish`.

### `Access denied` от netsh

Приложение запущено без elevation или манифест удалён.

### TURN READY, но интернет отсутствует

Проверить `/32` bypass routes для peer и всех динамических TURN IP.

### `address=1.0.0.1:64787`

Неверно разобран `TUNCONF`: последний сегмент является локальным UDP-портом.

### Русский текст вида `РљР›Р...`

Проверить `StandardOutputEncoding/StandardErrorEncoding = UTF8` и вызов `LogText.Repair` до показа строки.

### После аварии пропала сеть

От имени администратора:

```powershell
netsh interface ipv4 delete route prefix=0.0.0.0/0 interface="CSQTT" store=active
route print -4
```

После этого удалить оставшиеся host routes только после точной проверки их назначения.

## 10. Безопасность

- Не печатать пароль и полную ссылку в журнал.
- Не добавлять реальный `config.json` в Git.
- Не отключать проверку TLS.
- Не загружать `wintun.dll` из случайного источника.
- Проверять SHA-256 release-архива.
- Сохранять лицензию upstream.
- Не принимать server IP/DNS без синтаксической проверки.
- Все нативные handle закрывать в `finally`, `Dispose` или `StopAsync`.

## 11. Производительность

Текущая реализация копирует каждый пакет дважды. Оптимизировать следует только после профилирования:

1. Измерить throughput и CPU.
2. Посчитать packet rate и allocations/sec.
3. Рассмотреть `ArrayPool<byte>`.
4. Уменьшить polling Wintun через read-wait event API.
5. Не внедрять unsafe zero-copy без нагрузочных и chaos-тестов.

## 12. Выпуск версии

Перед релизом:

```powershell
cargo test --release
dotnet build CSQTT.Windows.csproj -c Release
.\build.ps1
Compress-Archive -Path .\publish\* -DestinationPath ..\CSQTT-Windows-x64.zip -Force
Get-FileHash ..\CSQTT-Windows-x64.zip -Algorithm SHA256
```

Проверить чистую виртуальную машину Windows 10 и Windows 11. Архив должен содержать:

```text
CSQTT.Windows.exe
CSQTT.Windows.dll
CSQTT.Windows.deps.json
CSQTT.Windows.runtimeconfig.json
client.exe
wintun.dll
LICENSE
```

## 13. Направления дальнейшего развития

1. Формальный test project и CI.
2. Split tunneling по приложениям через Windows Filtering Platform.
3. Интерактивная WebView-капча.
4. Auto JS режим.
5. Реакция на смену физического интерфейса.
6. Tray icon и автоподключение.
7. Подписанный installer/MSIX.
8. Structured logging и экспорт support bundle.
9. Автоматическое обновление.
10. IPv6 после согласования серверного протокола.

Главный инженерный принцип проекта: платформенный слой Windows может меняться, но wire protocol должен оставаться тем же, что использует Android-клиент.
