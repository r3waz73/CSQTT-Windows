$ErrorActionPreference = 'Stop'
# Скрипт намеренно прерывается при первой ошибке: частично заполненный publish
# нельзя выдавать пользователю как рабочую сборку.
$root = $PSScriptRoot
$native = Join-Path $root 'native'
$archive = Join-Path $env:TEMP 'wintun-0.14.1.zip'
$unpacked = Join-Path $env:TEMP 'csqtt-wintun-0.14.1'

New-Item -ItemType Directory -Force $native | Out-Null
if (-not (Test-Path (Join-Path $native 'wintun.dll'))) {
    # Wintun — внешний нативный компонент. Он загружается только с официального
    # сайта и не коммитится в репозиторий.
    Invoke-WebRequest 'https://www.wintun.net/builds/wintun-0.14.1.zip' -OutFile $archive
    if (Test-Path $unpacked) { Remove-Item -Recurse -Force $unpacked }
    Expand-Archive $archive $unpacked
    Copy-Item (Join-Path $unpacked 'wintun\bin\amd64\wintun.dll') $native
}

if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) {
    throw 'Rust/Cargo не найден. Установите rustup с https://rustup.rs и повторите сборку.'
}

Push-Location (Join-Path $root 'Core\rust-client')
# Сначала собирается протокольное ядро. Push/Pop-Location гарантируют, что
# последующая dotnet-команда снова выполняется из корня Windows-проекта.
try { cargo build --release } finally { Pop-Location }
# Framework-dependent publish уменьшает архив; на целевом ПК нужен .NET Desktop
# Runtime 10. Для автономного пакета заменить false на true.
dotnet publish (Join-Path $root 'CSQTT.Windows.csproj') -c Release -r win-x64 --self-contained false -o (Join-Path $root 'publish')
$publish = Join-Path $root 'publish'
Copy-Item (Join-Path $native 'wintun.dll') (Join-Path $publish 'wintun.dll') -Force

$required = @('CSQTT.Windows.exe', 'CSQTT.Windows.dll', 'client.exe', 'wintun.dll', 'LICENSE')
# Финальная проверка защищает от повторения ошибки, когда publish был создан без
# wintun.dll или client.exe.
$missing = $required | Where-Object { -not (Test-Path (Join-Path $publish $_)) }
if ($missing) { throw "Сборка неполна, отсутствуют: $($missing -join ', ')" }
Write-Host "Готово: $(Join-Path $root 'publish\CSQTT.Windows.exe')"
