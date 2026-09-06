using System.Diagnostics;
using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;
using System.Text.Json;

namespace Csqtt.Windows;

/// <summary>
/// Координатор жизненного цикла туннеля. Он соединяет три независимые части:
/// Rust client.exe (протокол CSQTT), Wintun (виртуальный NIC) и Windows routes.
/// UI взаимодействует только с этим классом через Start/Stop и два события.
/// </summary>
internal sealed partial class TunnelController : IAsyncDisposable
{
    private CancellationTokenSource? cts;
    private Process? core;
    private nint adapter, session;
    private readonly RouteManager routes = new();
    private UdpClient? bridge;
    private readonly ConcurrentDictionary<string, byte> transportAddresses = new(StringComparer.OrdinalIgnoreCase);
    private readonly SemaphoreSlim dnsApplyLock = new(1, 1);
    private TaskCompletionSource<(string ip, string dns)> configReady = NewConfigWaiter();
    private string latestDns = "", appliedDns = "";
    private volatile bool routesReady;
    public event Action<string>? Log;
    public event Action<bool>? StateChanged;

    public async Task StartAsync(ClientConfig cfg, string password)
    {
        // Наличие cts означает, что экземпляр уже запущен. Это защищает от
        // двойного клика и создания двух конкурирующих default routes.
        if (cts is not null) return;
        bool autoVk = cfg.VkHashMode == "auto_js";
        if (string.IsNullOrWhiteSpace(cfg.Peer) || string.IsNullOrWhiteSpace(password))
            throw new ArgumentException("Укажите peer и пароль подключения");
        if (autoVk && string.IsNullOrWhiteSpace(cfg.GetVkToken()))
            throw new ArgumentException("Для автоматического режима сначала войдите в VK");
        if (!autoVk && string.IsNullOrWhiteSpace(cfg.VkHashes))
            throw new ArgumentException("Для ручного режима укажите VK-хеши");
        var baseDir = AppContext.BaseDirectory;
        var exe = Path.Combine(baseDir, "client.exe");
        if (!File.Exists(exe)) throw new FileNotFoundException("Не найден client.exe. Выполните build.ps1.", exe);
        if (!File.Exists(Path.Combine(baseDir, "wintun.dll"))) throw new FileNotFoundException("Не найден wintun.dll. Выполните build.ps1.");

        cts = new();
        transportAddresses.Clear();
        configReady = NewConfigWaiter();
        routesReady = false;
        latestDns = appliedDns = "";
        // После аварийного завершения адаптер может уже существовать, поэтому
        // сначала пробуем создать его, а затем открыть существующий.
        adapter = Wintun.CreateAdapter("CSQTT", "CSQTT", 0);
        if (adapter == 0) adapter = Wintun.OpenAdapter("CSQTT");
        if (adapter == 0) Wintun.ThrowLast("Не удалось создать Wintun-адаптер");
        session = Wintun.StartSession(adapter, 0x400000);
        if (session == 0) Wintun.ThrowLast("Не удалось открыть Wintun-сессию");
        // Rust-ядро уже умеет обмениваться сырыми IP-пакетами по локальному UDP.
        // Это позволяет не менять серверный протокол и не портировать TUN FD IPC.
        var corePort = ReserveUdpPort();
        bridge = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
        var coreEndpoint = new IPEndPoint(IPAddress.Loopback, corePort);
        var args = BuildArgs(cfg, password, corePort);
        var startInfo = new ProcessStartInfo(exe, args) { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true, RedirectStandardInput = true, StandardOutputEncoding = Encoding.UTF8, StandardErrorEncoding = Encoding.UTF8 };
        startInfo.Environment["CSQTT_EVENTS"] = "1";
        startInfo.Environment["TOKIO_WORKER_THREADS"] = Math.Clamp(Environment.ProcessorCount, 2, 8).ToString();
        startInfo.Environment["RAYON_NUM_THREADS"] = "2";
        core = Process.Start(startInfo)!;
        if (autoVk)
        {
            // Android-клиент использует тот же служебный кадр. Токен не попадает
            // ни в аргументы процесса, ни в журнал — только в stdin Rust-ядра.
            string json = JsonSerializer.Serialize(new { token = cfg.GetVkToken() });
            string bootstrap = Convert.ToBase64String(Encoding.UTF8.GetBytes(json));
            await core.StandardInput.WriteLineAsync("VK_JS_BOOTSTRAP:" + bootstrap);
            await core.StandardInput.FlushAsync();
        }
        // stdout и stderr читаются параллельно: события идут в stdout, а большая
        // часть диагностических сообщений Rust — в stderr.
        _ = PumpLogs(core.StandardOutput, cts.Token); _ = PumpLogs(core.StandardError, cts.Token);
        var conf = await WaitForConfigAsync(cts.Token);
        // CONFIG is printed on stdout while TURN diagnostics use stderr. Give both
        // readers a short window to collect every address learned during auth.
        await Task.Delay(750, cts.Token);
        // Если сервер успел прислать hot-DNS TUNCONF до завершения настройки
        // маршрутов, применяем сразу последнее значение, а не первый снимок.
        var newestDns = Volatile.Read(ref latestDns);
        if (!string.IsNullOrWhiteSpace(newestDns)) conf = (conf.ip, newestDns);
        var hosts = new[] { cfg.Peer, cfg.TurnHost, "api.vk.me", "api.vk.ru", "login.vk.ru", "id.vk.com", "vk.com", "vk.ru", "calls.okcdn.ru", "api.ok.ru", "api.okcdn.ru" }
            .Concat(transportAddresses.Keys)
            .ToArray();
        Log?.Invoke($"[WINDOWS] Обход VPN для транспорта: {string.Join(", ", transportAddresses.Keys.Order())}");
        await routes.ConfigureAsync(conf.ip, conf.dns, hosts, cts.Token);
        Volatile.Write(ref appliedDns, conf.dns);
        routesReady = true;
        // Закрывает ещё одну гонку: повторный TUNCONF мог прийти после чтения
        // latestDns выше, но до окончания долгой настройки маршрутов.
        await ApplyLatestDnsAsync(cts.Token);
        // Закрывает гонку между снимком hosts выше и окончанием ConfigureAsync:
        // каждый TURN IP, замеченный в этот промежуток, тоже получает /32 route.
        foreach (string address in transportAddresses.Keys)
            await TryAddTransportBypassAsync(address, cts.Token);
        // Пакетные циклы запускаются только после настройки адреса и маршрутов.
        _ = TunToCore(coreEndpoint, cts.Token); _ = CoreToTun(cts.Token);
        StateChanged?.Invoke(true);
    }

    private string BuildArgs(ClientConfig c, string password, int port)
    {
        // Сервер ожидает воркеры группами по 9. Итоговое число зависит от
        // количества хешей, но никогда не должно быть меньше одной группы.
        bool autoVk = c.VkHashMode == "auto_js";
        int hashes = c.VkHashes.Split([',', ' ', '\r', '\n'], StringSplitOptions.RemoveEmptyEntries).Take(6).Count();
        int workers = autoVk ? Math.Clamp(c.AutoWorkers, 9, 54) : Math.Max(9, c.WorkersPerHash) * Math.Max(1, hashes);
        var a = new List<string> { "-peer", c.Peer, "-n", workers.ToString(), "-listen", $"127.0.0.1:{port}", "-fingerprint", c.Fingerprint, "-client-ids", c.ClientIds, "-obfs", c.Obfs, "-turn-transport", c.TurnTransport, "-vk-auth-mode", autoVk ? "auto_js" : c.VkAuthMode, "-vk-hash-mode", autoVk ? "auto_js" : "manual", "-device-id", c.DeviceId, "-password", password, "-captcha-mode", c.CaptchaMode };
        if (autoVk) a.Add("--allow-hash-redistribution");
        else { a.Add("-vk"); a.Add(c.VkHashes); }
        if (!string.IsNullOrWhiteSpace(c.TurnHost)) { a.Add("-turn"); a.Add(c.TurnHost); }
        if (!string.IsNullOrWhiteSpace(c.TurnPort)) { a.Add("-port"); a.Add(c.TurnPort); }
        return string.Join(' ', a.Select(Quote));
    }
    private static string Quote(string s) => "\"" + s.Replace("\\", "\\\\").Replace("\"", "\\\"") + "\"";

    private static TaskCompletionSource<(string ip, string dns)> NewConfigWaiter() => new(TaskCreationOptions.RunContinuationsAsynchronously);
    private static int ReserveUdpPort()
    {
        // Привязка к порту 0 просит Windows выбрать свободный ephemeral port.
        // Сокет сразу закрывается, после чего порт занимает client.exe.
        using var socket = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
        return ((IPEndPoint)socket.Client.LocalEndPoint!).Port;
    }
    private async Task PumpLogs(StreamReader reader, CancellationToken ct)
    {
        // Помимо вывода в UI этот цикл извлекает управляющие данные из журнала:
        // TURN IP для bypass routes и TUNCONF для настройки адаптера.
        while (!ct.IsCancellationRequested && await reader.ReadLineAsync(ct) is { } line)
        {
            line = LogText.Repair(line);
            Log?.Invoke(line);
            if (line.Contains("TURN", StringComparison.OrdinalIgnoreCase) || line.Contains("Relay", StringComparison.OrdinalIgnoreCase))
                foreach (Match address in Ipv4Address().Matches(line))
                    if (IPAddress.TryParse(address.Value, out _) && transportAddresses.TryAdd(address.Value, 0))
                        await TryAddTransportBypassAsync(address.Value, ct);
            // Wire format: TUNCONF:<tunnel-ip>:<comma-separated-dns>:<local-port>.
            // The final port belongs to the core UDP listener, not to the DNS address.
            var m = TunConfigLine().Match(line);
            if (m.Success)
            {
                string nextIp = m.Groups[1].Value, nextDns = m.Groups[2].Value;
                Volatile.Write(ref latestDns, nextDns);
                bool first = configReady.TrySetResult((nextIp, nextDns));
                if (!first && routesReady && !string.Equals(Volatile.Read(ref appliedDns), nextDns, StringComparison.Ordinal))
                    await ApplyLatestDnsAsync(ct);
            }
        }
    }

    private async Task ApplyLatestDnsAsync(CancellationToken ct)
    {
        await dnsApplyLock.WaitAsync(ct);
        try
        {
            // Значение читается уже под блокировкой. Если несколько TUNCONF
            // пришли подряд, применяем только последний и не откатываем DNS
            // более поздним завершением устаревшей операции.
            string nextDns = Volatile.Read(ref latestDns);
            if (!routesReady || string.IsNullOrWhiteSpace(nextDns)
                || string.Equals(Volatile.Read(ref appliedDns), nextDns, StringComparison.Ordinal)) return;
            await routes.UpdateDnsAsync(nextDns, ct);
            Volatile.Write(ref appliedDns, nextDns);
            Log?.Invoke($"[WINDOWS] DNS обновлён без переподключения: {nextDns}");
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { }
        catch (Exception ex) { Log?.Invoke($"[WINDOWS][ПРЕДУПРЕЖДЕНИЕ] Не удалось обновить DNS: {ex.Message}"); }
        finally { dnsApplyLock.Release(); }
    }

    private async Task TryAddTransportBypassAsync(string address, CancellationToken ct)
    {
        try
        {
            if (await routes.AddBypassAsync(address, ct))
                Log?.Invoke($"[WINDOWS] Добавлен динамический обход VPN для TURN: {address}");
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { }
        catch (Exception ex) { Log?.Invoke($"[WINDOWS][ПРЕДУПРЕЖДЕНИЕ] Не удалось добавить обход для TURN {address}: {ex.Message}"); }
    }
    private async Task<(string ip, string dns)> WaitForConfigAsync(CancellationToken ct) => await configReady.Task.WaitAsync(TimeSpan.FromSeconds(90), ct);
    private async Task TunToCore(IPEndPoint coreEndpoint, CancellationToken ct)
    {
        // Направление Windows -> сервер: Wintun отдаёт сырой IPv4-пакет,
        // Marshal.Copy переносит его в managed byte[], затем пакет уходит ядру.
        while (!ct.IsCancellationRequested)
        {
            var packet = Wintun.ReceivePacket(session, out var size);
            if (packet == 0) { await Task.Delay(2, ct); continue; }
            try { var data = new byte[size]; Marshal.Copy(packet, data, 0, (int)size); await bridge!.SendAsync(data, coreEndpoint, ct); }
            finally { Wintun.ReleaseReceivePacket(session, packet); }
        }
    }
    private async Task CoreToTun(CancellationToken ct)
    {
        // Направление сервер -> Windows. Память AllocateSendPacket принадлежит
        // Wintun и после SendPacket освобождается самой библиотекой.
        while (!ct.IsCancellationRequested)
        {
            var result = await bridge!.ReceiveAsync(ct);
            var packet = Wintun.AllocateSendPacket(session, (uint)result.Buffer.Length);
            if (packet == 0) continue;
            Marshal.Copy(result.Buffer, 0, packet, result.Buffer.Length); Wintun.SendPacket(session, packet);
        }
    }
    public async Task StopAsync()
    {
        // Interlocked.Exchange делает Stop идемпотентным: только первый вызов
        // получает активный CTS и действительно выполняет очистку ресурсов.
        var old = Interlocked.Exchange(ref cts, null); if (old is null) return;
        old.Cancel(); routesReady = false; routes.Dispose(); bridge?.Dispose(); bridge = null;
        try { if (core is { HasExited: false }) { core.StandardInput.WriteLine("STOP"); if (!core.WaitForExit(2000)) core.Kill(true); } } catch { }
        core?.Dispose(); core = null;
        if (session != 0) { Wintun.EndSession(session); session = 0; }
        if (adapter != 0) { Wintun.CloseAdapter(adapter); adapter = 0; }
        old.Dispose(); StateChanged?.Invoke(false); await Task.CompletedTask;
    }
    public async ValueTask DisposeAsync() => await StopAsync();

    [GeneratedRegex(@"(?<![\d.])(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}(?![\d.])")]
    private static partial Regex Ipv4Address();
    [GeneratedRegex("TUNCONF:([^:\\s\\\"]+):([^:\\s\\\"]+)(?::\\d+)?")]
    private static partial Regex TunConfigLine();
}
