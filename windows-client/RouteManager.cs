using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;

namespace Csqtt.Windows;

/// <summary>
/// Настраивает IPv4-маршруты и DNS для виртуального адаптера CSQTT.
/// Главная тонкость: адреса peer, VK/OK и TURN должны идти через физический
/// шлюз, иначе транспорт попадёт внутрь собственного VPN и зациклится.
/// </summary>
internal sealed class RouteManager : IDisposable
{
    private readonly HashSet<string> bypass = new(StringComparer.OrdinalIgnoreCase);
    private readonly SemaphoreSlim routeLock = new(1, 1);
    private string? gateway;
    private int physicalIndex;

    public async Task ConfigureAsync(string ip, string dns, IEnumerable<string> protectedHosts, CancellationToken ct)
    {
        // Физическим считаем поднятый не-loopback интерфейс с IPv4-шлюзом.
        // Поиск выполняется до добавления default route через Wintun.
        var physical = NetworkInterface.GetAllNetworkInterfaces().FirstOrDefault(n =>
            n.OperationalStatus == OperationalStatus.Up &&
            n.NetworkInterfaceType != NetworkInterfaceType.Loopback &&
            n.GetIPProperties().GatewayAddresses.Any(g => g.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork));
        if (physical is null) throw new InvalidOperationException("Не найден исходный IPv4-шлюз");
        gateway = physical.GetIPProperties().GatewayAddresses.First(g => g.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork).Address.ToString();
        physicalIndex = physical.GetIPProperties().GetIPv4Properties()!.Index;

        // Имена резолвятся заранее, пока системный DNS ещё доступен напрямую.
        var addresses = new HashSet<IPAddress>();
        foreach (var host in protectedHosts.Where(x => !string.IsNullOrWhiteSpace(x)))
        {
            var bare = host.Trim();
            if (bare.StartsWith('[')) bare = bare[1..bare.IndexOf(']')];
            else if (bare.Count(c => c == ':') == 1) bare = bare[..bare.LastIndexOf(':')];
            if (IPAddress.TryParse(bare, out var parsed)) addresses.Add(parsed);
            else foreach (var resolved in await Dns.GetHostAddressesAsync(bare, ct)) if (resolved.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork) addresses.Add(resolved);
        }
        foreach (var address in addresses) await AddBypassAsync(address.ToString(), ct);
        // Сервер выдаёт клиенту один адрес, поэтому используется маска /32.
        await Exec("netsh.exe", "interface ipv4 set address name=\"CSQTT\" source=static address=" + ip + " mask=255.255.255.255", ct);
        await Exec("netsh.exe", "interface ipv4 set subinterface \"CSQTT\" mtu=1300 store=active", ct);
        var dnsServers = dns.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Select(value => IPAddress.TryParse(value, out var address) && address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork ? address.ToString() : null)
            .Where(value => value is not null)
            .Distinct()
            .ToArray();
        if (dnsServers.Length == 0) throw new InvalidOperationException($"Сервер передал некорректный DNS: {dns}");
        var dnsIndex = 1;
        foreach (var server in dnsServers)
            await Exec("netsh.exe", $"interface ipv4 add dnsservers name=\"CSQTT\" address={server} index={dnsIndex++} validate=no", ct);
        // Default route добавляется последним: к этому моменту все исключения
        // уже существуют и управляющее соединение не потеряется.
        await Exec("netsh.exe", "interface ipv4 add route prefix=0.0.0.0/0 interface=\"CSQTT\" nexthop=0.0.0.0 metric=5 store=active", ct);
    }

    /// <summary>
    /// Добавляет /32-маршрут уже после запуска туннеля. Auto JS периодически
    /// выдаёт новые TURN-серверы, поэтому статического списка при старте мало.
    /// </summary>
    public async Task<bool> AddBypassAsync(string value, CancellationToken ct)
    {
        if (!IPAddress.TryParse(value, out var address) || address.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork) return false;
        await routeLock.WaitAsync(ct);
        try
        {
            if (bypass.Contains(address.ToString())) return false;
            if (gateway is null || physicalIndex <= 0) return false;
            // /32 host route имеет больший приоритет, чем 0.0.0.0/0 через Wintun.
            await Exec("route.exe", $"ADD {address} MASK 255.255.255.255 {gateway} IF {physicalIndex} METRIC 1", ct);
            bypass.Add(address.ToString());
            return true;
        }
        finally { routeLock.Release(); }
    }

    public void Dispose()
    {
        // Очистка идёт в обратном порядке. Ошибки здесь намеренно подавляются:
        // повторное удаление отсутствующего маршрута является нормальным.
        RunQuiet("netsh.exe", "interface ipv4 delete route prefix=0.0.0.0/0 interface=\"CSQTT\" store=active");
        routeLock.Wait();
        try
        {
            if (gateway is not null) foreach (var ip in bypass) RunQuiet("route.exe", $"DELETE {ip}");
            bypass.Clear(); gateway = null; physicalIndex = 0;
        }
        finally { routeLock.Release(); }
    }
    private static async Task Exec(string file, string args, CancellationToken ct)
    {
        using var p = Process.Start(new ProcessStartInfo(file, args) { UseShellExecute = false, CreateNoWindow = true, RedirectStandardError = true, RedirectStandardOutput = true })!;
        await p.WaitForExitAsync(ct);
        if (p.ExitCode != 0)
        {
            var stderr = await p.StandardError.ReadToEndAsync(ct);
            var stdout = await p.StandardOutput.ReadToEndAsync(ct);
            throw new InvalidOperationException($"{file} {args}: {(stderr + Environment.NewLine + stdout).Trim()}");
        }
    }
    private static void RunQuiet(string file, string args) { try { Process.Start(new ProcessStartInfo(file, args) { UseShellExecute = false, CreateNoWindow = true })?.WaitForExit(3000); } catch { } }
}
