using System.Text.Json;

namespace Csqtt.Windows;

/// <summary>
/// Преобразует технический журнал ядра в пользовательский. Фильтрация живёт
/// отдельно от TunnelController: полные исходные сообщения не теряются внутри
/// ядра, а UI может менять детализацию прямо во время подключения.
/// </summary>
internal sealed class LogPresenter
{
    private readonly object sync = new();
    private DateTime lastStatsAt;
    private DateTime previousSampleAt;
    private DateTime lastRetryAt, lastTurnConnectAt;
    private long previousDown, previousUp;
    private int hiddenRetries, hiddenTurnConnections;

    public string? Present(string line, LogVerbosity level)
    {
        lock (sync)
        {
            if (TryFormatStats(line, level, out var statistics)) return statistics;

            // Ядро дополнительно печатает собственную расшифровку STATS. Она
            // дублирует нашу строку, поэтому скрывается на всех уровнях.
            if (line.Contains("[СТАТИСТИКА]", StringComparison.OrdinalIgnoreCase)) return null;
            if (level == LogVerbosity.Full) return line;

            // PATH_HEALTH и внутренние CSQTT_EVENT полезны разработчику, но при
            // обычной эксплуатации быстро заполняют окно повторяющимися JSON.
            if (line.Contains("__CSQTT_EVENT__", StringComparison.Ordinal) ||
                line.Contains("PATH_HEALTH", StringComparison.OrdinalIgnoreCase)) return null;

            if (level == LogVerbosity.Standard)
            {
                DateTime now = DateTime.UtcNow;
                if (line.Contains("[TURN][RETRY]", StringComparison.OrdinalIgnoreCase))
                {
                    hiddenRetries++;
                    if (lastRetryAt != default && (now - lastRetryAt).TotalSeconds < 10) return null;
                    int hidden = Math.Max(0, hiddenRetries - 1); hiddenRetries = 0; lastRetryAt = now;
                    return hidden > 0 ? $"{line} · скрыто похожих: {hidden}" : line;
                }
                if (line.StartsWith("[TURN] Подключение к", StringComparison.OrdinalIgnoreCase))
                {
                    hiddenTurnConnections++;
                    if (lastTurnConnectAt != default && (now - lastTurnConnectAt).TotalSeconds < 10) return null;
                    int hidden = Math.Max(0, hiddenTurnConnections - 1); hiddenTurnConnections = 0; lastTurnConnectAt = now;
                    return hidden > 0 ? $"{line} · скрыто похожих: {hidden}" : line;
                }
                if (line.Contains("[READ]", StringComparison.OrdinalIgnoreCase) ||
                    line.Contains("[DIRECT]", StringComparison.OrdinalIgnoreCase)) return null;
                return line;
            }

            // Минимальный уровень: состояние жизненного цикла, предупреждения,
            // ошибки и периодическая сводка трафика/потоков.
            string lower = line.ToLowerInvariant();
            string[] important = ["[windows]", "ошиб", "error", "warning", "предуп", "подключ", "отключ", "сессия готова", "туннель", "tunconf", "relay", "готов к передаче"];
            return important.Any(lower.Contains) ? line : null;
        }
    }

    public void Reset()
    {
        lock (sync) { lastStatsAt = previousSampleAt = lastRetryAt = lastTurnConnectAt = default; previousDown = previousUp = 0; hiddenRetries = hiddenTurnConnections = 0; }
    }

    private bool TryFormatStats(string line, LogVerbosity level, out string? formatted)
    {
        formatted = null;
        const string marker = "|STATS|";
        int markerAt = line.IndexOf(marker, StringComparison.Ordinal);
        if (markerAt < 0 || !line.Contains("__CSQTT_EVENT__", StringComparison.Ordinal)) return false;
        try
        {
            using var json = JsonDocument.Parse(line[(markerAt + marker.Length)..]);
            int active = json.RootElement.GetProperty("active").GetInt32();
            long down = json.RootElement.GetProperty("bytes_down").GetInt64();
            long up = json.RootElement.GetProperty("bytes_up").GetInt64();
            DateTime now = DateTime.UtcNow;
            double seconds = previousSampleAt == default ? 0 : Math.Max(.001, (now - previousSampleAt).TotalSeconds);
            double downSpeed = seconds == 0 ? 0 : Math.Max(0, down - previousDown) * 8 / seconds;
            double upSpeed = seconds == 0 ? 0 : Math.Max(0, up - previousUp) * 8 / seconds;
            previousSampleAt = now; previousDown = down; previousUp = up;

            double interval = level switch { LogVerbosity.Minimum => 5, LogVerbosity.Standard => 3, _ => 1 };
            if (lastStatsAt != default && (now - lastStatsAt).TotalSeconds < interval) return true;
            lastStatsAt = now;
            string speed = seconds > 0 ? $" · скорость ↓ {Rate(downSpeed)}  ↑ {Rate(upSpeed)}" : "";
            formatted = $"[СОСТОЯНИЕ] Потоки: {active} · получено ↓ {Size(down)} · отправлено ↑ {Size(up)}{speed}";
        }
        catch
        {
            // При изменении формата события полный режим всё равно покажет сырой
            // JSON, а сокращённые режимы безопасно пропустят непонятную строку.
            formatted = level == LogVerbosity.Full ? line : null;
        }
        return true;
    }

    private static string Size(long bytes) => bytes switch
    {
        >= 1_073_741_824 => $"{bytes / 1_073_741_824d:0.00} ГБ",
        >= 1_048_576 => $"{bytes / 1_048_576d:0.00} МБ",
        >= 1024 => $"{bytes / 1024d:0.0} КБ",
        _ => $"{bytes} Б"
    };
    private static string Rate(double bits) => bits >= 1_000_000 ? $"{bits / 1_000_000:0.00} Мбит/с" : bits >= 1000 ? $"{bits / 1000:0.0} Кбит/с" : $"{bits:0} бит/с";
}

internal enum LogVerbosity { Minimum, Standard, Full }
