using System.Text.RegularExpressions;

namespace Csqtt.Windows;

/// <summary>Результат разбора ссылки подключения CSQTT.</summary>
internal sealed record CsqttLink(string Host, int Port, string Password, IReadOnlyList<string> Hashes)
{
    public string PeerAddress => Host.Contains(':') && !Host.StartsWith('[') ? $"[{Host}]:{Port}" : $"{Host}:{Port}";
}

/// <summary>
/// Парсер повторяет правила Android-клиента. Поддерживаются современный формат
/// csqtt://connect?v=2&amp;... и legacy-формат csqtt://password@host:port.
/// </summary>
internal static partial class CsqttLinkParser
{
    public static bool TryParse(string raw, out CsqttLink? result, out string error)
    {
        // Метод TryParse не выбрасывает исключения из-за пользовательского ввода:
        // вызывающий код получает false и текст, который можно показать в UI.
        result = null;
        error = "Некорректная ссылка CSQTT";
        var text = raw.Trim();
        if (!text.StartsWith("csqtt://", StringComparison.OrdinalIgnoreCase) ||
            !Uri.TryCreate(text, UriKind.Absolute, out var uri) ||
            !uri.Scheme.Equals("csqtt", StringComparison.OrdinalIgnoreCase) ||
            !string.IsNullOrEmpty(uri.Fragment)) return false;

        if (uri.Host.Equals("connect", StringComparison.OrdinalIgnoreCase))
            return TryParseV2(uri, out result, out error);

        if (string.IsNullOrWhiteSpace(uri.Host) || uri.Port is < 1 or > 65535 || string.IsNullOrWhiteSpace(uri.UserInfo)) return false;
        result = new(uri.Host, uri.Port, Decode(uri.UserInfo) ?? uri.UserInfo, []);
        error = "";
        return true;
    }

    private static bool TryParseV2(Uri uri, out CsqttLink? result, out string error)
    {
        result = null;
        error = "Некорректная ссылка CSQTT v2";
        if (!string.IsNullOrEmpty(uri.UserInfo) || !string.IsNullOrEmpty(uri.AbsolutePath.Trim('/')) || uri.IsDefaultPort == false) return false;
        var parameters = ParseQuery(uri.Query.TrimStart('?'));
        if (!parameters.TryGetValue("v", out var version) || Decode(version) != "2" ||
            !parameters.TryGetValue("host", out var rawHost) ||
            !parameters.TryGetValue("peer", out var rawPort) ||
            !parameters.TryGetValue("password", out var rawPassword)) return false;
        var host = Decode(rawHost);
        var password = Decode(rawPassword);
        if (string.IsNullOrWhiteSpace(host) || host.Any(char.IsWhiteSpace) || string.IsNullOrWhiteSpace(password) || password.Any(char.IsWhiteSpace) ||
            !int.TryParse(Decode(rawPort), out var port) || port is < 1 or > 65535) return false;
        var hashes = new List<string>();
        if (parameters.TryGetValue("hashes", out var rawHashes))
        {
            // Символ '+' разделяет хеши. Закодированный %2B, напротив, является
            // частью самого хеша и декодируется только после Split.
            var parts = rawHashes.Split('+');
            if (parts.Length is < 1 or > 6 || parts.Any(string.IsNullOrEmpty)) { error = "В ссылке должно быть от 1 до 6 VK-хешей"; return false; }
            foreach (var part in parts)
            {
                var hash = StripVkUrl(Decode(part) ?? "");
                if (hash.Length < 16 || hash.Any(char.IsWhiteSpace) || hashes.Contains(hash)) { error = "Ссылка содержит некорректные или повторяющиеся VK-хеши"; return false; }
                hashes.Add(hash);
            }
        }
        result = new(host, port, password, hashes);
        error = "";
        return true;
    }

    private static Dictionary<string, string> ParseQuery(string raw)
    {
        // Сначала обрабатываем нормальный query string. Второй проход регулярным
        // выражением нужен для совместимости со старыми «склеенными» ссылками.
        raw = raw.Replace("&amp;", "&", StringComparison.OrdinalIgnoreCase);
        var result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var part in raw.Split(['&', ';'], StringSplitOptions.RemoveEmptyEntries))
        {
            var at = part.IndexOf('='); if (at > 0) result[Decode(part[..at]) ?? part[..at]] = part[(at + 1)..];
        }
        if (HasRequired(result)) return result;
        result.Clear();
        foreach (Match match in ConcatenatedParameters().Matches(raw)) result[match.Groups[1].Value] = match.Groups[2].Value;
        return result;
    }
    private static bool HasRequired(Dictionary<string, string> p) => p.ContainsKey("v") && p.ContainsKey("host") && p.ContainsKey("peer") && p.ContainsKey("password");
    private static string? Decode(string value) { try { return Uri.UnescapeDataString(value.Replace("+", "%2B")); } catch { return null; } }
    private static string StripVkUrl(string input)
    {
        // В поле hashes допускается как чистый хеш, так и полная VK join-ссылка.
        var value = input.Trim();
        var match = VkJoinPrefix().Match(value); if (match.Success) value = value[match.Length..];
        var cut = value.IndexOfAny(['?', '#']); if (cut >= 0) value = value[..cut];
        return value.TrimEnd('/');
    }

    [GeneratedRegex("(?:^|[&;]|(?<=[a-zA-Z0-9_]))(v|host|peer|password|hashes)=([^&?]*?)(?=(?:v|host|peer|password|hashes)=|$)", RegexOptions.IgnoreCase)]
    private static partial Regex ConcatenatedParameters();
    [GeneratedRegex(@"^(?:https?://)?(?:m\.)?vk\.(?:com|ru)/call/join/", RegexOptions.IgnoreCase)]
    private static partial Regex VkJoinPrefix();
}
