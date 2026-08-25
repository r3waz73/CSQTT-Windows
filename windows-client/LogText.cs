using System.Text;

namespace Csqtt.Windows;

/// <summary>
/// Исправляет mojibake — текст UTF-8, ошибочно прочитанный как Windows-1251.
/// Некоторые строки исходного Rust-клиента повреждены более одного раза,
/// поэтому преобразование допускает до трёх безопасных проходов.
/// </summary>
internal static class LogText
{
    private static readonly Encoding Windows1251;

    static LogText()
    {
        Encoding.RegisterProvider(CodePagesEncodingProvider.Instance);
        Windows1251 = Encoding.GetEncoding(1251);
    }

    public static string Repair(string value)
    {
        var current = value;
        for (var attempt = 0; attempt < 3 && LooksBroken(current); attempt++)
        {
            var candidate = Encoding.UTF8.GetString(Windows1251.GetBytes(current));
            // U+FFFD означает потерю данных. В таком случае оставляем предыдущий
            // вариант строки, чтобы не испортить уже корректный русский текст.
            if (candidate.Contains('\uFFFD') || candidate == current) break;
            current = candidate;
        }
        return current;
    }

    private static bool LooksBroken(string value) =>
        value.Contains("Р", StringComparison.Ordinal) ||
        value.Contains("С", StringComparison.Ordinal) ||
        value.Contains("вЂ", StringComparison.Ordinal) ||
        value.Contains("вњ", StringComparison.Ordinal) ||
        value.Contains("â", StringComparison.Ordinal) ||
        value.Contains("Ð", StringComparison.Ordinal);
}
