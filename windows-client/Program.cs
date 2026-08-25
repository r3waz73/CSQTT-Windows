namespace Csqtt.Windows;

/// <summary>
/// Точка входа Windows-приложения. Атрибут STAThread обязателен для WinForms,
/// буфера обмена, диалогов и других COM-компонентов пользовательского интерфейса.
/// </summary>
internal static class Program
{
    [STAThread]
    private static void Main()
    {
        ApplicationConfiguration.Initialize();
        Application.Run(new MainForm());
    }
}
