using Microsoft.Web.WebView2.Core;
using Microsoft.Web.WebView2.WinForms;

namespace Csqtt.Windows;

/// <summary>
/// Встроенная OAuth-авторизация VK. Форма никогда не получает логин и пароль:
/// пользователь вводит их на странице oauth.vk.ru, а приложение перехватывает
/// только access_token из адреса возврата VK.
/// </summary>
internal sealed class VkAuthForm : Form
{
    private const string Redirect = "https://oauth.vk.ru/blank.html";
    private const string AuthUrl = "https://oauth.vk.ru/authorize?client_id=7793118&scope=1073737727&redirect_uri=https%3A%2F%2Foauth.vk.ru%2Fblank.html&display=page&response_type=token&revoke=1&v=5.199";
    private readonly WebView2 browser = new() { Dock = DockStyle.Fill };
    public string AccessToken { get; private set; } = "";
    public string UserId { get; private set; } = "";

    public VkAuthForm()
    {
        Text = "Вход в VK — CSQTT";
        Width = 820; Height = 720; MinimumSize = new(640, 540);
        StartPosition = FormStartPosition.CenterParent;
        Controls.Add(browser);
        Shown += async (_, _) => await StartAsync();
    }

    private async Task StartAsync()
    {
        try
        {
            await browser.EnsureCoreWebView2Async();
            browser.CoreWebView2.Settings.AreDevToolsEnabled = false;
            browser.CoreWebView2.Settings.IsPasswordAutosaveEnabled = false;
            browser.CoreWebView2.NavigationStarting += OnNavigation;
            browser.Source = new Uri(AuthUrl);
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, "Не удалось открыть страницу VK. Установите Microsoft Edge WebView2 Runtime.\n\n" + ex.Message, "CSQTT", MessageBoxButtons.OK, MessageBoxIcon.Error);
            DialogResult = DialogResult.Abort;
            Close();
        }
    }

    private void OnNavigation(object? sender, CoreWebView2NavigationStartingEventArgs e)
    {
        if (!e.Uri.StartsWith(Redirect, StringComparison.OrdinalIgnoreCase)) return;
        var uri = new Uri(e.Uri);
        var values = Parse(uri.Fragment.TrimStart('#'));
        if (!values.TryGetValue("access_token", out var token) || string.IsNullOrWhiteSpace(token)) return;
        e.Cancel = true;
        AccessToken = token;
        values.TryGetValue("user_id", out var userId);
        UserId = userId ?? "";
        DialogResult = DialogResult.OK;
        Close();
    }

    private static Dictionary<string, string> Parse(string value) => value
        .Split('&', StringSplitOptions.RemoveEmptyEntries)
        .Select(part => part.Split('=', 2))
        .Where(part => part.Length == 2)
        .ToDictionary(part => Uri.UnescapeDataString(part[0]), part => Uri.UnescapeDataString(part[1]), StringComparer.OrdinalIgnoreCase);
}
