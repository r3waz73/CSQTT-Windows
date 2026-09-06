using System.Text.Json;

namespace Csqtt.Windows;

/// <summary>
/// Сериализуемая конфигурация Windows-оболочки. Обычные параметры записываются
/// в JSON, а ссылка и пароль сначала передаются в ProtectedStore.
/// </summary>
public sealed class ClientConfig
{
    public string Peer { get; set; } = "";
    public string VkHashes { get; set; } = "";
    public string TurnHost { get; set; } = "";
    public string TurnPort { get; set; } = "";
    public int WorkersPerHash { get; set; } = 9;
    public string Obfs { get; set; } = "video";
    // Начиная с CSQTT 2.1 сервер и клиент умеют работать через TURN UDP либо
    // TURN TCP/TLS. Значение совпадает с Android и напрямую передаётся ядру.
    public string TurnTransport { get; set; } = "udp";
    public string Fingerprint { get; set; } = "firefox";
    public string ClientIds { get; set; } = "8202606,6287487";
    public string VkAuthMode { get; set; } = "vkcalls";
    public string VkHashMode { get; set; } = "manual";
    public int AutoWorkers { get; set; } = 18;
    public string CaptchaMode { get; set; } = "auto";
    public string LogLevel { get; set; } = "Средний";
    public string DeviceId { get; set; } = Guid.NewGuid().ToString("N");
    public string ProtectedLink { get; set; } = "";
    public string ProtectedPassword { get; set; } = "";
    public string ProtectedVkToken { get; set; } = "";
    public string VkUserId { get; set; } = "";
    public bool LegacyWebPortDefaultMigrated { get; set; }
    public DeployConfig Deploy { get; set; } = new();

    public string GetLink() => ProtectedStore.Decrypt(ProtectedLink);
    public string GetPassword() => ProtectedStore.Decrypt(ProtectedPassword);
    public string GetVkToken() => ProtectedStore.Decrypt(ProtectedVkToken);
    public void SetVkToken(string token) => ProtectedVkToken = ProtectedStore.Encrypt(token);
    public void SetSecrets(string link, string password)
    {
        ProtectedLink = ProtectedStore.Encrypt(link);
        ProtectedPassword = ProtectedStore.Encrypt(password);
    }

    // LocalApplicationData выбран намеренно: файл относится к конкретному
    // пользователю Windows и не требует прав администратора для записи.
    public static string PathName => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "CSQTT", "config.json");
    public static ClientConfig Load()
    {
        // Повреждённый или отсутствующий JSON не должен мешать запуску UI:
        // в таком случае возвращаем конфигурацию со значениями по умолчанию.
        try
        {
            var config = JsonSerializer.Deserialize<ClientConfig>(File.ReadAllText(PathName)) ?? new();
            // Первые Windows-сборки ошибочно использовали 8080, хотя Android и
            // deploy.sh используют 46002. Только это конкретное старое значение
            // мигрируется; любой другой выбранный пользователем порт сохраняется.
            if (!config.LegacyWebPortDefaultMigrated)
            {
                if (config.Deploy.WebPort == 8080) config.Deploy.WebPort = 46002;
                config.LegacyWebPortDefaultMigrated = true;
            }
            return config;
        }
        catch { return new(); }
    }
    public void Save()
    {
        // Каталог создаётся лениво при первом сохранении.
        Directory.CreateDirectory(Path.GetDirectoryName(PathName)!);
        File.WriteAllText(PathName, JsonSerializer.Serialize(this, new JsonSerializerOptions { WriteIndented = true }));
    }
}

/// <summary>Сохранённые параметры удалённого сервера. Пароли защищены DPAPI.</summary>
public sealed class DeployConfig
{
    public string Host { get; set; } = "";
    public int SshPort { get; set; } = 22;
    public string User { get; set; } = "root";
    public string PrivateKeyPath { get; set; } = "";
    public string ServerBinaryPath { get; set; } = "";
    public string Mode { get; set; } = "systemd";
    public int PeerPort { get; set; } = 46000;
    public int WebPort { get; set; } = 46002;
    public string WebLogin { get; set; } = "admin";
    // Оставлены для чтения конфигураций Windows 3.12. В CSQTT 2.1.9 DNS
    // выбирается в web-панели сервера и хранится в его SQLite-базе.
    public string Dns1 { get; set; } = "";
    public string Dns2 { get; set; } = "";
    public string CertificatePath { get; set; } = "";
    public bool BindMainPasswordToThisDevice { get; set; } = false;
    public string ProtectedSshPassword { get; set; } = "";
    public string ProtectedKeyPassphrase { get; set; } = "";
    public string ProtectedMainPassword { get; set; } = "";
    public string ProtectedWebPassword { get; set; } = "";
    public string GetSshPassword() => ProtectedStore.Decrypt(ProtectedSshPassword);
    public string GetKeyPassphrase() => ProtectedStore.Decrypt(ProtectedKeyPassphrase);
    public string GetMainPassword() => ProtectedStore.Decrypt(ProtectedMainPassword);
    public string GetWebPassword() => ProtectedStore.Decrypt(ProtectedWebPassword);
    public void SetSecrets(string ssh, string key, string main, string web)
    {
        ProtectedSshPassword = ProtectedStore.Encrypt(ssh);
        ProtectedKeyPassphrase = ProtectedStore.Encrypt(key);
        ProtectedMainPassword = ProtectedStore.Encrypt(main);
        ProtectedWebPassword = ProtectedStore.Encrypt(web);
    }
}
