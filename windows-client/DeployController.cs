using System.Text;
using System.Text.Json;
using Renci.SshNet;

namespace Csqtt.Windows;

/// <summary>
/// Устанавливает сервер CSQTT тем же способом, что Android-клиент: четыре
/// временных файла загружаются по SFTP, после чего deploy.sh запускается от root.
/// Контроллер не знает ничего о WinForms и сообщает ход работы через Progress.
/// </summary>
internal sealed class DeployController
{
    public event Action<string>? Log;
    public event Action<int, string>? Progress;

    public async Task DeployAsync(DeployConfig cfg, string deviceId, CancellationToken ct)
    {
        Validate(cfg);
        await Task.Run(() => Deploy(cfg, deviceId, ct), ct);
    }

    private void Deploy(DeployConfig cfg, string deviceId, CancellationToken ct)
    {
        Progress?.Invoke(2, "Подключение по SSH…");
        var connection = BuildConnection(cfg);
        using var ssh = new SshClient(connection);
        using var sftp = new SftpClient(connection);
        // Как и Android-приложение, текущая версия принимает host key. Его SHA256
        // обязательно показывается в журнале, чтобы администратор мог сверить ключ.
        ssh.HostKeyReceived += (_, e) => { Log?.Invoke($"SSH host key: {e.FingerPrintSHA256}"); e.CanTrust = true; };
        sftp.HostKeyReceived += (_, e) => e.CanTrust = true;
        ssh.Connect(); ct.ThrowIfCancellationRequested();
        sftp.Connect(); Log?.Invoke("SSH-соединение установлено");

        string temp = Path.Combine(Path.GetTempPath(), "csqtt-deploy-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(temp);
        try
        {
            string env = Path.Combine(temp, "csqtt.env");
            string json = Path.Combine(temp, "csqtt-deploy.json");
            string script = Path.Combine(temp, "deploy.sh");
            // Репозиторий может быть checkout-нут на Windows с core.autocrlf.
            // Bash воспринимает CR как часть команды (`$'\r': command not found`),
            // поэтому перед SFTP всегда создаём отдельную LF-копию скрипта.
            string bundledScript = Path.Combine(AppContext.BaseDirectory, "Assets", "deploy.sh");
            string scriptText = File.ReadAllText(bundledScript).Replace("\r\n", "\n").Replace('\r', '\n');
            File.WriteAllText(script, scriptText, new UTF8Encoding(false));
            File.WriteAllText(env, $"CSQTT_WEB_USER={Env(cfg.WebLogin)}\nCSQTT_WEB_PASS={Env(cfg.GetWebPassword())}\n", new UTF8Encoding(false));
            File.WriteAllText(json, JsonSerializer.Serialize(new { main_password = cfg.GetMainPassword(), device_id = deviceId, dns = string.Join(',', new[] { cfg.Dns1, cfg.Dns2 }.Where(x => !string.IsNullOrWhiteSpace(x))) }), new UTF8Encoding(false));
            Progress?.Invoke(8, "Загрузка файлов…");
            Upload(sftp, script, "/tmp/deploy.sh", 10);
            Upload(sftp, cfg.ServerBinaryPath, "/tmp/csqtt", 35);
            Upload(sftp, env, "/tmp/csqtt.env", 55);
            Upload(sftp, json, "/tmp/csqtt-deploy.json", 60);
            ct.ThrowIfCancellationRequested();

            Progress?.Invoke(65, "Установка сервера…");
            string install = $"env CSQTT_PEER_PORT={cfg.PeerPort} CSQTT_SSH_PORT={cfg.SshPort} CSQTT_WEB_PORT={cfg.WebPort} CSQTT_DEPLOY_MODE={cfg.Mode} bash /tmp/deploy.sh";
            string command = cfg.User == "root" ? install : $"printf '%s\\n' {Sh(cfg.GetSshPassword())} | sudo -S -- sh -c {Sh(install)}";
            using var cmd = ssh.CreateCommand(command);
            cmd.CommandTimeout = TimeSpan.FromMinutes(20);
            string output = cmd.Execute();
            string all = output + Environment.NewLine + cmd.Error;
            foreach (string line in all.Split('\n'))
            {
                string value = line.TrimEnd('\r');
                if (value.Length > 0) Log?.Invoke(value);
            }
            if (cmd.ExitStatus != 0 || !all.Split('\n').Any(x => x.Trim() == "CSQTT_DEPLOY_OK"))
                throw new InvalidOperationException($"Установщик завершился с кодом {cmd.ExitStatus} и не вернул CSQTT_DEPLOY_OK");
            Progress?.Invoke(100, "Сервер установлен");
        }
        finally
        {
            try { Directory.Delete(temp, true); } catch { }
        }
    }

    private ConnectionInfo BuildConnection(DeployConfig cfg)
    {
        var methods = new List<AuthenticationMethod>();
        if (!string.IsNullOrWhiteSpace(cfg.PrivateKeyPath))
        {
            var key = string.IsNullOrEmpty(cfg.GetKeyPassphrase()) ? new PrivateKeyFile(cfg.PrivateKeyPath) : new PrivateKeyFile(cfg.PrivateKeyPath, cfg.GetKeyPassphrase());
            methods.Add(new PrivateKeyAuthenticationMethod(cfg.User, key));
        }
        if (!string.IsNullOrEmpty(cfg.GetSshPassword())) methods.Add(new PasswordAuthenticationMethod(cfg.User, cfg.GetSshPassword()));
        return new ConnectionInfo(cfg.Host, cfg.SshPort, cfg.User, methods.ToArray()) { Timeout = TimeSpan.FromSeconds(30) };
    }

    private void Upload(SftpClient client, string local, string remote, int percent)
    {
        Log?.Invoke($"Загрузка {Path.GetFileName(local)}");
        using var stream = File.OpenRead(local);
        client.UploadFile(stream, remote, true);
        Progress?.Invoke(percent, $"Загружен {Path.GetFileName(local)}");
    }

    private static void Validate(DeployConfig c)
    {
        if (string.IsNullOrWhiteSpace(c.Host) || string.IsNullOrWhiteSpace(c.User)) throw new ArgumentException("Укажите адрес и пользователя SSH");
        if (!File.Exists(c.ServerBinaryPath)) throw new FileNotFoundException("Выберите Linux-бинарник сервера csqtt", c.ServerBinaryPath);
        string script = Path.Combine(AppContext.BaseDirectory, "Assets", "deploy.sh");
        if (!File.Exists(script)) throw new FileNotFoundException("Не найден Assets/deploy.sh", script);
        if (string.IsNullOrWhiteSpace(c.GetMainPassword())) throw new ArgumentException("Укажите основной пароль CSQTT");
        if (string.IsNullOrWhiteSpace(c.GetWebPassword())) throw new ArgumentException("Укажите пароль веб-панели");
        if (string.IsNullOrWhiteSpace(c.GetSshPassword()) && string.IsNullOrWhiteSpace(c.PrivateKeyPath)) throw new ArgumentException("Укажите SSH-пароль или приватный ключ");
    }
    private static string Env(string s) => "'" + s.Replace("'", "'\\''") + "'";
    private static string Sh(string s) => "'" + s.Replace("'", "'\\''") + "'";
}
