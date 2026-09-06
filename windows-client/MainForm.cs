using System.Drawing.Drawing2D;
using System.Collections.Concurrent;
using System.Text;

namespace Csqtt.Windows;

/// <summary>
/// Главное окно приложения. Здесь намеренно нет сетевой логики: форма только
/// собирает ввод, сохраняет конфигурацию и вызывает TunnelController.
/// Такое разделение позволяет тестировать парсер и туннель независимо от UI.
/// </summary>
internal sealed class MainForm : Form
{
    // Палитра вынесена в одно место, чтобы студент мог изменить тему без поиска
    // цветов по всему файлу. Все цвета заданы в RGB.
    private static readonly Color Background = Color.FromArgb(15, 18, 26);
    private static readonly Color Surface = Color.FromArgb(24, 29, 40);
    private static readonly Color Surface2 = Color.FromArgb(32, 38, 52);
    private static readonly Color Accent = Color.FromArgb(99, 102, 241);
    private static readonly Color TextMain = Color.FromArgb(238, 241, 248);
    private static readonly Color TextMuted = Color.FromArgb(148, 158, 178);
    private static readonly Color Success = Color.FromArgb(45, 205, 140);

    private readonly ClientConfig cfg = ClientConfig.Load();
    private readonly TunnelController tunnel = new();
    private readonly TextBox link = Input(), peer = Input(), hashes = Input(true), password = Input(), turn = Input(), turnPort = Input(), ids = Input();
    private readonly ThemedLogView logs = new(200), deployLogs = new(500);
    private readonly NumericUpDown workers = new();
    private readonly ComboBox obfs = SelectInput(), turnTransport = SelectInput(), fingerprint = SelectInput(), auth = SelectInput(), captcha = SelectInput();
    private readonly ComboBox vkMode = SelectInput(), deployMode = SelectInput();
    private readonly ComboBox logDetail = SelectInput();
    private readonly Button toggle = Button("Подключиться", Accent), connectionNav = NavButton("◉   Туннель"), deployNav = NavButton("⇧   Развернуть"), logNav = NavButton("≡   Журнал");
    private readonly Button vkLogin = Button("Войти через VK", Color.FromArgb(0, 119, 255)), deployStart = Button("Установить на сервер", Accent);
    private readonly Label vkState = new();
    private readonly TextBox deployHost = Input(), deploySshPort = Input(), deployPeerPort = Input(), deployWebPort = Input(), deployUser = Input(), deploySshPassword = Input(), deployKey = Input(), deployKeyPass = Input(), deployBinary = Input(), deployMainPassword = Input(), deployWebLogin = Input(), deployWebPassword = Input();
    private readonly CheckBox deployBindDevice = new() { Text = "Привязать главный пароль к этому компьютеру", AutoSize = true, ForeColor = TextMain };
    private readonly ProgressBar deployProgress = new();
    private readonly LogPresenter logPresenter = new();
    private readonly ConcurrentQueue<string> pendingLogs = new();
    private readonly System.Windows.Forms.Timer logFlushTimer = new() { Interval = 200 };
    private int pendingLogCount, droppedLogCount;
    private int selectedLogLevel = (int)LogVerbosity.Standard;
    private readonly Label status = new();
    private readonly Panel connectionPage = new(), deployPage = new(), logPage = new();

    public MainForm()
    {
        // Конструктор строит дерево WinForms-контролов программно. Для небольшого
        // учебного проекта это удобнее Designer.cs и уменьшает число файлов.
        Text = "CSQTT for Windows 3.13";
        Width = 1080; Height = 760; MinimumSize = new(900, 650); StartPosition = FormStartPosition.CenterScreen;
        BackColor = Background; ForeColor = TextMain; Font = new("Segoe UI", 10); DoubleBuffered = true;

        var shell = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 2, BackColor = Background };
        shell.ColumnStyles.Add(new(SizeType.Absolute, 215)); shell.ColumnStyles.Add(new(SizeType.Percent, 100)); Controls.Add(shell);
        shell.Controls.Add(BuildSidebar(), 0, 0);
        var content = new Panel { Dock = DockStyle.Fill, Padding = new(28, 22, 28, 28) }; shell.Controls.Add(content, 1, 0);

        connectionPage.Dock = DockStyle.Fill; connectionPage.BackColor = Background;
        deployPage.Dock = DockStyle.Fill; deployPage.BackColor = Background; deployPage.Visible = false;
        logPage.Dock = DockStyle.Fill; logPage.BackColor = Background; logPage.Visible = false;
        content.Controls.Add(logPage); content.Controls.Add(deployPage); content.Controls.Add(connectionPage);
        BuildConnectionPage(); BuildDeployPage(); BuildLogPage();

        LoadConfiguration();
        connectionNav.Click += (_, _) => ShowPage(0);
        deployNav.Click += (_, _) => ShowPage(1);
        logNav.Click += (_, _) => ShowPage(2);
        vkLogin.Click += LoginVk;
        deployStart.Click += StartDeploy;
        toggle.Click += Toggle;
        tunnel.Log += value =>
        {
            var shown = logPresenter.Present(value, (LogVerbosity)Volatile.Read(ref selectedLogLevel));
            if (shown is null) return;
            EnqueueLog(shown);
        };
        logFlushTimer.Tick += (_, _) => FlushLogs();
        logFlushTimer.Start();
        tunnel.StateChanged += running => BeginInvoke(() => UpdateState(running));
        FormClosing += async (_, _) => { logFlushTimer.Stop(); await tunnel.StopAsync(); };
        ShowPage(0); UpdateState(false);
    }

    private Control BuildSidebar()
    {
        // Боковая панель не пересоздаётся при навигации: меняется только Visible
        // у двух страниц, поэтому введённые значения не теряются.
        var side = new Panel { Dock = DockStyle.Fill, BackColor = Color.FromArgb(19, 23, 33), Padding = new(18, 24, 18, 18) };
        var logo = new Label { Text = "CSQTT", Font = new("Segoe UI Semibold", 22), ForeColor = TextMain, Dock = DockStyle.Top, Height = 48, TextAlign = ContentAlignment.MiddleLeft };
        var subtitle = new Label { Text = "Windows client by komar73", Font = new("Segoe UI Semibold", 8.5f), ForeColor = Accent, Dock = DockStyle.Top, Height = 32 };
        connectionNav.Dock = DockStyle.Top; connectionNav.Height = 48; connectionNav.Margin = new(0, 8, 0, 0);
        logNav.Dock = DockStyle.Top; logNav.Height = 48;
        deployNav.Dock = DockStyle.Top; deployNav.Height = 48;
        var license = new Label { Text = "CSQTT 2.1.9\nWindows client 3.13", ForeColor = TextMuted, Dock = DockStyle.Bottom, Height = 48 };
        // DockStyle.Top располагает элементы в обратном порядке добавления.
        // Поэтому deploy добавляется раньше log и визуально оказывается ниже.
        side.Controls.Add(license); side.Controls.Add(deployNav); side.Controls.Add(logNav); side.Controls.Add(connectionNav); side.Controls.Add(subtitle); side.Controls.Add(logo);
        return side;
    }

    private void BuildConnectionPage()
    {
        // Внешний TableLayoutPanel резервирует фиксированное место под заголовок
        // и нижнюю панель, а центральная область получает прокрутку.
        var layout = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 3, BackColor = Background };
        layout.RowStyles.Add(new(SizeType.Absolute, 82)); layout.RowStyles.Add(new(SizeType.Percent, 100)); layout.RowStyles.Add(new(SizeType.Absolute, 72));
        connectionPage.Controls.Add(layout);
        var title = new Label { Text = "Подключение", Font = new("Segoe UI Semibold", 24), ForeColor = TextMain, Dock = DockStyle.Fill, TextAlign = ContentAlignment.MiddleLeft };
        layout.Controls.Add(title, 0, 0);

        var scroll = new ThemedScrollHost { Dock = DockStyle.Fill };
        var cards = scroll.Content; cards.Padding = new(0, 0, 12, 12);
        layout.Controls.Add(scroll, 0, 1);

        var quick = Card("Быстрое подключение", "Вставьте ту же ссылку csqtt://, которую используете на Android.");
        var linkRow = new TableLayoutPanel { Dock = DockStyle.Top, Height = 46, Width = 710, MinimumSize = new Size(710, 46), AutoSize = false, ColumnCount = 2 };
        linkRow.ColumnStyles.Add(new(SizeType.Percent, 100)); linkRow.ColumnStyles.Add(new(SizeType.Absolute, 128));
        link.PlaceholderText = "csqtt://connect?v=2&host=...";
        link.Dock = DockStyle.Fill;
        var apply = Button("Применить", Surface2); apply.Dock = DockStyle.Fill; apply.Click += (_, _) => ApplyLink(true);
        linkRow.Controls.Add(link, 0, 0); linkRow.Controls.Add(apply, 1, 0); quick.Controls.Add(linkRow); cards.Controls.Add(quick);

        var main = Card("Параметры туннеля", "Поля заполняются автоматически из ссылки и сохраняются между запусками.");
        var fields = FormGrid();
        AddField(fields, "Сервер", peer, "Адрес peer, например 203.0.113.10:46000");
        AddField(fields, "Режим VK", vkMode, "Автоматически через VK или вручную");
        var vkPanel = new TableLayoutPanel { Dock = DockStyle.Top, Height = 42, ColumnCount = 2 };
        vkPanel.ColumnStyles.Add(new(SizeType.Percent, 100)); vkPanel.ColumnStyles.Add(new(SizeType.Absolute, 180));
        vkState.Dock = DockStyle.Fill; vkState.TextAlign = ContentAlignment.MiddleLeft; vkState.ForeColor = TextMuted;
        vkLogin.Dock = DockStyle.Fill; vkPanel.Controls.Add(vkState, 0, 0); vkPanel.Controls.Add(vkLogin, 1, 0);
        AddField(fields, "Аккаунт VK", vkPanel, "Токен хранится зашифрованно в Windows");
        AddField(fields, "VK-хеши", hashes, "До шести хешей, разделённых запятой");
        password.UseSystemPasswordChar = true; AddField(fields, "Пароль", password, "Хранится зашифрованно средствами Windows");
        AddField(fields, "Воркеров на хеш", workers, "9 — рекомендуемое значение");
        main.Controls.Add(fields); cards.Controls.Add(main);

        var advanced = Card("Дополнительные настройки", "Меняйте их только если соответствующие параметры заданы на Android.");
        var extra = FormGrid();
        AddField(extra, "TURN host", turn); AddField(extra, "TURN port", turnPort);
        AddField(extra, "TURN-транспорт", turnTransport, "UDP рекомендуется; TCP/TLS полезен в сетях, где UDP заблокирован");
        AddField(extra, "Обфускация", obfs); AddField(extra, "TLS fingerprint", fingerprint);
        AddField(extra, "Client IDs", ids); AddField(extra, "VK auth", auth); AddField(extra, "Captcha", captcha);
        advanced.Controls.Add(extra); cards.Controls.Add(advanced);

        var footer = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 2, Padding = new(0, 12, 0, 0) };
        footer.ColumnStyles.Add(new(SizeType.Percent, 100)); footer.ColumnStyles.Add(new(SizeType.Absolute, 210));
        status.Dock = DockStyle.Fill; status.TextAlign = ContentAlignment.MiddleLeft; status.Font = new("Segoe UI Semibold", 10);
        toggle.Dock = DockStyle.Fill; footer.Controls.Add(status, 0, 0); footer.Controls.Add(toggle, 1, 0); layout.Controls.Add(footer, 0, 2);
    }

    private void BuildDeployPage()
    {
        var layout = new TableLayoutPanel { Dock = DockStyle.Fill, RowCount = 3 };
        layout.RowStyles.Add(new(SizeType.Absolute, 72)); layout.RowStyles.Add(new(SizeType.Percent, 100)); layout.RowStyles.Add(new(SizeType.Absolute, 62)); deployPage.Controls.Add(layout);
        layout.Controls.Add(new Label { Text = "Развёртывание сервера", Font = new("Segoe UI Semibold", 24), ForeColor = TextMain, Dock = DockStyle.Fill, TextAlign = ContentAlignment.MiddleLeft }, 0, 0);
        var scroll = new ThemedScrollHost { Dock = DockStyle.Fill }; layout.Controls.Add(scroll, 0, 1);
        var cards = scroll.Content;

        var sshCard = Card("Доступ к VPS", "Поддерживаются пароль, приватный SSH-ключ или оба способа."); var ssh = FormGrid();
        AddField(ssh, "Адрес VPS", deployHost); AddField(ssh, "SSH-порт", deploySshPort); AddField(ssh, "Пользователь", deployUser);
        deploySshPassword.UseSystemPasswordChar = true; AddField(ssh, "SSH-пароль", deploySshPassword);
        AddBrowseField(ssh, "Приватный ключ", deployKey, "Все файлы (*.*)|*.*"); deployKeyPass.UseSystemPasswordChar = true; AddField(ssh, "Пароль ключа", deployKeyPass);
        sshCard.Controls.Add(ssh); cards.Controls.Add(sshCard);

        var serverCard = Card("CSQTT-сервер", "Выберите Linux x86_64 musl-бинарник csqtt из сборки серверного проекта."); var server = FormGrid();
        AddBrowseField(server, "Бинарник csqtt", deployBinary, "csqtt|csqtt;csqtt.*|Все файлы (*.*)|*.*"); AddField(server, "Режим", deployMode);
        AddField(server, "Peer-порт", deployPeerPort); AddField(server, "Web-порт", deployWebPort);
        deployMainPassword.UseSystemPasswordChar = true; AddField(server, "Пароль CSQTT", deployMainPassword); AddField(server, "Web-логин", deployWebLogin); deployWebPassword.UseSystemPasswordChar = true; AddField(server, "Web-пароль", deployWebPassword);
        AddField(server, "Привязка устройства", deployBindDevice, "По умолчанию первое подключение занимает главный пароль");
        serverCard.Controls.Add(server); cards.Controls.Add(serverCard);
        var logCard = Card("Ход установки", "Вывод удалённого установщика."); deployLogs.Height = 320; deployLogs.MinimumSize = new Size(710, 320); deployLogs.Dock = DockStyle.Top; logCard.Controls.Add(deployLogs); cards.Controls.Add(logCard);

        var footer = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 2, Padding = new(0, 8, 0, 0) }; footer.ColumnStyles.Add(new(SizeType.Percent, 100)); footer.ColumnStyles.Add(new(SizeType.Absolute, 230));
        deployProgress.Dock = DockStyle.Fill; deployStart.Dock = DockStyle.Fill; footer.Controls.Add(deployProgress, 0, 0); footer.Controls.Add(deployStart, 1, 0); layout.Controls.Add(footer, 0, 2);
    }

    private void BuildLogPage()
    {
        // Журнал ReadOnly, но пользователь может выделять и копировать текст.
        var layout = new TableLayoutPanel { Dock = DockStyle.Fill, RowCount = 2 };
        layout.RowStyles.Add(new(SizeType.Absolute, 82)); layout.RowStyles.Add(new(SizeType.Percent, 100)); logPage.Controls.Add(layout);
        var header = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 3 };
        header.ColumnStyles.Add(new(SizeType.Percent, 100)); header.ColumnStyles.Add(new(SizeType.Absolute, 190)); header.ColumnStyles.Add(new(SizeType.Absolute, 120));
        header.Controls.Add(new Label { Text = "Журнал", Font = new("Segoe UI Semibold", 24), ForeColor = TextMain, Dock = DockStyle.Fill, TextAlign = ContentAlignment.MiddleLeft }, 0, 0);
        logDetail.Dock = DockStyle.Fill; logDetail.Margin = new(8, 20, 12, 20);
        var clear = Button("Очистить", Surface2); clear.Dock = DockStyle.Fill; clear.Margin = new(0, 20, 0, 20); clear.Click += (_, _) => ClearLogs(); header.Controls.Add(logDetail, 1, 0); header.Controls.Add(clear, 2, 0); layout.Controls.Add(header, 0, 0);
        logs.Dock = DockStyle.Fill;
        layout.Controls.Add(logs, 0, 1);
    }

    private void LoadConfiguration()
    {
        // UI заполняется только после создания всех контролов. Значения ComboBox
        // нормализуются по списку допустимых вариантов.
        link.Text = cfg.GetLink(); peer.Text = cfg.Peer; hashes.Text = cfg.VkHashes; password.Text = cfg.GetPassword(); turn.Text = cfg.TurnHost; turnPort.Text = cfg.TurnPort; ids.Text = cfg.ClientIds;
        workers.Minimum = 9; workers.Maximum = 27; workers.Increment = 9; workers.Value = Math.Clamp(cfg.WorkersPerHash, 9, 27); StyleNumeric(workers);
        Fill(turnTransport, ["udp", "tcp_tls"], cfg.TurnTransport); Fill(obfs, ["video", "audio"], cfg.Obfs); Fill(fingerprint, ["firefox", "chrome", "edge", "safari", "opera"], cfg.Fingerprint); Fill(auth, ["vkcalls", "legacy"], cfg.VkAuthMode); Fill(captcha, ["auto", "manual"], cfg.CaptchaMode);
        Fill(vkMode, ["Автоматически (VK)", "Вручную"], cfg.VkHashMode == "auto_js" ? "Автоматически (VK)" : "Вручную");
        vkMode.SelectedIndexChanged += (_, _) => UpdateVkControls(); UpdateVkControls();
        vkState.Text = string.IsNullOrWhiteSpace(cfg.GetVkToken()) ? "Не выполнен вход" : $"Вход выполнен{(cfg.VkUserId.Length > 0 ? " · ID " + cfg.VkUserId : "")}";
        var d = cfg.Deploy;
        // Релиз содержит штатный Linux musl-сервер. Пользовательский путь имеет
        // приоритет, но при первом запуске деплой уже готов без ручного выбора.
        string bundledServer = Path.Combine(AppContext.BaseDirectory, "csqtt");
        bool legacyBundledPath = string.Equals(Path.GetFileName(d.ServerBinaryPath), "csqtt", StringComparison.OrdinalIgnoreCase)
            && string.Equals(Path.GetFileName(Path.GetDirectoryName(d.ServerBinaryPath)), "Assets", StringComparison.OrdinalIgnoreCase);
        if ((string.IsNullOrWhiteSpace(d.ServerBinaryPath) || !File.Exists(d.ServerBinaryPath) || legacyBundledPath) && File.Exists(bundledServer))
            d.ServerBinaryPath = bundledServer;
        deployHost.Text = d.Host; deployUser.Text = d.User; deploySshPassword.Text = d.GetSshPassword(); deployKey.Text = d.PrivateKeyPath; deployKeyPass.Text = d.GetKeyPassphrase(); deployBinary.Text = d.ServerBinaryPath; deployMainPassword.Text = d.GetMainPassword(); deployWebLogin.Text = d.WebLogin; deployWebPassword.Text = d.GetWebPassword(); deployBindDevice.Checked = d.BindMainPasswordToThisDevice;
        deploySshPort.Text = d.SshPort.ToString(); deployPeerPort.Text = d.PeerPort.ToString(); deployWebPort.Text = d.WebPort.ToString(); Fill(deployMode, ["systemd", "docker"], d.Mode);
        Fill(logDetail, ["Минимум", "Средний", "Полный"], cfg.LogLevel);
        selectedLogLevel = logDetail.SelectedIndex;
        logDetail.SelectedIndexChanged += (_, _) => { Volatile.Write(ref selectedLogLevel, logDetail.SelectedIndex); cfg.LogLevel = logDetail.Text; cfg.Save(); };
    }

    private async void Toggle(object? sender, EventArgs e)
    {
        // async void допустим для обработчика события WinForms. В остальных
        // местах следует возвращать Task, чтобы ошибки можно было await-ить.
        toggle.Enabled = false;
        try
        {
            if (toggle.Text == "Отключиться") await tunnel.StopAsync();
            else
            {
                if (!string.IsNullOrWhiteSpace(link.Text) && !ApplyLink(false)) return;
                Save(); ClearLogs(); status.Text = "●  Подключение…"; status.ForeColor = Color.FromArgb(251, 191, 36);
                await tunnel.StartAsync(cfg, password.Text);
            }
        }
        catch (Exception ex) { await tunnel.StopAsync(); MessageBox.Show(this, ex.Message, "CSQTT", MessageBoxButtons.OK, MessageBoxIcon.Error); }
        finally { toggle.Enabled = true; }
    }

    private bool ApplyLink(bool notify)
    {
        // Импорт ссылки заполняет обычные поля. Дальнейший старт использует уже
        // ClientConfig и не зависит от конкретного формата ссылки.
        if (!CsqttLinkParser.TryParse(link.Text, out var parsed, out var error)) { MessageBox.Show(this, error, "CSQTT", MessageBoxButtons.OK, MessageBoxIcon.Warning); return false; }
        peer.Text = parsed!.PeerAddress; password.Text = parsed.Password; if (parsed.Hashes.Count > 0) hashes.Text = string.Join(",", parsed.Hashes); Save();
        if (notify) MessageBox.Show(this, "Конфигурация применена и сохранена", "CSQTT", MessageBoxButtons.OK, MessageBoxIcon.Information);
        return true;
    }

    private void Save(bool requireValidDeployPorts = false)
    {
        // Секреты передаются отдельно: ClientConfig.SetSecrets шифрует их перед
        // сериализацией JSON.
        cfg.Peer = peer.Text.Trim(); cfg.VkHashes = hashes.Text.Trim(); cfg.VkHashMode = vkMode.SelectedIndex == 0 ? "auto_js" : "manual"; cfg.TurnHost = turn.Text.Trim(); cfg.TurnPort = turnPort.Text.Trim(); cfg.WorkersPerHash = (int)workers.Value; cfg.TurnTransport = turnTransport.Text; cfg.Obfs = obfs.Text; cfg.Fingerprint = fingerprint.Text; cfg.ClientIds = ids.Text; cfg.VkAuthMode = auth.Text; cfg.CaptchaMode = captcha.Text; cfg.LogLevel = logDetail.Text;
        var d = cfg.Deploy; d.Host = deployHost.Text.Trim(); d.User = deployUser.Text.Trim(); d.SshPort = ParsePort(deploySshPort.Text, d.SshPort, "SSH-порт", requireValidDeployPorts); d.PrivateKeyPath = deployKey.Text.Trim(); d.ServerBinaryPath = deployBinary.Text.Trim(); d.Mode = deployMode.Text; d.PeerPort = ParsePort(deployPeerPort.Text, d.PeerPort, "Peer-порт", requireValidDeployPorts); d.WebPort = ParsePort(deployWebPort.Text, d.WebPort, "Web-порт", requireValidDeployPorts); d.WebLogin = deployWebLogin.Text.Trim(); d.BindMainPasswordToThisDevice = deployBindDevice.Checked; d.SetSecrets(deploySshPassword.Text, deployKeyPass.Text, deployMainPassword.Text, deployWebPassword.Text);
        cfg.SetSecrets(link.Text.Trim(), password.Text); cfg.Save();
    }

    private void UpdateState(bool running)
    {
        // Пока туннель активен, изменение параметров запрещено: процесс уже
        // запущен с копией этих аргументов и не увидит правки формы.
        toggle.Text = running ? "Отключиться" : "Подключиться"; toggle.BackColor = running ? Color.FromArgb(220, 70, 90) : Accent;
        status.Text = running ? "●  Туннель активен" : "●  Отключено"; status.ForeColor = running ? Success : TextMuted;
        foreach (Control control in new Control[] { link, peer, hashes, password, vkMode, vkLogin, turn, turnPort, workers, turnTransport, obfs, fingerprint, ids, auth, captcha }) control.Enabled = !running;
        if (!running) UpdateVkControls();
    }

    private void ShowPage(int page)
    {
        connectionPage.Visible = page == 0; deployPage.Visible = page == 1; logPage.Visible = page == 2;
        if (page == 0) connectionPage.BringToFront(); else if (page == 1) deployPage.BringToFront(); else logPage.BringToFront();
        connectionNav.BackColor = page == 0 ? Surface2 : Color.Transparent; deployNav.BackColor = page == 1 ? Surface2 : Color.Transparent; logNav.BackColor = page == 2 ? Surface2 : Color.Transparent;
    }

    private void UpdateVkControls()
    {
        bool automatic = vkMode.SelectedIndex == 0;
        hashes.Enabled = !automatic && toggle.Text != "Отключиться"; vkLogin.Visible = automatic;
        auth.Enabled = !automatic && toggle.Text != "Отключиться";
    }

    private void LoginVk(object? sender, EventArgs e)
    {
        using var dialog = new VkAuthForm();
        if (dialog.ShowDialog(this) != DialogResult.OK) return;
        cfg.SetVkToken(dialog.AccessToken); cfg.VkUserId = dialog.UserId; cfg.Save();
        vkState.Text = $"Вход выполнен{(dialog.UserId.Length > 0 ? " · ID " + dialog.UserId : "")}"; vkState.ForeColor = Success;
    }

    private void EnqueueLog(string line)
    {
        pendingLogs.Enqueue(line);
        int count = Interlocked.Increment(ref pendingLogCount);
        // Даже полный журнал не должен забить очередь UI при шторме повторных
        // TURN-подключений. Старейшие строки сбрасываются с явным счётчиком.
        while (count > 4000 && pendingLogs.TryDequeue(out _))
        {
            Interlocked.Decrement(ref pendingLogCount);
            Interlocked.Increment(ref droppedLogCount);
            count--;
        }
    }

    private void FlushLogs()
    {
        var batch = new StringBuilder();
        int dropped = Interlocked.Exchange(ref droppedLogCount, 0);
        if (dropped > 0) batch.AppendLine($"[WINDOWS] Пропущено {dropped} повторяющихся строк: UI защищён от переполнения");
        for (int i = 0; i < 300 && pendingLogs.TryDequeue(out string? line); i++)
        {
            Interlocked.Decrement(ref pendingLogCount);
            batch.AppendLine(line);
        }
        if (batch.Length > 0) logs.AppendText(batch.ToString());
    }

    private void ClearLogs()
    {
        while (pendingLogs.TryDequeue(out _)) Interlocked.Decrement(ref pendingLogCount);
        Interlocked.Exchange(ref droppedLogCount, 0);
        logs.Clear(); logPresenter.Reset();
    }

    private async void StartDeploy(object? sender, EventArgs e)
    {
        deployStart.Enabled = false; deployLogs.Clear(); deployProgress.Value = 0;
        try
        {
            Save(true);
            var controller = new DeployController();
            controller.Log += line => BeginInvoke(() => deployLogs.AppendText(line + Environment.NewLine));
            controller.Progress += (value, text) => BeginInvoke(() => { deployProgress.Value = Math.Clamp(value, 0, 100); deployStart.Text = text; });
            await controller.DeployAsync(cfg.Deploy, cfg.Deploy.BindMainPasswordToThisDevice ? cfg.DeviceId : "", CancellationToken.None);
            MessageBox.Show(this, "Сервер CSQTT успешно установлен", "CSQTT", MessageBoxButtons.OK, MessageBoxIcon.Information);
        }
        catch (Exception ex) { MessageBox.Show(this, ex.Message, "Ошибка развёртывания", MessageBoxButtons.OK, MessageBoxIcon.Error); }
        finally { deployStart.Enabled = true; deployStart.Text = "Установить на сервер"; }
    }

    private static int ParsePort(string text, int previous, string field, bool required)
    {
        if (int.TryParse(text.Trim(), out int value) && value is >= 1 and <= 65535) return value;
        if (!required) return previous;
        throw new ArgumentException($"{field} должен быть числом от 1 до 65535");
    }

    private static Panel Card(string title, string description)
    {
        var body = new FlowLayoutPanel { Dock = DockStyle.Top, AutoSize = true, FlowDirection = FlowDirection.TopDown, WrapContents = false };
        body.Controls.Add(new Label { Text = title, Font = new("Segoe UI Semibold", 14), ForeColor = TextMain, AutoSize = true });
        body.Controls.Add(new Label { Text = description, ForeColor = TextMuted, AutoSize = true, Margin = new(0, 3, 0, 16) });
        return new CardPanel(body) { BackColor = Surface, Padding = new(22), Margin = new(0, 0, 0, 16), Width = 760, Height = 120, AutoSize = false };
    }

    private static TableLayoutPanel FormGrid() { var grid = new TableLayoutPanel { AutoSize = false, ColumnCount = 2, Width = 710, Height = 10, MinimumSize = new Size(710, 10) }; grid.ColumnStyles.Add(new(SizeType.Absolute, 180)); grid.ColumnStyles.Add(new(SizeType.Absolute, 530)); return grid; }
    private static void AddField(TableLayoutPanel grid, string label, Control input, string hint = "") { int row = grid.RowCount++; grid.RowStyles.Add(new(SizeType.Absolute, 78)); grid.Height = grid.RowCount * 78; grid.MinimumSize = new Size(710, grid.Height); var caption = new Label { Text = label + (hint.Length > 0 ? "\n" + hint : ""), ForeColor = hint.Length > 0 ? TextMuted : TextMain, AutoSize = true, Margin = new(0, 10, 12, 10) }; input.Dock = DockStyle.Top; input.Width = 510; input.Margin = new(0, 6, 0, 8); grid.Controls.Add(caption, 0, row); grid.Controls.Add(input, 1, row); }
    private static void AddBrowseField(TableLayoutPanel grid, string label, TextBox input, string filter)
    {
        var row = new TableLayoutPanel { Dock = DockStyle.Top, Height = 40, ColumnCount = 2 }; row.ColumnStyles.Add(new(SizeType.Percent, 100)); row.ColumnStyles.Add(new(SizeType.Absolute, 110)); input.Dock = DockStyle.Fill;
        var browse = Button("Обзор…", Surface2); browse.Dock = DockStyle.Fill; browse.Click += (_, _) => { using var dialog = new OpenFileDialog { Filter = filter, CheckFileExists = true }; if (dialog.ShowDialog() == DialogResult.OK) input.Text = dialog.FileName; };
        row.Controls.Add(input, 0, 0); row.Controls.Add(browse, 1, 0); AddField(grid, label, row);
    }
    private static TextBox Input(bool multiline = false) => new() { BackColor = Surface2, ForeColor = TextMain, BorderStyle = BorderStyle.FixedSingle, Multiline = multiline, Height = multiline ? 58 : 34, Font = new("Segoe UI", 10), Margin = new(0, 4, 0, 4) };
    private static ComboBox SelectInput() => new DarkComboBox { Height = 34 };
    private static Button Button(string text, Color color) { var button = new ThemeButton { Text = text, BackColor = color, ForeColor = TextMain, FlatStyle = FlatStyle.Flat, Height = 40, Cursor = Cursors.Hand, Font = new("Segoe UI Semibold", 10), UseVisualStyleBackColor = false }; button.FlatAppearance.BorderSize = 0; button.FlatAppearance.MouseOverBackColor = color == Color.Transparent ? Surface2 : ControlPaint.Light(color, .08f); button.FlatAppearance.MouseDownBackColor = color == Color.Transparent ? Color.FromArgb(45, 50, 72) : ControlPaint.Dark(color, .08f); return button; }
    private static Button NavButton(string text) { var button = Button(text, Color.Transparent); button.TextAlign = ContentAlignment.MiddleLeft; button.Padding = new(14, 0, 0, 0); button.TabStop = false; return button; }
    private static void Fill(ComboBox box, string[] values, string selected) { box.Items.AddRange(values); box.SelectedItem = values.Contains(selected) ? selected : values[0]; }
    private static void StyleNumeric(NumericUpDown box) { box.BackColor = Surface2; box.ForeColor = TextMain; box.BorderStyle = BorderStyle.FixedSingle; box.Height = 34; }

    private class RoundedPanel : Panel
    {
        protected override void OnResize(EventArgs e) { base.OnResize(e); using var path = new GraphicsPath(); int r = 14; path.AddArc(0, 0, r, r, 180, 90); path.AddArc(Width-r, 0, r, r, 270, 90); path.AddArc(Width-r, Height-r, r, r, 0, 90); path.AddArc(0, Height-r, r, r, 90, 90); path.CloseFigure(); Region = new Region(path); }
    }
    private sealed class CardPanel : RoundedPanel
    {
        private readonly FlowLayoutPanel body;
        public CardPanel(FlowLayoutPanel content)
        {
            body = content;
            body.Dock = DockStyle.Top;
            body.Width = 716;
            Controls.Add(body);
            ResizeCard();
        }
        protected override void OnControlAdded(ControlEventArgs e)
        {
            if (e.Control is { } added && added != body && body is not null)
            {
                Controls.Remove(added);
                added.Width = Math.Max(added.Width, 710);
                body.Controls.Add(added);
                ResizeCard();
            }
            base.OnControlAdded(e);
        }
        protected override void OnResize(EventArgs e)
        {
            if (body is not null) body.Width = Math.Max(200, ClientSize.Width - Padding.Horizontal);
            base.OnResize(e);
        }
        private void ResizeCard()
        {
            body.PerformLayout();
            body.Height = body.GetPreferredSize(new Size(body.Width, 0)).Height;
            Height = Math.Max(110, body.Height + Padding.Vertical);
        }
    }
}
