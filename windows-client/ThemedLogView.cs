using System.Runtime.InteropServices;

namespace Csqtt.Windows;

/// <summary>
/// RichTextBox без системных белых полос прокрутки. Текст переносится по ширине,
/// а справа рисуется компактный scrollbar из палитры приложения.
/// </summary>
internal sealed class ThemedLogView : UserControl
{
    private const int EmGetFirstVisibleLine = 0x00CE;
    private const int EmLineScroll = 0x00B6;
    private readonly RichTextBox text = new()
    {
        Dock = DockStyle.Fill,
        ReadOnly = true,
        WordWrap = true,
        ScrollBars = RichTextBoxScrollBars.None,
        BorderStyle = BorderStyle.None,
        BackColor = Color.FromArgb(11, 14, 21),
        ForeColor = Color.FromArgb(204, 213, 229),
        Font = new Font("Cascadia Mono", 9.5f),
        DetectUrls = false,
        HideSelection = false
    };
    private readonly DarkScrollBar scroll = new() { Dock = DockStyle.Right, Width = 13 };
    private bool syncing;
    private readonly int maxLines;

    public ThemedLogView(int maxLines = 0)
    {
        this.maxLines = Math.Max(0, maxLines);
        BackColor = text.BackColor;
        Padding = new Padding(10, 8, 3, 8);
        Controls.Add(text); Controls.Add(scroll);
        text.TextChanged += (_, _) => UpdateScroll();
        text.VScroll += (_, _) => UpdateScroll();
        text.MouseWheel += (_, e) =>
        {
            // У RichTextBox скрыты штатные полосы прокрутки, поэтому Windows
            // больше не прокручивает его колёсиком автоматически. Двигаем
            // видимую область явно и затем синхронизируем наш тёмный scrollbar.
            int configuredLines = SystemInformation.MouseWheelScrollLines;
            int lines = configuredLines < 1 ? 3 : configuredLines;
            SendMessage(text.Handle, EmLineScroll, 0, -Math.Sign(e.Delta) * lines);
            BeginInvoke(UpdateScroll);
        };
        text.Resize += (_, _) => UpdateScroll();
        scroll.ValueChanged += value =>
        {
            if (syncing || !text.IsHandleCreated) return;
            int current = (int)SendMessage(text.Handle, EmGetFirstVisibleLine, 0, 0);
            SendMessage(text.Handle, EmLineScroll, 0, value - current);
            UpdateScroll();
        };
    }

    public void AppendText(string value)
    {
        text.AppendText(value);
        TrimOldLines();
        ScrollToEnd();
    }
    public void Clear() { text.Clear(); UpdateScroll(); }
    public void ScrollToEnd()
    {
        text.SelectionStart = text.TextLength;
        text.ScrollToCaret();
        UpdateScroll();
    }

    private void TrimOldLines()
    {
        if (maxLines <= 0) return;
        int lineCount = text.GetLineFromCharIndex(text.TextLength) + 1;
        int removeLines = lineCount - maxLines;
        if (removeLines <= 0) return;
        int removeChars = text.GetFirstCharIndexFromLine(removeLines);
        if (removeChars <= 0) return;
        // Нельзя удалять через SelectedText у ReadOnly RichTextBox: Win32
        // воспринимает это как запрещённый пользовательский ввод и включает
        // системный Beep. Прямое присваивание Text является программным и тихим.
        text.Text = text.Text[removeChars..];
    }

    private void UpdateScroll()
    {
        if (!text.IsHandleCreated) return;
        int lines = Math.Max(1, text.GetLineFromCharIndex(text.TextLength) + 1);
        int visible = Math.Max(1, text.ClientSize.Height / Math.Max(1, text.Font.Height));
        int first = Math.Max(0, (int)SendMessage(text.Handle, EmGetFirstVisibleLine, 0, 0));
        syncing = true;
        scroll.SetMetrics(Math.Max(0, lines - visible), visible, first);
        syncing = false;
    }

    [DllImport("user32.dll")]
    private static extern nint SendMessage(nint hwnd, int msg, nint wParam, nint lParam);

    private sealed class DarkScrollBar : Control
    {
        private int maximum, page = 1, value;
        private bool dragging, hovering;
        private int dragOffset;
        public event Action<int>? ValueChanged;

        public DarkScrollBar()
        {
            SetStyle(ControlStyles.AllPaintingInWmPaint | ControlStyles.OptimizedDoubleBuffer | ControlStyles.UserPaint, true);
            Cursor = Cursors.Hand;
        }

        public void SetMetrics(int max, int pageSize, int current)
        {
            maximum = Math.Max(0, max); page = Math.Max(1, pageSize); value = Math.Clamp(current, 0, maximum);
            Visible = maximum > 0; Invalidate();
        }

        protected override void OnPaint(PaintEventArgs e)
        {
            e.Graphics.Clear(Color.FromArgb(16, 20, 29));
            if (maximum <= 0) return;
            Rectangle thumb = Thumb();
            using var brush = new SolidBrush(dragging || hovering ? Color.FromArgb(99, 102, 241) : Color.FromArgb(65, 74, 94));
            e.Graphics.FillRectangle(brush, thumb);
        }

        protected override void OnMouseDown(MouseEventArgs e)
        {
            base.OnMouseDown(e); Rectangle thumb = Thumb();
            if (thumb.Contains(e.Location)) { dragging = true; dragOffset = e.Y - thumb.Y; Capture = true; }
            else SetFromPixel(e.Y - thumb.Height / 2);
        }
        protected override void OnMouseMove(MouseEventArgs e)
        {
            base.OnMouseMove(e); hovering = Thumb().Contains(e.Location); if (dragging) SetFromPixel(e.Y - dragOffset); Invalidate();
        }
        protected override void OnMouseUp(MouseEventArgs e) { base.OnMouseUp(e); dragging = false; Capture = false; Invalidate(); }
        protected override void OnMouseLeave(EventArgs e) { base.OnMouseLeave(e); if (!dragging) hovering = false; Invalidate(); }

        private Rectangle Thumb()
        {
            int height = Math.Max(30, (int)(Height * (page / (double)(maximum + page))));
            height = Math.Min(Height, height);
            int travel = Math.Max(0, Height - height);
            int top = maximum == 0 ? 0 : (int)Math.Round(travel * value / (double)maximum);
            return new Rectangle(3, top, Math.Max(4, Width - 6), height);
        }
        private void SetFromPixel(int top)
        {
            int travel = Math.Max(1, Height - Thumb().Height);
            int next = Math.Clamp((int)Math.Round(Math.Clamp(top, 0, travel) * maximum / (double)travel), 0, maximum);
            if (next == value) return; value = next; ValueChanged?.Invoke(value); Invalidate();
        }
    }
}
