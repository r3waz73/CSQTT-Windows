namespace Csqtt.Windows;

internal sealed class ThemeButton : Button
{
    protected override bool ShowFocusCues => false;
    protected override void OnGotFocus(EventArgs e) { base.OnGotFocus(e); Invalidate(); }
}

/// <summary>Прокручиваемая страница без системного светлого scrollbar.</summary>
internal sealed class ThemedScrollHost : UserControl
{
    private readonly Panel viewport = new() { Dock = DockStyle.Fill };
    private readonly DarkPageScrollBar scroll = new() { Dock = DockStyle.Right, Width = 13 };
    public FlowLayoutPanel Content { get; } = new()
    {
        AutoSize = true,
        FlowDirection = FlowDirection.TopDown,
        WrapContents = false,
        Location = Point.Empty
    };

    public ThemedScrollHost()
    {
        BackColor = Color.FromArgb(15, 18, 26);
        viewport.BackColor = BackColor;
        viewport.Controls.Add(Content);
        Controls.Add(viewport); Controls.Add(scroll);
        Resize += (_, _) => UpdateLayoutAndScroll();
        Content.SizeChanged += (_, _) => UpdateLayoutAndScroll();
        Content.ControlAdded += (_, e) => { if (e.Control is not null) HookPageWheel(e.Control); };
        MouseWheel += (_, e) => ScrollBy(-Math.Sign(e.Delta) * 72);
        viewport.MouseWheel += (_, e) => ScrollBy(-Math.Sign(e.Delta) * 72);
        Content.MouseWheel += (_, e) => ScrollBy(-Math.Sign(e.Delta) * 72);
        scroll.ValueChanged += value => { Content.Top = -value; scroll.SetValue(-Content.Top); };
    }

    private void HookPageWheel(Control control)
    {
        // Внутренний журнал прокручивается самостоятельно. Все остальные поля
        // передают колесо странице; особенно важно это для портов и selector-ов.
        if (control is ThemedLogView) return;
        control.MouseWheel += (_, e) => ScrollBy(-Math.Sign(e.Delta) * 72);
        control.ControlAdded += (_, e) => { if (e.Control is not null) HookPageWheel(e.Control); };
        foreach (Control child in control.Controls) HookPageWheel(child);
    }

    public void ScrollBy(int pixels)
    {
        int maximum = Math.Max(0, Content.Height - viewport.ClientSize.Height);
        int next = Math.Clamp(-Content.Top + pixels, 0, maximum);
        Content.Top = -next; scroll.SetValue(next);
    }

    private void UpdateLayoutAndScroll()
    {
        Content.Width = Math.Max(400, viewport.ClientSize.Width - 8);
        int maximum = Math.Max(0, Content.Height - viewport.ClientSize.Height);
        int current = Math.Clamp(-Content.Top, 0, maximum);
        Content.Top = -current;
        scroll.SetMetrics(maximum, viewport.ClientSize.Height, current);
    }
}

/// <summary>Owner-draw ComboBox с тёмным списком и без светлого hover.</summary>
internal sealed class DarkComboBox : ComboBox
{
    private const int WmPaint = 0x000F;
    private const int WmNcPaint = 0x0085;
    private bool arrowHovered;

    public DarkComboBox()
    {
        BackColor = Color.FromArgb(32, 38, 52);
        ForeColor = Color.FromArgb(238, 241, 248);
        FlatStyle = FlatStyle.Flat;
        DropDownStyle = ComboBoxStyle.DropDownList;
        DrawMode = DrawMode.OwnerDrawFixed;
        ItemHeight = 28;
        IntegralHeight = false;
        DropDownHeight = 224;
    }

    protected override void OnDrawItem(DrawItemEventArgs e)
    {
        if (e.Index < 0) return;
        // ComboBoxEdit означает закрытую часть selector-а. Она всегда остаётся
        // спокойной тёмной; акцент нужен только строке под курсором в списке.
        bool closedField = (e.State & DrawItemState.ComboBoxEdit) != 0;
        bool selected = !closedField && (e.State & DrawItemState.Selected) != 0;
        Color fieldColor = Color.FromArgb(32, 38, 52);
        using var background = new SolidBrush(selected ? Color.FromArgb(55, 61, 92) : closedField ? fieldColor : Color.FromArgb(24, 29, 40));
        using var foreground = new SolidBrush(Enabled ? Color.FromArgb(238, 241, 248) : Color.FromArgb(120, 130, 150));
        e.Graphics.FillRectangle(background, e.Bounds);
        TextRenderer.DrawText(e.Graphics, GetItemText(Items[e.Index]), Font,
            new Rectangle(e.Bounds.Left + 9, e.Bounds.Top, Math.Max(0, e.Bounds.Width - 12), e.Bounds.Height),
            foreground.Color, TextFormatFlags.Left | TextFormatFlags.VerticalCenter | TextFormatFlags.EndEllipsis);
    }

    protected override void OnMouseMove(MouseEventArgs e)
    {
        base.OnMouseMove(e);
        bool next = e.X >= ClientSize.Width - 32;
        if (next == arrowHovered) return;
        arrowHovered = next;
        Invalidate();
    }

    protected override void OnMouseLeave(EventArgs e)
    {
        base.OnMouseLeave(e);
        arrowHovered = false;
        Invalidate();
    }

    protected override void WndProc(ref Message m)
    {
        base.WndProc(ref m);
        if (m.Msg is WmPaint or WmNcPaint) DrawDarkChrome();
    }

    private void DrawDarkChrome()
    {
        if (!IsHandleCreated || ClientSize.Width <= 0 || ClientSize.Height <= 0) return;
        using Graphics graphics = Graphics.FromHwnd(Handle);
        int buttonWidth = Math.Min(32, ClientSize.Width);
        var button = new Rectangle(ClientSize.Width - buttonWidth, 1, buttonWidth - 1, Math.Max(0, ClientSize.Height - 2));
        Color buttonColor = !Enabled
            ? Color.FromArgb(27, 32, 44)
            : arrowHovered || DroppedDown ? Color.FromArgb(43, 49, 70) : Color.FromArgb(32, 38, 52);
        using (var fill = new SolidBrush(buttonColor)) graphics.FillRectangle(fill, button);

        int centerX = button.Left + button.Width / 2;
        int centerY = button.Top + button.Height / 2 + 1;
        Point[] arrow = [new(centerX - 5, centerY - 2), new(centerX + 5, centerY - 2), new(centerX, centerY + 3)];
        using (var arrowBrush = new SolidBrush(Enabled ? Color.FromArgb(174, 184, 204) : Color.FromArgb(93, 102, 121)))
            graphics.FillPolygon(arrowBrush, arrow);
        using var border = new Pen(DroppedDown || Focused ? Color.FromArgb(99, 102, 241) : Color.FromArgb(55, 64, 82));
        graphics.DrawRectangle(border, 0, 0, ClientSize.Width - 1, ClientSize.Height - 1);
    }

    protected override void OnMouseWheel(MouseEventArgs e)
    {
        // Закрытый selector не должен случайно менять значение при прокрутке
        // страницы. Колесо передаётся ближайшему ThemedScrollHost.
        Control? parent = Parent;
        while (parent is not null && parent is not ThemedScrollHost) parent = parent.Parent;
        if (parent is ThemedScrollHost host) host.ScrollBy(-Math.Sign(e.Delta) * 72);
    }
}

/// <summary>Минималистичный вертикальный scrollbar из общей палитры.</summary>
internal sealed class DarkPageScrollBar : Control
{
    private int maximum, page = 1, value, dragOffset;
    private bool dragging, hovering;
    public event Action<int>? ValueChanged;

    public DarkPageScrollBar()
    {
        SetStyle(ControlStyles.AllPaintingInWmPaint | ControlStyles.OptimizedDoubleBuffer | ControlStyles.UserPaint, true);
        Cursor = Cursors.Hand;
    }
    public void SetMetrics(int max, int pageSize, int current) { maximum = Math.Max(0, max); page = Math.Max(1, pageSize); value = Math.Clamp(current, 0, maximum); Visible = maximum > 0; Invalidate(); }
    public void SetValue(int current) { value = Math.Clamp(current, 0, maximum); Invalidate(); }
    protected override void OnPaint(PaintEventArgs e)
    {
        e.Graphics.Clear(Color.FromArgb(16, 20, 29)); if (maximum <= 0) return;
        using var brush = new SolidBrush(dragging || hovering ? Color.FromArgb(99, 102, 241) : Color.FromArgb(65, 74, 94));
        e.Graphics.FillRectangle(brush, Thumb());
    }
    protected override void OnMouseDown(MouseEventArgs e) { base.OnMouseDown(e); var thumb = Thumb(); if (thumb.Contains(e.Location)) { dragging = true; dragOffset = e.Y - thumb.Y; Capture = true; } else SetFromPixel(e.Y - thumb.Height / 2); }
    protected override void OnMouseMove(MouseEventArgs e) { base.OnMouseMove(e); hovering = Thumb().Contains(e.Location); if (dragging) SetFromPixel(e.Y - dragOffset); Invalidate(); }
    protected override void OnMouseUp(MouseEventArgs e) { base.OnMouseUp(e); dragging = false; Capture = false; Invalidate(); }
    protected override void OnMouseLeave(EventArgs e) { base.OnMouseLeave(e); if (!dragging) hovering = false; Invalidate(); }
    private Rectangle Thumb() { int height = Math.Min(Height, Math.Max(30, (int)(Height * page / (double)(maximum + page)))); int travel = Math.Max(0, Height - height); int top = maximum == 0 ? 0 : (int)Math.Round(travel * value / (double)maximum); return new Rectangle(3, top, Math.Max(4, Width - 6), height); }
    private void SetFromPixel(int top) { int travel = Math.Max(1, Height - Thumb().Height); int next = Math.Clamp((int)Math.Round(Math.Clamp(top, 0, travel) * maximum / (double)travel), 0, maximum); if (next == value) return; value = next; ValueChanged?.Invoke(value); Invalidate(); }
}
