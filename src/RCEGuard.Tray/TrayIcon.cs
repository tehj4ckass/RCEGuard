using System.Runtime.InteropServices;
using RCEGuard.Tray.Model;
using Drawing = System.Drawing;
using Forms = System.Windows.Forms;

namespace RCEGuard.Tray;

/// <summary>
/// The icon in the notification area: a shield in the colour of the state, a tooltip, a menu and
/// the pop-ups for new findings. The icons are drawn here, so the application ships no image files.
/// </summary>
internal sealed class TrayIcon : IDisposable
{
    private readonly Forms.NotifyIcon icon;
    private readonly Dictionary<TrayKind, Drawing.Icon> icons = [];

    /// <summary>Creates the icon.</summary>
    /// <param name="open">Called when the user wants the window.</param>
    /// <param name="openFolder">Called when the user wants the data folder.</param>
    /// <param name="exit">Called when the user ends the tray application.</param>
    public TrayIcon(Action open, Action openFolder, Action exit)
    {
        foreach (var kind in Enum.GetValues<TrayKind>())
        {
            icons[kind] = Draw(kind);
        }

        var menu = new Forms.ContextMenuStrip();
        var openItem = new Forms.ToolStripMenuItem("Open RCEGuard", null, (_, _) => open());
        openItem.Font = new Drawing.Font(openItem.Font, Drawing.FontStyle.Bold);
        menu.Items.Add(openItem);
        menu.Items.Add(new Forms.ToolStripMenuItem("Open data folder", null, (_, _) => openFolder()));
        menu.Items.Add(new Forms.ToolStripSeparator());
        // Ending this application ends the pop-ups, not the guard: the service keeps running.
        menu.Items.Add(new Forms.ToolStripMenuItem("Exit (the guard service keeps running)", null, (_, _) => exit()));

        icon = new Forms.NotifyIcon
        {
            Icon = icons[TrayKind.NotWatching],
            Text = "RCEGuard",
            ContextMenuStrip = menu,
            Visible = true,
        };
        icon.DoubleClick += (_, _) => open();
        icon.BalloonTipClicked += (_, _) => open();
    }

    /// <summary>Shows the state: icon and tooltip.</summary>
    public void Show(TrayState state)
    {
        icon.Icon = icons[state.Kind];
        // Windows takes at most 127 characters here.
        icon.Text = state.Tooltip.Length <= 127 ? state.Tooltip : state.Tooltip[..127];
    }

    /// <summary>Shows a pop-up. Windows 10 and 11 show it as a notification and keep it in the notification centre.</summary>
    public void Toast(string title, string text) => icon.ShowBalloonTip(10_000, title, text, Forms.ToolTipIcon.Warning);

    /// <inheritdoc />
    public void Dispose()
    {
        icon.Visible = false;
        icon.Dispose();
        foreach (var drawn in icons.Values)
        {
            drawn.Dispose();
        }
    }

    /// <summary>Draws the shield for a state, 32 x 32 pixels.</summary>
    internal static Drawing.Icon Draw(TrayKind kind)
    {
        var (r, g, b) = MainWindow.ColorOf(kind);
        using var bitmap = new Drawing.Bitmap(32, 32);
        using (var graphics = Drawing.Graphics.FromImage(bitmap))
        {
            graphics.SmoothingMode = Drawing.Drawing2D.SmoothingMode.AntiAlias;
            graphics.Clear(Drawing.Color.Transparent);
            using var path = new Drawing.Drawing2D.GraphicsPath();
            // A shield: flat top, straight sides, a point at the bottom.
            path.AddPolygon(
            [
                new Drawing.PointF(16, 1), new Drawing.PointF(29, 5), new Drawing.PointF(29, 15),
                new Drawing.PointF(25, 24), new Drawing.PointF(16, 31), new Drawing.PointF(7, 24),
                new Drawing.PointF(3, 15), new Drawing.PointF(3, 5),
            ]);
            using var fill = new Drawing.SolidBrush(Drawing.Color.FromArgb(r, g, b));
            graphics.FillPath(fill, path);
            using var outline = new Drawing.Pen(Drawing.Color.FromArgb(230, 255, 255, 255), 1.5f);
            graphics.DrawPath(outline, path);

            // What the state means, readable without colour: tick, exclamation mark, bar, ring, cross.
            using var mark = new Drawing.Pen(Drawing.Color.White, 3.2f)
            {
                StartCap = Drawing.Drawing2D.LineCap.Round,
                EndCap = Drawing.Drawing2D.LineCap.Round,
                LineJoin = Drawing.Drawing2D.LineJoin.Round,
            };
            switch (kind)
            {
                case TrayKind.Watching:
                    graphics.DrawLines(mark, [new Drawing.PointF(10, 15), new Drawing.PointF(14.5f, 20), new Drawing.PointF(22, 10)]);
                    break;
                case TrayKind.Alert:
                    graphics.DrawLine(mark, 16, 8, 16, 17);
                    graphics.DrawLine(mark, 16, 22.5f, 16, 22.6f);
                    break;
                case TrayKind.Locked:
                    graphics.DrawLine(mark, 10, 15, 22, 15);
                    break;
                case TrayKind.Learning:
                    // An open ring: looking, not holding.
                    graphics.DrawEllipse(mark, 10.5f, 9, 11, 11);
                    break;
                default:
                    graphics.DrawLine(mark, 11, 10, 21, 20);
                    graphics.DrawLine(mark, 21, 10, 11, 20);
                    break;
            }
        }

        var handle = bitmap.GetHicon();
        try
        {
            // The clone owns its own copy; the handle from the bitmap has to be freed by hand.
            return (Drawing.Icon)Drawing.Icon.FromHandle(handle).Clone();
        }
        finally
        {
            DestroyIcon(handle);
        }
    }

    [DllImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool DestroyIcon(IntPtr handle);
}
