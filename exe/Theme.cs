using System;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Drawing.Text;
using System.IO;
using System.Runtime.InteropServices;
using System.Windows.Forms;

namespace ModAnzer
{
    /// <summary>RyftTiers colours (from the RyftTiers queue cards) and shared drawing helpers.</summary>
    internal static class Theme
    {
        // Same tokens as the RyftTiers queue cards and website: near-black navy, a slightly
        // lighter card, hairline borders, blue accent and an orange "ember" for warnings.
        public static readonly Color Bg = Hex("#060810");
        public static readonly Color Bg2 = Hex("#0a0d14");
        public static readonly Color Panel = Hex("#0d1117");
        public static readonly Color Panel2 = Hex("#161b22");
        public static readonly Color Row = Hex("#11161e");
        public static readonly Color Stone = Hex("#161b22");
        public static readonly Color StoneHi = Hex("#1f2630");
        public static readonly Color Purple = Hex("#3fa0f5");   // RyftTiers accent blue (name kept for MainForm)
        public static readonly Color PurpleD = Hex("#2f86d6");
        public static readonly Color PurpleDD = Hex("#0f2a45");
        public static readonly Color Text = Hex("#f0f1f3");
        public static readonly Color Muted = Hex("#9ca3af");
        public static readonly Color Dim = Hex("#6b7280");
        public static readonly Color Gold = Hex("#f97316");     // ember orange, like "Queue is closed"
        public static readonly Color Win = Hex("#4ade80");
        public static readonly Color Loss = Hex("#f87171");
        public static readonly Color Line = Color.FromArgb(18, 255, 255, 255);
        public static readonly Color LineHi = Color.FromArgb(40, 255, 255, 255);

        public static float Scale = 1f;
        public static int S(int px) { return (int)Math.Round(px * Scale); }

        public static Color Hex(string h)
        {
            h = h.TrimStart('#');
            return Color.FromArgb(Convert.ToInt32(h.Substring(0, 2), 16), Convert.ToInt32(h.Substring(2, 2), 16), Convert.ToInt32(h.Substring(4, 2), 16));
        }

        // Headings: the RyftTiers cards use a heavy geometric sans (Plus Jakarta Sans).
        // Segoe UI Bold is the closest font every Windows PC already has. The old pixel
        // font sizes were set for Silkscreen, which runs wider, so scale them down a bit.
        public static Font Pixel(float px)
        {
            return new Font("Segoe UI", px * 0.86f * Scale, FontStyle.Bold, GraphicsUnit.Pixel);
        }

        public static Font Sans(float px, FontStyle style = FontStyle.Regular)
        {
            return new Font("Segoe UI", px * Scale, style, GraphicsUnit.Pixel);
        }

        public static Font Mono(float px)
        {
            foreach (var name in new[] { "Cascadia Mono", "Consolas" })
            {
                using (var f = new Font(name, px * Scale, GraphicsUnit.Pixel))
                    if (f.Name == name) return new Font(name, px * Scale, GraphicsUnit.Pixel);
            }
            return new Font(FontFamily.GenericMonospace, px * Scale, GraphicsUnit.Pixel);
        }

        public static GraphicsPath Round(RectangleF r, float radius)
        {
            float d = Math.Min(radius * 2, Math.Min(r.Width, r.Height));
            var p = new GraphicsPath();
            if (d <= 0) { p.AddRectangle(r); return p; }
            p.AddArc(r.X, r.Y, d, d, 180, 90);
            p.AddArc(r.Right - d, r.Y, d, d, 270, 90);
            p.AddArc(r.Right - d, r.Bottom - d, d, d, 0, 90);
            p.AddArc(r.X, r.Bottom - d, d, d, 90, 90);
            p.CloseFigure();
            return p;
        }

        /// <summary>Rounded card like the RyftTiers queue card: fill, then a 1px hairline border.
        /// The corners outside the rounding are painted with <paramref name="behind"/>.</summary>
        public static void Card(Graphics g, Rectangle r, Color fill, Color border, Color behind, int radius)
        {
            using (var b = new SolidBrush(behind)) g.FillRectangle(b, r);
            var old = g.SmoothingMode;
            g.SmoothingMode = SmoothingMode.AntiAlias;
            var rf = new RectangleF(r.X + 0.5f, r.Y + 0.5f, r.Width - 1.5f, r.Height - 1.5f);
            using (var path = Round(rf, S(radius)))
            using (var b = new SolidBrush(fill))
            using (var p = new Pen(border, 1))
            {
                g.FillPath(b, path);
                g.DrawPath(p, path);
            }
            g.SmoothingMode = old;
        }

        /// <summary>Kept for callers: now draws the flat RyftTiers hairline border instead of a bevel.</summary>
        public static void Bevel(Graphics g, Rectangle r, bool outline)
        {
            using (var p = new Pen(outline ? LineHi : Line, 1))
                g.DrawRectangle(p, r.X, r.Y, r.Width - 1, r.Height - 1);
        }

        /// <summary>The soft blue (top right) and violet (bottom left) glows behind the RyftTiers cards.</summary>
        public static void Grid(Graphics g, Rectangle r)
        {
            Glow(g, r.X + r.Width * 0.88f, r.Y + r.Height * 0.08f, r.Width * 0.65f, Color.FromArgb(56, 56, 120, 240));
            Glow(g, r.X + r.Width * 0.05f, r.Y + r.Height * 0.92f, r.Width * 0.48f, Color.FromArgb(36, 109, 40, 217));
        }

        private static void Glow(Graphics g, float cx, float cy, float radius, Color c)
        {
            if (radius < 1) return;
            using (var path = new GraphicsPath())
            {
                path.AddEllipse(cx - radius, cy - radius, radius * 2, radius * 2);
                using (var b = new PathGradientBrush(path))
                {
                    b.CenterColor = c;
                    b.SurroundColors = new[] { Color.FromArgb(0, c) };
                    g.FillPath(b, path);
                }
            }
        }

        private static bool IsPixel(Font f) { return f.FontFamily.Name.StartsWith("Silkscreen"); }

        /// <summary>Width of the text as it is really drawn (no GDI+ padding).</summary>
        public static float TextWidth(Graphics g, string text, Font font)
        {
            g.TextRenderingHint = IsPixel(font) ? TextRenderingHint.SingleBitPerPixelGridFit : TextRenderingHint.ClearTypeGridFit;
            using (var sf = (StringFormat)StringFormat.GenericTypographic.Clone())
            {
                sf.FormatFlags |= StringFormatFlags.MeasureTrailingSpaces | StringFormatFlags.NoWrap;
                return g.MeasureString(text, font, PointF.Empty, sf).Width;
            }
        }

        public static void DrawText(Graphics g, string text, Font font, Color color, RectangleF r, StringAlignment h = StringAlignment.Near, StringAlignment v = StringAlignment.Center)
        {
            if (string.IsNullOrEmpty(text)) return;
            bool pixel = IsPixel(font);
            g.TextRenderingHint = pixel ? TextRenderingHint.SingleBitPerPixelGridFit : TextRenderingHint.ClearTypeGridFit;
            Font use = font;
            try
            {
                if (pixel)
                {
                    // The pixel font has no usable "..." glyph (it draws as "_") and GDI+ drops the whole
                    // line when it is taller than the box. So never trim or clip it: shrink it to fit instead.
                    float w = TextWidth(g, text, use);
                    while (w > r.Width && use.Size > 8)
                    {
                        var smaller = new Font(use.FontFamily, use.Size - 1, use.Style, GraphicsUnit.Pixel);
                        if (!ReferenceEquals(use, font)) use.Dispose();
                        use = smaller;
                        w = TextWidth(g, text, use);
                    }
                }
                using (var sf = new StringFormat(StringFormatFlags.NoWrap | (pixel ? StringFormatFlags.NoClip : 0)) { Alignment = h, LineAlignment = v, Trimming = pixel ? StringTrimming.None : StringTrimming.EllipsisCharacter })
                using (var br = new SolidBrush(color))
                    g.DrawString(text, use, br, r, sf);
            }
            finally
            {
                if (!ReferenceEquals(use, font)) use.Dispose();
            }
        }
    }

    /// <summary>Rounded button in the RyftTiers card style; selected buttons look like the status chips.</summary>
    internal class PixelButton : Control
    {
        public enum Kind { Stone, Purple }
        public Kind Style = Kind.Stone;
        public bool Selected;
        public string Subtitle = "";
        public Font TitleFont;
        public Font SubFont;
        private bool _hover, _down;

        public PixelButton()
        {
            SetStyle(ControlStyles.AllPaintingInWmPaint | ControlStyles.OptimizedDoubleBuffer | ControlStyles.UserPaint | ControlStyles.ResizeRedraw, true);
            Cursor = Cursors.Hand;
            TitleFont = Theme.Pixel(16);
            SubFont = Theme.Sans(13);
        }

        protected override void OnMouseEnter(EventArgs e) { _hover = true; Invalidate(); base.OnMouseEnter(e); }
        protected override void OnMouseLeave(EventArgs e) { _hover = false; _down = false; Invalidate(); base.OnMouseLeave(e); }
        protected override void OnMouseDown(MouseEventArgs e) { _down = true; Invalidate(); base.OnMouseDown(e); }
        protected override void OnMouseUp(MouseEventArgs e) { _down = false; Invalidate(); base.OnMouseUp(e); }
        protected override void OnEnabledChanged(EventArgs e) { Cursor = Enabled ? Cursors.Hand : Cursors.Default; Invalidate(); base.OnEnabledChanged(e); }
        protected override void OnTextChanged(EventArgs e) { Invalidate(); base.OnTextChanged(e); }

        protected override void OnPaint(PaintEventArgs e)
        {
            var g = e.Graphics;
            var r = ClientRectangle;
            bool primary = Style == Kind.Purple;
            Color fill, border;
            if (!Enabled) { fill = Theme.Panel; border = Theme.Line; }
            else if (primary) { fill = _hover ? Theme.Purple : Theme.PurpleD; border = Color.FromArgb(90, 255, 255, 255); }
            else if (Selected) { fill = Theme.PurpleDD; border = Color.FromArgb(110, Theme.Purple); }
            else { fill = _hover ? Theme.StoneHi : Theme.Stone; border = _hover ? Theme.LineHi : Theme.Line; }
            Theme.Card(g, r, fill, border, Parent != null ? Parent.BackColor : Theme.Bg, 10);
            int pad = Theme.S(16);
            int shift = _down ? Theme.S(1) : 0;
            Color fg = !Enabled ? Theme.Dim : (Selected && !primary ? Theme.Purple : Color.White);
            if (string.IsNullOrEmpty(Subtitle))
            {
                Theme.DrawText(g, Text, TitleFont, fg, new RectangleF(pad, shift, r.Width - 2 * pad, r.Height), StringAlignment.Center);
            }
            else
            {
                float th = TitleFont.GetHeight(g);
                float sh = SubFont.GetHeight(g);
                float top = (r.Height - th - sh - Theme.S(2)) / 2f + shift;
                Theme.DrawText(g, Text, TitleFont, fg, new RectangleF(pad, top, r.Width - 2 * pad, th), StringAlignment.Near, StringAlignment.Near);
                Theme.DrawText(g, Subtitle, SubFont, Enabled ? (primary ? Color.FromArgb(220, 236, 255) : Theme.Muted) : Theme.Dim,
                    new RectangleF(pad, top + th + Theme.S(2), r.Width - 2 * pad, sh), StringAlignment.Near, StringAlignment.Near);
            }
        }
    }

    /// <summary>Rounded dark card with a hairline border, like the RyftTiers queue card.</summary>
    internal class BevelPanel : Panel
    {
        public BevelPanel()
        {
            SetStyle(ControlStyles.AllPaintingInWmPaint | ControlStyles.OptimizedDoubleBuffer | ControlStyles.UserPaint | ControlStyles.ResizeRedraw, true);
            BackColor = Theme.Panel;
        }

        protected override void OnPaint(PaintEventArgs e)
        {
            Theme.Card(e.Graphics, ClientRectangle, BackColor, Theme.Line, Parent != null ? Parent.BackColor : Theme.Bg, 16);
        }
    }

    /// <summary>One number in a box, like the "Ranked players 696" boxes on the site.</summary>
    internal class StatBox : Control
    {
        public string Label = "";
        public string Value = "-";
        public Color ValueColor = Theme.Dim;
        private readonly Font _labelFont = Theme.Sans(13);
        private readonly Font _valueFont = Theme.Pixel(32);

        public StatBox()
        {
            SetStyle(ControlStyles.AllPaintingInWmPaint | ControlStyles.OptimizedDoubleBuffer | ControlStyles.UserPaint | ControlStyles.ResizeRedraw, true);
        }

        public void Set(string value, Color color) { Value = value; ValueColor = color; Invalidate(); }

        protected override void OnPaint(PaintEventArgs e)
        {
            var g = e.Graphics;
            Theme.Card(g, ClientRectangle, Theme.Panel, Theme.Line, Parent != null ? Parent.BackColor : Theme.Bg, 12);
            int h = ClientRectangle.Height;
            Theme.DrawText(g, Label, _labelFont, Theme.Muted, new RectangleF(0, Theme.S(8), Width, h * 0.38f), StringAlignment.Center);
            Theme.DrawText(g, Value, _valueFont, ValueColor, new RectangleF(Theme.S(6), h * 0.38f, Width - Theme.S(12), h * 0.56f), StringAlignment.Center);
        }
    }

    /// <summary>Text drawn with GDI+ so the embedded pixel font works.</summary>
    internal class PixelLabel : Control
    {
        public StringAlignment Align = StringAlignment.Near;

        public PixelLabel()
        {
            SetStyle(ControlStyles.AllPaintingInWmPaint | ControlStyles.OptimizedDoubleBuffer | ControlStyles.UserPaint | ControlStyles.ResizeRedraw | ControlStyles.SupportsTransparentBackColor, true);
            BackColor = Color.Transparent;
        }

        protected override void OnTextChanged(EventArgs e) { Invalidate(); base.OnTextChanged(e); }

        protected override void OnPaint(PaintEventArgs e)
        {
            Theme.DrawText(e.Graphics, Text, Font, ForeColor, new RectangleF(0, 0, Width, Height), Align, StringAlignment.Near);
        }
    }
}
