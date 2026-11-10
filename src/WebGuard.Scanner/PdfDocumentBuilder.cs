using System.Globalization;
using System.IO.Compression;
using System.Text;

namespace WebGuard.Scanner;

/// <summary>An sRGB colour for PDF text and fills (0–1 per channel).</summary>
public readonly record struct PdfColor(double R, double G, double B)
{
    public static PdfColor Black { get; } = new(0.12, 0.13, 0.16);
    public static PdfColor Gray { get; } = new(0.42, 0.45, 0.50);
    public static PdfColor White { get; } = new(1, 1, 1);

    public static PdfColor FromHex(string hex)
    {
        ArgumentNullException.ThrowIfNull(hex);
        var v = Convert.ToInt32(hex.TrimStart('#'), 16);
        return new PdfColor(((v >> 16) & 0xFF) / 255.0, ((v >> 8) & 0xFF) / 255.0, (v & 0xFF) / 255.0);
    }
}

public enum PdfFont { Regular, Bold, Mono }

/// <summary>One table cell: text, optional colour and font, and an optional smaller grey note below it.</summary>
public sealed record PdfCell(string Text, PdfColor? Color = null, PdfFont Font = PdfFont.Regular, string? Note = null);

public sealed record PdfColumn(string Header, double Width);

/// <summary>
/// Minimal PDF 1.4 writer (no dependencies): A4 pages, the standard Helvetica and Courier fonts with WinAnsi encoding,
/// wrapped paragraphs, key/value lists and tables that continue on the next page with their header repeated, plus a
/// footer with page numbers. Text outside WinAnsi is replaced with '?'.
/// </summary>
public sealed class PdfDocumentBuilder
{
    public const double PageWidth = 595.28;
    public const double PageHeight = 841.89;
    public const double Margin = 40;
    private const double FooterHeight = 26;
    private readonly List<StringBuilder> _pages = [];
    private StringBuilder _page = null!;
    private double _y;

    public PdfDocumentBuilder() => NewPage();

    public const double ContentWidth = PageWidth - 2 * Margin;

    /// <summary>Text drawn left in every footer (the page number is drawn right).</summary>
    public string FooterText { get; set; } = string.Empty;

    public void NewPage()
    {
        _page = new StringBuilder();
        _pages.Add(_page);
        _y = PageHeight - Margin;
    }

    /// <summary>Full-width coloured band with a title and subtitle at the top of the current page.</summary>
    public void TitleBand(string title, string subtitle, PdfColor band)
    {
        const double height = 64;
        Rect(0, PageHeight - height, PageWidth, height, band);
        Text(Margin, PageHeight - 30, title, PdfFont.Bold, 18, PdfColor.White);
        Text(Margin, PageHeight - 48, subtitle, PdfFont.Regular, 10, new PdfColor(0.85, 0.89, 0.97));
        _y = PageHeight - height - 22;
    }

    public void Heading(string text)
    {
        Ensure(40);
        _y -= 8;
        Text(Margin, _y - 12, text, PdfFont.Bold, 13, PdfColor.Black);
        _y -= 18;
        Rect(Margin, _y, ContentWidth, 0.7, new PdfColor(0.80, 0.83, 0.88));
        _y -= 8;
    }

    public void Paragraph(string text, double size = 9.5, PdfColor? color = null, PdfFont font = PdfFont.Regular, double indent = 0)
    {
        foreach (var line in Wrap(text, font, size, ContentWidth - indent))
        {
            Ensure(size * 1.35);
            Text(Margin + indent, _y - size, line, font, size, color ?? PdfColor.Black);
            _y -= size * 1.35;
        }
        _y -= 4;
    }

    /// <summary>
    /// Start of an entry: a coloured bar with a bold tag (e.g. "AI analysis") and a bold title; kept on one page with
    /// at least a few lines of what follows.
    /// </summary>
    public void EntryHeader(string tag, PdfColor tagColor, string title, string? meta = null)
    {
        const double size = 10;
        var tagWidth = Width(tag, PdfFont.Bold, 8) + 12;
        var lines = Wrap(title, PdfFont.Bold, size, ContentWidth - tagWidth - 8);
        Ensure(lines.Count * size * 1.35 + 60);
        _y -= 6;
        Rect(Margin, _y - lines.Count * size * 1.35 - 2, 2.5, lines.Count * size * 1.35 + 2, tagColor);
        Rect(Margin + 8, _y - 12, tagWidth, 12, tagColor);
        Text(Margin + 14, _y - 9, tag, PdfFont.Bold, 8, PdfColor.White);
        foreach (var line in lines)
        {
            Text(Margin + 8 + tagWidth + 6, _y - size, line, PdfFont.Bold, size, PdfColor.Black);
            _y -= size * 1.35;
        }
        if (!string.IsNullOrWhiteSpace(meta)) Paragraph(meta, 8, PdfColor.Gray, indent: 8);
        else _y -= 2;
    }

    /// <summary>Small grey caps label above a block.</summary>
    public void Label(string text, double indent = 8)
    {
        Ensure(24);
        Text(Margin + indent, _y - 8, text.ToUpperInvariant(), PdfFont.Bold, 7, PdfColor.Gray);
        _y -= 12;
    }

    /// <summary>
    /// Monospaced block on a light background. With <paramref name="diff"/>, lines starting with '+' or '-' are
    /// tinted green or red and '@@' lines blue. Very long blocks are cut after <paramref name="maxLines"/> lines.
    /// </summary>
    public void CodeBlock(string text, bool diff = false, double indent = 8, int maxLines = 300)
    {
        const double size = 7.2;
        const double line = size * 1.4;
        const double pad = 4;
        var width = ContentWidth - indent;
        var lines = new List<(string Text, char Kind)>();
        foreach (var raw in (text ?? string.Empty).Replace("\r", string.Empty, StringComparison.Ordinal).TrimEnd('\n').Split('\n'))
        {
            var kind = !diff || raw.Length == 0 ? ' '
                : raw.StartsWith("@@", StringComparison.Ordinal) ? '@'
                : raw.StartsWith("+++", StringComparison.Ordinal) || raw.StartsWith("---", StringComparison.Ordinal) ? 'h'
                : raw[0] is '+' or '-' ? raw[0] : ' ';
            // Monospaced: cut by character count so indentation is kept exactly.
            var perLine = Math.Max(10, (int)((width - 2 * pad) / (0.6 * size)));
            var expanded = raw.Replace("\t", "    ", StringComparison.Ordinal);
            if (expanded.Length == 0) lines.Add((" ", kind));
            for (var at = 0; at < expanded.Length; at += perLine) lines.Add((expanded.Substring(at, Math.Min(perLine, expanded.Length - at)), kind));
        }
        var hidden = Math.Max(0, lines.Count - maxLines);
        if (hidden > 0) lines = [.. lines.Take(maxLines), ($"… {hidden} more line(s) not shown", 'h')];
        _y -= 1;
        foreach (var (content, kind) in lines)
        {
            Ensure(line);
            var (bg, fg) = kind switch
            {
                '+' => (new PdfColor(0.90, 0.97, 0.91), PdfColor.FromHex("#166534")),
                '-' => (new PdfColor(0.99, 0.92, 0.92), PdfColor.FromHex("#991B1B")),
                '@' => (new PdfColor(0.92, 0.94, 0.99), PdfColor.FromHex("#1E40AF")),
                'h' => (new PdfColor(0.95, 0.955, 0.965), PdfColor.Gray),
                _ => (new PdfColor(0.965, 0.97, 0.978), PdfColor.Black),
            };
            Rect(Margin + indent, _y - line, width, line, bg);
            // Baseline well inside the row so descenders (_, g, p) are not covered by the next row's background.
            Text(Margin + indent + pad, _y - line + 2.8, content, PdfFont.Mono, size, fg);
            _y -= line;
        }
        _y -= 6;
    }

    /// <summary>Thin separator between entries.</summary>
    public void Divider()
    {
        Ensure(10);
        Rect(Margin, _y - 4, ContentWidth, 0.5, new PdfColor(0.86, 0.88, 0.91));
        _y -= 10;
    }

    /// <summary>Two-column list: bold labels, wrapped values.</summary>
    public void KeyValues(IEnumerable<(string Key, string Value, PdfColor? Color)> items, double labelWidth = 120)
    {
        ArgumentNullException.ThrowIfNull(items);
        const double size = 9.5;
        foreach (var (key, value, color) in items)
        {
            var lines = Wrap(value, PdfFont.Regular, size, ContentWidth - labelWidth);
            Ensure(size * 1.4 * Math.Min(lines.Count, 3));
            Text(Margin, _y - size, key, PdfFont.Bold, size, PdfColor.Gray);
            foreach (var line in lines)
            {
                Ensure(size * 1.4);
                Text(Margin + labelWidth, _y - size, line, PdfFont.Regular, size, color ?? PdfColor.Black);
                _y -= size * 1.4;
            }
        }
        _y -= 4;
    }

    /// <summary>
    /// A table whose column widths are given in points; one column with width 0 takes the remaining width.
    /// Rows never split across pages; the header is repeated after a page break.
    /// </summary>
    public void Table(IReadOnlyList<PdfColumn> columns, IEnumerable<IReadOnlyList<PdfCell>> rows, int maxLinesPerCell = 6)
    {
        ArgumentNullException.ThrowIfNull(columns);
        ArgumentNullException.ThrowIfNull(rows);
        var widths = columns.Select(c => c.Width).ToArray();
        var flexible = Array.FindIndex(widths, w => w <= 0);
        if (flexible >= 0) widths[flexible] = ContentWidth - widths.Where((_, i) => i != flexible).Sum();
        const double size = 8.5;
        const double noteSize = 7.5;
        const double pad = 4;
        var line = size * 1.3;

        void Header()
        {
            Ensure(line + 2 * pad + line);
            Rect(Margin, _y - line - 2 * pad, ContentWidth, line + 2 * pad, new PdfColor(0.91, 0.93, 0.96));
            var x = Margin;
            for (var i = 0; i < columns.Count; i++)
            {
                Text(x + pad, _y - pad - size, Fit(columns[i].Header, PdfFont.Bold, size, widths[i] - 2 * pad), PdfFont.Bold, size, PdfColor.Gray);
                x += widths[i];
            }
            _y -= line + 2 * pad;
        }

        Header();
        var index = 0;
        foreach (var row in rows)
        {
            var laidOut = row.Select((cell, i) =>
            {
                var main = Wrap(cell.Text, cell.Font, size, widths[i] - 2 * pad).Take(maxLinesPerCell).ToList();
                var note = cell.Note is null ? [] : Wrap(cell.Note, PdfFont.Regular, noteSize, widths[i] - 2 * pad).Take(maxLinesPerCell).ToList();
                return (Cell: cell, Main: main, Note: note);
            }).ToList();
            var height = laidOut.Max(c => c.Main.Count * line + c.Note.Count * noteSize * 1.3) + 2 * pad;
            if (_y - height < Margin + FooterHeight)
            {
                NewPage();
                Header();
            }
            if (index++ % 2 == 1) Rect(Margin, _y - height, ContentWidth, height, new PdfColor(0.97, 0.975, 0.985));
            var x = Margin;
            for (var i = 0; i < laidOut.Count; i++)
            {
                var (cell, main, note) = laidOut[i];
                var cy = _y - pad;
                foreach (var text in main)
                {
                    Text(x + pad, cy - size, text, cell.Font, size, cell.Color ?? PdfColor.Black);
                    cy -= line;
                }
                foreach (var text in note)
                {
                    Text(x + pad, cy - noteSize, text, PdfFont.Regular, noteSize, PdfColor.Gray);
                    cy -= noteSize * 1.3;
                }
                x += widths[i];
            }
            _y -= height;
            Rect(Margin, _y, ContentWidth, 0.4, new PdfColor(0.88, 0.90, 0.93));
        }
        _y -= 10;
    }

    /// <summary>Small coloured boxes in a row, each with a big number and a label.</summary>
    public void StatTiles(IReadOnlyList<(string Value, string Label, PdfColor Color)> tiles)
    {
        ArgumentNullException.ThrowIfNull(tiles);
        const double height = 44;
        const double gap = 8;
        Ensure(height + 8);
        var width = (ContentWidth - gap * (tiles.Count - 1)) / tiles.Count;
        for (var i = 0; i < tiles.Count; i++)
        {
            var x = Margin + i * (width + gap);
            Rect(x, _y - height, width, height, new PdfColor(0.95, 0.96, 0.98));
            Rect(x, _y - height, 3, height, tiles[i].Color);
            Text(x + 10, _y - 20, Fit(tiles[i].Value, PdfFont.Bold, 15, width - 14), PdfFont.Bold, 15, tiles[i].Color);
            Text(x + 10, _y - 35, Fit(tiles[i].Label, PdfFont.Regular, 8, width - 14), PdfFont.Regular, 8, PdfColor.Gray);
        }
        _y -= height + 12;
    }

    public void Save(Stream destination, string title, DateTimeOffset createdUtc, bool compress = true)
    {
        ArgumentNullException.ThrowIfNull(destination);
        var count = _pages.Count;
        for (var i = 0; i < count; i++)
        {
            var page = _pages[i];
            var footer = new StringBuilder();
            AppendRect(footer, Margin, Margin - 2, ContentWidth, 0.5, new PdfColor(0.85, 0.87, 0.90));
            var number = string.Create(CultureInfo.InvariantCulture, $"Page {i + 1} of {count}");
            AppendText(footer, Margin, Margin - 14, Fit(FooterText, PdfFont.Regular, 7.5, ContentWidth - 80), PdfFont.Regular, 7.5, PdfColor.Gray);
            AppendText(footer, PageWidth - Margin - Width(number, PdfFont.Regular, 7.5), Margin - 14, number, PdfFont.Regular, 7.5, PdfColor.Gray);
            page.Append(footer);
        }

        var objects = new List<byte[]>();
        int Add(string body) { objects.Add(Encoding.ASCII.GetBytes(body)); return objects.Count; }
        int AddRaw(byte[] body) { objects.Add(body); return objects.Count; }

        Add("<< /Type /Catalog /Pages 2 0 R >>");
        Add("PAGES");   // placeholder, replaced below
        var fonts = new[] { Add(FontObject("Helvetica")), Add(FontObject("Helvetica-Bold")), Add(FontObject("Courier")) };
        var info = Add($"<< /Title {PdfString(title)} /Producer (Azura WebGuard Inspector) /CreationDate (D:{createdUtc.UtcDateTime:yyyyMMddHHmmss}Z) >>");
        var pageIds = new List<int>();
        foreach (var page in _pages)
        {
            var raw = Encoding.ASCII.GetBytes(page.ToString());
            byte[] data;
            string filter;
            if (compress)
            {
                using var ms = new MemoryStream();
                using (var z = new ZLibStream(ms, CompressionLevel.Optimal, leaveOpen: true)) z.Write(raw);
                data = ms.ToArray();
                filter = " /Filter /FlateDecode";
            }
            else
            {
                (data, filter) = (raw, string.Empty);
            }
            var header = Encoding.ASCII.GetBytes(string.Create(CultureInfo.InvariantCulture, $"<< /Length {data.Length}{filter} >>\nstream\n"));
            var content = AddRaw([.. header, .. data, .. "\nendstream"u8]);
            pageIds.Add(Add(string.Create(CultureInfo.InvariantCulture,
                $"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 {PageWidth:0.##} {PageHeight:0.##}] " +
                $"/Resources << /Font << /F1 {fonts[0]} 0 R /F2 {fonts[1]} 0 R /F3 {fonts[2]} 0 R >> >> /Contents {content} 0 R >>")));
        }
        objects[1] = Encoding.ASCII.GetBytes($"<< /Type /Pages /Kids [{string.Join(' ', pageIds.Select(p => p + " 0 R"))}] /Count {pageIds.Count} >>");

        using var output = new MemoryStream();
        void Write(string s) => output.Write(Encoding.ASCII.GetBytes(s));
        Write("%PDF-1.4\n");
        output.Write([0x25, 0xE2, 0xE3, 0xCF, 0xD3, 0x0A]);   // binary marker comment
        var offsets = new List<long>();
        for (var i = 0; i < objects.Count; i++)
        {
            offsets.Add(output.Position);
            Write($"{i + 1} 0 obj\n");
            output.Write(objects[i]);
            Write("\nendobj\n");
        }
        var xref = output.Position;
        Write($"xref\n0 {objects.Count + 1}\n0000000000 65535 f \n");
        foreach (var offset in offsets) Write(offset.ToString("D10", CultureInfo.InvariantCulture) + " 00000 n \n");
        Write($"trailer\n<< /Size {objects.Count + 1} /Root 1 0 R /Info {info} 0 R >>\nstartxref\n{xref}\n%%EOF\n");
        output.Position = 0;
        output.CopyTo(destination);
    }

    // ---- Drawing primitives ------------------------------------------------------------------------------------

    private void Ensure(double height)
    {
        if (_y - height < Margin + FooterHeight) NewPage();
    }

    private void Text(double x, double y, string text, PdfFont font, double size, PdfColor color) => AppendText(_page, x, y, text, font, size, color);

    private void Rect(double x, double y, double w, double h, PdfColor color) => AppendRect(_page, x, y, w, h, color);

    private static void AppendText(StringBuilder sb, double x, double y, string text, PdfFont font, double size, PdfColor color)
    {
        if (string.IsNullOrEmpty(text)) return;
        sb.Append(CultureInfo.InvariantCulture,
            $"BT /{FontName(font)} {size:0.##} Tf {color.R:0.###} {color.G:0.###} {color.B:0.###} rg {x:0.##} {y:0.##} Td {PdfString(text)} Tj ET\n");
    }

    private static void AppendRect(StringBuilder sb, double x, double y, double w, double h, PdfColor color) =>
        sb.Append(CultureInfo.InvariantCulture, $"{color.R:0.###} {color.G:0.###} {color.B:0.###} rg {x:0.##} {y:0.##} {w:0.##} {h:0.##} re f\n");

    private static string FontName(PdfFont font) => font switch { PdfFont.Bold => "F2", PdfFont.Mono => "F3", _ => "F1" };

    private static string FontObject(string baseFont) => $"<< /Type /Font /Subtype /Type1 /BaseFont /{baseFont} /Encoding /WinAnsiEncoding >>";

    // ---- Text encoding and measuring ---------------------------------------------------------------------------

    /// <summary>A PDF literal string in WinAnsi, with bytes above 127 written as octal escapes so the content stays ASCII.</summary>
    public static string PdfString(string text)
    {
        var sb = new StringBuilder("(");
        foreach (var b in ToWinAnsi(text))
        {
            switch (b)
            {
                case (byte)'(' or (byte)')' or (byte)'\\':
                    sb.Append('\\').Append((char)b);
                    break;
                case < 32 or > 126:
                    sb.Append('\\').Append(Convert.ToString(b, 8).PadLeft(3, '0'));
                    break;
                default:
                    sb.Append((char)b);
                    break;
            }
        }
        return sb.Append(')').ToString();
    }

    private static readonly Dictionary<char, byte> WinAnsiExtras = new()
    {
        ['€'] = 0x80, ['‚'] = 0x82, ['ƒ'] = 0x83, ['„'] = 0x84, ['…'] = 0x85, ['†'] = 0x86, ['‡'] = 0x87, ['ˆ'] = 0x88, ['‰'] = 0x89,
        ['Š'] = 0x8A, ['‹'] = 0x8B, ['Œ'] = 0x8C, ['Ž'] = 0x8E, ['‘'] = 0x91, ['’'] = 0x92, ['“'] = 0x93, ['”'] = 0x94, ['•'] = 0x95,
        ['–'] = 0x96, ['—'] = 0x97, ['˜'] = 0x98, ['™'] = 0x99, ['š'] = 0x9A, ['›'] = 0x9B, ['œ'] = 0x9C, ['ž'] = 0x9E, ['Ÿ'] = 0x9F,
    };

    private static readonly Dictionary<char, string> Substitutes = new()
    {
        ['→'] = "->", ['←'] = "<-", ['≥'] = ">=", ['≤'] = "<=", ['−'] = "-", ['✓'] = "v", ['✗'] = "x", ['\t'] = "    ", ['\r'] = "", ['\n'] = " ",
    };

    public static byte[] ToWinAnsi(string text)
    {
        var bytes = new List<byte>(text.Length);
        foreach (var c in text)
        {
            if (Substitutes.TryGetValue(c, out var sub)) bytes.AddRange(sub.Select(ch => (byte)ch));
            else if (c is >= ' ' and <= '~' || c is >= ' ' and <= 'ÿ') bytes.Add((byte)c);
            else if (WinAnsiExtras.TryGetValue(c, out var b)) bytes.Add(b);
            else bytes.Add((byte)'?');
        }
        return [.. bytes];
    }

    // Glyph widths (1/1000 em) of Helvetica and Helvetica-Bold for ASCII 32–126 (Adobe AFM).
    private static readonly short[] Helvetica =
    [
        278, 278, 355, 556, 556, 889, 667, 191, 333, 333, 389, 584, 278, 333, 278, 278, 556, 556, 556, 556, 556, 556, 556, 556, 556, 556,
        278, 278, 584, 584, 584, 556, 1015, 667, 667, 722, 722, 667, 611, 778, 722, 278, 500, 667, 556, 833, 722, 778, 667, 778, 722, 667,
        611, 722, 667, 944, 667, 667, 611, 278, 278, 278, 469, 556, 333, 556, 556, 500, 556, 556, 278, 556, 556, 222, 222, 500, 222, 833,
        556, 556, 556, 556, 333, 500, 278, 556, 500, 722, 500, 500, 500, 334, 260, 334, 584,
    ];

    private static readonly short[] HelveticaBold =
    [
        278, 333, 474, 556, 556, 889, 722, 238, 333, 333, 389, 584, 278, 333, 278, 278, 556, 556, 556, 556, 556, 556, 556, 556, 556, 556,
        333, 333, 584, 584, 584, 611, 975, 722, 722, 722, 722, 667, 611, 778, 722, 278, 556, 722, 611, 833, 722, 778, 667, 778, 722, 667,
        611, 722, 667, 944, 667, 667, 611, 333, 278, 333, 584, 556, 333, 556, 611, 556, 611, 556, 333, 611, 611, 278, 278, 556, 278, 889,
        611, 611, 611, 611, 389, 556, 333, 611, 556, 778, 556, 556, 500, 389, 280, 389, 584,
    ];

    public static double Width(string text, PdfFont font, double size)
    {
        double units = 0;
        foreach (var b in ToWinAnsi(text ?? string.Empty))
        {
            units += font switch
            {
                PdfFont.Mono => 600,
                _ when b is >= 32 and <= 126 => (font == PdfFont.Bold ? HelveticaBold : Helvetica)[b - 32],
                _ when b is 0x85 or 0x97 or 0x89 => 1000,
                _ => 556,
            };
        }
        return units * size / 1000;
    }

    /// <summary>Greedy word wrap; words longer than the width (paths, hashes) are broken by characters.</summary>
    public static List<string> Wrap(string? text, PdfFont font, double size, double width)
    {
        var lines = new List<string>();
        foreach (var paragraph in (text ?? string.Empty).Replace("\r", string.Empty, StringComparison.Ordinal).Split('\n'))
        {
            var current = string.Empty;
            foreach (var word in paragraph.Split(' '))
            {
                var candidate = current.Length == 0 ? word : current + " " + word;
                if (Width(candidate, font, size) <= width)
                {
                    current = candidate;
                    continue;
                }
                if (current.Length > 0) lines.Add(current);
                current = word;
                while (Width(current, font, size) > width && current.Length > 1)
                {
                    var cut = current.Length - 1;
                    while (cut > 1 && Width(current[..cut], font, size) > width) cut--;
                    lines.Add(current[..cut]);
                    current = current[cut..];
                }
            }
            lines.Add(current);
        }
        return lines;
    }

    /// <summary>The text cut with "…" so it fits on one line.</summary>
    public static string Fit(string text, PdfFont font, double size, double width)
    {
        if (Width(text, font, size) <= width) return text;
        var cut = text.Length;
        while (cut > 0 && Width(text[..cut] + "…", font, size) > width) cut--;
        return text[..cut] + "…";
    }
}
