using System.Globalization;
using WebGuard.Core.Scanning;

namespace WebGuard.Presentation.Formatting;

public static class DisplayFormat
{
    private static readonly string[] Units = ["B", "KB", "MB", "GB", "TB"];

    public static string Bytes(long bytes)
    {
        if (bytes < 1024) return bytes.ToString("N0", CultureInfo.CurrentCulture) + " B";
        double value = bytes;
        var unit = 0;
        while (value >= 1024 && unit < Units.Length - 1)
        {
            value /= 1024;
            unit++;
        }
        return value.ToString(value >= 100 ? "N0" : "N1", CultureInfo.CurrentCulture) + " " + Units[unit];
    }

    public static string Count(int value) => value.ToString("N0", CultureInfo.CurrentCulture);

    public static string Duration(TimeSpan span)
    {
        if (span.TotalSeconds < 1) return $"{Math.Max(1, (int)span.TotalMilliseconds)} ms";
        if (span.TotalMinutes < 1) return span.TotalSeconds.ToString("0.0", CultureInfo.CurrentCulture) + " sec";
        return $"{(int)span.TotalMinutes} min {span.Seconds} sec";
    }

    public static string DateTime(DateTimeOffset? value) =>
        value is null ? "—" : value.Value.ToLocalTime().ToString("MMM d, yyyy h:mm tt", CultureInfo.CurrentCulture);

    public static string Status(FileScanStatus status) => status switch
    {
        FileScanStatus.Hashed => "Hashed",
        FileScanStatus.SkippedSize => "Skipped (size)",
        FileScanStatus.SkippedLink => "Skipped (link)",
        _ => "Error",
    };

    public static string Percent(double ratio) => ratio.ToString("P0", CultureInfo.CurrentCulture);
}
