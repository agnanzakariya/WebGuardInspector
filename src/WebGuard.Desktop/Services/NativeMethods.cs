using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Interop;

namespace WebGuard.Desktop.Services;

/// <summary>Colours the Windows 11 title bar to match the theme. No-op on older systems.</summary>
internal static class NativeMethods
{
    private const int DwmwaUseImmersiveDarkMode = 20;

    [DllImport("dwmapi.dll", PreserveSig = true)]
    private static extern int DwmSetWindowAttribute(IntPtr hwnd, int attribute, ref int value, int size);

    public static void SetDarkTitleBar(Window window, bool dark)
    {
        var handle = new WindowInteropHelper(window).Handle;
        if (handle == IntPtr.Zero) return;
        var value = dark ? 1 : 0;
        _ = DwmSetWindowAttribute(handle, DwmwaUseImmersiveDarkMode, ref value, sizeof(int));
    }
}
