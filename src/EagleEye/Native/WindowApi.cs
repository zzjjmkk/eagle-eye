using System.Runtime.InteropServices;
using System.Text;

namespace EagleEye.Native;

/// <summary>
/// 窗口/光标相关的只读查询。
/// 只做枚举与属性读取：不 SetWindowLong、不 SetForegroundWindow、不发消息、
/// 不截取窗口内容、不安装任何钩子。
/// </summary>
public static class WindowApi
{
    public const long WS_EX_TOPMOST = 0x00000008L;
    public const long WS_EX_TRANSPARENT = 0x00000020L;
    public const long WS_EX_TOOLWINDOW = 0x00000080L;
    public const long WS_EX_LAYERED = 0x00080000L;
    public const long WS_EX_NOACTIVATE = 0x08000000L;

    private const int GWL_EXSTYLE = -20;

    [StructLayout(LayoutKind.Sequential)]
    public struct RECT
    {
        public int Left;
        public int Top;
        public int Right;
        public int Bottom;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct POINT
    {
        public int X;
        public int Y;
    }

    public readonly record struct WindowInfo(
        IntPtr Handle, int ProcessId, string Title, bool Visible,
        int Left, int Top, int Width, int Height, long ExStyle)
    {
        public int Area => Width * Height;
    }

    private delegate bool EnumWindowsProc(IntPtr hWnd, IntPtr lParam);

    [DllImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool EnumWindows(EnumWindowsProc lpEnumFunc, IntPtr lParam);

    [DllImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool IsWindowVisible(IntPtr hWnd);

    [DllImport("user32.dll", SetLastError = true)]
    private static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint lpdwProcessId);

    [DllImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetWindowRect(IntPtr hWnd, out RECT lpRect);

    [DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern int GetWindowTextW(IntPtr hWnd, StringBuilder lpString, int nMaxCount);

    [DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern int GetWindowTextLengthW(IntPtr hWnd);

    [DllImport("user32.dll", EntryPoint = "GetWindowLongPtrW", SetLastError = true)]
    private static extern IntPtr GetWindowLongPtr64(IntPtr hWnd, int nIndex);

    [DllImport("user32.dll", EntryPoint = "GetWindowLongW", SetLastError = true)]
    private static extern int GetWindowLong32(IntPtr hWnd, int nIndex);

    [DllImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool GetCursorPos(out POINT lpPoint);

    private static long GetExStyle(IntPtr hWnd)
    {
        return Environment.Is64BitProcess
            ? GetWindowLongPtr64(hWnd, GWL_EXSTYLE).ToInt64()
            : GetWindowLong32(hWnd, GWL_EXSTYLE);
    }

    public static List<WindowInfo> EnumerateVisibleWindows()
    {
        var list = new List<WindowInfo>();

        EnumWindows((hWnd, _) =>
        {
            try
            {
                if (!IsWindowVisible(hWnd)) return true;
                if (!GetWindowRect(hWnd, out RECT rect)) return true;

                int width = rect.Right - rect.Left;
                int height = rect.Bottom - rect.Top;
                if (width <= 0 || height <= 0) return true;

                GetWindowThreadProcessId(hWnd, out uint pid);

                string title = "";
                int length = GetWindowTextLengthW(hWnd);
                if (length > 0 && length < 512)
                {
                    var sb = new StringBuilder(length + 1);
                    GetWindowTextW(hWnd, sb, sb.Capacity);
                    title = sb.ToString();
                }

                list.Add(new WindowInfo(hWnd, (int)pid, title, true,
                    rect.Left, rect.Top, width, height, GetExStyle(hWnd)));
            }
            catch
            {
                // 单个窗口失败不影响整体
            }

            return true;
        }, IntPtr.Zero);

        return list;
    }
}