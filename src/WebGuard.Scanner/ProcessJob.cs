using System.Diagnostics;
using System.Runtime.InteropServices;

namespace WebGuard.Scanner;

/// <summary>
/// Windows Job Object holding a tool and every process it starts. Wrappers such as semgrep.exe launch workers
/// (pysemgrep, semgrep-core) and may exit before them, so killing the original process tree can miss the workers.
/// Terminating the job stops all of them; disposing it (kill-on-close) guarantees nothing outlives the run.
/// On other platforms this is a no-op and the runner falls back to <see cref="Process.Kill(bool)"/>.
/// </summary>
internal sealed class ProcessJob : IDisposable
{
    private readonly IntPtr _handle;

    private ProcessJob(IntPtr handle) => _handle = handle;

    public static ProcessJob? TryAttach(Process process)
    {
        if (!OperatingSystem.IsWindows()) return null;
        var handle = NativeMethods.CreateJobObject(IntPtr.Zero, null);
        if (handle == IntPtr.Zero) return null;

        var limits = new NativeMethods.JobObjectExtendedLimitInformation
        {
            BasicLimitInformation = new NativeMethods.JobObjectBasicLimitInformation { LimitFlags = NativeMethods.JobObjectLimitKillOnJobClose },
        };
        var size = Marshal.SizeOf<NativeMethods.JobObjectExtendedLimitInformation>();
        if (!NativeMethods.SetInformationJobObject(handle, NativeMethods.JobObjectExtendedLimitInformationClass, ref limits, (uint)size) ||
            !NativeMethods.AssignProcessToJobObject(handle, process.Handle))
        {
            NativeMethods.CloseHandle(handle);
            return null;
        }
        return new ProcessJob(handle);
    }

    /// <summary>Terminates every process in the job and waits (bounded) until none is left.</summary>
    public void TerminateAndWait(TimeSpan timeout)
    {
        NativeMethods.TerminateJobObject(_handle, 1);
        var sw = Stopwatch.StartNew();
        while (ActiveProcesses() > 0 && sw.Elapsed < timeout) Thread.Sleep(25);
    }

    private uint ActiveProcesses()
    {
        var info = default(NativeMethods.JobObjectBasicAccountingInformation);
        return NativeMethods.QueryInformationJobObject(_handle, NativeMethods.JobObjectBasicAccountingInformationClass, ref info,
            (uint)Marshal.SizeOf<NativeMethods.JobObjectBasicAccountingInformation>(), IntPtr.Zero)
            ? info.ActiveProcesses
            : 0;
    }

    public void Dispose() => NativeMethods.CloseHandle(_handle);

    private static class NativeMethods
    {
        public const uint JobObjectLimitKillOnJobClose = 0x2000;
        public const int JobObjectBasicAccountingInformationClass = 1;
        public const int JobObjectExtendedLimitInformationClass = 9;

        [StructLayout(LayoutKind.Sequential)]
        public struct JobObjectBasicLimitInformation
        {
            public long PerProcessUserTimeLimit;
            public long PerJobUserTimeLimit;
            public uint LimitFlags;
            public UIntPtr MinimumWorkingSetSize;
            public UIntPtr MaximumWorkingSetSize;
            public uint ActiveProcessLimit;
            public UIntPtr Affinity;
            public uint PriorityClass;
            public uint SchedulingClass;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct IoCounters
        {
            public ulong ReadOperationCount;
            public ulong WriteOperationCount;
            public ulong OtherOperationCount;
            public ulong ReadTransferCount;
            public ulong WriteTransferCount;
            public ulong OtherTransferCount;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct JobObjectExtendedLimitInformation
        {
            public JobObjectBasicLimitInformation BasicLimitInformation;
            public IoCounters IoInfo;
            public UIntPtr ProcessMemoryLimit;
            public UIntPtr JobMemoryLimit;
            public UIntPtr PeakProcessMemoryUsed;
            public UIntPtr PeakJobMemoryUsed;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct JobObjectBasicAccountingInformation
        {
            public long TotalUserTime;
            public long TotalKernelTime;
            public long ThisPeriodTotalUserTime;
            public long ThisPeriodTotalKernelTime;
            public uint TotalPageFaultCount;
            public uint TotalProcesses;
            public uint ActiveProcesses;
            public uint TotalTerminatedProcesses;
        }

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        public static extern IntPtr CreateJobObject(IntPtr attributes, string? name);

        [DllImport("kernel32.dll", SetLastError = true)]
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool SetInformationJobObject(IntPtr job, int infoClass, ref JobObjectExtendedLimitInformation info, uint length);

        [DllImport("kernel32.dll", SetLastError = true)]
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool QueryInformationJobObject(IntPtr job, int infoClass, ref JobObjectBasicAccountingInformation info, uint length, IntPtr returnLength);

        [DllImport("kernel32.dll", SetLastError = true)]
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool AssignProcessToJobObject(IntPtr job, IntPtr process);

        [DllImport("kernel32.dll", SetLastError = true)]
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool TerminateJobObject(IntPtr job, uint exitCode);

        [DllImport("kernel32.dll", SetLastError = true)]
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CloseHandle(IntPtr handle);
    }
}
