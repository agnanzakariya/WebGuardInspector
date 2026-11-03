using System.Diagnostics;
using System.Text;
using WebGuard.Core.Detection;

namespace WebGuard.Scanner;

/// <summary>
/// Runs an engine executable without a shell: absolute path only, arguments passed as a list (no command-line parsing),
/// stdin closed, no window, output capped, process tree killed on timeout or cancellation.
/// </summary>
public sealed class ExternalProcessRunner : IExternalProcessRunner
{
    public async Task<ProcessRunResult> RunAsync(ProcessRunRequest request, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (!Path.IsPathFullyQualified(request.ExecutablePath))
            throw new ArgumentException("Executable path must be absolute.", nameof(request));
        if (!File.Exists(request.ExecutablePath))
            throw new FileNotFoundException("Executable not found.", request.ExecutablePath);
        if (!Directory.Exists(request.WorkingDirectory))
            throw new DirectoryNotFoundException($"Working directory not found: {request.WorkingDirectory}");

        var info = new ProcessStartInfo(request.ExecutablePath)
        {
            WorkingDirectory = request.WorkingDirectory,
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            StandardOutputEncoding = Encoding.UTF8,
            StandardErrorEncoding = Encoding.UTF8,
        };
        foreach (var argument in request.Arguments) info.ArgumentList.Add(argument);
        if (request.Environment is not null)
        {
            foreach (var (key, value) in request.Environment) info.Environment[key] = value;
        }

        var stdout = new CappedBuffer(request.MaxOutputBytes);
        var stderr = new CappedBuffer(Math.Min(request.MaxOutputBytes, 1024 * 1024));
        using var process = new Process { StartInfo = info, EnableRaisingEvents = true };
        process.OutputDataReceived += (_, e) => { if (e.Data is not null) stdout.AppendLine(e.Data); };
        process.ErrorDataReceived += (_, e) => { if (e.Data is not null) stderr.AppendLine(e.Data); };

        var sw = Stopwatch.StartNew();
        process.Start();
        // Disposing the job (kill-on-close) also ends any worker the tool left behind after a normal exit.
        using var job = ProcessJob.TryAttach(process);
        process.StandardInput.Close();
        process.BeginOutputReadLine();
        process.BeginErrorReadLine();

        using var timeout = new CancellationTokenSource(request.Timeout);
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, timeout.Token);
        var timedOut = false;
        try
        {
            await process.WaitForExitAsync(linked.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            Kill(process, job);
            if (cancellationToken.IsCancellationRequested) throw;
            timedOut = true;
        }

        // Second wait (no token) drains the asynchronous output readers after exit.
        if (!timedOut) process.WaitForExit();
        sw.Stop();
        return new ProcessRunResult(
            timedOut ? -1 : process.ExitCode,
            stdout.ToString(),
            stderr.ToString(),
            sw.Elapsed,
            timedOut,
            stdout.Truncated);
    }

    private static readonly TimeSpan KillWait = TimeSpan.FromSeconds(5);

    /// <summary>
    /// Kills the tool and every process it started (e.g. semgrep.exe → pysemgrep → semgrep-core) and waits for them
    /// to go, so a canceled scan never leaves workers reading the project in the background.
    /// </summary>
    private static void Kill(Process process, ProcessJob? job)
    {
        try
        {
            if (job is not null)
            {
                job.TerminateAndWait(KillWait);
                return;
            }
            if (!process.HasExited) process.Kill(entireProcessTree: true);
            process.WaitForExit(KillWait);
        }
        catch (InvalidOperationException)
        {
            // Already exited.
        }
    }

    private sealed class CappedBuffer(long maxChars)
    {
        private readonly StringBuilder _builder = new();
        private readonly Lock _gate = new();

        public bool Truncated { get; private set; }

        public void AppendLine(string line)
        {
            lock (_gate)
            {
                if (Truncated) return;
                if (_builder.Length + line.Length + 1 > maxChars)
                {
                    Truncated = true;
                    return;
                }
                _builder.Append(line).Append('\n');
            }
        }

        public override string ToString()
        {
            lock (_gate) return _builder.ToString();
        }
    }
}
