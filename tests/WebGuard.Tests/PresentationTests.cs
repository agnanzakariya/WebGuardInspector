using WebGuard.Core.Scanning;
using WebGuard.Detection;
using WebGuard.Presentation.Services;
using WebGuard.Presentation.ViewModels;
using WebGuard.Scanner;

namespace WebGuard.Tests;

internal sealed class FakeFolderPicker(string? result) : IFolderPicker
{
    public string? PickFolder(string? initialFolder) => result;
}

internal sealed class FakeSaveDialog(string? path) : ISaveFileDialogService
{
    public string? PickSavePath(string title, string filter, string defaultFileName) => path;
}

internal sealed class FakeClipboard : IClipboardService
{
    public string? Text { get; private set; }
    public void SetText(string text) => Text = text;
}

internal sealed class FakeDialogs : IDialogService
{
    public List<string> Errors { get; } = [];
    public void ShowError(string title, string message) => Errors.Add(message);
    public void ShowInfo(string title, string message) { }
}

internal sealed class FakeTheme : IThemeService
{
    public AppTheme Current { get; private set; } = AppTheme.Dark;
    public void Apply(AppTheme theme) => Current = theme;
}

internal sealed class MemorySettingsStore : ISettingsStore
{
    public AppSettings Saved { get; private set; } = new();
    public AppSettings Load() => Saved;
    public void Save(AppSettings settings) => Saved = settings;
}

public static class PresentationTests
{
    private static (ScanWorkspaceViewModel Vm, FakeClipboard Clip, MemorySettingsStore Store, FakeDialogs Dialogs) CreateWorkspace(string? pickFolder = null, string? savePath = null)
    {
        var store = new MemorySettingsStore();
        var clip = new FakeClipboard();
        var dialogs = new FakeDialogs();
        var vm = new ScanWorkspaceViewModel(new LocalFolderScanner(TestEngines.Offline()), new JsonReportExporter(),
            new InMemoryScanHistoryStore(), new SettingsService(store), new FakeFolderPicker(pickFolder),
            new FakeSaveDialog(savePath), clip, dialogs);
        return (vm, clip, store, dialogs);
    }

    [Test]
    public static async Task Workspace_scan_populates_stats_files_steps_and_settings()
    {
        using var temp = new TempFolder();
        temp.Write("a.cs", "a");
        temp.Write("config/.env", "SECRET=1");
        var (vm, clip, store, _) = CreateWorkspace(pickFolder: temp.Path);

        Assert.Equal(false, vm.StartScanCommand.CanExecute(null), "cannot start without folder");
        vm.BrowseCommand.Execute(null);
        Assert.True(vm.IsStep1Complete, "step 1 complete");
        Assert.True(vm.StartScanCommand.CanExecute(null), "can start");

        await vm.StartScanAsync();

        Assert.True(vm.HasReport, "has report");
        Assert.True(vm.IsStep3Active, "investigate step active");
        Assert.Equal("2", vm.TotalFilesText, "total files");
        Assert.Equal(2, vm.Files.Count, "rows");
        Assert.True(vm.SelectedFile is not null, "first file selected");
        Assert.True(vm.Insights.Any(i => i.Title == "Possible secret containers"), ".env insight");
        Assert.Equal(temp.Path, store.Saved.LastFolder, "last folder persisted");

        vm.CopyHashCommand.Execute(null);
        Assert.Equal(vm.SelectedFile!.Sha256, clip.Text, "hash copied");
    }

    [Test]
    public static async Task Workspace_filters_by_search_and_status()
    {
        using var temp = new TempFolder();
        temp.Write("src/Program.cs", "p");
        temp.Write("src/Startup.cs", "s");
        temp.Write("README.md", "r");
        var (vm, _, _, _) = CreateWorkspace(pickFolder: temp.Path);
        vm.BrowseCommand.Execute(null);
        await vm.StartScanAsync();

        vm.SearchText = "startup";
        Assert.Equal(1, vm.Files.Count, "search");
        Assert.True(vm.InventoryCaption.StartsWith("1 of 3", StringComparison.Ordinal), "caption " + vm.InventoryCaption);
        vm.SearchText = string.Empty;
        vm.StatusFilter = "Errors";
        Assert.Equal(0, vm.Files.Count, "no errors");
        vm.StatusFilter = "All";
        Assert.Equal(3, vm.Files.Count, "all");
    }

    [Test]
    public static async Task Second_scan_of_same_folder_reports_file_delta()
    {
        using var temp = new TempFolder();
        for (var i = 0; i < 4; i++) temp.Write($"f{i}.txt", "x");
        var (vm, _, _, _) = CreateWorkspace(pickFolder: temp.Path);
        vm.BrowseCommand.Execute(null);
        await vm.StartScanAsync();
        temp.Write("f4.txt", "x");
        await vm.StartScanAsync();
        Assert.Equal("+25", vm.FilesDeltaText.Replace(" ", string.Empty, StringComparison.Ordinal).Replace("%", string.Empty, StringComparison.Ordinal), "delta");
    }

    [Test]
    public static async Task Export_writes_json_report()
    {
        using var temp = new TempFolder();
        temp.Write("a.txt", "a");
        var output = Path.Combine(Path.GetTempPath(), "wg-export-" + Guid.NewGuid().ToString("N") + ".json");
        try
        {
            var (vm, _, _, dialogs) = CreateWorkspace(pickFolder: temp.Path, savePath: output);
            vm.BrowseCommand.Execute(null);
            await vm.StartScanAsync();
            await vm.ExportCommand.ExecuteAsync();
            Assert.True(File.Exists(output), "file written");
            Assert.True((await File.ReadAllTextAsync(output)).Contains("\"files\"", StringComparison.Ordinal), "json content");
            Assert.Equal(0, dialogs.Errors.Count, "no errors");
        }
        finally { File.Delete(output); }
    }

    [Test]
    public static async Task Shell_navigates_and_updates_findings_after_scan()
    {
        using var temp = new TempFolder();
        temp.Write("a.txt", "a");
        var store = new MemorySettingsStore();
        var settings = new SettingsService(store);
        var engines = TestEngines.Offline();
        var history = new InMemoryScanHistoryStore();
        var workspace = new ScanWorkspaceViewModel(new LocalFolderScanner(engines), new JsonReportExporter(), history, settings,
            new FakeFolderPicker(temp.Path), new FakeSaveDialog(null), new FakeClipboard(), new FakeDialogs());
        var catalog = new EngineCatalogViewModel(engines);
        var findings = new FindingsViewModel(catalog);
        var theme = new FakeTheme();
        var historyVm = new ScanHistoryViewModel(history);
        var shell = new ShellViewModel(workspace,
            new OverviewViewModel(workspace, findings, catalog),
            new LocalScannerViewModel(workspace, settings),
            findings,
            new AiAnalystViewModel(new WebGuard.AI.PlannedAiSecurityAnalyst(), new WebGuard.AI.PlannedMcpServerHost()),
            new SecondBrainViewModel(new WebGuard.Persistence.PlannedSecondBrainRepository()),
            new IntelligenceViewModel(new WebGuard.Intelligence.PlannedVulnerabilityIntelligence(), [new WebGuard.Intelligence.PlannedMalwareHashIntelligence()]),
            historyVm,
            new SettingsViewModel(settings, theme, catalog),
            catalog, settings, theme);

        await shell.InitializeAsync();
        Assert.Equal("Disabled", catalog.Engines[0].Availability, "engine shows disabled state");
        Assert.Equal(PageKey.Overview, shell.CurrentPage.Key, "starts on overview");
        shell.Navigate(PageKey.Settings);
        Assert.Equal(PageKey.Settings, shell.CurrentPage.Key, "navigated");
        shell.NavigateCommand.Execute("Findings");
        Assert.Equal(PageKey.Findings, shell.CurrentPage.Key, "navigate by string");

        workspace.BrowseCommand.Execute(null);
        await workspace.StartScanAsync();
        await Task.Delay(50);
        Assert.True(findings.HasNoFindings, "no findings when no engine runs");
        Assert.Equal("No security engine ran", findings.EmptyTitle, "empty state explains why");
        Assert.Equal(4, findings.EngineRuns.Count, "engine runs listed");
        Assert.Equal(1, historyVm.Items.Count, "history updated");

        shell.ToggleThemeCommand.Execute(null);
        Assert.Equal(AppTheme.Light, store.Saved.Theme, "theme persisted");
    }

    [Test]
    public static void Settings_validation_rejects_bad_hash_limit_and_saves_exclusions()
    {
        var store = new MemorySettingsStore();
        var settings = new SettingsService(store);
        var vm = new SettingsViewModel(settings, new FakeTheme(), new EngineCatalogViewModel(TestEngines.Offline()));
        vm.MaxHashMegabytesText = "abc";
        vm.SaveCommand.Execute(null);
        Assert.True(vm.SaveMessage.StartsWith("Hash limit", StringComparison.Ordinal), "validation message");

        vm.MaxHashMegabytesText = "50";
        vm.ExcludedDirectoriesText = "bin\nobj\nBIN\n vendor ";
        vm.SaveCommand.Execute(null);
        Assert.Equal(50, store.Saved.MaxHashMegabytes, "mb saved");
        Assert.Equal("bin|obj|vendor", string.Join('|', store.Saved.ExcludedDirectories), "exclusions saved");
        Assert.Equal(50L * 1024 * 1024, settings.Current.ToScanOptions().MaxHashBytes, "scan options");
    }

    [Test]
    public static void Json_settings_store_round_trips_and_survives_corrupt_file()
    {
        using var temp = new TempFolder();
        var path = Path.Combine(temp.Path, "settings.json");
        var store = new JsonSettingsStore(path);
        store.Save(new AppSettings { Theme = AppTheme.Light, MaxHashMegabytes = 7 });
        Assert.Equal(7, store.Load().MaxHashMegabytes, "round trip");
        Assert.Equal(AppTheme.Light, store.Load().Theme, "theme");
        File.WriteAllText(path, "{ not json");
        Assert.Equal(AppTheme.Dark, store.Load().Theme, "falls back to defaults");
    }
}
