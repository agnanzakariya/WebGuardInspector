using WebGuard.Presentation.Services;
using WebGuard.Presentation.ViewModels;

namespace WebGuard.Tests;

public static class SetupWizardTests
{
    [Test]
    public static void Wizard_requires_an_explicit_choice_for_every_optional_feature_and_saves_each_step()
    {
        using var vault = new TempFolder();
        var settings = new SettingsService(new MemorySettingsStore());
        var wizard = new SetupWizardViewModel(settings, new FakeTheme(), new EngineCatalogViewModel([]));
        var completed = false;
        wizard.Completed += (_, _) => completed = true;

        Assert.Equal(SetupStep.Welcome, wizard.Step, "starts on welcome");
        wizard.Next();
        wizard.Next();
        Assert.Equal(SetupStep.Privacy, wizard.Step, "welcome and engines only need confirming");

        wizard.Next();
        Assert.Equal(SetupStep.Privacy, wizard.Step, "privacy cannot be skipped without a choice");
        Assert.True(wizard.ValidationMessage.Length > 0, "the missing choice is explained");
        wizard.IntelChoice = SetupWizardViewModel.OfflineOnly;
        wizard.Next();
        Assert.Equal(SetupStep.AiAnalyst, wizard.Step, "privacy confirmed");
        Assert.True(!settings.Current.AllowExternalIntelligence, "offline choice saved");

        wizard.AiChoice = SetupWizardViewModel.UseIt;
        wizard.AiEndpoint = "http://example.com:1234/v1";
        wizard.Next();
        Assert.Equal(SetupStep.AiAnalyst, wizard.Step, "remote AI endpoint refused");
        wizard.AiEndpoint = "http://127.0.0.1:1234/v1";
        wizard.Next();
        Assert.True(settings.Current.AiEnabled && settings.Current.AiEndpoint == "http://127.0.0.1:1234/v1", "AI choice saved");

        wizard.ClaudeChoice = SetupWizardViewModel.DontUse;
        wizard.Next();
        Assert.True(!settings.Current.ClaudeFixEnabled, "Claude off saved");

        wizard.VaultChoice = SetupWizardViewModel.UseIt;
        wizard.VaultPath = Path.Combine(vault.Path, "missing");
        wizard.Next();
        Assert.Equal(SetupStep.SecondBrain, wizard.Step, "vault must exist");
        wizard.VaultPath = vault.Path;
        wizard.Next();
        Assert.Equal(vault.Path, settings.Current.SecondBrainVaultPath, "vault saved");

        wizard.ThemeChoice = nameof(AppTheme.Light);
        wizard.Parallelism = 2;
        wizard.Next();
        Assert.Equal(SetupStep.Summary, wizard.Step, "summary reached");
        Assert.Equal(AppTheme.Light, settings.Current.Theme, "theme saved");
        Assert.True(wizard.Summary.Any(l => l.Label == "Claude fixing" && l.Value == "Off"), "summary lists the choices");
        Assert.True(!settings.Current.SetupCompleted, "not complete before Finish");

        wizard.Next();
        Assert.True(completed && settings.Current.SetupCompleted, "Finish completes the setup");
    }

    [Test]
    public static void Shell_shows_the_wizard_until_finished_and_settings_can_reopen_it()
    {
        var settings = new SettingsService(new MemorySettingsStore());
        var theme = new FakeTheme();
        var catalog = new EngineCatalogViewModel([]);
        var findings = new FindingsViewModel(catalog);
        var history = new WebGuard.Scanner.InMemoryScanHistoryStore();
        var workspace = new ScanWorkspaceViewModel(new WebGuard.Scanner.LocalFolderScanner([]), new WebGuard.Scanner.JsonReportExporter(), history, settings,
            new FakeFolderPicker(null), new FakeSaveDialog(null), new FakeClipboard(), new FakeDialogs());
        var settingsPage = new SettingsViewModel(settings, theme, catalog);
        var wizard = new SetupWizardViewModel(settings, theme, catalog);
        var shell = new ShellViewModel(workspace,
            new OverviewViewModel(workspace, findings, catalog),
            new LocalScannerViewModel(workspace, settings),
            findings,
            new FixingViewModel(findings, null, new WebGuard.Core.Fixing.FixApplier(Path.GetTempPath())),
            new AiAnalystViewModel(new WebGuard.AI.PlannedAiSecurityAnalyst(), new WebGuard.AI.PlannedMcpServerHost()),
            new SecondBrainViewModel(new WebGuard.Persistence.PlannedSecondBrainRepository()),
            new IntelligenceViewModel(new WebGuard.Intelligence.PlannedVulnerabilityIntelligence(), [new WebGuard.Intelligence.PlannedMalwareHashIntelligence()]),
            new ScanHistoryViewModel(history),
            settingsPage,
            catalog, settings, theme, wizard);

        Assert.True(shell.IsSetupRequired, "fresh install shows the wizard");
        settings.Update(s => s with { SetupCompleted = true });
        Assert.True(!shell.IsSetupRequired, "finished setup hides it");
        settingsPage.RunSetupCommand.Execute(null);
        Assert.True(shell.IsSetupRequired && !settings.Current.SetupCompleted, "Settings can run the wizard again");
        Assert.Equal(SetupStep.Welcome, wizard.Step, "and it starts over");
        Assert.Equal(null, wizard.AiChoice, "feature choices must be made again");
    }
}
