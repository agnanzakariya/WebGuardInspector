using WebGuard.Core.AI;
using WebGuard.Core.Findings;
using WebGuard.Core.Scanning;
using WebGuard.Presentation.Formatting;
using WebGuard.Presentation.ViewModels;

namespace WebGuard.Tests;

public static class CoreTests
{
    [Test]
    public static void Fingerprint_is_stable_across_whitespace_path_separators_and_line_moves()
    {
        var a = FindingFingerprint.Compute("semgrep", "rule.x", @"src\Api\Program.cs", "subprocess.run( x,  shell=True )");
        var b = FindingFingerprint.Compute("SEMGREP", "rule.x", "src/api/program.cs", "subprocess.run( x, shell=True )\n");
        Assert.Equal(a, b, "fingerprint");
        Assert.True(a.StartsWith("wgf1:", StringComparison.Ordinal), "prefix");
        var c = FindingFingerprint.Compute("semgrep", "rule.y", "src/api/program.cs", "subprocess.run( x, shell=True )");
        Assert.True(a != c, "different rule gives different fingerprint");
    }

    [Test]
    public static void Secret_redactor_never_reveals_the_full_value()
    {
        Assert.Equal("AKIA****************", SecretRedactor.Redact("AKIAIOSFODNN7EXAMPLE"), "long secret");
        Assert.Equal("******", SecretRedactor.Redact("abc123"), "short secret fully masked");
        Assert.Equal(string.Empty, SecretRedactor.Redact(null), "null");
    }

    [Test]
    public static void Scan_options_normalize_trims_dedupes_and_disables_link_following()
    {
        var o = new ScanOptions { ExcludedDirectories = [" bin ", "BIN", "/obj/", ""], MaxHashBytes = -5, MaxDegreeOfParallelism = 99, FollowReparsePoints = true }.Normalize();
        Assert.Equal("bin|obj", string.Join('|', o.ExcludedDirectories), "exclusions");
        Assert.Equal(1L, o.MaxHashBytes, "min hash bytes");
        Assert.Equal(16, o.MaxDegreeOfParallelism, "max parallelism");
        Assert.Equal(false, o.FollowReparsePoints, "links never followed");
    }

    [Test]
    public static void Severity_summary_counts_each_level()
    {
        var loc = new SourceLocation("a.cs", 1, 1);
        SecurityFinding F(Severity s) => new(Guid.NewGuid(), "fp", "e", "r", "t", "d", FindingCategory.Vulnerability, s,
            Confidence.High, FindingOrigin.Engine, loc, [], [], [], null, ValidationStatus.New, DateTimeOffset.UtcNow);
        var summary = SeveritySummary.From([F(Severity.Critical), F(Severity.High), F(Severity.High), F(Severity.Low)]);
        Assert.Equal(1, summary.Critical, "critical");
        Assert.Equal(2, summary.High, "high");
        Assert.Equal(4, summary.Total, "total");
    }

    [Test]
    public static void Mcp_catalog_matches_project_instructions_and_write_tools_need_approval()
    {
        var names = McpToolCatalog.Tools.Select(t => t.Name).ToArray();
        Assert.Equal(9, names.Length, "tool count");
        Assert.True(names.Contains("save_security_finding"), "save tool present");
        Assert.True(McpToolCatalog.Tools.Where(t => t.Access != McpToolAccess.ReadOnly).All(t => t.RequiresHumanApproval),
            "every non-read-only tool requires human approval");
    }

    [Test]
    public static void Byte_formatting_is_human_readable()
    {
        Assert.Equal("12.4 KB", DisplayFormat.Bytes(12_721).Replace(',', '.'), "kb");
        Assert.True(DisplayFormat.Bytes(512).EndsWith(" B", StringComparison.Ordinal), "bytes");
    }

    [Test]
    public static void Inventory_insights_flag_secret_containers_by_name_only()
    {
        FileInventoryItem I(string p) => new(p, Path.GetExtension(p), 10, null, "x", FileScanStatus.Hashed, 0, null);
        var insights = InventoryInsights.Analyze([I(".env"), I("certs/server.pfx"), I("package-lock.json"), I("src/app.cs")]);
        Assert.True(insights.Any(i => i.Title == "Possible secret containers" && i.Tone == StatusTone.Danger), "secret containers");
        Assert.True(insights.Any(i => i.Title == "Dependency manifests"), "lockfile");
        var clean = InventoryInsights.Analyze([I("src/app.cs")]);
        Assert.Equal("No notable file types", clean.Single().Title, "clean project");
    }
}
