using System.Text.RegularExpressions;
using WebGuard.Core.Findings;
using WebGuard.Detection;

namespace WebGuard.Tests;

/// <summary>
/// Checks the bundled rule files ship with the app and are well formed. The rules themselves are verified against
/// sample code with the real Semgrep and YARA-X CLIs (see README), which these offline tests do not start.
/// </summary>
public static class RuleTests
{
    private static readonly string RulesFolder = Path.Combine(AppContext.BaseDirectory, "rules");

    [Test]
    public static void Php_semgrep_rules_ship_with_metadata()
    {
        var path = Path.Combine(RulesFolder, "semgrep", "webguard-php.yaml");
        Assert.True(File.Exists(path), "webguard-php.yaml is copied next to the app");
        var text = File.ReadAllText(path);
        var blocks = Regex.Split(text, @"(?m)^  - id: ").Skip(1).ToArray();
        Assert.Equal(13, blocks.Length, "rule count");
        foreach (var block in blocks)
        {
            var id = block.Split('\n')[0].Trim();
            Assert.True(id.StartsWith("webguard.php.", StringComparison.Ordinal), "id prefix: " + id);
            foreach (var key in new[] { "languages: [php]", "severity: ", "message: ", "cwe: [\"CWE-", "confidence: ", "remediation: " })
                Assert.True(block.Contains(key, StringComparison.Ordinal), $"{id} has {key.Trim()}");
        }
        Assert.Equal(blocks.Length, blocks.Select(b => b.Split('\n')[0].Trim()).Distinct().Count(), "ids are unique");
        Assert.True(!Regex.IsMatch(text, @":\s*[*&]\w"), "no YAML anchors or aliases (Semgrep does not resolve them)");
    }

    [Test]
    public static void Php_yara_rules_ship_with_metadata_and_require_php()
    {
        var path = Path.Combine(RulesFolder, "yara", "webguard-php.yar");
        Assert.True(File.Exists(path), "webguard-php.yar is copied next to the app");
        var blocks = Regex.Split(File.ReadAllText(path), @"(?m)^rule ").Skip(1).ToArray();
        Assert.Equal(7, blocks.Length, "rule count");
        foreach (var block in blocks)
        {
            var name = block.Split('\n')[0].Trim();
            foreach (var key in new[] { "title = ", "description = ", "severity = ", "confidence = ", "category = ", "remediation = " })
                Assert.True(block.Contains(key, StringComparison.Ordinal), $"{name} has {key.Trim()}");
            Assert.True(block.Contains("$open = \"<?php\" nocase", StringComparison.Ordinal) && block.Contains("$open and", StringComparison.Ordinal),
                name + " only matches PHP files");
        }
    }

    [Test]
    public static void Semgrep_evidence_and_php_credential_forms_are_redacted()
    {
        var json = """
            {"results":[{"check_id":"webguard.php.hardcoded-credential","path":"config.php",
              "start":{"line":3,"col":1},"end":{"line":3,"col":40},
              "extra":{"message":"A password, secret or API key is hard-coded in source code.","severity":"WARNING",
                       "lines":"$db_password = \"Pr0dDbPassw0rd!2024\";","metadata":{"category":"security","cwe":["CWE-798: x"]}}}]}
            """;
        var finding = SemgrepEngine.Parse(json, Path.GetTempPath(), DateTimeOffset.UnixEpoch).Single();
        var snippet = finding.Evidence.Single().RedactedSnippet!;
        Assert.True(!snippet.Contains("Pr0dDbPassw0rd", StringComparison.Ordinal) && snippet.Contains(SourceRedactor.Mask, StringComparison.Ordinal),
            "Semgrep evidence is redacted");

        foreach (var (line, secret) in new[]
                 {
                     ("define('API_KEY', 'a8f5f167f44f4964e6c9');", "a8f5f167f44f4964e6c9"),
                     ("$config = ['smtp_password' => 'MailP4ss!x9'];", "MailP4ss!x9"),
                     ("$this->auth_token = \"tok_9f8e7d6c5b\";", "tok_9f8e7d6c5b"),
                 })
        {
            Assert.True(!SourceRedactor.Redact(line, "config.php").Contains(secret, StringComparison.Ordinal), "redacted: " + line);
        }
        Assert.Equal("$total = add($price, $tax);", SourceRedactor.Redact("$total = add($price, $tax);", "a.php"), "ordinary code untouched");
    }
}
