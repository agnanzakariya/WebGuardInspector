// WebGuard Inspector baseline YARA-X rules: web shells and obfuscated loaders commonly planted in web projects.
// Meta keys read by WebGuard: title, description, severity, confidence, category (malware|suspicious), remediation.

rule php_webshell_eval_input
{
    meta:
        title = "PHP web shell: eval of request input"
        description = "Evaluates code taken directly from a request parameter or cookie, a hallmark of PHP web shells."
        severity = "critical"
        confidence = "high"
        category = "malware"
    strings:
        $open = "<?php" nocase
        $e1 = /(eval|assert|system|passthru|shell_exec)\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)\s*\[/ nocase
        $e2 = /(eval|assert)\s*\(\s*(base64_decode|gzinflate|str_rot13|gzuncompress)\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)/ nocase
    condition:
        $open and any of ($e*)
}

rule php_obfuscated_loader
{
    meta:
        title = "Obfuscated PHP loader"
        description = "Nested decode-and-eval chain such as eval(gzinflate(base64_decode(...))) used to hide malicious PHP."
        severity = "high"
        confidence = "medium"
        category = "malware"
    strings:
        $chain = /eval\s*\(\s*(gzinflate|gzuncompress|str_rot13|strrev)\s*\(\s*base64_decode\s*\(/ nocase
        $b64 = /base64_decode\s*\(\s*['"][A-Za-z0-9+\/=]{400,}/
    condition:
        $chain or ($b64 and filesize < 2MB)
}

rule js_eval_atob_payload
{
    meta:
        title = "JavaScript eval of decoded payload"
        description = "Decodes a long base64 or char-code payload and evaluates it, typical of injected skimmers and droppers."
        severity = "high"
        confidence = "medium"
        category = "suspicious"
    strings:
        $a = /eval\s*\(\s*atob\s*\(\s*['"][A-Za-z0-9+\/=]{200,}/
        $b = /eval\s*\(\s*String\.fromCharCode\s*\((\s*\d+\s*,){50,}/
        $c = /new\s+Function\s*\(\s*atob\s*\(/
    condition:
        any of them
}

rule powershell_download_execute
{
    meta:
        title = "PowerShell download-and-execute"
        description = "Downloads content and executes it in memory (IEX with WebClient) or runs a long encoded command."
        severity = "high"
        confidence = "medium"
        category = "suspicious"
    strings:
        $iex = /(IEX|Invoke-Expression)[\s(]{0,4}New-Object\s+(System\.)?Net\.WebClient/ nocase
        $dl = /DownloadString\s*\(\s*['"]https?:/ nocase
        $enc = /powershell(\.exe)?\s[^\r\n]{0,40}-(e|enc|encodedcommand)\s+[A-Za-z0-9+\/=]{100,}/ nocase
    condition:
        ($iex and $dl) or $enc
}

rule npm_install_script_downloader
{
    meta:
        title = "Install script fetches and runs remote code"
        description = "package.json lifecycle script that pipes a remote download into a shell, a common supply-chain attack vector."
        severity = "high"
        confidence = "medium"
        category = "suspicious"
    strings:
        $hook = /"(pre|post)?install"\s*:/
        $pipe = /(curl|wget)\s[^"]{0,200}\|\s*(sh|bash|node)/
        $iwr = /(iwr|Invoke-WebRequest)[^"]{0,200}\|\s*iex/ nocase
    condition:
        $hook and ($pipe or $iwr)
}
