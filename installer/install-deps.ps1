<#
.SYNOPSIS
  Installs the optional dependencies of Azura - WebGuard Inspector. Run by Setup for the components the user ticked;
  can also be run by hand later (e.g. from the Start Menu folder of the app).
.DESCRIPTION
  Gitleaks, OSV-Scanner and YARA-X ship inside the app (tools\), so they are not installed here.
  Everything is installed for the current user only (no administrator rights needed):
    -Semgrep     Python 3 (winget, if missing) + "pip install --user semgrep"
    -ClaudeCode  Claude Code CLI via Anthropic's official installer (sign in afterwards with: claude, then /login)
    -Obsidian    Obsidian (winget)
    -LMStudio    LM Studio (winget; download a chat model inside LM Studio afterwards)
  A log is written to %LOCALAPPDATA%\WebGuardInspector\logs\install-deps.log.
.EXAMPLE
  powershell -ExecutionPolicy Bypass -File install-deps.ps1 -Semgrep -ClaudeCode
#>
[CmdletBinding()]
param(
  [switch]$Semgrep,
  [switch]$ClaudeCode,
  [switch]$Obsidian,
  [switch]$LMStudio,
  [switch]$NoPause
)
$ErrorActionPreference = 'Continue'
$logDir = Join-Path $env:LOCALAPPDATA 'WebGuardInspector\logs'
New-Item -ItemType Directory -Force -Path $logDir | Out-Null
$log = Join-Path $logDir 'install-deps.log'
$results = [ordered]@{}

function Write-Step([string]$text) {
  Write-Host ''
  Write-Host "== $text ==" -ForegroundColor Cyan
  Add-Content -Path $log -Value "[$(Get-Date -Format s)] == $text" -Encoding utf8
}

function Write-Log([string]$text) {
  Write-Host $text
  Add-Content -Path $log -Value "[$(Get-Date -Format s)] $text" -Encoding utf8
}

function Update-SessionPath {
  # Tools installed a moment ago add themselves to the persisted PATH; pick that up without a new console.
  $env:PATH = [Environment]::GetEnvironmentVariable('PATH', 'Machine') + ';' + [Environment]::GetEnvironmentVariable('PATH', 'User')
}

function Test-Winget {
  if (Get-Command winget -ErrorAction SilentlyContinue) { return $true }
  Write-Log 'winget (App Installer) was not found. Install "App Installer" from the Microsoft Store, then run this script again.'
  return $false
}

function Install-WingetPackage([string]$id, [string]$name) {
  if (-not (Test-Winget)) { return $false }
  $listed = winget list --id $id --exact --accept-source-agreements 2>$null | Out-String
  if ($listed -match [regex]::Escape($id)) {
    Write-Log "$name is already installed."
    return $true
  }
  Write-Log "Installing $name with winget ($id)..."
  winget install --id $id --exact --scope user --silent --accept-package-agreements --accept-source-agreements --disable-interactivity
  if ($LASTEXITCODE -ne 0) {
    # Some packages have no per-user installer; try the default scope (may ask for administrator rights).
    winget install --id $id --exact --silent --accept-package-agreements --accept-source-agreements --disable-interactivity
  }
  Update-SessionPath
  $ok = $LASTEXITCODE -eq 0
  Write-Log ($(if ($ok) { "$name installed." } else { "$name could not be installed (winget exit code $LASTEXITCODE)." }))
  return $ok
}

function Find-Python {
  foreach ($candidate in @('py', 'python')) {
    $cmd = Get-Command $candidate -ErrorAction SilentlyContinue
    if (-not $cmd -or $cmd.Source -like '*\WindowsApps\*') { continue }   # skip the Store alias stub
    $versionArgs = if ($candidate -eq 'py') { @('-3', '--version') } else { @('--version') }
    $out = & $cmd.Source @versionArgs 2>&1 | Out-String
    if ($LASTEXITCODE -eq 0 -and $out -match 'Python 3\.(\d+)' -and [int]$Matches[1] -ge 9) {
      return @{ Exe = $cmd.Source; Prefix = $(if ($candidate -eq 'py') { @('-3') } else { @() }) }
    }
  }
  return $null
}

Add-Content -Path $log -Value "`n[$(Get-Date -Format s)] ===== install-deps.ps1 $($PSBoundParameters.Keys -join ' ')" -Encoding utf8

if ($Semgrep) {
  Write-Step 'Semgrep (static analysis)'
  $python = Find-Python
  if (-not $python) {
    Write-Log 'Python 3.9+ not found.'
    if (Install-WingetPackage 'Python.Python.3.13' 'Python 3.13') { $python = Find-Python }
  }
  if ($python) {
    Write-Log "Using Python: $($python.Exe)"
    & $python.Exe @($python.Prefix) -m pip install --user --upgrade --disable-pip-version-check semgrep
    $results['Semgrep'] = $(if ($LASTEXITCODE -eq 0) { 'installed' } else { "failed (pip exit code $LASTEXITCODE)" })
  } else {
    $results['Semgrep'] = 'skipped: Python is not available'
  }
  Write-Log "Semgrep: $($results['Semgrep'])"
}

if ($ClaudeCode) {
  Write-Step 'Claude Code CLI (Fixing)'
  $claude = Join-Path $env:USERPROFILE '.local\bin\claude.exe'
  if (Test-Path $claude) {
    $results['Claude Code'] = 'already installed'
  } else {
    Write-Log 'Running the official installer from https://claude.ai/install.ps1 ...'
    try {
      Invoke-RestMethod -Uri 'https://claude.ai/install.ps1' -UseBasicParsing | Invoke-Expression
      $results['Claude Code'] = $(if (Test-Path $claude) { 'installed' } else { 'installer finished, claude.exe not found' })
    } catch {
      $results['Claude Code'] = "failed: $($_.Exception.Message)"
    }
  }
  Write-Log "Claude Code: $($results['Claude Code'])"
  Write-Log 'Sign in once before using Fixing: open a terminal, run "claude" and type /login.'
}

if ($Obsidian) {
  Write-Step 'Obsidian (Second Brain)'
  $results['Obsidian'] = $(if (Install-WingetPackage 'Obsidian.Obsidian' 'Obsidian') { 'installed' } else { 'failed (see log)' })
}

if ($LMStudio) {
  Write-Step 'LM Studio (local AI analyst)'
  $results['LM Studio'] = $(if (Install-WingetPackage 'ElementLabs.LMStudio' 'LM Studio') { 'installed' } else { 'failed (see log)' })
  Write-Log 'In LM Studio: download a chat model (e.g. a small Qwen), then Developer -> Start Server.'
}

Write-Step 'Summary'
foreach ($k in $results.Keys) { Write-Log ("{0,-12} {1}" -f $k, $results[$k]) }
Write-Log "Log: $log"
Write-Host ''
Write-Host 'Azura checks every engine again when it starts; the setup wizard shows what is ready.' -ForegroundColor Green
if (-not $NoPause) {
  Write-Host 'This window closes in 15 seconds...'
  Start-Sleep -Seconds 15
}
