<#
.SYNOPSIS
  Builds the standalone installer: publishes Azura - WebGuard Inspector self-contained for win-x64, bundles Gitleaks,
  OSV-Scanner and YARA-X with their licenses, and compiles installer\azura.iss with Inno Setup 6.
.EXAMPLE
  .\installer\build-installer.ps1
  .\installer\build-installer.ps1 -ToolsDir D:\tools      # take gitleaks.exe, osv-scanner.exe and yr.exe from a folder
.NOTES
  Needs the .NET 10 SDK with the win-x64 runtime packs in the NuGet cache (no download when they are there) and
  Inno Setup 6 (winget install JRSoftware.InnoSetup). Output: installer\out\Azura-WebGuard-Inspector-Setup-<version>.exe
#>
[CmdletBinding()]
param(
  [string]$ToolsDir,
  [switch]$SkipTests
)
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
$out = Join-Path $PSScriptRoot 'out'
$app = Join-Path $out 'app'
Set-Location $root

[xml]$props = Get-Content (Join-Path $root 'Directory.Build.props')
$version = ($props.Project.PropertyGroup | ForEach-Object { $_.Version } | Where-Object { $_ }) | Select-Object -First 1
if (-not $version) { throw 'Version not found in Directory.Build.props' }
Write-Host "== Azura - WebGuard Inspector $version ==" -ForegroundColor Cyan

if (-not $SkipTests) {
  Write-Host '== Tests ==' -ForegroundColor Cyan
  dotnet run --project .\tests\WebGuard.Tests\WebGuard.Tests.csproj -c Release
  if ($LASTEXITCODE -ne 0) { throw 'Tests failed' }
}

Write-Host '== Publish (self-contained, win-x64) ==' -ForegroundColor Cyan
if (Test-Path $app) { Remove-Item $app -Recurse -Force }
$common = @('-c', 'Release', '-r', 'win-x64', '--self-contained', 'true', '-p:DebugType=none', '-p:DebugSymbols=false', '-p:SatelliteResourceLanguages=en', '-o', $app, '-nologo')
dotnet publish .\src\WebGuard.Desktop\WebGuard.Desktop.csproj @common
if ($LASTEXITCODE -ne 0) { throw 'Publish of the desktop app failed' }
# Published second so WebGuard.Mcp.exe gets its own self-contained runtimeconfig (the desktop publish copies a
# framework-dependent one from the project reference).
dotnet publish .\src\WebGuard.Mcp\WebGuard.Mcp.csproj @common
if ($LASTEXITCODE -ne 0) { throw 'Publish of the MCP server failed' }

Write-Host '== Bundled engines ==' -ForegroundColor Cyan
$tools = Join-Path $app 'tools'
New-Item -ItemType Directory -Force -Path (Join-Path $tools 'licenses') | Out-Null
$wingetPackages = Join-Path $env:LOCALAPPDATA 'Microsoft\WinGet\Packages'
foreach ($exe in 'gitleaks.exe', 'osv-scanner.exe', 'yr.exe') {
  $source = $null
  if ($ToolsDir -and (Test-Path (Join-Path $ToolsDir $exe))) { $source = Join-Path $ToolsDir $exe }
  if (-not $source) { $source = (Get-Command $exe -ErrorAction SilentlyContinue).Source }
  if (-not $source -and (Test-Path $wingetPackages)) {
    $source = Get-ChildItem $wingetPackages -Recurse -Filter $exe -ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty FullName
  }
  if (-not $source) { throw "$exe not found. Install it (winget) or pass -ToolsDir." }
  Copy-Item $source $tools -Force
  $ver = (& (Join-Path $tools $exe) --version 2>&1 | Select-Object -First 1)
  Write-Host ("  {0,-16} {1}  ({2})" -f $exe, $ver, $source)
}
Copy-Item (Join-Path $PSScriptRoot 'licenses\*.txt') (Join-Path $tools 'licenses') -Force

Write-Host '== Inno Setup ==' -ForegroundColor Cyan
$iscc = @(
  (Join-Path $env:LOCALAPPDATA 'Programs\Inno Setup 6\ISCC.exe'),
  (Join-Path ${env:ProgramFiles(x86)} 'Inno Setup 6\ISCC.exe'),
  (Join-Path $env:ProgramFiles 'Inno Setup 6\ISCC.exe')
) | Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $iscc) { throw 'Inno Setup 6 not found. Install it with: winget install JRSoftware.InnoSetup' }
& $iscc "/DAppVersion=$version" (Join-Path $PSScriptRoot 'azura.iss')
if ($LASTEXITCODE -ne 0) { throw 'Inno Setup failed' }

$setup = Join-Path $out "Azura-WebGuard-Inspector-Setup-$version.exe"
$size = '{0:N1} MB' -f ((Get-Item $setup).Length / 1MB)
Write-Host "Installer: $setup ($size)" -ForegroundColor Green
