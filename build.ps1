<#
.SYNOPSIS
  Restore, build and test WebGuard Inspector, then optionally launch the desktop app.
.EXAMPLE
  .\build.ps1            # Debug build + tests
  .\build.ps1 -Run       # ...and start the WPF app
  .\build.ps1 -Configuration Release
#>
[CmdletBinding()]
param(
  [ValidateSet('Debug', 'Release')] [string]$Configuration = 'Debug',
  [switch]$Run
)
$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot

Write-Host "== dotnet SDK ==" -ForegroundColor Cyan
dotnet --version
if ($LASTEXITCODE -ne 0) { throw ".NET SDK not found. Install .NET 10 SDK." }

Write-Host "== Restore ==" -ForegroundColor Cyan
dotnet restore .\WebGuardInspector.slnx
if ($LASTEXITCODE -ne 0) { throw "Restore failed" }

Write-Host "== Build ($Configuration) ==" -ForegroundColor Cyan
dotnet build .\WebGuardInspector.slnx -c $Configuration --no-restore
if ($LASTEXITCODE -ne 0) { throw "Build failed" }

Write-Host "== Tests ==" -ForegroundColor Cyan
dotnet run --project .\tests\WebGuard.Tests\WebGuard.Tests.csproj -c $Configuration --no-build
if ($LASTEXITCODE -ne 0) { throw "Tests failed" }

Write-Host "PASS: build and tests completed" -ForegroundColor Green
if ($Run) {
  dotnet run --project .\src\WebGuard.Desktop\WebGuard.Desktop.csproj -c $Configuration --no-build
} else {
  Write-Host "Run UI: .\build.ps1 -Run   (or F5 in Visual Studio with WebGuard.Desktop as startup project)"
}
