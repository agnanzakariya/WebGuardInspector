; Inno Setup script for Azura - WebGuard Inspector.
; Built by installer\build-installer.ps1, which publishes the app (self-contained, win-x64) into installer\out\app first.
; Per-user install by default (no administrator rights); the Setup dialog offers an all-users install as well.

#ifndef AppVersion
  #define AppVersion "0.0.0"
#endif
#define AppName "Azura - WebGuard Inspector"
#define AppExe "WebGuard.Desktop.exe"

[Setup]
AppId={{D715C38C-037F-428C-94A5-E176D4009BB6}
AppName={#AppName}
AppVersion={#AppVersion}
AppVerName={#AppName} {#AppVersion}
AppPublisher=Agnan Zakariya
AppPublisherURL=https://github.com/agnanzakariya/WebGuardInspector
AppSupportURL=https://github.com/agnanzakariya/WebGuardInspector
VersionInfoVersion={#AppVersion}
VersionInfoProductName={#AppName}
DefaultDirName={autopf}\Azura WebGuard Inspector
DefaultGroupName=Azura WebGuard Inspector
DisableProgramGroupPage=yes
PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=dialog
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0.17763
OutputDir=out
OutputBaseFilename=Azura-WebGuard-Inspector-Setup-{#AppVersion}
SetupIconFile=..\src\WebGuard.Desktop\Assets\azura.ico
UninstallDisplayIcon={app}\{#AppExe}
UninstallDisplayName={#AppName}
WizardStyle=modern
Compression=lzma2/ultra64
SolidCompression=yes
CloseApplications=yes
RestartApplications=no

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[CustomMessages]
english.DepsGroup=Install dependencies (internet connection needed):
english.DepSemgrep=Semgrep static analysis (installs Python 3 if missing, then pip install semgrep)
english.DepClamAV=ClamAV antivirus engine (winget, administrator rights) + signature database (~110 MB)
english.DepClaude=Claude Code CLI - for Fixing with Claude (sign in afterwards)
english.DepObsidian=Obsidian - for the Second Brain
english.DepLMStudio=LM Studio - for the local AI analyst (large download)
english.RunDeps=Installing the selected dependencies...
english.RepairDeps=Install or repair dependencies

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"
Name: "semgrep"; Description: "{cm:DepSemgrep}"; GroupDescription: "{cm:DepsGroup}"
Name: "clamav"; Description: "{cm:DepClamAV}"; GroupDescription: "{cm:DepsGroup}"; Flags: unchecked
Name: "claude"; Description: "{cm:DepClaude}"; GroupDescription: "{cm:DepsGroup}"; Flags: unchecked
Name: "obsidian"; Description: "{cm:DepObsidian}"; GroupDescription: "{cm:DepsGroup}"; Flags: unchecked
Name: "lmstudio"; Description: "{cm:DepLMStudio}"; GroupDescription: "{cm:DepsGroup}"; Flags: unchecked

[Files]
; App, runtime, rules and the bundled engines (tools\gitleaks.exe, tools\osv-scanner.exe, tools\yr.exe + licenses).
Source: "out\app\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "install-deps.ps1"; DestDir: "{app}\setup"; Flags: ignoreversion

[Icons]
Name: "{group}\{#AppName}"; Filename: "{app}\{#AppExe}"
Name: "{group}\{cm:RepairDeps}"; Filename: "powershell.exe"; \
  Parameters: "-NoProfile -ExecutionPolicy Bypass -File ""{app}\setup\install-deps.ps1"" -Semgrep -ClaudeCode"; WorkingDir: "{app}\setup"
Name: "{group}\{cm:UninstallProgram,{#AppName}}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\{#AppName}"; Filename: "{app}\{#AppExe}"; Tasks: desktopicon

[Run]
Filename: "powershell.exe"; Parameters: "-NoProfile -ExecutionPolicy Bypass -File ""{app}\setup\install-deps.ps1"" {code:DepsArgs}"; \
  WorkingDir: "{app}\setup"; StatusMsg: "{cm:RunDeps}"; Check: AnyDepsSelected; Flags: waituntilterminated
Filename: "{app}\{#AppExe}"; Description: "{cm:LaunchProgram,{#AppName}}"; Flags: nowait postinstall skipifsilent

[Code]
function DepsArgs(Param: String): String;
begin
  Result := '';
  if WizardIsTaskSelected('semgrep') then Result := Result + ' -Semgrep';
  if WizardIsTaskSelected('clamav') then Result := Result + ' -ClamAV';
  if WizardIsTaskSelected('claude') then Result := Result + ' -ClaudeCode';
  if WizardIsTaskSelected('obsidian') then Result := Result + ' -Obsidian';
  if WizardIsTaskSelected('lmstudio') then Result := Result + ' -LMStudio';
end;

function AnyDepsSelected: Boolean;
begin
  Result := DepsArgs('') <> '';
end;
