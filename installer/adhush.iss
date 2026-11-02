; AdHush setup. Build with installer\build.ps1 (it stages files into installer\stage first).
#define AppVersion GetEnv("ADHUSH_VERSION")
#if AppVersion == ""
  #define AppVersion "0.1.0"
#endif

[Setup]
AppId={{6E3F1C2A-5B7D-4E8F-9A1B-2C3D4E5F6071}
AppName=AdHush
AppVersion={#AppVersion}
AppVerName=AdHush {#AppVersion}
AppPublisher=AdHush
DefaultDirName={autopf}\AdHush
DefaultGroupName=AdHush
DisableProgramGroupPage=yes
PrivilegesRequired=admin
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0.17763
SetupIconFile=adhush.ico
UninstallDisplayIcon={app}\adhush-tray.exe
UninstallDisplayName=AdHush ad blocker
OutputDir=output
OutputBaseFilename=AdHushSetup-{#AppVersion}
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
CloseApplications=force
RestartApplications=no

[Tasks]
Name: dns; Description: "Block ads for the whole PC (point Windows DNS at AdHush)"; GroupDescription: "Protection:"
Name: web; Description: "Advanced: also filter inside web pages, e.g. YouTube ads (installs a certificate unique to this PC; can break some sites)"; GroupDescription: "Protection:"; Flags: unchecked
Name: autostart; Description: "Show the AdHush icon in the notification area at sign-in"; GroupDescription: "Other:"

[Files]
Source: "stage\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{group}\AdHush"; Filename: "{app}\adhush-tray.exe"
Name: "{group}\Restore normal internet"; Filename: "{app}\scripts\restore-internet.cmd"; IconFilename: "{sys}\shell32.dll"; IconIndex: 238; Comment: "Use this if the internet stops working: turns off AdHush whole-PC protection and puts your normal DNS back"
Name: "{group}\Uninstall AdHush"; Filename: "{uninstallexe}"

[Registry]
Root: HKLM; Subkey: "Software\Microsoft\Windows\CurrentVersion\Run"; ValueType: string; ValueName: "AdHush"; ValueData: """{app}\adhush-tray.exe"""; Flags: uninsdeletevalue; Tasks: autostart

[Run]
Filename: "powershell.exe"; Parameters: "-NoProfile -ExecutionPolicy Bypass -File ""{app}\installer\post-install.ps1"" -AppDir ""{app}"" {code:TaskSwitches}"; StatusMsg: "Starting the AdHush service…"; Flags: runhidden waituntilterminated
; Automatic updates run as SYSTEM: the user's own tray relaunches itself, so don't start one here.
Filename: "{app}\adhush-tray.exe"; Description: "Open AdHush"; Flags: postinstall nowait runasoriginaluser; Check: not IsUpdate

[UninstallRun]
Filename: "powershell.exe"; Parameters: "-NoProfile -ExecutionPolicy Bypass -File ""{app}\installer\pre-uninstall.ps1"" -AppDir ""{app}"""; RunOnceId: "AdHushCleanup"; Flags: runhidden waituntilterminated

[UninstallDelete]
Type: filesandordirs; Name: "{commonappdata}\AdHush"
Type: files; Name: "{app}\host\com.adhush.host.json"

[Code]
function TaskSwitches(Param: String): String;
begin
  Result := '';
  if WizardIsTaskSelected('dns') then Result := Result + ' -Dns';
  if WizardIsTaskSelected('web') then Result := Result + ' -Web';
end;

// /UPDATE: started by the AdHush service's updater (see service/src/updater.rs).
function IsUpdate: Boolean;
var
  I: Integer;
begin
  Result := False;
  for I := 1 to ParamCount do
    if CompareText(ParamStr(I), '/UPDATE') = 0 then Result := True;
end;

// On upgrade, stop the running service and tray so their files can be replaced.
// "net stop" waits until the service has stopped (it restores Windows DNS first).
function PrepareToInstall(var NeedsRestart: Boolean): String;
var
  Code: Integer;
begin
  Exec(ExpandConstant('{sys}\taskkill.exe'), '/F /IM adhush-tray.exe', '', SW_HIDE, ewWaitUntilTerminated, Code);
  Exec(ExpandConstant('{sys}\net.exe'), 'stop AdHush', '', SW_HIDE, ewWaitUntilTerminated, Code);
  Exec(ExpandConstant('{sys}\taskkill.exe'), '/F /IM adhush-core.exe', '', SW_HIDE, ewWaitUntilTerminated, Code);
  Result := '';
end;

// If setup stopped the service and then failed or was cancelled, start the old one again
// (harmless when the new version is already running).
procedure DeinitializeSetup;
var
  Code: Integer;
begin
  Exec(ExpandConstant('{sys}\sc.exe'), 'start AdHush', '', SW_HIDE, ewWaitUntilTerminated, Code);
end;
