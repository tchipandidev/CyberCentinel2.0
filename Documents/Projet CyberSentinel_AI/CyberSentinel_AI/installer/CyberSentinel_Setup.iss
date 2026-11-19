; ==============================================================================
; CYBERSENTINEL AI - INNO SETUP INSTALLER SCRIPT
; ==============================================================================
; Script de packaging professionnel pour Windows 10 / 11 (x64)
; ==============================================================================

#define MyAppName "CyberSentinel AI"
#define MyAppVersion "1.0.0"
#define MyAppPublisher "CyberSentinel Engineering Team"
#define MyAppURL "https://github.com/CyberSentinel-AI"
#define MyAppExeName "CyberSentinel.Desktop.exe"
#define MyAppAssocName MyAppName + " File"
#define MyAppAssocExt ".exe"
#define MyAppAssocKey StringChange(MyAppAssocName, " ", "") + MyAppAssocExt

[Setup]
AppId={{E68A4287-B38E-4A9B-98F1-3D5A726FA291}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}
AppUpdatesURL={#MyAppURL}
DefaultDirName={autopf}\{#MyAppName}
DefaultGroupName={#MyAppName}
AllowNoIcons=yes
LicenseFile=..\LICENSE.txt
OutputDir=..\publish\installer
OutputBaseFilename=CyberSentinel_Setup_v{#MyAppVersion}_x64
Compression=lzma2/ultra64
SolidCompression=yes
WizardStyle=modern
ArchitecturesInstallIn64BitMode=x64
PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=dialog

[Languages]
Name: "french"; MessagesFile: "compiler:Languages\French.isl"
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked
Name: "contextmenu"; Description: "Ajouter 'Analyser avec CyberSentinel AI' au menu contextuel de l'Explorateur"; GroupDescription: "Intégration Windows:"

[Files]
; Binaires de l'application
Source: "..\publish\win-x64\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs
; Exclure les données temporaires
; NOTE: Ne pas marquer les fichiers de configuration comme ignoreversion s'ils existent déjà
Source: "..\publish\win-x64\appsettings.json"; DestDir: "{app}"; Flags: onlyifdoesntexist

[Dirs]
; Répertoires de données applicatives sécurisées
Name: "{commonappdata}\CyberSentinel"; Permissions: users-modify
Name: "{commonappdata}\CyberSentinel\Quarantine"; Permissions: users-modify
Name: "{commonappdata}\CyberSentinel\Logs"; Permissions: users-modify
Name: "{localappdata}\CyberSentinel"; Permissions: users-modify

[Icons]
Name: "{group}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"
Name: "{group}\Désinstaller {#MyAppName}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; Tasks: desktopicon

[Registry]
; Intégration du menu contextuel Windows Explorer pour les fichiers
Root: HKCU; Subkey: "Software\Classes\*\shell\CyberSentinel"; ValueType: string; ValueName: ""; ValueData: "Analyser avec CyberSentinel AI"; Tasks: contextmenu; Flags: uninsdeletekey
Root: HKCU; Subkey: "Software\Classes\*\shell\CyberSentinel\command"; ValueType: string; ValueName: ""; ValueData: """{app}\{#MyAppExeName}"" --scan ""%1"""; Tasks: contextmenu; Flags: uninsdeletekey

; Intégration du menu contextuel Windows Explorer pour les dossiers
Root: HKCU; Subkey: "Software\Classes\Directory\shell\CyberSentinel"; ValueType: string; ValueName: ""; ValueData: "Analyser le dossier avec CyberSentinel AI"; Tasks: contextmenu; Flags: uninsdeletekey
Root: HKCU; Subkey: "Software\Classes\Directory\shell\CyberSentinel\command"; ValueType: string; ValueName: ""; ValueData: """{app}\{#MyAppExeName}"" --scan-dir ""%1"""; Tasks: contextmenu; Flags: uninsdeletekey

[Run]
Filename: "{app}\{#MyAppExeName}"; Description: "{cm:LaunchProgram,{#StringChange(MyAppName, '&', '&&')}}"; Flags: nowait postinstall skipifsilent

[UninstallDelete]
; Nettoyage des caches et logs temporaires à la désinstallation
Type: files; Name: "{localappdata}\CyberSentinel\*.tmp"
Type: dirifempty; Name: "{localappdata}\CyberSentinel"

[Code]
// Vérification des prérequis .NET 10.0 Runtime au début de l'installation
function InitializeSetup(): Boolean;
var
  ErrorCode: Integer;
  Net10Installed: Boolean;
begin
  // Vérification de la présence du runtime .NET 10.0 dans le registre Windows
  Net10Installed := RegKeyExists(HKLM, 'SOFTWARE\dotnet\Setup\InstalledVersions\x64\sharedhost') or
                    RegKeyExists(HKLM, 'SOFTWARE\WOW6432Node\dotnet\Setup\InstalledVersions\x64\sharedhost') or
                    FileExists(ExpandConstant('{commonpf}\dotnet\dotnet.exe'));
  
  if not Net10Installed then
  begin
    if MsgBox('Le composant .NET 10.0 Desktop Runtime n''a pas été détecté sur votre système.' + #13#10 +
              'Souhaitez-vous continuer quand même ?', mbConfirmation, MB_YESNO) = IDNO then
    begin
      Result := False;
      Exit;
    end;
  end;
  
  Result := True;
end;

// Question à l'utilisateur lors de la désinstallation pour préserver ou purger la quarantaine
procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  QuarantineDir: String;
begin
  if CurUninstallStep = usUninstall then
  begin
    QuarantineDir := ExpandConstant('{commonappdata}\CyberSentinel\Quarantine');
    if DirExists(QuarantineDir) then
    begin
      if MsgBox('Souhaitez-vous purger définitivement les fichiers isolés en quarantaine et l''historique des audits ?', 
                mbConfirmation, MB_YESNO or MB_DEFBUTTON2) = IDYES then
      begin
        DelTree(ExpandConstant('{commonappdata}\CyberSentinel'), True, True, True);
      end;
    end;
  end;
end;

