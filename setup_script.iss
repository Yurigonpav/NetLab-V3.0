[Setup]

AppName=NetLab Educacional
AppVersion=1.1
AppPublisher=Yuri Goncalves Pavao

DefaultDirName={autopf}\NetLab
DefaultGroupName=NetLab Educacional

OutputDir=Output
OutputBaseFilename=NetLab_Setup

Compression=lzma
SolidCompression=yes
WizardStyle=modern
PrivilegesRequired=admin


[Files]

Source: "dist\NetLab\*"; DestDir: "{app}"; Flags: recursesubdirs

Source: "installers\npcap-1.87.exe"; DestDir: "{tmp}"
Source: "installers\vc_redist.x64.exe"; DestDir: "{tmp}"


[Icons]

Name: "{group}\NetLab Educacional"; Filename: "{app}\NetLab.exe"
Name: "{commondesktop}\NetLab Educacional"; Filename: "{app}\NetLab.exe"


[Run]

Filename: "{tmp}\vc_redist.x64.exe"; Parameters: "/install /quiet /norestart"; StatusMsg: "Instalando Visual C++..."

Filename: "{tmp}\npcap-1.87.exe"; Parameters: "/winpcap_mode=yes"; StatusMsg: "Instalando Npcap..."

Filename: "{app}\NetLab.exe"; Description: "Executar NetLab"; Flags: nowait postinstall skipifsilent