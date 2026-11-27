; Script de Inno Setup (https://jrsoftware.org/isinfo.php)
; Crea "DetectorRed-Instalador.exe": asistente de instalación con acceso
; directo en el menú Inicio y desinstalador en "Agregar o quitar programas".
;
; Requisito: haber generado antes dist\DetectorRed.exe con construir_windows.bat
; Uso: abrir este archivo con Inno Setup Compiler y presionar "Compile".

#define NombreApp "Detector de dispositivos"
#define VersionApp "0.8.0"
#define Autor "Jhan Camilo Valencia Giraldo"

[Setup]
AppId={{6E0B5A43-2F7C-4B8E-9C1D-3A5F7B9D2E41}
AppName={#NombreApp}
AppVersion={#VersionApp}
AppPublisher={#Autor}
DefaultDirName={autopf}\DetectorRed
DefaultGroupName={#NombreApp}
OutputDir=..\salida_instalador
OutputBaseFilename=DetectorRed-Instalador-{#VersionApp}
Compression=lzma2
SolidCompression=yes
LicenseFile=..\LICENSE
; No pide permisos de administrador: se instala para el usuario actual
PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=dialog
WizardStyle=modern

[Languages]
Name: "spanish"; MessagesFile: "compiler:Languages\Spanish.isl"

[Tasks]
Name: "escritorio"; Description: "Crear acceso directo en el escritorio"; Flags: unchecked

[Files]
Source: "..\dist\DetectorRed.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\README.md"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\LICENSE"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\{#NombreApp}"; Filename: "{app}\DetectorRed.exe"
Name: "{group}\Desinstalar {#NombreApp}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\{#NombreApp}"; Filename: "{app}\DetectorRed.exe"; Tasks: escritorio

[Run]
; Regla de firewall: solo si se instala como administrador ("para todos los
; usuarios"). Permite RESPUESTAS UDP (mDNS/SSDP/NetBIOS) a este programa, solo
; en redes privadas. Si se instala sin permisos, el programa avisa y explica
; cómo crearla con:  DetectorRed.exe --configurar-firewall
Filename: "{sys}\netsh.exe"; Parameters: "advfirewall firewall add rule name=""Detector de red"" dir=in action=allow program=""{app}\DetectorRed.exe"" protocol=UDP profile=private enable=yes"; Flags: runhidden; Check: IsAdminInstallMode; StatusMsg: "Configurando el firewall..."
Filename: "{app}\DetectorRed.exe"; Description: "Abrir {#NombreApp}"; Flags: nowait postinstall skipifsilent

[UninstallRun]
Filename: "{sys}\netsh.exe"; Parameters: "advfirewall firewall delete rule name=""Detector de red"""; Flags: runhidden; Check: IsAdminInstallMode; RunOnceId: "QuitarReglaFirewall"

; Nota: el inventario y el historial viven en %APPDATA%\DetectorRed,
; así que desinstalar o actualizar NO borra los datos del usuario.
