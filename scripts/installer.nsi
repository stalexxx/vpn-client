; NSIS installer for the Windows client. Build: makensis -DVERSION=x.y.z -DSTAGE=<dir> -DOUT=<exe> -DICON=<ico> installer.nsi
Unicode true
!include "MUI2.nsh"
!include "LogicLib.nsh"

Name "VPN Client"
OutFile "${OUT}"
InstallDir "$PROGRAMFILES64\VPN Client"
InstallDirRegKey HKLM "Software\VPNClient" "InstallDir"
RequestExecutionLevel admin
SetCompressor /SOLID lzma
!define MUI_ICON "${ICON}"
!define MUI_UNICON "${ICON}"
!define MUI_ABORTWARNING
!define MUI_FINISHPAGE_RUN "$INSTDIR\VPNClient.exe"
!define MUI_FINISHPAGE_RUN_TEXT "Запустить VPN Client"

!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES
!insertmacro MUI_LANGUAGE "Russian"

VIProductVersion "${VERSION}.0"
VIAddVersionKey "ProductName" "VPN Client"
VIAddVersionKey "FileVersion" "${VERSION}"
VIAddVersionKey "FileDescription" "VPN Client installer"

Function StopApp
  nsExec::Exec 'taskkill /F /IM VPNClient.exe'
  nsExec::Exec 'taskkill /F /IM vpnclient-xray.exe'
  Sleep 500
FunctionEnd

Section "VPN Client" SecMain
  SetOutPath "$INSTDIR"
  Call StopApp
  File /r "${STAGE}\*.*"
  WriteUninstaller "$INSTDIR\Uninstall.exe"
  CreateDirectory "$SMPROGRAMS\VPN Client"
  CreateShortcut "$SMPROGRAMS\VPN Client\VPN Client.lnk" "$INSTDIR\VPNClient.exe"
  CreateShortcut "$SMPROGRAMS\VPN Client\Удалить VPN Client.lnk" "$INSTDIR\Uninstall.exe"
  CreateShortcut "$DESKTOP\VPN Client.lnk" "$INSTDIR\VPNClient.exe"
  WriteRegStr HKLM "Software\VPNClient" "InstallDir" "$INSTDIR"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\VPNClient" "DisplayName" "VPN Client"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\VPNClient" "DisplayVersion" "${VERSION}"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\VPNClient" "DisplayIcon" "$INSTDIR\VPNClient.exe"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\VPNClient" "UninstallString" '"$INSTDIR\Uninstall.exe"'
  WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\VPNClient" "NoModify" 1
  WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\VPNClient" "NoRepair" 1

  ; The UI needs the Edge WebView2 runtime (present on Windows 11 and updated Windows 10); fetch it if missing.
  SetRegView 32
  ReadRegStr $0 HKLM "SOFTWARE\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}" "pv"
  ${If} $0 == ""
    ReadRegStr $0 HKCU "Software\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}" "pv"
  ${EndIf}
  SetRegView 64
  ${If} $0 == ""
    DetailPrint "Загрузка Microsoft Edge WebView2…"
    NSISdl::download "https://go.microsoft.com/fwlink/p/?LinkId=2124703" "$TEMP\MicrosoftEdgeWebview2Setup.exe"
    Pop $1
    ${If} $1 == "success"
      ExecWait '"$TEMP\MicrosoftEdgeWebview2Setup.exe" /silent /install'
    ${Else}
      MessageBox MB_OK|MB_ICONEXCLAMATION "Не удалось скачать WebView2 ($1). Установите Microsoft Edge WebView2 Runtime вручную, иначе окно приложения не откроется."
    ${EndIf}
    Delete "$TEMP\MicrosoftEdgeWebview2Setup.exe"
  ${EndIf}
SectionEnd

Section "Uninstall"
  nsExec::Exec 'taskkill /F /IM VPNClient.exe'
  nsExec::Exec 'taskkill /F /IM vpnclient-xray.exe'
  Sleep 500
  Delete "$DESKTOP\VPN Client.lnk"
  RMDir /r "$SMPROGRAMS\VPN Client"
  RMDir /r "$INSTDIR"
  DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\VPNClient"
  DeleteRegKey HKLM "Software\VPNClient"
SectionEnd
