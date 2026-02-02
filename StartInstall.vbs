' ============================================================================
' Installation.ps1 starter - debug (Fenster bleibt offen)
' ============================================================================

Option Explicit

Dim objShell, objFSO, strScriptPath, strPSPath, strCmd
Set objShell = CreateObject("Shell.Application")
Set objFSO   = CreateObject("Scripting.FileSystemObject")

' USB-Stick-Ordner (fix)
strScriptPath = "D:\Datein\Skripte"
strPSPath     = objFSO.BuildPath(strScriptPath, "Installation.ps1")

If Not objFSO.FileExists(strPSPath) Then
    MsgBox "Fehler: Datei nicht gefunden:" & vbCrLf & strPSPath, vbCritical, "Start Fehler"
    WScript.Quit 1
End If

' /k = CMD bleibt offen, -NoExit = PowerShell bleibt offen
strCmd = "/k powershell.exe -NoProfile -ExecutionPolicy Bypass -NoExit -File """ & strPSPath & """"

objShell.ShellExecute "cmd.exe", strCmd, strScriptPath, "runas", 1
