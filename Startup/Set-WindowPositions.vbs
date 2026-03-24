' ============================================================================
' Startup/Set-WindowPositions.vbs
' Stiller Launcher fuer Set-WindowPositions.ps1 (kein Konsolenfenster sichtbar)
' ============================================================================
' Optional: Diese Datei (oder Verknuepfung) in den Autostart-Ordner legen
' wenn weitere Programme (Chrome, Outlook, Teams ...) auf bestimmten
' Monitoren gestartet werden sollen.
'   Win+R  ->  shell:startup  ->  Enter
' ============================================================================

Option Explicit

Dim oShell, strScript, strCommand

Set oShell = CreateObject("WScript.Shell")

strScript = Replace(WScript.ScriptFullName, WScript.ScriptName, "") & "Set-WindowPositions.ps1"
strCommand = "powershell.exe -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File """ & strScript & """"

oShell.Run strCommand, 0, False

Set oShell = Nothing
