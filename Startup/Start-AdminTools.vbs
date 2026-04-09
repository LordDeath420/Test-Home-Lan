' ============================================================================
' Startup/Start-AdminTools.vbs
' Stiller Launcher fuer Start-AdminTools.ps1 (kein Konsolenfenster sichtbar)
' ============================================================================
' Diese Datei (oder eine Verknuepfung darauf) in den Autostart-Ordner legen:
'   Win+R  ->  shell:startup  ->  Enter
' ============================================================================

Option Explicit

Dim oShell, strScript, strCommand

Set oShell = CreateObject("WScript.Shell")

' Pfad zum PowerShell-Skript (im gleichen Ordner wie diese VBS-Datei)
strScript = Replace(WScript.ScriptFullName, WScript.ScriptName, "") & "Start-AdminTools.ps1"

' PowerShell voellig lautlos starten (WindowStyle 0 = versteckt)
strCommand = "powershell.exe -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File """ & strScript & """"

oShell.Run strCommand, 0, False

Set oShell = Nothing
