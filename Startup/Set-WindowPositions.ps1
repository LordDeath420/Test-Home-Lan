# ============================================================================
# Startup/Set-WindowPositions.ps1
# Positioniert Autostart-Programme auf die konfigurierten Monitore
# ============================================================================
# Wird nach dem Login ausgefuehrt um weitere Programme (Chrome, Outlook, Teams ...)
# automatisch auf den richtigen Monitor zu verschieben.
# Monitor-Zuweisungen in Config.psd1 unter 'AutostartMonitors' konfigurieren.
# ============================================================================

#Requires -Version 5.1

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'

Add-Type -AssemblyName System.Windows.Forms

Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;

public class WinAPIPos {
    [DllImport("user32.dll", SetLastError = true)]
    public static extern bool SetWindowPos(
        IntPtr hWnd, IntPtr hWndInsertAfter,
        int X, int Y, int cx, int cy, uint uFlags);

    [DllImport("user32.dll")]
    public static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);

    public const uint SWP_NOSIZE     = 0x0001;
    public const uint SWP_NOZORDER   = 0x0004;
    public const uint SWP_SHOWWINDOW = 0x0040;
    public const int  SW_RESTORE     = 9;
}
'@

$ConfigPath = Join-Path $PSScriptRoot 'Config.psd1'
if (-not (Test-Path $ConfigPath)) {
    Write-Error "Config.psd1 nicht gefunden: $ConfigPath"
    exit 1
}
$Config = Import-PowerShellDataFile -Path $ConfigPath

if ($Config.AutostartMonitors.Count -eq 0) {
    Write-Host 'Keine AutostartMonitors in Config.psd1 konfiguriert - nichts zu tun.' -ForegroundColor Yellow
    exit 0
}

Write-Host "Warte $($Config.AutostartWaitSeconds)s auf Autostart-Programme..." -ForegroundColor Yellow
Start-Sleep -Seconds $Config.AutostartWaitSeconds

$screens = [System.Windows.Forms.Screen]::AllScreens
$moved   = 0
$missed  = 0

foreach ($entry in $Config.AutostartMonitors.GetEnumerator()) {
    $processName  = $entry.Key
    $monitorIndex = $entry.Value

    if ($monitorIndex -ge $screens.Count) {
        Write-Warning "Monitor $monitorIndex fuer '$processName' nicht vorhanden - uebersprungen."
        $missed++
        continue
    }
    $screen = $screens[$monitorIndex]

    $procs = Get-Process -Name $processName -ErrorAction SilentlyContinue
    if (-not $procs) {
        Write-Warning "'$processName' laeuft nicht - uebersprungen."
        $missed++
        continue
    }

    foreach ($proc in $procs) {
        $hwnd = $proc.MainWindowHandle
        if ($hwnd -eq [IntPtr]::Zero) { continue }

        [void][WinAPIPos]::ShowWindow($hwnd, [WinAPIPos]::SW_RESTORE)
        [void][WinAPIPos]::SetWindowPos(
            $hwnd, [IntPtr]::Zero,
            $screen.Bounds.X, $screen.Bounds.Y,
            0, 0,
            ([WinAPIPos]::SWP_NOSIZE -bor [WinAPIPos]::SWP_NOZORDER -bor [WinAPIPos]::SWP_SHOWWINDOW)
        )
        Write-Host "[OK] '$processName' (PID $($proc.Id))  ->  Monitor $monitorIndex  @ ($($screen.Bounds.X), $($screen.Bounds.Y))" -ForegroundColor Green
        $moved++
    }
}

Write-Host ''
Write-Host "Fenster positioniert: $moved  |  Uebersprungen: $missed" -ForegroundColor Cyan
