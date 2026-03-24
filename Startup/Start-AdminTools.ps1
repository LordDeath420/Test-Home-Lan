# ============================================================================
# Startup/Start-AdminTools.ps1
# Startet AD.msc (als ADM) und DHCP.msc (als T1) maximiert auf dem richtigen Monitor
# ============================================================================
# Voraussetzung : Setup-Credentials.ps1 wurde einmalig ausgefuehrt
# Starten ueber : Start-AdminTools.vbs  (lautlos, kein Konsolenfenster)
# ============================================================================

#Requires -Version 5.1

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'

Add-Type -AssemblyName System.Windows.Forms

# Win32-API fuer Fensterpositionierung und Maximierung
Add-Type -TypeDefinition @'
using System;
using System.Text;
using System.Runtime.InteropServices;

public class WinAPI {
    [DllImport("user32.dll", SetLastError = true)]
    public static extern bool SetWindowPos(
        IntPtr hWnd, IntPtr hWndInsertAfter,
        int X, int Y, int cx, int cy, uint uFlags);

    [DllImport("user32.dll")]
    public static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);

    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    public static extern int GetWindowText(IntPtr hWnd, StringBuilder text, int count);

    public const uint SWP_NOSIZE   = 0x0001;
    public const uint SWP_NOZORDER = 0x0004;
    public const int  SW_RESTORE   = 9;
    public const int  SW_MAXIMIZE  = 3;
}
'@

# ============================================================
# Konfiguration laden
# ============================================================
$ConfigPath = Join-Path $PSScriptRoot 'Config.psd1'
if (-not (Test-Path $ConfigPath)) {
    [System.Windows.Forms.MessageBox]::Show(
        "Config.psd1 nicht gefunden:`n$ConfigPath",
        'Start-AdminTools Fehler',
        [System.Windows.Forms.MessageBoxButtons]::OK,
        [System.Windows.Forms.MessageBoxIcon]::Error
    ) | Out-Null
    exit 1
}
$Config = Import-PowerShellDataFile -Path $ConfigPath

# ============================================================
# Hilfsfunktionen
# ============================================================
function Test-CredentialExists {
    param([string]$Username)
    $result = & cmdkey.exe /list:$Username 2>&1
    return ($result -match [regex]::Escape($Username))
}

function Get-MonitorBounds {
    param([int]$Index)
    $screens = [System.Windows.Forms.Screen]::AllScreens
    if ($Index -lt $screens.Count) { return $screens[$Index].Bounds }
    Write-Warning "Monitor $Index nicht vorhanden - verwende primaeren Monitor."
    return ([System.Windows.Forms.Screen]::PrimaryScreen).Bounds
}

function Wait-MaximizeWindowOnMonitor {
    <#
    .SYNOPSIS
        Wartet bis ein mmc.exe-Fenster mit passendem Titel erscheint,
        verschiebt es auf den Ziel-Monitor und maximiert es dort.
        Reihenfolge: restore -> auf Monitor verschieben -> maximieren
        (Nur so landet das Fenster maximiert auf dem richtigen Monitor.)
    #>
    param(
        [string]$TitleContains,
        [System.Drawing.Rectangle]$Bounds,
        [int]$TimeoutSeconds = 30
    )

    Write-Host "  Warte auf Fenster '$TitleContains' (max. ${TimeoutSeconds}s)..." -ForegroundColor Yellow

    $elapsed = 0
    while ($elapsed -lt $TimeoutSeconds) {
        Start-Sleep -Seconds 1
        $elapsed++

        $procs = Get-Process -Name 'mmc' -ErrorAction SilentlyContinue
        foreach ($proc in $procs) {
            try {
                $hwnd = $proc.MainWindowHandle
                if ($hwnd -eq [IntPtr]::Zero) { continue }

                $buf = [System.Text.StringBuilder]::new(256)
                [void][WinAPI]::GetWindowText($hwnd, $buf, 256)
                $title = $buf.ToString()

                if ($title -like "*$TitleContains*") {
                    # 1. Zuerst restore (falls bereits maximiert auf falschem Monitor)
                    [void][WinAPI]::ShowWindow($hwnd, [WinAPI]::SW_RESTORE)
                    Start-Sleep -Milliseconds 100

                    # 2. Fenster auf Ziel-Monitor verschieben (Groesse unveraendert)
                    [void][WinAPI]::SetWindowPos(
                        $hwnd, [IntPtr]::Zero,
                        $Bounds.X, $Bounds.Y,
                        0, 0,
                        ([WinAPI]::SWP_NOSIZE -bor [WinAPI]::SWP_NOZORDER)
                    )
                    Start-Sleep -Milliseconds 100

                    # 3. Auf dem Ziel-Monitor maximieren
                    [void][WinAPI]::ShowWindow($hwnd, [WinAPI]::SW_MAXIMIZE)

                    Write-Host "  [OK] '$title'  ->  Monitor maximiert @ ($($Bounds.X), $($Bounds.Y))" -ForegroundColor Green
                    return $true
                }
            }
            catch { <# Prozess koennte inzwischen beendet sein #> }
        }
    }

    Write-Warning "  Timeout: Fenster '$TitleContains' nicht gefunden (${TimeoutSeconds}s)."
    return $false
}

# ============================================================
# Credentials pruefen
# ============================================================
Write-Host ''
Write-Host '=== Start-AdminTools ===' -ForegroundColor Cyan

$adMissing = -not (Test-CredentialExists -Username $Config.ADMUser)
$t1Missing = -not (Test-CredentialExists -Username $Config.T1User)

if ($adMissing -or $t1Missing) {
    $missing = @()
    if ($adMissing) { $missing += $Config.ADMUser }
    if ($t1Missing) { $missing += $Config.T1User  }

    $msg = "Credentials nicht im Credential Manager gefunden:`n" +
           ($missing -join "`n") +
           "`n`nBitte zuerst ausfuehren:`n$PSScriptRoot\Setup-Credentials.ps1"

    [System.Windows.Forms.MessageBox]::Show(
        $msg, 'Credentials fehlen',
        [System.Windows.Forms.MessageBoxButtons]::OK,
        [System.Windows.Forms.MessageBoxIcon]::Warning
    ) | Out-Null
    exit 1
}

# ============================================================
# Monitor-Bounds ermitteln
# ============================================================
$adBounds   = Get-MonitorBounds -Index $Config.ADMonitor
$dhcpBounds = Get-MonitorBounds -Index $Config.DHCPMonitor

Write-Host "AD.msc   -> Monitor $($Config.ADMonitor)  @ ($($adBounds.X), $($adBounds.Y))  [maximiert]" -ForegroundColor Cyan
Write-Host "DHCP.msc -> Monitor $($Config.DHCPMonitor)  @ ($($dhcpBounds.X), $($dhcpBounds.Y))  [maximiert]" -ForegroundColor Cyan
Write-Host ''

# ============================================================
# AD.msc als ADM-Benutzer starten
# ============================================================
Write-Host "Starte AD.msc als [$($Config.ADMUser)]..." -ForegroundColor White
$adArgs = "/savedcred /user:$($Config.ADMUser) `"mmc.exe `\`"$($Config.ADConsolePath)`\`"`""
Start-Process -FilePath 'runas.exe' -ArgumentList $adArgs

Start-Sleep -Seconds 2

# ============================================================
# DHCP.msc als T1-Benutzer starten
# Hinweis: Die doppelte Passwortabfrage der DHCP-Konsole (MMC intern) wird
# durch runas /savedcred vollstaendig abgefangen - kein manuelles Eingreifen noetig.
# ============================================================
Write-Host "Starte DHCP.msc als [$($Config.T1User)]..." -ForegroundColor White
$dhcpArgs = "/savedcred /user:$($Config.T1User) `"mmc.exe `\`"$($Config.DHCPConsolePath)`\`"`""
Start-Process -FilePath 'runas.exe' -ArgumentList $dhcpArgs

# ============================================================
# Fenster maximiert auf Ziel-Monitor positionieren
# ============================================================
Write-Host ''
Write-Host "Warte $($Config.WindowWaitSeconds)s auf Fenster-Initialisierung..." -ForegroundColor Yellow
Start-Sleep -Seconds $Config.WindowWaitSeconds

Wait-MaximizeWindowOnMonitor `
    -TitleContains  'Active Directory' `
    -Bounds         $adBounds `
    -TimeoutSeconds 20

Wait-MaximizeWindowOnMonitor `
    -TitleContains  'DHCP' `
    -Bounds         $dhcpBounds `
    -TimeoutSeconds 20

Write-Host ''
Write-Host '=== Fertig ===' -ForegroundColor Green
