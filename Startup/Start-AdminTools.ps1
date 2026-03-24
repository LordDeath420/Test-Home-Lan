# ============================================================================
# Startup/Start-AdminTools.ps1
# Startet AD.msc (als ADM) und DHCP.msc (als T1) auf den richtigen Monitoren
# ============================================================================
# Voraussetzung : Setup-Credentials.ps1 wurde einmalig ausgefuehrt
# Starten ueber : Start-AdminTools.vbs  (lautlos, kein Konsolenfenster)
# ============================================================================

#Requires -Version 5.1

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'

Add-Type -AssemblyName System.Windows.Forms

# Win32-API fuer Fensterpositionierung
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

    public const uint SWP_SHOWWINDOW = 0x0040;
    public const int  SW_RESTORE     = 9;
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

function Wait-AndPositionWindow {
    <#
    .SYNOPSIS
        Wartet bis ein mmc.exe-Fenster mit passendem Titel erscheint und positioniert es.
        Funktioniert auch wenn mmc als anderer Benutzer laeuft (selbe Windows-Session).
    #>
    param(
        [string]$TitleContains,
        [System.Drawing.Rectangle]$Bounds,
        [int]$Width,
        [int]$Height,
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
                    [void][WinAPI]::ShowWindow($hwnd, [WinAPI]::SW_RESTORE)
                    [void][WinAPI]::SetWindowPos(
                        $hwnd, [IntPtr]::Zero,
                        $Bounds.X, $Bounds.Y,
                        $Width, $Height,
                        [WinAPI]::SWP_SHOWWINDOW
                    )
                    Write-Host "  [OK] '$title'  ->  Monitor-Position ($($Bounds.X), $($Bounds.Y))" -ForegroundColor Green
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

Write-Host "AD.msc   -> Monitor $($Config.ADMonitor)  @ ($($adBounds.X), $($adBounds.Y))" -ForegroundColor Cyan
Write-Host "DHCP.msc -> Monitor $($Config.DHCPMonitor)  @ ($($dhcpBounds.X), $($dhcpBounds.Y))" -ForegroundColor Cyan
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
# Der DHCP-Server-Credential (zweite Abfrage) ist bereits im Credential Manager
# unter dem Eintrag '$Config.DHCPServer' hinterlegt (gespeichert durch Setup-Credentials.ps1)
# ============================================================
Write-Host "Starte DHCP.msc als [$($Config.T1User)]..." -ForegroundColor White
$dhcpArgs = "/savedcred /user:$($Config.T1User) `"mmc.exe `\`"$($Config.DHCPConsolePath)`\`"`""
Start-Process -FilePath 'runas.exe' -ArgumentList $dhcpArgs

# ============================================================
# Fenster positionieren
# ============================================================
Write-Host ''
Write-Host "Warte $($Config.WindowWaitSeconds)s auf Fenster-Initialisierung..." -ForegroundColor Yellow
Start-Sleep -Seconds $Config.WindowWaitSeconds

# AD-Konsole (Fenstertitel enthaelt typischerweise 'Active Directory' oder den Konsolennamen)
Wait-AndPositionWindow `
    -TitleContains  'Active Directory' `
    -Bounds         $adBounds `
    -Width          $Config.WindowWidth `
    -Height         $Config.WindowHeight `
    -TimeoutSeconds 20

# DHCP-Konsole
Wait-AndPositionWindow `
    -TitleContains  'DHCP' `
    -Bounds         $dhcpBounds `
    -Width          $Config.WindowWidth `
    -Height         $Config.WindowHeight `
    -TimeoutSeconds 20

Write-Host ''
Write-Host '=== Fertig ===' -ForegroundColor Green
