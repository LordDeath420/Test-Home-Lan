# ============================================================================
# Startup/Setup-Credentials.ps1
# Einmalige Einrichtung - Speichert Credentials im Windows Credential Manager
# ============================================================================
# AUSFUEHREN ALS: angemeldeter Benutzer (KEIN Admin erforderlich)
# EINMALIG ausfuehren - danach startet Start-AdminTools.ps1 ohne Passwort-Abfrage
#
# Sicherheit:
#   - Passwoerter werden NUR ueber sichere GUI-Dialoge abgefragt (Get-Credential)
#   - Speicherung im Windows Credential Manager (DPAPI: maschinengebunden)
#   - Kein Klartext in Dateien oder Skripten
#   - Passwort wird nach Verwendung sofort aus dem Arbeitsspeicher geloescht
# ============================================================================

#Requires -Version 5.1

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$ConfigPath = Join-Path $PSScriptRoot 'Config.psd1'
if (-not (Test-Path $ConfigPath)) {
    Write-Error "Config.psd1 nicht gefunden: $ConfigPath"
    exit 1
}
$Config = Import-PowerShellDataFile -Path $ConfigPath

function Save-CredentialToManager {
    <#
    .SYNOPSIS
        Speichert Credentials sicher im Windows Credential Manager via cmdkey.
        Das Klartextpasswort existiert nur kurz im Arbeitsspeicher und wird danach ueberschrieben.
    #>
    param(
        [Parameter(Mandatory)]
        [string]$Target,

        [Parameter(Mandatory)]
        [string]$Username,

        [Parameter(Mandatory)]
        [System.Security.SecureString]$SecurePassword
    )

    $bstr = [System.IntPtr]::Zero
    try {
        $bstr   = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecurePassword)
        $plain  = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
        $result = & cmdkey.exe /add:$Target /user:$Username /pass:$plain 2>&1
        if ($LASTEXITCODE -ne 0) {
            throw "cmdkey fehlgeschlagen: $result"
        }
        Write-Host "  [OK] Credential gespeichert: $Target  (Benutzer: $Username)" -ForegroundColor Green
    }
    finally {
        if ($bstr -ne [System.IntPtr]::Zero) {
            [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
        }
        Remove-Variable plain -ErrorAction SilentlyContinue
        [System.GC]::Collect()
        [System.GC]::WaitForPendingFinalizers()
    }
}

Write-Host ''
Write-Host '============================================================' -ForegroundColor Cyan
Write-Host ' Startup Credentials Setup' -ForegroundColor Cyan
Write-Host '============================================================' -ForegroundColor Cyan
Write-Host ' Passwoerter werden NUR im Windows Credential Manager' -ForegroundColor Yellow
Write-Host ' gespeichert (DPAPI-verschluesselt, kein Klartext in Dateien).' -ForegroundColor Yellow
Write-Host ''

# ============================================================
# 1. ADM-Konto fuer AD.msc
# ============================================================
Write-Host '--- 1/2: ADM-Konto (fuer AD.msc) ---' -ForegroundColor Cyan
Write-Host "Benutzername aus Config: $($Config.ADMUser)"
$credADM = Get-Credential -Message 'ADM-Konto eingeben (fuer AD.msc via runas)' -UserName $Config.ADMUser

if (-not $credADM) {
    Write-Warning 'Abgebrochen - ADM-Credentials nicht gespeichert.'
}
else {
    Save-CredentialToManager `
        -Target         $credADM.UserName `
        -Username       $credADM.UserName `
        -SecurePassword $credADM.Password
}

Write-Host ''

# ============================================================
# 2. T1-Konto fuer DHCP.msc
# Hinweis: Die doppelte Passwortabfrage der DHCP-Konsole (MMC intern) wird
# durch runas /savedcred vollstaendig abgefangen - kein zweiter Eintrag noetig.
# ============================================================
Write-Host '--- 2/2: T1-Konto (fuer DHCP.msc) ---' -ForegroundColor Cyan
Write-Host "Benutzername aus Config: $($Config.T1User)"
$credT1 = Get-Credential -Message 'T1-Konto eingeben (fuer DHCP.msc via runas)' -UserName $Config.T1User

if (-not $credT1) {
    Write-Warning 'Abgebrochen - T1-Credentials nicht gespeichert.'
}
else {
    Save-CredentialToManager `
        -Target         $credT1.UserName `
        -Username       $credT1.UserName `
        -SecurePassword $credT1.Password
}

Write-Host ''
Write-Host '============================================================' -ForegroundColor Cyan
Write-Host ' Setup abgeschlossen!' -ForegroundColor Green
Write-Host '============================================================' -ForegroundColor Cyan
Write-Host ''
Write-Host 'Gespeicherte Credentials pruefen:' -ForegroundColor Yellow
Write-Host '  cmdkey /list' -ForegroundColor White
Write-Host ''
Write-Host 'Naechster Schritt - Autostart einrichten:' -ForegroundColor Yellow
Write-Host '  1. Win+R  ->  shell:startup  ->  Enter' -ForegroundColor White
Write-Host '  2. Verknuepfung zu Start-AdminTools.vbs in diesen Ordner erstellen' -ForegroundColor White
Write-Host ''
Write-Host 'Test (manuell starten):' -ForegroundColor Yellow
Write-Host "  powershell -File `"$PSScriptRoot\Start-AdminTools.ps1`"" -ForegroundColor White
Write-Host ''
