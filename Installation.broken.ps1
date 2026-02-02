# ============================================================================
# Installation.ps1 - Hauptskript für automatisierte Windows-Einrichtung
# Version: 2.0.0
# ============================================================================

#region Skript-Parameter
# -------------------------------------------------------------------------
# Parameter für Automatisierung und Unattended-Modus
# -------------------------------------------------------------------------
param(
    # Unattended-Modus: Keine Benutzerinteraktion, alle Werte aus Parametern
    [switch]$Unattended,

    # Gerätetyp (für Unattended-Modus)
    [ValidateSet('Rechner', 'Baaske', 'ImportRechner', 'NUC', 'Laptop', 'VPN', 'Einstellen', 'TreiberEntpacken', 'WindowsUpdateReset')]
    [string]$Modus,

    # Rechnername (für Unattended-Modus)
    [string]$ComputerName,

    # Hardware-ID (für Unattended-Modus)
    [string]$HardwareID,

    # Ticket-ID (für Unattended-Modus)
    [string]$TicketID,

    # Modell für Laptop/NUC/VPN (für Unattended-Modus)
    [string]$Modell,

    # Standort für Laptop/NUC (für Unattended-Modus)
    [ValidateSet('Bochum', 'Hattingen', 'Linden', 'Extern')]
    [string]$Standort,

    # VPN-Passwort als SecureString (für Unattended-Modus)
    [SecureString]$VpnPasswort,

    # JSON-Konfigurationsdatei für Batch-Verarbeitung
    [string]$ConfigFile,

    # WhatIf-Modus: Zeigt was passieren würde, ohne Änderungen durchzuführen
    [switch]$WhatIf,

    # Verbose-Modus für detaillierte Ausgabe
    [switch]$VerboseOutput
)

# -------------------------------------------------------------------------
# Exit-Codes für Automatisierung
# -------------------------------------------------------------------------
$script:ExitCodes = @{
    Success             = 0
    InvalidParameter    = 1
    MissingPath         = 2
    DriverError         = 3
    NetworkError        = 4
    UserError           = 5
    ActivationError     = 6
    RebootRequired      = 100
    UnknownError        = 99
}

# Aktueller Exit-Code (wird am Ende gesetzt)
$script:CurrentExitCode = $script:ExitCodes.Success

function Set-ExitCode {
    param([int]$Code)
    if ($Code -gt $script:CurrentExitCode -and $Code -ne $script:ExitCodes.RebootRequired) {
        $script:CurrentExitCode = $Code
    }
}

# WhatIf-Modus aktivieren
if ($WhatIf) {
    $script:WhatIfMode = $true
    Write-Host "============================================" -ForegroundColor Cyan
    Write-Host "  WHATIF-MODUS AKTIV - Keine Änderungen!" -ForegroundColor Cyan
    Write-Host "============================================" -ForegroundColor Cyan
} else {
    $script:WhatIfMode = $false
}

# Unattended-Validierung
if ($Unattended) {
    if (-not $Modus) {
        Write-Error "Unattended-Modus erfordert -Modus Parameter!"
        exit $script:ExitCodes.InvalidParameter
    }
    if (-not $ComputerName -and $Modus -notin @('TreiberEntpacken', 'WindowsUpdateReset')) {
        Write-Error "Unattended-Modus erfordert -ComputerName Parameter!"
        exit $script:ExitCodes.InvalidParameter
    }
    if ($Modus -in @('Laptop', 'VPN', 'NUC') -and -not $Modell) {
        Write-Error "Modus '$Modus' erfordert -Modell Parameter!"
        exit $script:ExitCodes.InvalidParameter
    }

    Write-Host "============================================" -ForegroundColor Green
    Write-Host "  UNATTENDED-MODUS AKTIV" -ForegroundColor Green
    Write-Host "  Modus: $Modus" -ForegroundColor Green
    Write-Host "  Name:  $ComputerName" -ForegroundColor Green
    Write-Host "============================================" -ForegroundColor Green
}
#endregion

#region Konfiguration laden
# -------------------------------------------------------------------------
# Externe Konfigurationsdatei laden (falls vorhanden)
# -------------------------------------------------------------------------
# --- Robust ScriptRoot (USB default D:\Datein\Skripte) ---
$script:ScriptRoot = $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($script:ScriptRoot) -or -not (Test-Path $script:ScriptRoot)) {
    if ($PSCommandPath) { $script:ScriptRoot = Split-Path -Parent $PSCommandPath }
    elseif ($MyInvocation.MyCommand.Path) { $script:ScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path }
    elseif (Test-Path 'D:\Datein\Skripte') { $script:ScriptRoot = 'D:\Datein\Skripte' }
    else { $script:ScriptRoot = (Get-Location).Path }
}

$script:ConfigPath = Join-Path $script:ScriptRoot 'Installation.Config.psd1'
$script:Config = $null

function Import-InstallationConfig {
    <#
        Lädt die externe Konfigurationsdatei.
        Falls nicht vorhanden, werden Standardwerte verwendet.
    #>
    param(
        [string]$Path = $script:ConfigPath
    )

    if (Test-Path $Path) {
        try {
            $script:Config = Import-PowerShellDataFile -Path $Path
            Write-Host "[CONFIG] Konfiguration geladen: $Path" -ForegroundColor Green
            return $true
        } catch {
            Write-Warning "[CONFIG] Fehler beim Laden der Konfiguration: $($_.Exception.Message)"
            return $false
        }
    } else {
        Write-Host "[CONFIG] Keine externe Konfiguration gefunden, verwende Standardwerte" -ForegroundColor Yellow
        return $false
    }
}

# Konfiguration beim Start laden
$configLoaded = Import-InstallationConfig

# Helper-Funktion zum Abrufen von Konfigurationswerten mit Fallback
function Get-ConfigValue {
    <#
        Ruft einen Wert aus der Konfiguration ab.
        Falls nicht vorhanden, wird der Standardwert zurückgegeben.
    #>
    param(
        [Parameter(Mandatory)][string]$Section,
        [Parameter(Mandatory)][string]$Key,
        $Default = $null
    )

    if ($script:Config -and $script:Config[$Section] -and $script:Config[$Section][$Key]) {
        return $script:Config[$Section][$Key]
    }
    return $Default
}

# -------------------------------------------------------------------------
# Credentials laden (separate Datei für Sicherheit)
# -------------------------------------------------------------------------
# -------------------------------------------------------------------------
# Konstanten für Magic Numbers und wiederkehrende Werte
# -------------------------------------------------------------------------
$script:Constants = @{
    # NetBIOS-Namenlimit
    MaxComputerNameLength = 15

    # Timeouts (in Sekunden)
    DriverInstallTimeout  = 1200
    ProcessWaitTimeout    = 300
    ServiceStartTimeout   = 30

    # MSI/Installer Exit-Codes
    ExitCode_Success      = 0
    ExitCode_RebootNeeded = 3010
    ExitCode_RebootInit   = 1641
    ExitCode_DPInstSoft   = 256

    # PnPCapabilities (Netzwerk Energieverwaltung)
    PnPCapabilities_DisablePowerMgmt = 24

    # Registry-Werte
    Registry_Enabled      = 1
    Registry_Disabled     = 0

    # WLAN-Adapter-Modi
    WlanMode_802_11_AC    = 'IEEE 802.11a/n/ac'

    # Font-Erweiterungen
    ValidFontExtensions   = @('.ttf', '.otf', '.ttc')

    # Installer-Dateinamen (Priorität)
    InstallerPriority     = @('setup.exe', 'driversetup.exe', 'asussetup.exe', 'setup.cmd', 'dpinst.exe')
}

$script:CredentialsPath = Join-Path $script:ScriptRoot 'Installation.Credentials.ps1'
$script:AdminPassword = $null
$script:VncPassword = $null

function Import-InstallationCredentials {
    <#
        Lädt Passwörter aus der separaten Credentials-Datei.
        Falls nicht vorhanden, werden die Standardwerte verwendet (mit Warnung).
    #>
    param(
        [string]$Path = $script:CredentialsPath
    )

    if (Test-Path $Path) {
        try {
            . $Path
            if ($script:Credentials) {
                $script:AdminPassword = $script:Credentials.AdminPassword
                $script:VncPassword = $script:Credentials.VncPassword
                Write-Host "[SECURITY] Credentials aus externer Datei geladen" -ForegroundColor Green
                return $true
            }
        } catch {
            Write-Warning "[SECURITY] Fehler beim Laden der Credentials: $($_.Exception.Message)"
        }
    }

    # Fallback mit Warnung
    Write-Warning "[SECURITY] Keine Credentials-Datei gefunden! Verwende Standard-Passwörter."
    Write-Warning "[SECURITY] Erstellen Sie 'Installation.Credentials.ps1' für sichere Passwort-Verwaltung."
    $script:AdminPassword = '@aka@'
    $script:VncPassword = 'qakaqq'
    return $false
}

# Credentials beim Start laden
$credentialsLoaded = Import-InstallationCredentials
#endregion

#region Performance - CIM/WMI Cache
# -------------------------------------------------------------------------
# Cache für häufig verwendete WMI/CIM-Abfragen
# Vermeidet mehrfache identische Abfragen während einer Session
# -------------------------------------------------------------------------
$script:CimCache = @{}

function Get-CachedCimInstance {
    <#
        Cached Version von Get-CimInstance.
        Speichert Ergebnisse im Session-Cache für wiederholte Abfragen.
    #>
    param(
        [Parameter(Mandatory)][string]$ClassName,
        [switch]$Force  # Cache ignorieren und neu abfragen
    )

    $cacheKey = $ClassName

    # Aus Cache zurückgeben falls vorhanden und nicht Force
    if (-not $Force -and $script:CimCache.ContainsKey($cacheKey)) {
        return $script:CimCache[$cacheKey]
    }

    # Neu abfragen
    try {
        $result = Get-CimInstance -ClassName $ClassName -ErrorAction Stop
        $script:CimCache[$cacheKey] = $result
        return $result
    } catch {
        Write-Log -Message "CIM-Abfrage fehlgeschlagen ($ClassName): $($_.Exception.Message)" -Level 'WARN'
        return $null
    }
}

function Clear-CimCache {
    <# Leert den CIM-Cache #>
    $script:CimCache = @{}
    Write-Log -Message "CIM-Cache geleert" -Level 'INFO'
}

# Hardware-Info beim Start cachen (wird häufig benötigt)
function Initialize-HardwareCache {
    <#
        Lädt häufig benötigte Hardware-Informationen in den Cache.
        Wird einmal beim Skriptstart aufgerufen.
    #>
    $null = Get-CachedCimInstance -ClassName 'Win32_ComputerSystem'
    $null = Get-CachedCimInstance -ClassName 'Win32_BaseBoard'
    $null = Get-CachedCimInstance -ClassName 'Win32_BIOS'
    $null = Get-CachedCimInstance -ClassName 'Win32_OperatingSystem'
}

# Cache beim Start initialisieren
Initialize-HardwareCache
#endregion

# --- Encoding & Logging (global) ---------------------------------------------
try { chcp 65001 | Out-Null } catch {}
try { [Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false) } catch {}

function Initialize-LogFile {
    param([Parameter(Mandatory)][string]$Path)
    $dir = Split-Path -Path $Path -Parent
    if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    if (-not (Test-Path $Path)) {
        # UTF-8 with BOM so Windows Editor/Notepad shows umlauts correctly
        '' | Out-File -FilePath $Path -Encoding utf8
    }
}


# --- Zentraler Log-Pfad (Notepad + PS 5.1 geeignet) ----------
$script:LogRoot = 'D:\Datein\Macs_und_Mainboards_Logs'
try {
    if (-not (Test-Path $script:LogRoot)) {
        New-Item -ItemType Directory -Path $script:LogRoot -Force | Out-Null
    }
} catch {
    # Fallback, falls D: nicht vorhanden / nicht beschreibbar ist
    $script:LogRoot = Join-Path $env:ProgramData 'Macs_und_Mainboards_Logs'
    if (-not (Test-Path $script:LogRoot)) { New-Item -ItemType Directory -Path $script:LogRoot -Force | Out-Null }
}

$script:MainLogPath       = Join-Path $script:LogRoot ("{0}.log" -f $env:COMPUTERNAME)
$script:DeleteUserLogPath = Join-Path $script:LogRoot ("{0}-userdelete.log" -f $env:COMPUTERNAME)

# Transcript schreibt in eine eigene Datei (damit $Name.log nie gelockt wird).
# Solange $Name noch nicht bekannt ist, nehmen wir COMPUTERNAME als Platzhalter.
$script:TranscriptPath = Join-Path $script:LogRoot ("{0}-transcript.log" -f $env:COMPUTERNAME)
$script:LOG = $script:MainLogPath
Initialize-LogFile -Path $script:LOG

# ============================================================================
# Vereinheitlichtes Logging-System
# ============================================================================

# Gültige Log-Level
$script:ValidLogLevels = @('DEBUG', 'INFO', 'WARN', 'ERROR', 'SUCCESS')

# Log-Level zu Farbe Mapping
$script:LogLevelColors = @{
    'DEBUG'   = 'DarkGray'
    'INFO'    = 'Gray'
    'WARN'    = 'Yellow'
    'ERROR'   = 'Red'
    'SUCCESS' = 'Green'
}

# Helper: Resolve log tag based on caller function (default: CORE)
function Get-CallerTag {
    $helpers = @('Write-Log', 'Get-CallerTag', 'Write-HostLog', 'Write-LogLine', 'Write-ActLog', 'Write-InstallationLog')
    $stack = Get-PSCallStack
    for ($i = 1; $i -lt $stack.Count; $i++) {
        $cmd = $stack[$i].Command
        if ($cmd -and ($helpers -notcontains $cmd)) { return $cmd }
    }
    return 'CORE'
}

# Hauptfunktion für vereinheitlichtes Logging
function Write-InstallationLog {
    <#
    .SYNOPSIS
        Zentrale Log-Funktion für das gesamte Skript.

    .DESCRIPTION
        Schreibt Nachrichten in Log-Datei und optional auf die Konsole.
        Unterstützt verschiedene Log-Level und automatisches Tag-Erkennung.

    .PARAMETER Message
        Die zu loggende Nachricht.

    .PARAMETER Level
        Log-Level: DEBUG, INFO, WARN, ERROR, SUCCESS

    .PARAMETER Tag
        Optionaler Tag (wird automatisch aus Caller-Funktion ermittelt falls nicht angegeben)

    .PARAMETER Path
        Optionaler Pfad zur Log-Datei (Standard: $script:LOG)

    .PARAMETER NoConsole
        Wenn gesetzt, wird nicht auf die Konsole ausgegeben

    .PARAMETER NoFile
        Wenn gesetzt, wird nicht in die Datei geschrieben
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0)]
        [string]$Message,

        [Parameter(Position = 1)]
        [ValidateSet('DEBUG', 'INFO', 'WARN', 'ERROR', 'SUCCESS')]
        [string]$Level = 'INFO',

        [string]$Tag,

        [string]$Path,

        [switch]$NoConsole,

        [switch]$NoFile
    )

    # Standard-Pfad und Tag
    if (-not $Path -or $Path.Trim() -eq '') {
        $Path = if ($script:LOG) { $script:LOG }
                elseif ($script:MainLogPath) { $script:MainLogPath }
                else { Join-Path $env:TEMP 'installation.log' }
    }

    if (-not $Tag -or $Tag.Trim() -eq '') {
        $Tag = Get-CallerTag
    }

    # Timestamp und formatierte Zeile
    $timestamp = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    $line = "[{0}] [{1}] [{2}] {3}" -f $timestamp, $Level, $Tag.ToUpper(), $Message

    # Konsolen-Ausgabe
    if (-not $NoConsole) {
        $color = $script:LogLevelColors[$Level]
        if (-not $color) { $color = 'Gray' }
        try {
            Write-Host $line -ForegroundColor $color
        } catch {
            Write-Host $line
        }
    }

    # Datei-Ausgabe
    if (-not $NoFile) {
        Initialize-LogFile -Path $Path

        try {
            Add-Content -Encoding UTF8 -Path $Path -Value $line -ErrorAction Stop
        } catch {
            # Retry mit .NET-Methode bei Lock
            for ($i = 1; $i -le 5; $i++) {
                try {
                    [System.IO.File]::AppendAllText($Path, $line + [Environment]::NewLine, (New-Object System.Text.UTF8Encoding($true)))
                    break
                } catch {
                    if ($i -eq 5) { throw }
                    Start-Sleep -Milliseconds 150
                }
            }
        }

        # Spiegeln ins Hauptlog (wenn anderer Pfad)
        $mainLog = $script:MainLogPath
        if ($mainLog -and $Path -ne $mainLog) {
            try {
                [System.IO.File]::AppendAllText($mainLog, $line + [Environment]::NewLine, (New-Object System.Text.UTF8Encoding($true)))
            } catch {}
        }
    }
}

# Alias für Rückwärtskompatibilität (wird später definiert, nach Write-Log)

# Write-Host wrapper that ALSO logs (tag = caller function)
function Write-HostLog {
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline = $true, Position = 0)]
        $Object,
        [ConsoleColor]$ForegroundColor,
        [ConsoleColor]$BackgroundColor,
        [switch]$NoNewline,
        $Separator
    )
    process {
        Microsoft.PowerShell.Utility\Write-Host @PSBoundParameters
        try {
            $msg = ($Object | Out-String).TrimEnd()
            if ($msg) { Write-Log -Message $msg -Level 'INFO' }
        } catch {}
    }
}




# Export a readable inventory report (TXT + CSV)
function Export-InventoryReport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Name,
        [string]$OutDir = $script:LogRoot,
        [string]$TicketID,
        [string]$HardwareID
    )

    if ([string]::IsNullOrWhiteSpace($OutDir)) { $OutDir = $script:LogRoot }

    if (-not (Test-Path $OutDir)) { New-Item -ItemType Directory -Path $OutDir -Force | Out-Null }

    # System / Vendor
    $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction SilentlyContinue
    $bios = Get-CimInstance -ClassName Win32_BIOS -ErrorAction SilentlyContinue
    $bb  = Get-CimInstance -ClassName Win32_BaseBoard -ErrorAction SilentlyContinue
    $os  = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction SilentlyContinue

    # Network (prefer NetAdapter)
    $net = @()
    try {
        $net = Get-NetAdapter -Physical -ErrorAction Stop | ForEach-Object {
            $ip = $null
            try { $ip = (Get-NetIPAddress -InterfaceIndex $_.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue | Select-Object -First 1).IPAddress } catch {}
            [pscustomobject]@{
                Name       = $_.Name
                Status     = $_.Status
                LinkSpeed  = $_.LinkSpeed
                MacAddress = $_.MacAddress
                IPv4       = $ip
            }
        }
    } catch {
        # fallback WMI
        $net = Get-CimInstance Win32_NetworkAdapterConfiguration -Filter "IPEnabled=True" -ErrorAction SilentlyContinue |
            ForEach-Object {
                [pscustomobject]@{
                    Name       = $_.Description
                    Status     = 'Up'
                    LinkSpeed  = ''
                    MacAddress = $_.MACAddress
                    IPv4       = ($_.IPAddress | Where-Object { $_ -match '^\d{1,3}(\.\d{1,3}){3}$' } | Select-Object -First 1)
                }
            }
    }

    $txtPath = Join-Path $OutDir "$Name.txt"
    $csvPath = Join-Path $OutDir "$Name.csv"
    $netCsv  = Join-Path $OutDir "$Name-Network.csv"

    $kv = @(
        [pscustomobject]@{ Key='TicketID'; Value=$TicketID }
        [pscustomobject]@{ Key='HardwareID'; Value=$HardwareID }
        [pscustomobject]@{ Key='Name (gewünscht)'; Value=$Name }
        [pscustomobject]@{ Key='ComputerName (aktuell)'; Value=$env:COMPUTERNAME }
        [pscustomobject]@{ Key='Hersteller'; Value=$cs.Manufacturer }
        [pscustomobject]@{ Key='Modell'; Value=$cs.Model }
        [pscustomobject]@{ Key='Mainboard Hersteller'; Value=$bb.Manufacturer }
        [pscustomobject]@{ Key='Mainboard Produkt'; Value=$bb.Product }
        [pscustomobject]@{ Key='Mainboard Seriennummer'; Value=$bb.SerialNumber }
        [pscustomobject]@{ Key='BIOS Version'; Value=$bios.SMBIOSBIOSVersion }
        [pscustomobject]@{ Key='BIOS Seriennummer'; Value=$bios.SerialNumber }
        [pscustomobject]@{ Key='OS'; Value=("{0} (Build {1})" -f $os.Caption, $os.BuildNumber) }
    )

    # TXT (readable)
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.AppendLine("===== INVENTAR =====")
    [void]$sb.AppendLine(("Erstellt: {0}" -f (Get-Date)))
    [void]$sb.AppendLine("")
    foreach ($row in $kv) {
        [void]$sb.AppendLine(("{0,-25}: {1}" -f $row.Key, $row.Value))
    }
    [void]$sb.AppendLine("")
    [void]$sb.AppendLine("===== NETZWERK =====")
    if ($net -and $net.Count -gt 0) {
        foreach ($n in $net) {
            [void]$sb.AppendLine(("- {0} | {1} | MAC {2} | IPv4 {3}" -f $n.Name, $n.Status, $n.MacAddress, $n.IPv4))
        }
    } else {
        [void]$sb.AppendLine("Keine Netzwerkadapter gefunden.")
    }

    $sb.ToString() | Out-File -Encoding UTF8 -FilePath $txtPath -Force

    # CSVs (optional aber praktisch)
    $kv | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8 -Force
    $net | Export-Csv -Path $netCsv -NoTypeInformation -Encoding UTF8 -Force

    Write-Log -Message "Inventar exportiert: $txtPath / $csvPath / $netCsv" -Level 'SUCCESS'
}

function Write-Log {
    <#
    .SYNOPSIS
        Zentrale Log-Funktion (Wrapper für Write-InstallationLog).

    .DESCRIPTION
        Schreibt Nachrichten in Log-Datei und auf die Konsole.
        Diese Funktion ist ein Wrapper für Rückwärtskompatibilität.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Message,
        [ValidateSet('DEBUG', 'INFO', 'WARN', 'ERROR', 'SUCCESS')][string]$Level = 'INFO',
        [string]$Tag,
        [string]$Path
    )

    # Delegiere an die neue zentrale Funktion
    Write-InstallationLog -Message $Message -Level $Level -Tag $Tag -Path $Path
}

function Set-LogSessionName {
    param([Parameter(Mandatory)][string]$Name)

    # Pfade
    $script:LogBaseName    = $Name
    $script:MainLogPath    = Join-Path $script:LogRoot ("{0}.log" -f $Name)
    $script:FontsLogPath   = Join-Path $script:LogRoot ("{0}-Fonts.log" -f $Name)
    $script:TreiberLogPath = Join-Path $script:LogRoot ("{0}-Treiber.log" -f $Name)
    $script:UserDelLogPath = Join-Path $script:LogRoot ("{0}-UserDelete.log" -f $Name)
    $script:DeleteUserLogPath = $script:UserDelLogPath
    $script:InfoPath       = Join-Path $script:LogRoot ("{0}.txt" -f $Name)

    # globale Kompatibilität
    $Global:LogPath = $script:LogRoot

    # Hauptlog als Default
    $script:LOG = $script:MainLogPath
    Initialize-LogFile -Path $script:MainLogPath
}

function Switch-ToNamedMainLog {
    param([Parameter(Mandatory)][string]$Name)

    $oldMain = $script:MainLogPath

    # Transcript sauber beenden (falls läuft)
    try { Stop-Transcript | Out-Null } catch {}

    Set-LogSessionName -Name $Name

    # Transcript-Pfad jetzt auf $Name setzen (eigene Datei, keine Locks im Hauptlog)
    $script:TranscriptPath = Join-Path $script:LogRoot ("{0}-transcript.log" -f $Name)

    # alten Hauptlog-Inhalt rüberkopieren (nur wenn anderer Pfad)
    if ($oldMain -and (Test-Path $oldMain) -and ($oldMain -ne $script:MainLogPath)) {
        try {
            Get-Content -Path $oldMain -ErrorAction SilentlyContinue | Add-Content -Encoding UTF8 -Path $script:MainLogPath
        } catch {}
    }

    # Transcript separat, damit Hauptlog nicht gesperrt wird
    try { Start-Transcript -Path $script:TranscriptPath -Append -ErrorAction Stop | Out-Null } catch {}
}

function Write-InfoFile {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$HWId,
        [Parameter(Mandatory)][string]$TID
    )

    $txtPath = $script:InfoPath
    if (-not $txtPath) { $txtPath = Join-Path $script:LogRoot ("{0}.txt" -f $Name) }
    $csvPath = Join-Path $script:LogRoot ("{0}.csv" -f $Name)
    $netCsv  = Join-Path $script:LogRoot ("{0}-Network.csv" -f $Name)

    # --- Basisinfos -----------------------------------------------------------
    $baseboard = $null
    $bios      = $null
    $cs        = $null
    $csp       = $null
    try { $baseboard = Get-CimInstance -ClassName Win32_BaseBoard -ErrorAction Stop } catch {}
    try { $bios      = Get-CimInstance -ClassName Win32_BIOS -ErrorAction Stop } catch {}
    try { $cs        = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop } catch {}
    try { $csp       = Get-CimInstance -ClassName Win32_ComputerSystemProduct -ErrorAction Stop } catch {}

    $kv = @(
        [PSCustomObject]@{ Key='TicketID'; Value=$TID }
        [PSCustomObject]@{ Key='HardwareID'; Value=$HWId }
        [PSCustomObject]@{ Key='Ziel-Rechnername'; Value=$Name }
        [PSCustomObject]@{ Key='Aktueller Computername'; Value=$env:COMPUTERNAME }
        [PSCustomObject]@{ Key='Datum/Zeit'; Value=(Get-Date).ToString('yyyy-MM-dd HH:mm:ss') }
        [PSCustomObject]@{ Key='Hersteller'; Value=$cs.Manufacturer }
        [PSCustomObject]@{ Key='Modell'; Value=$cs.Model }
        [PSCustomObject]@{ Key='System-UUID'; Value=$csp.UUID }
        [PSCustomObject]@{ Key='Mainboard Hersteller'; Value=$baseboard.Manufacturer }
        [PSCustomObject]@{ Key='Mainboard Produkt'; Value=$baseboard.Product }
        [PSCustomObject]@{ Key='Mainboard Seriennr.'; Value=$baseboard.SerialNumber }
        [PSCustomObject]@{ Key='BIOS Version'; Value=$bios.SMBIOSBIOSVersion }
        [PSCustomObject]@{ Key='BIOS Seriennr.'; Value=$bios.SerialNumber }
    ) | Where-Object { $_.Value -ne $null -and "$($_.Value)".Trim() -ne "" }

    # --- Netzwerk ------------------------------------------------------------
    $ipByIf = @{}
    try {
        Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
            Where-Object { $_.IPAddress -and $_.InterfaceIndex } |
            ForEach-Object {
                if (-not $ipByIf.ContainsKey($_.InterfaceIndex)) { $ipByIf[$_.InterfaceIndex] = @() }
                $ipByIf[$_.InterfaceIndex] += $_.IPAddress
            }
    } catch {}

    $adapters = @()
    try {
        $adapters = Get-NetAdapter -Physical -ErrorAction SilentlyContinue | ForEach-Object {
            $ips = $null
            if ($ipByIf.ContainsKey($_.ifIndex)) { $ips = ($ipByIf[$_.ifIndex] -join ', ') }
            [PSCustomObject]@{
                Name                = $_.Name
                Status              = $_.Status
                InterfaceDescription= $_.InterfaceDescription
                MAC                 = $_.MacAddress
                LinkSpeed           = $_.LinkSpeed
                IPv4                = $ips
            }
        }
    } catch {}

    # --- TXT (schön lesbar) --------------------------------------------------
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.AppendLine("===============================================")
    [void]$sb.AppendLine((" INVENTAR / INSTALLATIONSINFO  ({0})" -f (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')))
    [void]$sb.AppendLine("===============================================")
    [void]$sb.AppendLine("")
    [void]$sb.AppendLine("Allgemein")
    [void]$sb.AppendLine("---------")
    [void]$sb.AppendLine(($kv | Format-Table -AutoSize | Out-String).TrimEnd())
    [void]$sb.AppendLine("")
    [void]$sb.AppendLine("Netzwerk (physische Adapter)")
    [void]$sb.AppendLine("----------------------------")
    if ($adapters -and $adapters.Count -gt 0) {
        [void]$sb.AppendLine(($adapters | Format-Table -AutoSize | Out-String).TrimEnd())
    } else {
        [void]$sb.AppendLine("Keine Adapter gefunden.")
    }
    [void]$sb.AppendLine("")
    [void]$sb.AppendLine(("Log-Pfad: {0}" -f $script:LogRoot))

    try {
        $sb.ToString() | Out-File -FilePath $txtPath -Encoding utf8
        Write-Log -Message ("[INFOFILE] TXT geschrieben: {0}" -f $txtPath) -Level INFO
    } catch {
        Write-Log -Message ("[INFOFILE] Konnte TXT nicht schreiben: {0}" -f $_.Exception.Message) -Level WARN
    }

    # --- CSV (optional, Excel-freundlich) ------------------------------------
    try {
        $kv | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
        if ($adapters -and $adapters.Count -gt 0) {
            $adapters | Export-Csv -Path $netCsv -NoTypeInformation -Encoding UTF8
        }
        Write-Log -Message ("[INFOFILE] CSV geschrieben: {0} (+ {1})" -f $csvPath, $netCsv) -Level INFO
    } catch {
        Write-Log -Message ("[INFOFILE] Konnte CSV nicht schreiben: {0}" -f $_.Exception.Message) -Level WARN
    }
}
function Rotate-Log {
    param([string]$Path = $script:MainLogPath, [int]$MaxMB = 5, [int]$Keep = 3)
    if (-not $Path -or -not (Test-Path $Path)) { return }
    $maxBytes = $MaxMB * 1024 * 1024
    $fi = Get-Item $Path -ErrorAction SilentlyContinue
    if (-not $fi -or $fi.Length -lt $maxBytes) { return }
    for ($i = $Keep; $i -ge 1; $i--) {
        $src = "$Path.$i"
        $dst = "$Path." + ($i + 1)
        if (Test-Path $src) {
            if ($i -eq $Keep) { Remove-Item $src -Force -ErrorAction SilentlyContinue }
            else { Rename-Item -Path $src -NewName (Split-Path $dst -Leaf) -Force -ErrorAction SilentlyContinue }
        }
    }
    Copy-Item -Path $Path -Destination "$Path.1" -Force -ErrorAction SilentlyContinue
    '' | Out-File -FilePath $Path -Encoding utf8
}
# ------------------------------------------------------------------------------

# --- Helper-Funktion für Cleanup von Jobs und Transcripts ---
function Stop-SessionCleanup {
    <#
        Beendet sauber Transcript und Background-Jobs.
        Sollte am Ende jeder Setup-Funktion aufgerufen werden.
    #>
    param(
        [System.Management.Automation.Job]$Job,
        [int]$TimeoutSeconds = 5
    )

    # Transcript stoppen (falls aktiv)
    try { Stop-Transcript -ErrorAction SilentlyContinue } catch {}

    # Job bereinigen
    if ($Job) {
        try {
            if ($Job.State -in 'Running', 'NotStarted') {
                Stop-Job -Job $Job -ErrorAction SilentlyContinue | Out-Null
                Wait-Job -Job $Job -Timeout $TimeoutSeconds -ErrorAction SilentlyContinue | Out-Null
            }
        } catch {}

        try { Remove-Job -Job $Job -Force -ErrorAction SilentlyContinue | Out-Null } catch {}
    }
}

# =====================================================================================================
# Installation.ps1 ? GUI-Version (Schritt 2)
# - Treiberinstallation VOR Firewall/Netzwerk
# - Hersteller automatisch, Laptop/VPN: Modell vom Benutzer (GUI)
# - Feste Pfade D:\Datein\...
# =====================================================================================================

#region Admin-Check
# --- Auto-Elevate auf Admin ---
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
    ).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator"))
{
    try {
        Write-Host "[INFO] Starte das Script erneut als Administrator..." -ForegroundColor Yellow
    } catch {}

    # Robustes Re-Launch (funktioniert auch bei 'Run with PowerShell')
    $argList = @(
        '-NoProfile'
        '-ExecutionPolicy','Bypass'
        '-File',"`"$PSCommandPath`""
    )

    try {
        Start-Process -FilePath 'powershell.exe' -ArgumentList $argList -Verb RunAs -WindowStyle Maximized -WorkingDirectory (Split-Path -Path $PSCommandPath -Parent) | Out-Null
    } catch {
        Write-Host "[ERROR] Konnte nicht als Administrator starten: $($_.Exception.Message)" -ForegroundColor Red
        try { Read-Host 'Enter zum Beenden' | Out-Null } catch {}
    }
    return
}

chcp 65001 > $null
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8

try {
    $raw = $Host.UI.RawUI

    # Maximal moegliche Fenstergroesse (physisch) auslesen
    $max = $raw.MaxPhysicalWindowSize
    if (-not $max.Width -or -not $max.Height) { $max = $raw.MaxWindowSize }

    # Buffer erst gross genug machen, sonst Exception beim Vergroessern des Fensters
    $newBufWidth  = [Math]::Max($raw.BufferSize.Width,  $max.Width)
    $newBufHeight = [Math]::Max($raw.BufferSize.Height, 3000)
    $raw.BufferSize = New-Object Management.Automation.Host.Size ($newBufWidth, $newBufHeight)

    # Fenster auf Maximum ziehen
    $raw.WindowSize = New-Object Management.Automation.Host.Size ($max.Width, $max.Height)

    # Fallback: WinAPI-Maximize (klassische Konsole)
    Add-Type @"
using System;
using System.Runtime.InteropServices;
public static class Win32 {
    [DllImport("kernel32.dll")] public static extern IntPtr GetConsoleWindow();
    [DllImport("user32.dll")]  public static extern bool   ShowWindow(IntPtr hWnd, int nCmdShow);
}
"@
    $h = [Win32]::GetConsoleWindow()
    if ($h -ne [IntPtr]::Zero) { [Win32]::ShowWindow($h, 3) | Out-Null }  # 3 = SW_MAXIMIZE
}
catch {
    Write-Warning "Konnte Fenster-/Puffergroesse nicht setzen: $_"
}


#endregion

#region Konstanten
# -------------------------------------------------------------------------
# Pfade werden aus Konfigurationsdatei geladen (falls vorhanden)
# -------------------------------------------------------------------------
$Global:BasePath = Get-ConfigValue -Section 'Paths' -Key 'BasePath' -Default 'D:\Datein'
$Global:logRoot = Join-Path $BasePath (Get-ConfigValue -Section 'Paths' -Key 'LogSubPath' -Default 'Macs_und_Mainboards_Logs')
$Global:BaseFilePath = Join-Path $BasePath (Get-ConfigValue -Section 'Paths' -Key 'InstallationSubPath' -Default 'Installation\Dokumente')
$Global:LogPath  = $Global:logRoot
$Global:FontsPath = Join-Path $BasePath (Get-ConfigValue -Section 'Paths' -Key 'FontsSubPath' -Default 'fonts')
$Global:TreiberPath = Join-Path $BasePath (Get-ConfigValue -Section 'Paths' -Key 'TreiberSubPath' -Default 'treiber')
$Global:ProgramPath = Join-Path $BasePath (Get-ConfigValue -Section 'Paths' -Key 'ProgramSubPath' -Default 'Installation\Dokumente\Installation von Programmen')

# Dateinamen aus Konfiguration
$Global:LayoutXml = Join-Path $BaseFilePath (Get-ConfigValue -Section 'Files' -Key 'LayoutXml' -Default 'LayoutModification.xml')
$Global:WlanPwFile = Join-Path $BaseFilePath (Get-ConfigValue -Section 'Files' -Key 'WlanPwFile' -Default 'wlan.txt')
$Global:MakFile = Join-Path $BaseFilePath (Get-ConfigValue -Section 'Files' -Key 'MakFile' -Default 'win10Ent-mak.txt')

# Treiber-Pfade
$Global:TreiberMainboardPath = Join-Path $BasePath (Get-ConfigValue -Section 'Paths' -Key 'TreiberMainboardSubPath' -Default 'treiber\Mainboard')
$Global:TreiberNotebookPath = Join-Path $BasePath (Get-ConfigValue -Section 'Paths' -Key 'TreiberNotebookSubPath' -Default 'treiber\Notebook')
$Global:TreiberNucPath = Join-Path $BasePath (Get-ConfigValue -Section 'Paths' -Key 'TreiberNucSubPath' -Default 'treiber\NUC')
$Global:TreiberAllinOnePCPath = Join-Path $BasePath (Get-ConfigValue -Section 'Paths' -Key 'TreiberAllinOnePCSubPath' -Default 'treiber\AllinOnePC')
$Global:doneDir = Join-Path $logRoot "erledigt"

# Geschützte Benutzer aus Konfiguration laden
$Global:ProtectedUsers = Get-ConfigValue -Section 'ProtectedUsers' -Key '' -Default @('Administrator', 'DefaultAccount', 'Guest', 'WDAGUtilityAccount', 'SYSTEM', 'LocalService', 'NetworkService')
if (-not $Global:ProtectedUsers) {
    $Global:ProtectedUsers = @('Administrator', 'DefaultAccount', 'Guest', 'WDAGUtilityAccount', 'SYSTEM', 'LocalService', 'NetworkService')
}
#endregion

#region Pfad-Validierung
# ================================
# Überprüfe kritische Pfade beim Start
# ================================
function Test-RequiredPaths {
    <#
        Prüft ob alle wichtigen Pfade existieren und gibt Warnungen aus.
        Gibt $true zurück wenn alle kritischen Pfade existieren.
    #>
    $criticalPaths = @{
        'BasePath'       = $Global:BasePath
        'LogPath'        = $Global:LogPath
        'TreiberPath'    = $Global:TreiberPath
    }

    $optionalPaths = @{
        'FontsPath'      = $Global:FontsPath
        'ProgramPath'    = $Global:ProgramPath
        'LayoutXml'      = $Global:LayoutXml
        'WlanPwFile'     = $Global:WlanPwFile
        'MakFile'        = $Global:MakFile
    }

    $allCriticalOk = $true

    # Kritische Pfade prüfen
    foreach ($key in $criticalPaths.Keys) {
        $path = $criticalPaths[$key]
        if (-not (Test-Path $path)) {
            Write-Warning "[KRITISCH] Pfad nicht gefunden: $key = $path"
            # Versuche Verzeichnisse zu erstellen
            if ($key -in @('LogPath')) {
                try {
                    New-Item -ItemType Directory -Path $path -Force | Out-Null
                    Write-Host "[INFO] Verzeichnis erstellt: $path" -ForegroundColor Green
                } catch {
                    Write-Warning "[FEHLER] Konnte Verzeichnis nicht erstellen: $path"
                    $allCriticalOk = $false
                }
            } else {
                $allCriticalOk = $false
            }
        }
    }

    # Optionale Pfade prüfen (nur Warnung)
    foreach ($key in $optionalPaths.Keys) {
        $path = $optionalPaths[$key]
        if ($path -and -not (Test-Path $path)) {
            Write-Host "[INFO] Optionaler Pfad nicht vorhanden: $key = $path" -ForegroundColor Yellow
        }
    }

    return $allCriticalOk
}

# Validierungsfunktion für Computernamen (NetBIOS-konform)
function Test-ValidComputerName {
    param(
        [Parameter(Mandatory)][string]$Name
    )

    # NetBIOS: max 15 Zeichen, nur A-Z, 0-9, Bindestrich (nicht am Anfang/Ende)
    if ([string]::IsNullOrWhiteSpace($Name)) {
        return @{ Valid = $false; Reason = "Name darf nicht leer sein" }
    }

    if ($Name.Length -gt 15) {
        return @{ Valid = $false; Reason = "Name zu lang (max. 15 Zeichen, aktuell: $($Name.Length))" }
    }

    if ($Name -notmatch '^[a-zA-Z0-9][a-zA-Z0-9\-]{0,13}[a-zA-Z0-9]$' -and $Name.Length -gt 1) {
        return @{ Valid = $false; Reason = "Ungültige Zeichen oder Format (nur A-Z, 0-9, Bindestrich erlaubt)" }
    }

    if ($Name.Length -eq 1 -and $Name -notmatch '^[a-zA-Z0-9]$') {
        return @{ Valid = $false; Reason = "Einzelnes Zeichen muss alphanumerisch sein" }
    }

    # Reservierte Namen prüfen
    $reserved = @('LOCALHOST', 'CON', 'PRN', 'AUX', 'NUL', 'COM1', 'COM2', 'COM3', 'COM4', 'LPT1', 'LPT2', 'LPT3')
    if ($reserved -contains $Name.ToUpper()) {
        return @{ Valid = $false; Reason = "Reservierter Name: $Name" }
    }

    return @{ Valid = $true; Reason = "" }
}

# Pfade beim Start prüfen
$pathsOk = Test-RequiredPaths
if (-not $pathsOk) {
    Write-Warning "=============================================="
    Write-Warning "ACHTUNG: Nicht alle kritischen Pfade verfügbar!"
    Write-Warning "Das Skript könnte fehlschlagen."
    Write-Warning "=============================================="
    $continue = Read-Host "Trotzdem fortfahren? (j/N)"
    if ($continue -notin @('j', 'J', 'ja', 'Ja', 'JA')) {
        Write-Host "Skript abgebrochen." -ForegroundColor Red
        exit 1
    }
}
#endregion

#region Letzten Rechner Namen
# ================================
# Die letzten 10 unterschiedlichen Rechnernamen anzeigen (nur Hauptlogs $Name.log)
# ================================

# Vorhandene Pfade sammeln
$paths = @()
if (Test-Path $logRoot) { $paths += $logRoot }
if (Test-Path $doneDir) { $paths += $doneDir }

if ($paths.Count -eq 0) {
    Write-HostLog "[WARN] Keine Log-Ordner gefunden unter: $logRoot, $doneDir" -ForegroundColor DarkYellow
} else {
    # Nur Hauptlogs sammeln: $Name.log (keine Bindestriche im Namen = keine Sub-Logs)
    $exclude = '(?i)-(Treiber|Fonts|transcript|userdelete|Einstellen)$'
    # Ausschließen: *-Treiber*, *-Fonts*, *-transcript*, *-userdelete*, *-Einstellen* etc.
    $allFiles = Get-ChildItem -Path $paths -File -ErrorAction SilentlyContinue |
        Where-Object { 
            $_.Extension -eq ".log" -and 
            $_.BaseName -ne 'Installation' -and
            $_.BaseName -notmatch $exclude
        }

    if ($allFiles.Count -eq 0) {
        Write-HostLog "[INFO] Keine Hauptlog-Dateien gefunden." -ForegroundColor DarkYellow
    } else {
        # Nach Dateiname gruppieren und neueste 10 anzeigen
        $uniqueLatest = $allFiles |
            Sort-Object LastWriteTime -Descending |
            Group-Object BaseName |
            ForEach-Object { $_.Group | Select-Object -First 1 } |
            Select-Object -First 10

        Write-HostLog ""
        Write-HostLog ">> Letzte 10 vergebene Rechnernamen:" -ForegroundColor Yellow
        Write-HostLog "---------------------------------------------"
        foreach ($file in $uniqueLatest) {
            $pcName = $file.BaseName
            $zeit   = $file.LastWriteTime.ToString("dd.MM.yyyy HH:mm")
            Write-HostLog ("{0,-30}  ({1})" -f $pcName, $zeit)
        }
        Write-HostLog "---------------------------------------------"
        Write-HostLog ""
    }
}
#endregion

#region Hilfsfunktionen (aufgeraeumt)
function Get-MBFolder {
    $root =  $TreiberMainboardPath
    $product = (Get-CimInstance Win32_BaseBoard).Product
    if ([string]::IsNullOrWhiteSpace($product)) { return $null }

    # PRIME am Anfang entfernen (auch ohne Leerzeichen) und alle Leerzeichen entfernen
    $clean = $product -replace '^PRIME', '' -replace '\s+', ''
    # Nicht erlaubte Zeichen raus
    $clean = $clean -replace '[^A-Za-z0-9\-_]', ''

    # Kandidaten holen: Ordnernamen ebenfalls normalisieren (Asus ignorieren, Leerzeichen raus)
    $dirs = Get-ChildItem -Path $root -Directory -ErrorAction SilentlyContinue |
        Where-Object {
            $normalized = ($_.Name -replace '^(Asus|ASUS)\s*','' -replace '\s+','')
            $normalized -like "$clean*"
        }

    if (-not $dirs -or $dirs.Count -eq 0) {
        Write-Warning "[ERR] Kein Treiberordner für $clean gefunden unter $root"
        return $null
    }

    if ($dirs.Count -eq 1) {
        return $dirs[0].FullName
    }

    # Mehrere ? Auswahlmen?s
    Write-HostLog "Mehrere m?gliche Treiberordner gefunden für '$product':"
    for ($i=0; $i -lt $dirs.Count; $i++) {
        Write-HostLog "$($i+1): $($dirs[$i].Name)"
    }
    do {
        $sel = Read-Host "Bitte Zahl für den gew?nschten Ordner eingeben"
    } until ($sel -as [int] -and $sel -gt 0 -and $sel -le $dirs.Count)

    return $dirs[$sel-1].FullName
}

function Get-LaptopFolder {
    param([string]$Modell)

    $vendor = (Get-CimInstance Win32_BaseBoard).Manufacturer
    $root =  Join-Path $TreiberNotebookPath "\$vendor"

    if (-not (Test-Path $root)) {
        Write-Warning "[ERR] Treiber-Stammordner nicht gefunden: $root"
        return $null
    }

    # Nur Ordner, die mit dem Modellnamen beginnen
    $dirs = Get-ChildItem -Path $root -Directory -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -like "$Modell*" }

    if (-not $dirs -or $dirs.Count -eq 0) {
        Write-Warning "[ERR] Kein Treiberordner fuer '$Modell' gefunden unter $root"
        return $null
    }

    if ($dirs.Count -eq 1) {
        return $dirs[0].FullName
    }

    # Mehrere Treffer ? Auswahlmen?
    Write-HostLog "Mehrere m?gliche Treiberordner gefunden für '$Modell':"
    for ($i=0; $i -lt $dirs.Count; $i++) {
        Write-HostLog "$($i+1): $($dirs[$i].Name)"
    }
    do {
        $sel = Read-Host "Bitte Zahl für den gew?nschten Ordner eingeben"
    } until ($sel -as [int] -and $sel -gt 0 -and $sel -le $dirs.Count)

    return $dirs[$sel-1].FullName
}

function Get-NucFolder {
    param([string]$Modell)

    $root = $TreiberNucPath

    if (-not (Test-Path $root)) {
        Write-Warning "[ERR] Treiber-Stammordner nicht gefunden: $root"
        return $null
    }

    # Nur Ordner, die mit dem Modellnamen beginnen
    $dirs = Get-ChildItem -Path $root -Directory -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -like "$Modell*" }

    if (-not $dirs -or $dirs.Count -eq 0) {
        Write-Warning "[ERR] Kein Treiberordner für '$Modell' gefunden unter $root"
        return $null
    }

    if ($dirs.Count -eq 1) {
        return $dirs[0].FullName
    }

    # Mehrere Treffer ? Auswahlmen?
    Write-HostLog "Mehrere m?gliche Treiberordner gefunden für '$Modell':"
    for ($i=0; $i -lt $dirs.Count; $i++) {
        Write-HostLog "$($i+1): $($dirs[$i].Name)"
    }
    do {
        $sel = Read-Host "Bitte Zahl für den gew?nschten Ordner eingeben"
    } until ($sel -as [int] -and $sel -gt 0 -and $sel -le $dirs.Count)

    return $dirs[$sel-1].FullName
}

function Get-MBShort {
    # Liefert Board-Produktnamen für Pfad wie D:\Datein\treiber\Mainboard\<MB>
    $product = (Get-CimInstance Win32_BaseBoard).Product
    if ([string]::IsNullOrWhiteSpace($product)) { return "Unknown" }

    # Alles au?er Buchstaben, Zahlen, Bindestrich entfernen
    $clean = ($product -replace '[^A-Za-z0-9\-_]', '')

    # Max. 15 Zeichen (wie altes Skript)
    if ($clean.Length -gt 15) {
        $clean = $clean.Substring(0,15)
    }

    # Pruefen ob es im Treiberordner existiert, sonst passenden Unterordner suchen
    $root = $TreiberMainboardPath
    $exact = Join-Path $root $clean
    if (Test-Path $exact) { return $clean }

    $match = Get-ChildItem -Path $root -Directory -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -like "$clean*" } |
        Select-Object -First 1

    if ($match) { return $match.Name } else { return $clean }
}

function Get-Manufacturer {
    <#
        Ermittelt den Hersteller des Systems.
        Nutzt CIM-Cache für bessere Performance.
    #>
    $src = ""

    # Aus Cache laden (schneller als direkte Abfrage)
    $cs = Get-CachedCimInstance -ClassName 'Win32_ComputerSystem'
    $bb = Get-CachedCimInstance -ClassName 'Win32_BaseBoard'

    if ($cs -and $cs.Manufacturer) { $src += " $($cs.Manufacturer)" }
    if ($bb -and $bb.Manufacturer) { $src += " $($bb.Manufacturer)" }

    $src = $src.Trim().ToUpperInvariant()

    # Hersteller-Mapping
    $manufacturerMap = @{
        'LENOVO'            = 'Lenovo'
        'DELL'              = 'Dell'
        'HEWLETT|HP INC|HP-'= 'HP'
        'ASUSTeK|ASUS'      = 'ASUS'
        'ACER'              = 'Acer'
        'MSI'               = 'MSI'
        'GIGABYTE'          = 'Gigabyte'
        'INTEL'             = 'Intel'
    }

    foreach ($pattern in $manufacturerMap.Keys) {
        if ($src -match $pattern) {
            return $manufacturerMap[$pattern]
        }
    }

    return "Unknown"
}

function Get-MacAddresses {
    <#
        Robuste MAC-Liste ohne harte Abh?ngigkeit von Win32_NetworkAdapterConfiguration.
        PS 5.1 kompatibel (kein tern?rer Operator).
        Fallbacks: Get-NetAdapter -> Win32_NetworkAdapter -> ipconfig /all -> wmic nic
    #>

    $entries = @()

    # --- 1) Prim?r: Get-NetAdapter ---
    try {
        $na = Get-NetAdapter -ErrorAction Stop | Where-Object { $_.MacAddress }
        foreach ($a in $na) {
            $entries += [pscustomobject]@{
                Description = $a.InterfaceDescription
                MacAddress  = (($a.MacAddress -replace ':','-') -replace '\s','').ToUpperInvariant()
            }
        }
    } catch {
        # weiter
    }

    # --- 2) Fallback: CIM Win32_NetworkAdapter (nicht *_Configuration) ---
    if (-not $entries -or $entries.Count -eq 0) {
        try {
            $cim = Get-CimInstance -ClassName Win32_NetworkAdapter -ErrorAction Stop |
                   Where-Object { $_.MACAddress -and $_.PhysicalAdapter -eq $true }
            foreach ($n in $cim) {
                $entries += [pscustomobject]@{
                    Description = $n.Name
                    MacAddress  = (($n.MACAddress -replace ':','-') -replace '\s','').ToUpperInvariant()
                }
            }
        } catch {
            # weiter
        }
    }

    # --- 3) Fallback: ipconfig /all parsen (DE/EN) ---
    if (-not $entries -or $entries.Count -eq 0) {
        try {
            $raw = & ipconfig /all 2>$null
            $curName = $null

            foreach ($line in $raw) {
                # Abschnitts?berschrift: "Ethernet-Adapter Ethernet:" / "Wireless LAN adapter Wi-Fi:"
                if ($line -match '^\s*([^\:]+)\:\s*$') {
                    $curName = $matches[1].Trim()
                    continue
                }

                # DE/EN: "Physikalische Adresse" / "Physical Address"
                if ($line -match '(?i)^\s*(Physikalische Adresse|Physical Address)\s*[\.\: ]+\s*([0-9A-Fa-f\-]{17})\s*$') {
                    $mac = $matches[2].Trim().ToUpperInvariant()
                    $desc = "ipconfig"
                    if ($curName -and $curName.Trim() -ne "") { $desc = $curName.Trim() }

                    $entries += [pscustomobject]@{
                        Description = $desc
                        MacAddress  = ($mac -replace ':','-')
                    }
                }
            }
        } catch {
            # weiter
        }
    }

    # --- 4) Fallback: wmic nic get name,macaddress ---
    if (-not $entries -or $entries.Count -eq 0) {
        try {
            $raw = & wmic nic where "MACAddress is not null and PhysicalAdapter=true" get Name,MACAddress /format:csv 2>$null
            foreach ($line in $raw) {
                if ($line -match '^[^,]*,(?<Name>[^,]+),(?<Mac>[0-9A-Fa-f:]{17})\s*$') {
                    $entries += [pscustomobject]@{
                        Description = $matches['Name'].Trim()
                        MacAddress  = (($matches['Mac'].Trim()) -replace ':','-').ToUpperInvariant()
                    }
                }
            }
        } catch {
            # nix mehr
        }
    }

    # --- Ausgabe bauen (immer ohne Throw) ---
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.AppendLine("Mac-Adressen:")

    if ($entries -and $entries.Count -gt 0) {
        $unique = $entries |
            Where-Object { $_.MacAddress } |
            Sort-Object Description,MacAddress -Unique

        foreach ($e in $unique) {
            [void]$sb.AppendLine(("{0,-50} {1}" -f $e.Description, $e.MacAddress))
        }
    }
    else {
        [void]$sb.AppendLine("Keine MAC-Adressen ermittelt (alle Methoden fehlgeschlagen).")
    }

    return $sb.ToString()
}

function Resolve-DriverFolder {
    <#
        Resolve-DriverFolder
        --------------------
        - Ermittelt den passenden Treiberordner anhand des Mainboards.
        - Spezielle Behandlung:
          * Lenovo Produkt 3780 -> Alias-Pfad
          * ASUS-Boards: "PRIME" am Anfang des Product-Namens wird entfernt
    #>
    try {
        <# --- Basisdaten vom Mainboard auslesen --- #>
        $bb           = Get-CimInstance Win32_BaseBoard
        $manufacturer = ($bb.Manufacturer | ForEach-Object { ($_ | Out-String).Trim() })
        $product      = ($bb.Product      | ForEach-Object { ($_ | Out-String).Trim() })

        <#
            ASUS-Sonderfall:
            Bei vielen ASUS-Boards steht vor dem eigentlichen Modell "PRIME",
            z.B. "PRIME B450M-A". Dieses Pr?fix wird hier entfernt, damit
            die Ordnerstruktur nur den eigentlichen Modellnamen verwendet.
        #>
        if ($manufacturer -like '*ASUS*') {
            # "PRIME" (case-insensitive) am Anfang entfernen, optional gefolgt von Leerzeichen
            $product = ($product -replace '^(?i)PRIME\s*', '').Trim()
        }

        <# --- Globale Pfade absichern (nur wenn leer) --- #>
        if (-not $Global:TreiberPath)           { $Global:TreiberPath           = "D:\Datein\treiber" }
        if (-not $Global:TreiberMainboardPath)  { $Global:TreiberMainboardPath  = Join-Path $Global:TreiberPath "Mainboard" }
        if (-not $Global:TreiberAllinOnePCPath) { $Global:TreiberAllinOnePCPath = Join-Path $Global:TreiberPath "AllinOnePC" }

        <#
            Optional: Hersteller/Produkt global bereitstellen,
            falls andere Funktionen (z.B. Get-MBFolder) das ben?tigen.
        #>
        $Global:BaseboardManufacturer = $manufacturer
        $Global:BaseboardProduct      = $product

        <#
            1.1) Spezieller Alias NUR für Lenovo mit Product = 3780
                 (All-in-One PC Neo 50a 24 G5)
        #>
        if ($manufacturer -eq 'Lenovo' -and $product -eq '3780') {
            $aliasPath = Join-Path (Join-Path $Global:TreiberAllinOnePCPath 'Lenovo') 'Neo 50a 24 G5'
            if (Test-Path $aliasPath) {
                Write-HostLog "[Alias] Lenovo Product=3780 -> $aliasPath" -ForegroundColor Cyan
                return $aliasPath
            }
            else {
                Write-Warning "[Alias] Zielordner fehlt: $aliasPath"
                # Kein Return -> weiter mit Fallback wie fr?her
            }
        }

        <#
            2) Fallback wie fr?her: Mainboard-Suche ?ber Hilfsfunktion Get-MBFolder
               (verwendet ggf. die globalen Variablen oder eigene Logik)
        #>
        $mbFolder = Get-MBFolder
        if ($mbFolder) {
            return $mbFolder
        }

        <# --- 3) Nichts gefunden -> $null zur?ckgeben --- #>
        return $null
    }
    catch {
        <# --- Fehlerbehandlung --- #>
        Write-Warning ("[Resolve-DriverFolder] Fehler: {0}" -f $_.Exception.Message)
        return $null
    }
}

function Close-AsusPopup {
    Add-Type @"
    using System;
    using System.Runtime.InteropServices;
    public class User32 {
        [DllImport("user32.dll", SetLastError=true)]
        public static extern IntPtr FindWindow(string lpClassName, string lpWindowName);
        [DllImport("user32.dll", SetLastError=true)]
        public static extern IntPtr SendMessage(IntPtr hWnd, uint Msg, IntPtr wParam, IntPtr lParam);
    }
"@

    $WM_CLOSE = 0x0010

    # Wir suchen bis zu 15 Sekunden nach dem Asus-Popup
    for ($i=0; $i -lt 30; $i++) {
        Start-Sleep -Milliseconds 500
        $hWnd = [User32]::FindWindow($null, "Does not support this Operating System: WNT_10.0P_64")
        if ($hWnd -ne [IntPtr]::Zero) {
            [User32]::SendMessage($hWnd, $WM_CLOSE, [IntPtr]::Zero, [IntPtr]::Zero) | Out-Null
            Write-HostLog "? Asus-Fehlerfenster automatisch geschlossen." -ForegroundColor Yellow
            return
        }
    }
}

function Invoke-IntelChipsetInstall {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$InstallerPath,   # z.B. D:\Datein\treiber\...\Setup.exe / SetupChipset.exe / *.msi
        [ValidateSet('MSI','InstallShieldMSI','IntelSetupChipset','Inno','NSIS')]
        [string]$InstallerType = 'InstallShieldMSI',
        [switch]$Overall,         # für Intel INF: -overall
        [switch]$NoRestartGuard,  # falls du den Guard NICHT willst
        [string]$LogFile = "C:\Temp\intel_chipset.log"
    )

    # ----- Reboot-Guard starten (verhindert fremde shutdowns) -----
    $guardJob = $null
    if (-not $NoRestartGuard) {
        $guardScript = {
            while ($true) {
                try { & shutdown.exe /a 2>$null | Out-Null } catch {}
                Start-Sleep -Milliseconds 800
            }
        }
        $guardJob = Start-Job -ScriptBlock $guardScript
        Write-HostLog "[Guard] Reboot-Guard gestartet (shutdown /a Loop)" -ForegroundColor Yellow
    }

    try {
        $logDir = Split-Path -Parent $LogFile
        if ($logDir -and -not (Test-Path $logDir)) { New-Item -ItemType Directory -Path $logDir -Force | Out-Null }

        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName = $InstallerPath
        $psi.UseShellExecute = $false
        $psi.RedirectStandardOutput = $true
        $psi.RedirectStandardError  = $true

        switch ($InstallerType) {
            'MSI' {
                $psi.FileName = "$env:SystemRoot\System32\msiexec.exe"
                $psi.Arguments = "/i `"$InstallerPath`" /qn REBOOT=ReallySuppress /L*v `"$LogFile`""
            }
            'InstallShieldMSI' {
                # MSI-in-EXE: /s für Silent, /v"...msi-args..."
                $psi.Arguments = "/s /v`"/qn REBOOT=ReallySuppress /L*v `"$LogFile`"`""
            }
            'IntelSetupChipset' {
                # H?ufige Intel INF-Schalter
                $intelArgs = @("-s","-norestart","-log",$LogFile)
                if ($Overall) { $intelArgs += "-overall" }

                # PS 5.1: Kein tern?rer Operator -> klassisches if/else fürs Quoten
                $quotedArgs = $intelArgs | ForEach-Object {
                    if ($_ -match '\s') { '"' + $_ + '"' } else { $_ }
                }
                $psi.Arguments = ($quotedArgs -join ' ')
            }
            'Inno' {
                $psi.Arguments = "/VERYSILENT /NORESTART /LOG=`"$LogFile`""
            }
            'NSIS' {
                # NSIS kennt oft nur /S ? daher v.a. Guard hilft
                $psi.Arguments = "/S"
            }
        }

        Write-HostLog "[Run] $($psi.FileName) $($psi.Arguments)" -ForegroundColor Cyan
        $p = New-Object System.Diagnostics.Process
        $p.StartInfo = $psi
        [void]$p.Start()
        $stdout = $p.StandardOutput.ReadToEnd()
        $stderr = $p.StandardError.ReadToEnd()
        $p.WaitForExit()

        if ($stdout) { Out-File -FilePath $LogFile -InputObject $stdout -Append -Encoding utf8 }
        if ($stderr) { Out-File -FilePath $LogFile -InputObject ("`n[stderr]`n"+$stderr) -Append -Encoding utf8 }

        $code = $p.ExitCode
        Write-HostLog "[ExitCode] $code" -ForegroundColor Gray

        # MSI: 0=OK, 3010=Reboot n?tig, 1641=hat reboot initiiert (sollte mit ReallySuppress nicht passieren)
        $rebootNeeded = $false
        if ($InstallerType -in @('MSI','InstallShieldMSI')) {
            if ($code -eq 3010) { $rebootNeeded = $true; Write-Host "[Info] Reboot erforderlich (3010)." -ForegroundColor Yellow }
            elseif ($code -eq 1641) { Write-Host "[Warn] Installer wollte reboot (1641)." -ForegroundColor Yellow }
            elseif ($code -ne 0) { Write-Warning "Installer-Exitcode: $code (siehe Log $LogFile)" }
        } else {
            if ($code -ne 0) { Write-Warning "Installer-Exitcode: $code (siehe Log $LogFile)" }
        }

        return [pscustomobject]@{
            Path         = $InstallerPath
            Type         = $InstallerType
            ExitCode     = $code
            RebootNeeded = $rebootNeeded
            LogFile      = $LogFile
        }
    }
    finally {
        if ($guardJob) {
            try { Stop-Job $guardJob -ErrorAction SilentlyContinue; Remove-Job $guardJob -Force -ErrorAction SilentlyContinue } catch {}
            Write-HostLog "[Guard] Reboot-Guard beendet" -ForegroundColor Yellow
        }
    }
}

function Install-Treiber {
    param(
        [Parameter(Mandatory)][string]$Pfad,      # Wurzelpfad für die Treiber
        [Parameter(Mandatory)][string]$LogDatei   # Logdatei-Pfad
    )

    # ---------------------------------------------
    # Konfiguration: Suchmuster & Zeitlimits
    # ---------------------------------------------
    # HINWEIS: AsusSetup.exe hier RICHTIG geschrieben (asussetup.exe)
    $exactExeOrder = @('setup.exe','driversetup.exe','asussetup.exe')   # EXE-Priorit?t
    $exactCmdOrder = @('setup.cmd')                                     # CMD
    $exactOther    = @('dpinst.exe')                                    # Fallback
    $searchOrder   = $exactExeOrder + $exactCmdOrder + $exactOther

    $waitTimeoutSeconds = 1200    # max. Wartezeit pro Versuch (Sekunden)
    $betweenTriesSleep  = 2       # kurze Pause zwischen Versuchen
    $defaultSilentArgs  = @(
        '/S',                              # NSIS/Allgemein
        '/silent',                         # Inno/Allgemein
        '/verysilent',                     # Inno
        '/quiet',                          # Microsoft/Advanced Installer
        '/quiet /norestart',               # Microsoft/Advanced Installer
        '/passive',                        # Microsoft
        '/passive /norestart',             # Microsoft
        '/s /v"/qn REBOOT=ReallySuppress"',# InstallShield (EXE->MSI)
        '/v"/qn REBOOT=ReallySuppress"',   # InstallShield (EXE->MSI)
        '/qn REBOOT=ReallySuppress',       # MSI-?hnlich (durchgereicht)
        '/norestart /quiet',               # Microsoft
        '/install /quiet /norestart'       # Advanced Installer Bootstrapper
    )

    # ---------------------------------------------
    # Helper: Logging
    # ---------------------------------------------
    function Write-LogLine {
        param([string]$Message,[string]$Level='INFO')
        # $LogDatei stammt aus Install-Treiber Parameter-Scope
        Write-Log -Message $Message -Level $Level -Path $LogDatei
    }

    # ---------------------------------------------
    # Helper: Liste installierter INF-Originalnamen aus DriverStore
    # - Sprachunabh?ngig:
    #   * pnputil /enum-drivers auslesen
    #   * Alle Tokens finden, die auf .inf enden
    # ---------------------------------------------
    function Get-InstalledInfNames {
        try {
            $out = & pnputil /enum-drivers 2>&1
        } catch {
            $out = @()
        }

        $names = @()

        foreach ($line in $out) {
            # Nur Zeilen betrachten, in denen ?berhaupt ".inf" vorkommt
            if ($line -notmatch '\.inf') { continue }

            # Alle Muster "irgendwas.inf" aus der Zeile holen (z.B. oem12.inf, xyz.inf)
            $matches = [regex]::Matches($line, '([0-9A-Za-z_\-\.]+\.inf)')
            foreach ($m in $matches) {
                $n = $m.Groups[1].Value.ToLower()
                if ($n -and ($names -notcontains $n)) {
                    $names += $n
                }
            }
        }

        return $names
    }

    # ---------------------------------------------
    # Helper: Soll Ordner (Paket) ?bersprungen werden?
    # - Wenn im Ordnerbaum irgendeine *.inf bereits im DriverStore vorkommt -> skip
    # ---------------------------------------------
    function ShouldSkipDriverFolder {
        param(
            [Parameter(Mandatory)][string]$Folder,
            [string[]]$InstalledInfNames
        )

        if (-not (Test-Path $Folder)) { return $false }

        try {
            $infFiles = Get-ChildItem -Path $Folder -Recurse -Filter *.inf -File -ErrorAction SilentlyContinue
        } catch {
            $infFiles = @()
        }

        foreach ($f in $infFiles) {
            $name = $f.Name.ToLower()
            if ($InstalledInfNames -contains $name) {
                Write-LogLine ("Skip Paket: INF bereits installiert -> {0}" -f $name) 'WARN'
                return $true
            }
        }

        return $false
    }

    # ---------------------------------------------
    # Helper: Exakten Installer in einem Ordner (ohne Rekursion) finden
    # ---------------------------------------------
    function Find-ExactInstallerInFolder {
        param([Parameter(Mandatory)][string]$Folder)
        if (-not (Test-Path $Folder)) { return $null }

        $files = Get-ChildItem -Path $Folder -File -ErrorAction SilentlyContinue

        foreach ($name in $searchOrder) {
            $hit = $files | Where-Object { $_.Name -ieq $name } | Select-Object -First 1
            if ($hit) { return $hit.FullName }
        }

        return $null
    }

    # ---------------------------------------------
    # Helper: Fallback-Suche (Rekursion ?ber gesamten Paket-Ordner)
    # - Wenn die normale 2-Ebenen-Suche nichts findet,
    #   wird hier im kompletten Unterbaum nach den bekannten EXE/CMD gesucht.
    # - So wird z.B. AsusSetup.exe gefunden, auch wenn sie tiefer liegt.
    # ---------------------------------------------
    function Find-InstallerRecursive {
        param(
            [Parameter(Mandatory)][string]$Root,
            [string]$OsTag,
            [string]$Arch,
            [string[]]$SearchNames
        )

        if (-not (Test-Path $Root)) { return $null }

        # Alle Dateien im Baum holen, die einen der gesuchten Namen haben
        $candidates = Get-ChildItem -Path $Root -Recurse -File -ErrorAction SilentlyContinue |
            Where-Object { $SearchNames -contains $_.Name.ToLower() }

        if (-not $candidates) { return $null }

        # Gewichtung: Pfade mit OS-Tag / Architektur zuerst
        $candidates =
            $candidates |
            Select-Object *, @{
                Name = 'Score'
                Expression = {
                    $score = 0
                    $p = $_.FullName
                    if ($OsTag -and $p -match [regex]::Escape($OsTag)) { $score -= 10 }  # OS-Treffer bevorzugen
                    if ($Arch  -and $p -match [regex]::Escape($Arch))  { $score -= 5 }   # Architektur bevorzugen
                    # Position des Dateinamens im Such-Array (fr?here = wichtiger)
                    $idx = [array]::IndexOf($SearchNames, $_.Name.ToLower())
                    if ($idx -ge 0) { $score -= (20 - $idx) }
                    $score
                }
            } |
            Sort-Object Score

        # Beste gefundene Datei nehmen
        return ($candidates | Select-Object -First 1).FullName
    }

    # ---------------------------------------------
    # Helper: EXE/CMD silent ausführen, mit Schalter-Cycle und Timeout
    # - Behandelt dpinst*.exe ExitCode 256 (0x00000100) als soft success
    # ---------------------------------------------
    function Invoke-ExecutableSilent {
        param(
            [Parameter(Mandatory)][string]$Path,
            [string[]]$ArgCandidates,
            [int]$TimeoutSec = 1200
        )

        $file = Get-Item $Path -ErrorAction SilentlyContinue
        if (-not $file) {
            return [pscustomobject]@{
                Success  = $false
                ExitCode = $null
                ArgsUsed = $null
                Message  = "File not found"
            }
        }

        $baseName = $file.Name.ToLowerInvariant()
        $prior = @()

        # Datei-spezifische bevorzugte Argumente
        if ($baseName -eq 'driversetup.exe') {
            $prior = @(
                '/silent','/verysilent',
                '/quiet /norestart','/passive /norestart',
                '/s /v"/qn REBOOT=ReallySuppress"'
            )
        }
        elseif ($baseName -eq 'setup.exe') {
            $prior = @(
                '/silent','/verysilent','/S',
                '/quiet /norestart','/passive /norestart',
				
                '/s /v"/qn REBOOT=ReallySuppress"'
            )
        }

        $argsOrdered =
            @($prior + $ArgCandidates) |
            Where-Object { $_ -and $_.Trim() -ne '' } |
            Select-Object -Unique

        foreach ($args in $argsOrdered) {
            try {
                Write-LogLine "Starte EXE silent: `"$($file.FullName)`" $args"

                $p = Start-Process -FilePath $file.FullName -ArgumentList $args -PassThru -WindowStyle Hidden
                if (-not $p) { throw "Start-Process returned null" }

                # Kurz warten, dann ggf. Asus-Popup schlie?en
                Start-Sleep -Seconds 2
                try { Close-AsusPopup } catch {}

                $exited = $p.WaitForExit($TimeoutSec * 1000)
                if (-not $exited) {
                    try { $p.Kill() } catch {}
                    Write-LogLine "Timeout nach $TimeoutSec s mit Args: $args" 'WARN'
                    Start-Sleep -Seconds $betweenTriesSleep
                    continue
                }

                $code = $p.ExitCode
                Write-LogLine "ExitCode=$code mit Args: $args" 'INFO'

                $isDpinst = ($baseName -like 'dpinst*.exe')
                $ok = $false

                if ($isDpinst) {
                    # DPInst: 0, 1641, 3010 = ok; 256 = soft success (Treiber evtl. bereits da oder nur kopiert)
                    if ($code -in 0,1641,3010) {
                        $ok = $true
                    }
                    elseif ($code -eq 256) {
                        $ok = $true
                        Write-LogLine "DPInst soft success (256): Treiber bereits vorhanden oder nur in Store kopiert." 'WARN'
                    }
                }
                else {
                    if ($code -in 0,1641,3010) { $ok = $true }
                }

                if ($ok) {
                    $level = 'SUCCESS'
                    if ($code -in 1641,3010) { $level = 'WARN' } # Install ok, aber Neustart empfohlen
                    Write-LogLine "Silent-Install erfolgreich." $level

                    return [pscustomobject]@{
                        Success  = $true
                        ExitCode = $code
                        ArgsUsed = $args
                        Message  = 'OK'
                    }
                }
                else {
                    Start-Sleep -Seconds $betweenTriesSleep
                }
            }
            catch {
                Write-LogLine ("Fehler beim Start mit Args '{0}': {1}" -f $args,$_.Exception.Message) 'ERROR'
                Start-Sleep -Seconds $betweenTriesSleep
            }
        }

        return [pscustomobject]@{
            Success  = $false
            ExitCode = $null
            ArgsUsed = $null
            Message  = 'Alle Silent-Varianten fehlgeschlagen'
        }
    }

    # ---------------------------------------------
    # Start: Logkopf und Pfadpr?fung
    # ---------------------------------------------
    "=== Treiberinstallation gestartet: $(Get-Date) ===" | Tee-Object -FilePath $LogDatei -Append

    if (-not (Test-Path $Pfad)) {
        "[ERR] Pfad nicht gefunden: $Pfad" | Tee-Object -FilePath $LogDatei -Append
        return
    }

    # OS/Arch zur Ordner-Priorisierung (nur für Ordnerwahl/Score, nicht für Skip)
    $osVer = (Get-CimInstance Win32_OperatingSystem).Caption
    if ($osVer -match "11") { $osTag = "Win11" }
    elseif ($osVer -match "10") { $osTag = "Win10" }
    else { $osTag = "Win7_Win8.1" }

    $arch = if ([Environment]::Is64BitOperatingSystem) { "x64" } else { "x86" }

    # DriverStore-Index einmalig laden (sprachunabh?ngig geparst)
    $installedInfs = Get-InstalledInfNames
    Write-LogLine ("DriverStore Original Names geladen: {0}" -f ($installedInfs.Count)) 'INFO'

    # Hauptordner (eine Ebene unterhalb Pfad) durchgehen
    $mainDirs = Get-ChildItem -Path $Pfad -Directory -ErrorAction SilentlyContinue

    foreach ($dir in $mainDirs) {

        # Skip, wenn INF aus diesem Ordner bereits installiert
        if (ShouldSkipDriverFolder -Folder $dir.FullName -InstalledInfNames $installedInfs) {
            "[SKIP] Paket bereits vorhanden: $($dir.FullName)" | Tee-Object -FilePath $LogDatei -Append
            continue
        }

        $setup = $null

        # 1) Direkt im Hauptordner exakte Namen pr?fen
        $setup = Find-ExactInstallerInFolder -Folder $dir.FullName

        # 2) Falls nicht vorhanden: Unterordner 1./2. Ebene mit Priorisierung
        if (-not $setup) {
            $subDirs = Get-ChildItem -Path $dir.FullName -Directory -ErrorAction SilentlyContinue

            # OS/Arch-bevorzugte Ordner nach vorne sortieren
            $preferred = $subDirs | Where-Object { $_.Name -match $osTag -or $_.Name -match $arch }
            if ($preferred) {
                $preferredList = @($preferred)
                $restList      = @($subDirs | Where-Object { $_ -notin $preferredList })
                $subDirs       = $preferredList + $restList
            }

            foreach ($sub in $subDirs) {
                # Pro Unterordner ggf. Skip (wenn dort schon INF installiert)
                if (ShouldSkipDriverFolder -Folder $sub.FullName -InstalledInfNames $installedInfs) {
                    "[SKIP] Paket bereits vorhanden: $($sub.FullName)" | Tee-Object -FilePath $LogDatei -Append
                    continue
                }

                $setup = Find-ExactInstallerInFolder -Folder $sub.FullName
                if ($setup) { break }

                $subSub = Get-ChildItem -Path $sub.FullName -Directory -ErrorAction SilentlyContinue
                foreach ($sub2 in $subSub) {
                    if (ShouldSkipDriverFolder -Folder $sub2.FullName -InstalledInfNames $installedInfs) {
                        "[SKIP] Paket bereits vorhanden: $($sub2.FullName)" | Tee-Object -FilePath $LogDatei -Append
                        continue
                    }

                    $setup = Find-ExactInstallerInFolder -Folder $sub2.FullName
                    if ($setup) { break }
                }

                if ($setup) { break }
            }
        }

        # 3) Fallback: gesamte Baum-Suche (Find-InstallerRecursive),
        #    z.B. wenn AsusSetup.exe tiefer in Win11\x64\... liegt
        if (-not $setup) {
            $setup = Find-InstallerRecursive -Root $dir.FullName -OsTag $osTag -Arch $arch -SearchNames $searchOrder
        }

        # Wenn endgültig kein Installer gefunden wurde -> n?chstes Paket
        if (-not $setup) { continue }

        ">> Installiere: $setup" | Tee-Object -FilePath $LogDatei -Append

        $ext = [IO.Path]::GetExtension($setup).ToLower()

        switch ($ext) {

            # ---------------- MSI: immer ?ber msiexec /qn ----------------
            ".msi" {
                try {
                    $msiLog = ($LogDatei -replace '\.log$', '') + "-msi.log"
                    Write-LogLine "MSI via msiexec: `"$setup`""

                    $psi = New-Object System.Diagnostics.ProcessStartInfo
                    $psi.FileName    = "$env:SystemRoot\System32\msiexec.exe"
                    $psi.Arguments   = "/i `"$setup`" /qn REBOOT=ReallySuppress /L*v `"$msiLog`""
                    $psi.UseShellExecute = $false

                    $p = [System.Diagnostics.Process]::Start($psi)
                    $null = $p.WaitForExit($waitTimeoutSeconds * 1000)

                    $code = if ($p.HasExited) { $p.ExitCode } else { try { $p.Kill() } catch {} ; 9999 }

                    Write-LogLine "MSI ExitCode=$code"

                    if ($code -notin 0,1641,3010) {
                        Write-LogLine "MSI-Installation meldete Fehlercode $code" 'WARN'
                    }
                }
                catch {
                    Write-LogLine "MSI-Start fehlgeschlagen: $($_.Exception.Message)" 'ERROR'
                }
            }

            # ---------------- EXE: Intel-Chipset zuerst dediziert ----------------
            ".exe" {
                $vi = (Get-Item $setup).VersionInfo
                $company = $vi.CompanyName
                $prod    = $vi.ProductName
                $bn      = [IO.Path]::GetFileName($setup)
				# --- dpinst.exe Spezial: NICHT mit Silent-Args "raten", sondern INF installieren ---
				if ($bn.ToLowerInvariant() -like "dpinst*.exe") {
					$folder = Split-Path -Parent $setup
					$pnpLog = ($LogDatei -replace '\.log$', '') + "-pnputil.log"

					Write-LogLine "DPInst gefunden -> installiere INF via pnputil aus: $folder" 'INFO'

					try {
						$cmd = "pnputil /add-driver `"$folder\*.inf`" /subdirs /install"
						$out = & cmd.exe /c $cmd 2>&1
						$out | Out-File -FilePath $pnpLog -Encoding UTF8

						Write-LogLine "pnputil fertig. Log: $pnpLog" 'SUCCESS'
					} catch {
						Write-LogLine "pnputil fehlgeschlagen: $($_.Exception.Message)" 'ERROR'
					}

					continue
				}

                $isIntel = ($company -match 'Intel' -or $prod -match 'Intel')
                $isChip  = ($bn -match 'SetupChipset|Chipset|INF' -or $prod -match 'Chipset|INF')

                if ($isIntel -and $isChip) {
                    # Intel-Chipset-Installer ?ber dedizierte Funktion (muss extern definiert sein)
                    $chipLog = ($LogDatei -replace '\.log$', '') + "-IntelChipset.log"
                    try {
                        $type = 'InstallShieldMSI'
                        if ($bn -match '^SetupChipset\.exe$') { $type = 'IntelSetupChipset' }

                        $res = Invoke-IntelChipsetInstall -InstallerPath $setup -InstallerType $type -Overall -LogFile $chipLog

                        Write-LogLine (
                            "Intel Chipset installiert: ExitCode={0}, RebootNeeded={1}, Log={2}" -f `
                            $res.ExitCode, $res.RebootNeeded, $res.LogFile
                        ) 'SUCCESS'
                    }
                    catch {
                        Write-LogLine "Intel-Chipset-Installer fehlgeschlagen: $($_.Exception.Message)" 'ERROR'
                    }
                }
                else {
                    # Normale EXE ?ber Silent-Schalter-Kombinationen
                    $result = Invoke-ExecutableSilent -Path $setup -ArgCandidates $defaultSilentArgs -TimeoutSec $waitTimeoutSeconds
                    if (-not $result.Success) {
                        Write-LogLine "Alle Silent-Varianten fehlgeschlagen: $setup" 'ERROR'
                    }
                }
            }

            # ---------------- CMD: ?ber cmd.exe /c ----------------
            ".cmd" {
                try {
                    Write-LogLine "Starte CMD silent: `"$setup`""

                    $p = Start-Process -FilePath "cmd.exe" -ArgumentList "/c `"$setup`"" -PassThru -WindowStyle Hidden

                    Start-Sleep -Seconds 2
                    try { Close-AsusPopup } catch {}

                    $null = $p.WaitForExit($waitTimeoutSeconds * 1000)

                    $code = if ($p.HasExited) { $p.ExitCode } else { try { $p.Kill() } catch {} ; 9999 }

                    Write-LogLine "CMD ExitCode=$code"

                    if ($code -ne 0) {
                        Write-LogLine "CMD-Installer meldete Fehlercode $code" 'WARN'
                    }
                }
                catch {
                    Write-LogLine "CMD-Start fehlgeschlagen: $($_.Exception.Message)" 'ERROR'
                }
            }
        }

        "[OK] Fertig: $setup" | Tee-Object -FilePath $LogDatei -Append
        Start-Sleep 2
    }

    "=== Alle Installationen abgeschlossen: $(Get-Date) ===" | Tee-Object -FilePath $LogDatei -Append
}

function Configure-RestorePoint {
    # 3% von C: reservieren
    $volume = Get-WmiObject Win32_LogicalDisk | ForEach-Object { $_.name, ($_.size/1GB) }
    $s = $volume[1]
    if ($s) {
        $num = $s.ToString()
        if ($num.Length -ge 3) { $gb = [int]([math]::Round(([int]$num.Substring(0,3))/100*3)) } else { $gb = 3 }
    } else { $gb = 3 }
    Enable-ComputerRestore -Drive "C:\" 2>$null
    vssadmin resize shadowstorage /On=C: /For=C: /Maxsize="$gb"GB | Out-Null
}

function Fonts {
    $fontsSource = $Global:FontsPath
    $fontsDest   = "$env:WINDIR\Fonts"
    $regPath     = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Fonts"
    $fontLogName = if ($Name) { $Name } else { $env:COMPUTERNAME }
    $logFile     = Join-Path $Global:LogPath "$fontLogName-Fonts.log"

    if (-not (Test-Path $fontsSource)) {
    Write-Log -Message "? Font-Quellordner nicht gefunden: $fontsSource" -Path $logFile -Level INFO
        return
    }

    # Alle Font-Dateien in allen Unterordnern suchen
    $fontFiles = Get-ChildItem -Path $fontsSource -File -Recurse -ErrorAction SilentlyContinue |
                 Where-Object { $_.Extension -in ".ttf", ".otf", ".ttc" }

    if (-not $fontFiles -or $fontFiles.Count -eq 0) {
    Write-Log -Message "? Keine Font-Dateien gefunden in: $fontsSource" -Path $logFile -Level INFO
        return
    }

    # Shell.Application für echte Font-Installation
    $objShell  = New-Object -ComObject Shell.Application
    $objFolder = $objShell.Namespace(0x14)  # Fonts-Folder
    Write-Log -Message "=== Font-Installation gestartet: $(Get-Date -Format 'dd.MM.yyyy HH:mm:ss') ===" -Path $logFile -Level INFO
    foreach ($file in $fontFiles) {
        $destFile = Join-Path $fontsDest $file.Name

        # Registry-Name anhand Extension bestimmen
        $fontName = $file.BaseName
        switch ($file.Extension.ToLower()) {
            ".ttf" { $regName = "$fontName (TrueType)" }
            ".otf" { $regName = "$fontName (OpenType)" }
            ".ttc" { $regName = "$fontName (TrueType Collection)" }
            default { $regName = $fontName }
        }

        # Vorhandene Datei löschen (erzwingt Neuinstallation)
        if (Test-Path $destFile) {
            try { Remove-Item $destFile -Force -ErrorAction SilentlyContinue } catch {}
        }

        # Vorhandenen Registryeintrag löschen
        if (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue) {
            try { Remove-ItemProperty -Path $regPath -Name $regName -Force -ErrorAction SilentlyContinue } catch {}
        }

        # Datei ins Fonts-Verzeichnis kopieren
        Copy-Item $file.FullName -Destination $destFile -Force

        # Font korrekt im System registrieren
        $objFolder.CopyHere($destFile)

        # Registry neu anlegen
        New-ItemProperty -Path $regPath -Name $regName -Value $file.Name -PropertyType String -Force | Out-Null
    Write-Log -Message "[OK] $($file.Name) installiert/aktualisiert." -Path $logFile -Level INFO
    }
    Write-Log -Message "=== Font-Installation abgeschlossen: $(Get-Date -Format 'dd.MM.yyyy HH:mm:ss') ===" -Path $logFile -Level INFO
    Write-HostLog "[OK] Alle Fonts installiert (erzwingend, ohne Nachfragen)."
}

function Remove-DefaultPrinter {
    <#
        Entfernt den Standard-PDF-Drucker "Microsoft Print to PDF".
        Alias: Drucker (für Rückwärtskompatibilität)
    #>
    $druckerName = "Microsoft Print to PDF"
    $p = Get-Printer | Where-Object Name -eq $druckerName
    if ($p) {
        Remove-Printer -Name $druckerName
        Write-Log -Message "Drucker '$druckerName' entfernt" -Level 'SUCCESS'
    } else {
        Write-Log -Message "Drucker '$druckerName' nicht gefunden (bereits entfernt)" -Level 'INFO'
    }
}
# Alias für Rückwärtskompatibilität
Set-Alias -Name Drucker -Value Remove-DefaultPrinter -Scope Script

function Set-NetworkPowerManagement {
    <#
        Deaktiviert Energiesparen an Ethernet-Adaptern (Registry).
        Alias: Netzwerk (für Rückwärtskompatibilität)
    #>
    $networkClassGuid = '{4D36E972-E325-11CE-BFC1-08002BE10318}'
    $pnpValue = $script:Constants.PnPCapabilities_DisablePowerMgmt

    for ($id = 0; $id -lt 255; $id++) {
        $cls = "HKLM:\SYSTEM\CurrentControlSet\Control\Class\$networkClassGuid\$("{0:D4}" -f $id)"
        $props = Get-ItemProperty -Path $cls -ErrorAction SilentlyContinue
        if ($null -eq $props) { continue }

        # Nur physische Ethernet-Adapter (ifType 6)
        if (($props."*ifType" -eq 6) -and
            ($props.DeviceInstanceID -notlike "ROOT\*") -and
            ($props.DeviceInstanceID -notlike "SW\*")) {
            Set-ItemProperty -Path $cls -Name "PnPCapabilities" -Value $pnpValue -Type DWord -ErrorAction SilentlyContinue
        }
    }
    Write-Log -Message "Netzwerk-Energieverwaltung konfiguriert (PnPCapabilities=$pnpValue)" -Level 'SUCCESS'
}
# Alias für Rückwärtskompatibilität
Set-Alias -Name Netzwerk -Value Set-NetworkPowerManagement -Scope Script

function Set-PowerPlan {
    <#
        Setzt den Energiesparplan auf Höchstleistung und deaktiviert Timeouts.
        Alias: Energiesparplan (für Rückwärtskompatibilität)
    #>
    # Alle Energiepläne auflisten (DE+EN kompatibel)
    $plans = powercfg /list | ForEach-Object {
        if ($_ -match '(?i)(?:GUID des Energieschemas|Power Scheme GUID):\s+([0-9a-fA-F\-]+)\s+\((.+?)\)') {
            [PSCustomObject]@{ Guid = $matches[1]; Name = $matches[2] }
        }
    }

    if (-not $plans -or $plans.Count -eq 0) {
        Write-Warning "? Keine Energiepläne gefunden!"
        return
    }

    # Zielplan w?hlen: H?chstleistung ? sonst Ausbalanciert
    $target = $plans | Where-Object { $_.Name -match "H?chstleistung|Ultimative Leistung|High performance|Ultimate Performance" } | Select-Object -First 1
    if (-not $target) {
        $target = $plans | Where-Object { $_.Name -match "Ausbalanciert|Balanced" } | Select-Object -First 1
    }

    if ($target) {
        powercfg /setactive $target.Guid | Out-Null
        Write-HostLog "[OK] Energiesparplan gesetzt: $($target.Name)" -ForegroundColor Green
    } else {
        Write-Warning "? Kein gültiger Energieplan gefunden."
        return
    }

    # Bildschirm ausschalten deaktivieren
    powercfg /change monitor-timeout-ac 0
    powercfg /change monitor-timeout-dc 0

    # Energiesparmodus deaktivieren
    powercfg /change standby-timeout-ac 0
    powercfg /change standby-timeout-dc 0

    # Ruhezustand deaktivieren
    powercfg /change hibernate-timeout-ac 0
    powercfg /change hibernate-timeout-dc 0
    powercfg /hibernate off

    Write-HostLog "[OK] Bildschirm-Aus, Energiesparmodus & Ruhezustand deaktiviert." -ForegroundColor Green
}
# Alias für Rückwärtskompatibilität
Set-Alias -Name Energiesparplan -Value Set-PowerPlan -Scope Script

function WakeonLan {
    if (Get-NetAdapterPowerManagement -Name "Ethernet" -ErrorAction SilentlyContinue) {
        Set-NetAdapterPowerManagement -Name "Ethernet" -WakeOnMagicPacket Enabled -ErrorAction SilentlyContinue
        Set-NetAdapterPowerManagement -Name "Ethernet" -AllowComputerToTurnOffDevice Enabled -AllowWakeFromPattern Enabled -ErrorAction SilentlyContinue
    }
}

function Add-WlanProfile {
    param([Parameter(Mandatory)][string]$SSID)
    if (-not (Test-Path $Global:WlanPwFile)) {
        Write-Warning "WLAN-Passwortdatei fehlt: $Global:WlanPwFile"
        return
    }
    $zeilen = Get-Content $Global:WlanPwFile | Where-Object { $_.Trim() -ne "" }
    for ($i=0; $i -lt $zeilen.Count; $i++) {
        if ($zeilen[$i].Trim() -eq "Wlan $SSID") {
            $pwd = $zeilen[$i+1].Trim()
@"
<?xml version="1.0"?>
<WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1">
  <name>$SSID</name>
  <SSIDConfig><SSID><name>$SSID</name></SSID></SSIDConfig>
  <connectionType>ESS</connectionType>
  <connectionMode>auto</connectionMode>
  <MSM><security>
    <authEncryption><authentication>WPA2PSK</authentication><encryption>AES</encryption><useOneX>false</useOneX></authEncryption>
    <sharedKey><keyType>passPhrase</keyType><protected>false</protected><keyMaterial>$pwd</keyMaterial></sharedKey>
  </security></MSM>
</WLANProfile>
"@ | Out-File -Encoding UTF8 -FilePath "$env:TEMP\$SSID.xml"
            netsh wlan add profile filename="$env:TEMP\$SSID.xml" user=all | Out-Null
            Remove-Item "$env:TEMP\$SSID.xml" -Force
            return
        }
    }
    Write-Warning "Kein Passwort zu SSID '$SSID' in Datei gefunden."
}

function UninstallWinProg {
    [CmdletBinding()]
    param(
        [string]$LogPath
    )

    # ===== Helpers ============================================================
    # Fehlercodes, die wir als ?nicht deinstallierbar/System? behandeln
    $NonRemovableErrorHex = @('0x80070032','0x80073CFA','0x80073CF1','0x80073D19')

    function Test-NonRemovableError {
        param([Parameter(Mandatory)][string]$Message)
        return ($NonRemovableErrorHex | ForEach-Object { $Message -match [regex]::Escape($_) }) -contains $true
    }

    function Invoke-RemoveAppxSafe {
        <#
            Versucht Remove-AppxPackage für ein konkretes Paket.
            R?ckgabe:
              @{ Status='Removed'|'NonRemovable'|'NotFound'|'Error'; Name='...', Reason='...' }
        #>
        param(
            [Parameter(Mandatory)]$PackageOrName  # AppxPackage-Objekt ODER String (Name)
        )
        $result = @{ Status='NotFound'; Name=''; Reason='' }

        if ($PackageOrName -is [string]) {
            $pkg = Get-AppxPackage -AllUsers -Name $PackageOrName -ErrorAction SilentlyContinue
            if (-not $pkg) { $result.Name = $PackageOrName; return $result }
        } else {
            $pkg = $PackageOrName
        }

        $result.Name = $pkg.Name

        if ($pkg.NonRemovable) {
            $result.Status = 'NonRemovable'
            $result.Reason = 'OS-Flag NonRemovable=True'
            return $result
        }

        try {
            Remove-AppxPackage -Package $pkg.PackageFullName -AllUsers -ErrorAction Stop
            $result.Status = 'Removed'
            return $result
        } catch {
            $msg = $_.Exception.Message
            if (Test-NonRemovableError -Message $msg) {
                $result.Status = 'NonRemovable'
                $result.Reason = $msg
            } else {
                $result.Status = 'Error'
                $result.Reason = $msg
            }
            return $result
        }
    }

    function Add-PendingDelete { param([Parameter(Mandatory)][string]$Path)
        try {
            $reg = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager"
            $name = "PendingFileRenameOperations"
            $val = (Get-ItemProperty -Path $reg -Name $name -ErrorAction SilentlyContinue).$name
            $list = New-Object System.Collections.ArrayList
            if ($val) { [void]$list.AddRange($val) }
            [void]$list.Add($Path); [void]$list.Add("")  # leeres Ziel = Delete
            Set-ItemProperty -Path $reg -Name $name -Value $list -Type MultiString -Force
            $script:Summary.RemovedFiles += "$Path (on reboot)"
            Write-Log "Scheduled delete on reboot: $Path" 'WARN'
            return $true
        } catch {
            $script:Summary.Errors += "Schedule delete $Path -> $($_.Exception.Message)"
            Write-Log "Failed to schedule delete for $Path | $($_.Exception.Message)" 'ERROR'
            return $false
        }
    }

    function Remove-ItemWithRetry { param([Parameter(Mandatory)][string]$Path)
        if (-not (Test-Path $Path)) { $script:Summary.SkippedNotFound += $Path; Write-Log "Not found (skip): $Path" 'WARN'; return }
        try {
            Remove-Item $Path -Recurse -Force -ErrorAction Stop
            $script:Summary.RemovedFiles += $Path
            Write-Log "Deleted: $Path" 'SUCCESS'
        } catch {
            $msg = $_.Exception.Message
            if ($msg -match 'Zugriff.*verweigert|access.*denied|in use|The process cannot access') {
                Write-Log "Access denied/in use -> stopping Explorer and retry: $Path" 'WARN'
                try {
                    Get-Process explorer -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
                    Start-Sleep -Seconds 2
                    Remove-Item $Path -Recurse -Force -ErrorAction Stop
                    $script:Summary.RemovedFiles += "$Path (after explorer stop)"
                    Write-Log "Deleted after explorer stop: $Path" 'SUCCESS'
                } catch {
                    Write-Log "Retry failed, scheduling delete on reboot: $Path" 'WARN'
                    [void](Add-PendingDelete -Path $Path)
                } finally {
                    Start-Process explorer.exe | Out-Null
                }
            } else {
                $script:Summary.Errors += "Remove $Path -> $msg"
                Write-Log "Failed to delete: $Path | $msg" 'ERROR'
            }
        }
    }

    function Remove-TaskSafe { param([Parameter(Mandatory)][string]$Name)
        $null = schtasks /Query /TN "$Name" 2>$null
        if ($LASTEXITCODE -eq 0) {
            try { schtasks /Delete /F /TN "$Name" 2>$null | Out-Null; $script:Summary.RemovedTasks += $Name; Write-Log "Deleted Task: $Name" 'SUCCESS' }
            catch { $script:Summary.Errors += "Task $Name -> $($_.Exception.Message)"; Write-Log "Failed to delete task $Name | $($_.Exception.Message)" 'ERROR' }
        } else { $script:Summary.SkippedNotFound += "Task:$Name"; Write-Log "Task not found (skip): $Name" 'WARN' }
    }

    # ===== Init ===============================================================
    if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
        Write-Warning "Bitte PowerShell als Administrator ausführen."; return
    }
    if (-not $LogPath) {
        $stamp   = (Get-Date).ToString('yyyyMMdd_HHmmss')
        $LogPath = Join-Path $env:ProgramData "Cleanup\uninstall-log-$stamp.txt"
    }
    $script:LOG = $LogPath
    Initialize-LogFile -Path $LOG
	$sw = [System.Diagnostics.Stopwatch]::StartNew()

    $script:Summary = [ordered]@{
        StartTime          = Get-Date
        RemovedAppx        = @()
        RemovedProvisioned = @()
        RemovedFiles       = @()
        RemovedTasks       = @()
        RemovedRegValues   = @()
        PoliciesSet        = @()
        SkippedNotFound    = @()
        SkippedNonRemovable= @()
        Errors             = @()
    }

    Write-Log "Starte Windows-Cleanup..." 'INFO'

    # ===== AppX + Provisioned =================================================
    # Diese beiden werden NICHT mehr vorab geskippt ? wir versuchen es immer:
    $AlwaysAttempt = @('Microsoft.Windows.NarratorQuickStart','Microsoft.XboxGameCallableUI')

    $apps = @(
    "Microsoft.Windows.NarratorQuickStart","Microsoft.BingNews","Microsoft.BingWeather","Microsoft.PowerAutomateDesktop",
    "Microsoft.Windows.Photos","Microsoft.WindowsAlarms","Microsoft.WindowsFeedbackHub","Microsoft.WindowsSoundRecorder",
    "Microsoft.MicrosoftOfficeHub","Microsoft.Xbox.TCUI","Microsoft.XboxGamingOverlay","Microsoft.XboxGameOverlay",
    "Microsoft.XboxGameCallableUI","Microsoft.XboxIdentityProvider","Microsoft.XboxSpeechToTextOverlay",
    "MicrosoftCorporationII.QuickAssist","Microsoft.Windows.Copilot","Clipchamp.Clipchamp","Microsoft.Xbox*",
    "Microsoft.GamingApp","Microsoft.Todos","Microsoft.ScreenSketch","Microsoft.GetHelp","Microsoft.Getstarted",
    "Microsoft.People","Microsoft.YourPhone","Microsoft.WindowsMaps","Microsoft.ZuneMusic","Microsoft.ZuneVideo",
    "Microsoft.MicrosoftSolitaireCollection","Microsoft.MicrosoftStickyNotes","Microsoft.OfficeHub",
    "Microsoft.OutlookForWindows","Microsoft.Teams","Microsoft.CommsPhone","Microsoft.WindowsCommunicationsApps",
    "Microsoft.549981C3F5F10","DolbyLaboratories.DolbyAccess","MicrosoftTeams*","MSTeams*",
    # --- NEU: OneDrive AppX / Realtek / Dolby Audio ---
    "Microsoft.OneDriveSync",                        # Win11 AppX-Provision (für Neu-User)
    "RealtekSemiconductorCorp.RealtekAudioControl*", # Realtek Audio Console
    "RealtekSemiconductorCorp.RealtekAudioConsole*", # manche Images benutzen diesen Namen
    "DolbyLaboratories.DolbyAudio*",                 # Dolby Audio (nicht Access)
    "DolbyLaboratories.Dolby*"                       # fallback
	)


    foreach ($a in $apps) {
        # Installierte Pakete
        $pkgs = Get-AppxPackage -AllUsers -Name $a -ErrorAction SilentlyContinue
        if (-not $pkgs) {
            $Summary.SkippedNotFound += "AppX:$a"
            Write-Log "AppX not found (skip): $a" 'WARN'
        } else {
            foreach ($p in $pkgs) {
                $res = Invoke-RemoveAppxSafe -PackageOrName $p
                switch ($res.Status) {
                    'Removed' {
                        $Summary.RemovedAppx += $res.Name
                        Write-Log "Removed AppX: $($res.Name) ($($p.PackageFullName))" 'SUCCESS'
                    }
                    'NonRemovable' {
                        $Summary.SkippedNonRemovable += $res.Name
                        Write-Log "Skip NonRemovable AppX: $($res.Name) | $($res.Reason)" 'WARN'
                    }
                    'Error' {
                        $Summary.Errors += "Remove-AppxPackage $($res.Name) -> $($res.Reason)"
                        Write-Log "Failed to remove AppX $($res.Name) | $($res.Reason)" 'ERROR'
                    }
                    Default {
                        $Summary.SkippedNotFound += "AppX:$a"
                        Write-Log "AppX not found (skip): $a" 'WARN'
                    }
                }
            }
        }

        # Provisioned Pakete (für neue Benutzer)
        $prov = Get-AppxProvisionedPackage -Online | Where-Object { $_.DisplayName -like $a }
        if ($prov) {
            foreach ($pp in $prov) {
                try {
                    Remove-AppxProvisionedPackage -Online -PackageName $pp.PackageName -ErrorAction Stop | Out-Null
                    $Summary.RemovedProvisioned += $pp.DisplayName
                    Write-Log "Removed Provisioned: $($pp.DisplayName)" 'SUCCESS'
                } catch {
                    $msg = $_.Exception.Message
                    if (Test-NonRemovableError -Message $msg) {
                        $Summary.SkippedNonRemovable += $pp.DisplayName
                        Write-Log "Skip NonRemovable Provisioned: $($pp.DisplayName) | $msg" 'WARN'
                    } else {
                        $Summary.Errors += "Remove-AppxProvisioned $($pp.DisplayName) -> $msg"
                        Write-Log "Failed to remove Provisioned $($pp.DisplayName) | $msg" 'ERROR'
                    }
                }
            }
        }
    }

    # ===== Policies ===========================================================
    try {
        $pol = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot"
        if (-not (Test-Path $pol)) { New-Item $pol -Force | Out-Null }
        New-ItemProperty -Path $pol -Name "TurnOffWindowsCopilot" -PropertyType DWord -Value 1 -Force | Out-Null
        $Summary.PoliciesSet += "WindowsCopilot:TurnOffWindowsCopilot=1"
        Write-Log "Policy set: TurnOffWindowsCopilot=1" 'SUCCESS'
    } catch { $Summary.Errors += "Copilot policy -> $($_.Exception.Message)"; Write-Log "Failed setting Copilot policy | $($_.Exception.Message)" 'ERROR' }
    try {
        $cloud = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent"
        if (-not (Test-Path $cloud)) { New-Item $cloud -Force | Out-Null }
        New-ItemProperty -Path $cloud -Name "DisableConsumerFeatures" -PropertyType DWord -Value 1 -Force | Out-Null
        New-ItemProperty -Path $cloud -Name "DisableCloudOptimizedContent" -PropertyType DWord -Value 1 -Force -ErrorAction SilentlyContinue | Out-Null
        $Summary.PoliciesSet += "CloudContent:DisableConsumerFeatures=1"
        Write-Log "Policy set: DisableConsumerFeatures=1" 'SUCCESS'
    } catch { $Summary.Errors += "CloudContent policy -> $($_.Exception.Message)"; Write-Log "Failed setting CloudContent policy | $($_.Exception.Message)" 'ERROR' }
    try {
        $odPol = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive"
        if (-not (Test-Path $odPol)) { New-Item $odPol -Force | Out-Null }
        New-ItemProperty -Path $odPol -Name "DisableFileSyncNGSC" -Value 1 -PropertyType DWORD -Force | Out-Null
        $Summary.PoliciesSet += "OneDrive:DisableFileSyncNGSC=1"
        Write-Log "Policy set: DisableFileSyncNGSC=1" 'SUCCESS'
    } catch { $Summary.Errors += "OneDrive policy -> $($_.Exception.Message)"; Write-Log "Failed setting OneDrive policy | $($_.Exception.Message)" 'ERROR' }

	function Uninstall-OneDriveHard {
		param()

		Write-Log "OneDrive Hard-Uninstall..." 'INFO'

		# 1) Prozesse killen (alle Benutzer)
		foreach ($n in @("OneDrive","OneDriveStandaloneUpdater","FileCoAuth","FileSyncHelper")) {
			Get-Process -Name $n -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
		}

		# 2) Per-Machine Uninstall (SysWOW64/ System32)
		$od64 = "$env:SystemRoot\SysWOW64\OneDriveSetup.exe"
		$od32 = "$env:SystemRoot\System32\OneDriveSetup.exe"
		foreach ($exe in @($od64,$od32) | Where-Object { $_ -and (Test-Path $_) }) {
			Start-Process $exe "/uninstall" -Wait
			Write-Log "Executed: $exe /uninstall" 'INFO'
		}

		# 3) Per-User Uninstall (jeder Profilordner, falls lokal installiert)
		Get-ChildItem "C:\Users" -Directory | Where-Object { $_.Name -notin @('Default','All Users','Public') } | ForEach-Object {
			$setupLocal = Join-Path $_.FullName "AppData\Local\Microsoft\OneDrive\OneDriveSetup.exe"
			if (Test-Path $setupLocal) {
				Start-Process $setupLocal "/uninstall" -Wait
				Write-Log "Executed: $setupLocal /uninstall" 'INFO'
			}
		}

		# 4) Run-Keys / Tasks / ShellExtensions s?ubern
		foreach ($p in @("HKCU:\Software\Microsoft\Windows\CurrentVersion\Run","HKLM:\Software\Microsoft\Windows\CurrentVersion\Run")) {
			if (Test-Path $p) { Remove-ItemProperty -Path $p -Name "OneDrive" -ErrorAction SilentlyContinue }
		}
		foreach ($t in @("\Microsoft\OneDrive\OneDrive Standalone Update Task",
						 "\Microsoft\OneDrive\OneDrive Per-Machine Standalone Update Task",
						 "OneDrive Standalone Update Task","OneDrive Per-Machine Standalone Update Task")) {
			Invoke-NativeQuiet "schtasks /Delete /TN `"$t`" /F"
		}

		# 5) Ordner entfernen (mit Retry & Explorer-Stop aus deiner Helper-Funktion)
		Get-ChildItem "C:\Users" -Directory | Where-Object { $_.Name -notin @('Default','All Users','Public') } | ForEach-Object {
			$user = $_.FullName
			foreach ($d in @(
				(Join-Path $user "OneDrive"),
				(Join-Path $user "AppData\Local\Microsoft\OneDrive"),
				(Join-Path $user "AppData\Local\OneDrive"),
				(Join-Path $user "AppData\Roaming\Microsoft\Windows\Start Menu\Programs\OneDrive.lnk"),
				(Join-Path $user "AppData\Local\Packages\Microsoft.OneDriveSync_*")
			)) { Remove-ItemWithRetry -Path $d }
		}
		foreach ($d in @("$env:ProgramData\Microsoft OneDrive",
						 "$env:LocalAppData\Microsoft\OneDrive",
						 "$env:ProgramFiles\Microsoft OneDrive",
						 "$env:ProgramFiles(x86)\Microsoft OneDrive")) {
			Remove-ItemWithRetry -Path $d
		}
	}

    # ===== OneDrive deinstallieren + Reste (Hard) ================================
	Write-Log "Entferne OneDrive..." 'INFO'
	Uninstall-OneDriveHard

    # ===== Teams (Personal) Reste ============================================
    Write-Log "Entferne Reste von Microsoft Teams (Personal)..." 'INFO'
    Get-ChildItem "C:\Users" -Directory | Where-Object { $_.Name -notin @('Default','All Users','Public') } | ForEach-Object {
        $user = $_.FullName
        foreach ($d in @(
            (Join-Path $user "AppData\Local\Microsoft\Teams"),
            (Join-Path $user "AppData\Roaming\Microsoft\Teams"),
            (Join-Path $user "AppData\Local\Packages\MSTeams_*"),
            (Join-Path $user "AppData\Local\Packages\MicrosoftTeams_*"),
            (Join-Path $user "AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Microsoft Teams (free).lnk")
        )) { Remove-ItemWithRetry -Path $d }
    }

    # ===== Dolby Access Reste ================================================
    Write-Log "Entferne Dolby Access Reste..." 'INFO'
    Get-ChildItem "C:\Users" -Directory | Where-Object { $_.Name -notin @('Default','All Users','Public') } | ForEach-Object {
        $glob = Join-Path $_.FullName "AppData\Local\Packages\DolbyLaboratories.DolbyAccess_*"
        Get-ChildItem $glob -ErrorAction SilentlyContinue | ForEach-Object { Remove-ItemWithRetry -Path $_.FullName }
    }

	# ===== Dolby Audio & Realtek Audio Console Reste ============================
	Write-Log "Entferne Dolby Audio & Realtek Audio Console Reste..." 'INFO'
	Get-ChildItem "C:\Users" -Directory | Where-Object { $_.Name -notin @('Default','All Users','Public') } | ForEach-Object {
		$user = $_.FullName
		foreach ($glob in @(
			(Join-Path $user "AppData\Local\Packages\DolbyLaboratories.DolbyAudio_*"),
			(Join-Path $user "AppData\Local\Packages\RealtekSemiconductorCorp.RealtekAudioControl_*"),
			(Join-Path $user "AppData\Local\Packages\RealtekSemiconductorCorp.RealtekAudioConsole_*")
		)) {
			Get-ChildItem $glob -ErrorAction SilentlyContinue | ForEach-Object { Remove-ItemWithRetry -Path $_.FullName }
		}
	}

    # ===== Abschluss ==========================================================
	$Summary.EndTime   = Get-Date
	try { $sw.Stop() } catch {}
	$Summary.DurationS = [int]$sw.Elapsed.TotalSeconds
    Write-Log "Cleanup abgeschlossen." 'SUCCESS'

    Write-HostLog "`n===================== ZUSAMMENFASSUNG =====================" -ForegroundColor Cyan
    Write-HostLog ("Logfile: {0}" -f $LOG)
    Write-HostLog ("Dauer:   {0}s" -f $Summary.DurationS)
    Write-HostLog ("AppX entfernt:        {0}" -f ($Summary.RemovedAppx.Count))
    Write-HostLog ("Provisioned entfernt: {0}" -f ($Summary.RemovedProvisioned.Count))
    Write-HostLog ("Dateien/Ordner:       {0}" -f ($Summary.RemovedFiles.Count))
    Write-HostLog ("Tasks gel?scht:       {0}" -f ($Summary.RemovedTasks.Count))
    Write-HostLog ("Reg-Werte gel?scht:   {0}" -f ($Summary.RemovedRegValues.Count))
    Write-HostLog ("Policies gesetzt:     {0}" -f ($Summary.PoliciesSet.Count))
    Write-HostLog ("Skipped NonRemovable: {0}" -f ($Summary.SkippedNonRemovable.Count))
    if ($Summary.Errors.Count -gt 0) { Write-Host ("Fehler:               {0}" -f ($Summary.Errors.Count)) -ForegroundColor Red } else { Write-Host "Fehler:               0" -ForegroundColor Green }
    Write-HostLog "------------------------------------------------------------"
    if ($Summary.RemovedAppx.Count)        { Write-Host "AppX:";               $Summary.RemovedAppx        | Sort-Object -Unique | ForEach-Object { Write-Host "  - $_" } }
    if ($Summary.RemovedProvisioned.Count) { Write-Host "Provisioned:";        $Summary.RemovedProvisioned | Sort-Object -Unique | ForEach-Object { Write-Host "  - $_" } }
    if ($Summary.RemovedFiles.Count)       { Write-Host "Dateien/Ordner:";     $Summary.RemovedFiles       | Sort-Object | ForEach-Object { Write-Host "  - $_" } }
    if ($Summary.RemovedTasks.Count)       { Write-Host "Tasks:";              $Summary.RemovedTasks       | Sort-Object | ForEach-Object { Write-Host "  - $_" } }
    if ($Summary.RemovedRegValues.Count)   { Write-Host "Registry-Werte:";     $Summary.RemovedRegValues   | Sort-Object | ForEach-Object { Write-Host "  - $_" } }
    if ($Summary.PoliciesSet.Count)        { Write-Host "Policies:";           $Summary.PoliciesSet        | Sort-Object | ForEach-Object { Write-Host "  - $_" } }
    if ($Summary.SkippedNonRemovable.Count){ Write-Host "NonRemovable (?bersprungen):"; $Summary.SkippedNonRemovable | Sort-Object -Unique | ForEach-Object { Write-Host "  - $_" } }
    if ($Summary.SkippedNotFound.Count)    { Write-Host "Nicht gefunden (ok):";$Summary.SkippedNotFound    | Sort-Object | ForEach-Object { Write-Host "  - $_" } }
    if ($Summary.Errors.Count)             { Write-Host "Fehlerdetails:" -ForegroundColor Red; $Summary.Errors | ForEach-Object { Write-Host "  - $_" } }

    [pscustomobject]$Summary
}


# --- Verbesserter User-Cleanup (aktuellen angemeldeten Benutzer entfernen) ---
function Get-InteractiveUsername {
    <#
      Liefert den derzeit interaktiv angemeldeten Benutzer (Console/aktive Session), möglichst zuverlässig.
      Rückgabe: "username" (ohne Domäne). Kann $null sein, wenn niemand angemeldet ist.
    #>
    try {
        # 1) Win32_ComputerSystem (liefert häufig DOM\user)
        $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
        if ($cs.UserName) {
            return ($cs.UserName -split '\\')[-1]
        }
    } catch {}

    try {
        # 2) quser: aktive Session ermitteln
        $q = (& quser 2>$null) | Out-String
        if ($q) {
            $lines = $q -split "`r?`n" | Where-Object { $_ -and ($_ -notmatch 'USERNAME') }
            foreach ($l in $lines) {
                # quser output ist spaltenbasiert; Username steht am Anfang
                $u = ($l.Trim() -split '\s+')[0]
                if ($u -and $u -ne '>') { return $u }
            }
        }
    } catch {}

    try {
        # 3) Fallback: aktueller Prozess-User (kann bei RunAs Administrator abweichen)
        if ($env:USERNAME) { return $env:USERNAME }
    } catch {}

    return $null
}

function New-DeleteUserScheduledTask {
    param(
        [Parameter(Mandatory=$true)][string]$UserToDelete,
        [string]$TaskName = "Installation_DeleteUser",
        [string]$WorkDir = "$env:ProgramData\Installation",
        [string]$LogPath = $global:LogFile
    )

    # Schutz: niemals diese Konten anfassen
    $blocked = @("Administrator","DefaultAccount","Guest","WDAGUtilityAccount","SYSTEM","LocalService","NetworkService")
    if ([string]::IsNullOrWhiteSpace($UserToDelete) -or ($blocked -contains $UserToDelete)) {
        Write-Log "User-Cleanup übersprungen: ungültiger/gesperrter Benutzer '$UserToDelete'." "WARN"
        return $false
    }

    try {
        if (-not (Test-Path $WorkDir)) { New-Item -ItemType Directory -Path $WorkDir -Force | Out-Null }

        $deleteScript = Join-Path $WorkDir "DeleteUser.ps1"
        $deleteLog    = $script:DeleteUserLogPath
        $mainLog      = $script:MainLogPath
        
        # DeleteUser.ps1 Inhalt - ALLE Variablen escaped mit ` für Here-String!
        $scriptContent = @'
param(
  [Parameter(Mandatory=$true)][string]$UserToDelete,
  [string]$LogPath,
  [string]$MainLogPath,
  [string]$TaskName
)

function Ensure-LogFile([string]$path){
  $dir = Split-Path -Path $path -Parent
  if ($dir -and -not (Test-Path $dir)) { 
    try { New-Item -ItemType Directory -Path $dir -Force | Out-Null } catch {} 
  }
  if(-not (Test-Path $path)){
    try { '' | Out-File -FilePath $path -Encoding utf8 -Force } catch {}
  }
}

function Log([string]$msg,[string]$lvl="INFO"){
  try{
    Ensure-LogFile -path $LogPath
    if ($MainLogPath -and $MainLogPath -ne $LogPath) { Ensure-LogFile -path $MainLogPath }
    $ts = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    "$ts [$lvl] $msg" | Out-File -FilePath $LogPath -Append -Encoding utf8
    if ($MainLogPath -and $MainLogPath -ne $LogPath) { try { "$ts [$lvl] $msg" | Out-File -FilePath $MainLogPath -Append -Encoding utf8 } catch {} }
  }catch{}
}

Log "DeleteUser Task gestartet. Zielbenutzer: '$UserToDelete'."

# 1) Warten bis User wirklich abgemeldet ist (max. 10 Minuten)
$deadline = (Get-Date).AddMinutes(10)

function Get-InteractiveSessions {
  try {
    $raw = & quser 2>$null
    if(-not $raw){ return @() }
    $lines = @($raw) | Where-Object { $_ -and $_.Trim() -and ($_ -notmatch 'USERNAME') }
    $sessions = @()
    foreach($l in $lines){
      $parts = ($l -replace '^\s*>?\s*','').Trim() -split '\s+'
      if($parts.Count -ge 3){
        $sessions += [pscustomobject]@{
          User = $parts[0]
          Id   = $parts[2]
          Raw  = $l
        }
      }
    }
    return $sessions
  } catch { return @() }
}

while((Get-Date) -lt $deadline){
  $sessions = Get-InteractiveSessions
  $hit = $sessions | Where-Object { $_.User -ieq $UserToDelete }
  if($hit -and $hit.Count -gt 0){
    $sessionId = if ($hit -is [array]) { $hit[0].Id } else { $hit.Id }
    Log "Benutzer '$UserToDelete' ist noch angemeldet (SessionId=$sessionId) - warte 5s..."
    Start-Sleep -Seconds 5
    continue
  }

  # Profil geladen?
  try{
    $sid = (New-Object System.Security.Principal.NTAccount($UserToDelete)).Translate([System.Security.Principal.SecurityIdentifier]).Value
    $p = Get-CimInstance Win32_UserProfile -Filter "SID='$sid'" -ErrorAction Stop
    if($p -and $p.Loaded){
      Log "Profil von '$UserToDelete' ist noch geladen - warte 5s..."
      Start-Sleep -Seconds 5
      continue
    }
  }catch{
    # Wenn SID/Profile nicht gefunden: nicht blockieren
  }

  break
}

# Falls nach Timeout noch aktiv: Session zwangsweise abmelden
$sessions = Get-InteractiveSessions
$hit = $sessions | Where-Object { $_.User -ieq $UserToDelete }
if($hit -and $hit.Count -gt 0){
  try{
    $sessionId = if ($hit -is [array]) { $hit[0].Id } else { $hit.Id }
    Log "Timeout erreicht - melde Benutzer '$UserToDelete' zwangsweise ab (SessionId=$sessionId)." "WARN"
    & logoff $sessionId 2>$null | Out-Null
    Start-Sleep -Seconds 8
  }catch{}
}

# 2) User loeschen (nur lokal) + Verifikation
$deletedUser = $false
try{
  $lu = $null
  if(Get-Command Get-LocalUser -ErrorAction SilentlyContinue){
    $lu = Get-LocalUser -Name $UserToDelete -ErrorAction SilentlyContinue
    if(-not $lu){
      Log "Benutzer ist kein lokales Konto oder existiert nicht - ueberspringe User-Loeschung." "WARN"
      $deletedUser = $true
    }else{
      Log "Loesche lokalen Benutzer: $UserToDelete"
      $maxDelTry = 5
      for($t=1;$t -le $maxDelTry;$t++){
        try{
          Remove-LocalUser -Name $UserToDelete -ErrorAction Stop
          break
        }catch{
          Log "Remove-LocalUser Versuch $t/$maxDelTry fehlgeschlagen: $($_.Exception.Message)" "WARN"
          Start-Sleep -Seconds 3
        }
      }
      # Fallback
      $lu = Get-LocalUser -Name $UserToDelete -ErrorAction SilentlyContinue
      if($lu){
        Log "Fallback: net user /delete fuer $UserToDelete" "WARN"
        try{ & net.exe user "$UserToDelete" /delete | Out-Null }catch{}
      }
      $lu = Get-LocalUser -Name $UserToDelete -ErrorAction SilentlyContinue
      if(-not $lu){
        Log "Benutzer geloescht/verifiziert." "SUCCESS"
        $deletedUser = $true
      }else{
        Log "Benutzer existiert nach Loeschversuch noch: $UserToDelete" "ERROR"
      }
    }
  }else{
    Log "Get-LocalUser nicht verfuegbar - nutze net user /delete" "WARN"
    try{ & net.exe user "$UserToDelete" /delete | Out-Null }catch{}
    $deletedUser = $true
  }
}catch{ Log "Fehler beim User-Delete: $($_.Exception.Message)" "ERROR" }

# 3) Profil loeschen (falls vorhanden)
try{
  $sid = $null
  try{ $sid = (New-Object System.Security.Principal.NTAccount($UserToDelete)).Translate([System.Security.Principal.SecurityIdentifier]).Value }catch{}
  if($sid){
    $prof = Get-CimInstance Win32_UserProfile -Filter "SID='$sid'" -ErrorAction SilentlyContinue
    if($prof){
      if(-not $prof.Loaded){
        Log "Loesche Benutzerprofil (Win32_UserProfile.Delete) fuer SID $sid"
        try{ $null = Invoke-CimMethod -InputObject $prof -MethodName Delete; Log "Profil geloescht (CIM Delete)." }
        catch{
          Log "CIM Delete fehlgeschlagen: $($_.Exception.Message) - Fallback Remove-CimInstance" "WARN"
          try{ Remove-CimInstance -InputObject $prof -ErrorAction Stop; Log "Profil entfernt (Remove-CimInstance)." }
          catch{ Log "Remove-CimInstance fehlgeschlagen: $($_.Exception.Message)" "WARN" }
        }
      }else{
        Log "Profil ist noch geladen - Profil-Loeschung uebersprungen." "WARN"
      }
    }
  }

  # Ordner-Fallback
  $homePath = "C:\Users\$UserToDelete"
  if(Test-Path $homePath){
    Log "Entferne Home-Ordner: $homePath"
    try { Remove-Item -LiteralPath $homePath -Recurse -Force -ErrorAction Stop; Log "Home-Ordner entfernt." }
    catch { Log "Home-Ordner konnte nicht entfernt werden: $($_.Exception.Message)" "WARN" }
  }
}catch{ Log "Fehler beim Profil/Home-Remove: $($_.Exception.Message)" "ERROR" }

# 4) Task self-cleanup
try{
  Log "Loesche Scheduled Task '$TaskName'..."
  Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue | Out-Null
}catch{
  try{ & schtasks.exe /Delete /TN "$TaskName" /F | Out-Null }catch{}
}

if(-not $deletedUser){ Log "WARNUNG: Benutzer konnte nicht sicher geloescht werden. Neustart erfolgt trotzdem." "ERROR" }

Log "User-Cleanup fertig. Starte Neustart."
try { & shutdown.exe /r /t 0 /f } catch {}
'@

        # Skript-Datei schreiben
        $scriptContent | Out-File -FilePath $deleteScript -Encoding utf8 -Force

        # Scheduled Task erstellen
        $psExe = Join-Path $env:SystemRoot "System32\WindowsPowerShell\v1.0\powershell.exe"
        if (-not (Test-Path $psExe)) { $psExe = "powershell.exe" }

        $taskArgs = @(
            '-NoProfile',
            '-ExecutionPolicy', 'Bypass',
            '-File', "`"$deleteScript`"",
            '-UserToDelete', "`"$UserToDelete`"",
            '-LogPath', "`"$deleteLog`"",
            '-MainLogPath', "`"$mainLog`"",
            '-TaskName', "`"$TaskName`""
        ) -join ' '

        $action    = New-ScheduledTaskAction -Execute $psExe -Argument $taskArgs
        $trigger   = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1)
        $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
        $settings  = New-ScheduledTaskSettingsSet -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit (New-TimeSpan -Minutes 30)

        Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null

        # Wichtig: sofort starten (Task wartet intern, bis User abgemeldet ist)
        Start-ScheduledTask -TaskName $TaskName

        Write-Log "DeleteUser Task registriert + gestartet: $TaskName (SYSTEM) für Benutzer '$UserToDelete'." "SUCCESS"
        return $true
    } catch {
        Write-Log "Fehler beim Erstellen/Starten des DeleteUser-Tasks: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

function Invoke-UserCleanupWithLogoff {
    param(
        [string]$TaskName = "Installation_DeleteUser"
    )
    
    $u = Get-InteractiveUsername
    if (-not $u) {
        Write-Log "Kein interaktiver Benutzer ermittelt – User-Cleanup wird übersprungen." "WARN"
        return $false
    }

    # Nur löschen, wenn lokaler User existiert
    $localUser = Get-LocalUser -Name $u -ErrorAction SilentlyContinue
    if (-not $localUser) {
        Write-Log "Interaktiver Benutzer '$u' ist kein lokales Konto oder existiert nicht – überspringe Löschung." "WARN"
        return $false
    }

    # Task erstellen
    $taskCreated = New-DeleteUserScheduledTask -UserToDelete $u -TaskName $TaskName
    if (-not $taskCreated) {
        Write-Log "DeleteUser-Task konnte nicht erstellt werden für '$u'." "ERROR"
        return $false
    }
    
    Write-Log "Melde Benutzer '$u' ab (Logoff), damit er gelöscht werden kann..." "INFO"
    
    # Robustere Session-Erkennung
    try {
        $quserOutput = & quser 2>$null
        if ($quserOutput) {
            # Konvertiere zu Array falls nötig
            $lines = @($quserOutput) | Where-Object { $_ -and $_.Trim() }
            
            # Suche nach dem Benutzer (case-insensitive)
            foreach ($line in $lines) {
                # Überspringe Header-Zeile
                if ($line -match 'USERNAME') { continue }
                
                # Extrahiere Username aus der Zeile (erstes Wort, ggf. mit > Präfix)
                $cleanLine = ($line -replace '^\s*>?\s*', '').Trim()
                $parts = $cleanLine -split '\s+'
                
                if ($parts.Count -ge 3 -and $parts[0] -ieq $u) {
                    # Session-ID ist das 3. Element (Index 2)
                    $sessionId = $parts[2]
                    if ($sessionId -match '^\d+$') {
                        Write-Log "Logoff Session $sessionId für Benutzer '$u'..." "INFO"
                        & logoff $sessionId 2>$null
                        return $true
                    }
                }
            }
        }
        
        # Fallback: shutdown /l (meldet aktuellen Benutzer ab)
        Write-Log "Fallback: shutdown /l für Benutzer-Abmeldung" "WARN"
        & shutdown.exe /l
        return $true
        
    } catch {
        Write-Log "Fehler bei Benutzer-Abmeldung: $($_.Exception.Message)" "ERROR"
        # Letzter Fallback
        try { & shutdown.exe /l } catch {}
        return $true
    }
}
# --- Ende User-Cleanup ---

function Restart-Immediate {
    param(
        [int]$DelaySeconds = 5,
        [switch]$Force
    )

    # 1) Transcripts und Jobs sauber beenden (auch evtl. Reboot-Guards)
    try { Stop-Transcript -ErrorAction SilentlyContinue } catch {}

    Get-Job | Where-Object { $_.State -in 'Running','NotStarted' } |
        Stop-Job -ErrorAction SilentlyContinue | Out-Null

    Get-Job | Remove-Job -ErrorAction SilentlyContinue | Out-Null

    # 2) Direkter, synchroner Aufruf von shutdown.exe (kein Start-Process)
    $shutdown = Join-Path $env:SystemRoot 'System32\shutdown.exe'
    $shutdownArgs = @('/r','/t', [string][Math]::Max(0,$DelaySeconds))
    if ($Force) { $shutdownArgs += '/f' }

    & $shutdown @shutdownArgs
    $exit1 = $LASTEXITCODE

    # kurz warten, damit das System den Shutdown registriert
    Start-Sleep -Milliseconds 500

    # 3) Fallback: One-shot-Task, falls irgendwas (z.B. ein verbliebener Guard) /a ausf?hrt
    if ($exit1 -ne 0) {
        try {
            $taskName = '\_RebootNow_UVNC_Once'
            # Task für +1 Minute erstellen (Uhrzeitformat ohne Sekunden)
            $runAt = (Get-Date).AddMinutes(1)
            $st = $runAt.ToString('HH:mm')
            $sd = $runAt.ToString('dd/MM/yyyy')   # passt auf de-DE
            schtasks /Create /TN $taskName /SC ONCE /ST $st /SD $sd /TR "shutdown.exe /r /f /t 0" /RL HIGHEST /F | Out-Null
            schtasks /Run /TN $taskName | Out-Null
        } catch {
            Write-Warning "Fallback-Task für Reboot konnte nicht angelegt/gestartet werden: $_"
        }
    }

    # 4) Prozess verlassen
    [Environment]::Exit(0)
}

function Ask-YesNo {
    param(
        [Parameter(Mandatory)][string]$Question,
        [switch]$DefaultYes
    )
    $suffix = if ($DefaultYes) { " (J/n)" } else { " (j/N)" }
    while ($true) {
        $ans = Read-Host ($Question + $suffix)
        if ([string]::IsNullOrWhiteSpace($ans)) {
            return [bool]$DefaultYes
        }
        switch ($ans.ToLower()) {
            {$_ -in @('j','ja','y','yes')} { return $true }
            {$_ -in @('n','nein','no')}    { return $false }
            default { Write-Host "Bitte 'j' oder 'n' eingeben." -ForegroundColor Yellow }
        }
    }
}

function Convert-To-UVNCPass {
    param(
        [Parameter(Mandatory)][string]$Password
    )
    # auf 8 Zeichen k?rzen und mit Nullbytes auff?llen
    $pwd = if ($Password.Length -gt 8) { $Password.Substring(0,8) } else { $Password }
    $block = New-Object byte[] 8
    [Text.Encoding]::ASCII.GetBytes($pwd).CopyTo($block, 0)

    # UltraVNC DES-Key (fix)
    $key = [byte[]](0x17,0x52,0x6B,0x06,0x23,0x4E,0x58,0x07)

    $des = [System.Security.Cryptography.DESCryptoServiceProvider]::new()
    $des.Mode    = [System.Security.Cryptography.CipherMode]::ECB
    $des.Padding = [System.Security.Cryptography.PaddingMode]::None
    $des.Key     = $key

    $enc = $des.CreateEncryptor()
    try {
        return $enc.TransformFinalBlock($block, 0, 8)
    } finally {
        $enc.Dispose()
        $des.Dispose()
    }
}

function Install-UltraVNCServer {
    param(
        [string]$Password,  # Passwort wird aus Credentials geladen falls nicht angegeben
        [switch]$ViewOnly,
        [string]$ProgramPath = $Global:ProgramPath
    )

    # Standard-Passwort aus Credentials laden falls nicht übergeben
    if (-not $Password) {
        $Password = $script:VncPassword
        if (-not $Password) {
            Write-Warning "Kein VNC-Passwort konfiguriert!"
            return
        }
    }
	
	$SetupPath = Join-Path $ProgramPath "UltraVNC_1_5_8_X64_Setup.exe"
	
    if (-not (Test-Path $SetupPath)) {
        Write-Error "UltraVNC Setup nicht gefunden: $SetupPath"
        return
    }

    # ggf. laufende UVNC-Dienste stoppen
    'uvnc_service','winvnc' | ForEach-Object {
        Get-Service $_ -ErrorAction SilentlyContinue | Stop-Service -Force -ErrorAction SilentlyContinue
    }

    # Silent-Installation nur Server (Parameter je nach Setup; diese funktionieren i.d.R.)
    $uvncArgs = '/verysilent /norestart /components=ultravnc_server'
    Start-Process -FilePath $SetupPath -ArgumentList $uvncArgs -Wait

    # Registry-Pfad und Passwort setzen (verschl?sselt)
    $rk = 'HKLM:\SOFTWARE\UltraVNC\WinVNC4'
    if (-not (Test-Path $rk)) { New-Item $rk -Force | Out-Null }

    $pwEnc = Convert-To-UVNCPass -Password $Password
    New-ItemProperty -Path $rk -Name 'passwd' -PropertyType Binary -Value $pwEnc -Force | Out-Null

    if ($ViewOnly) {
        New-ItemProperty -Path $rk -Name 'ViewOnly' -PropertyType DWord -Value 1 -Force | Out-Null
        # optional eigenes ViewOnly-Passwort:
        # New-ItemProperty -Path $rk -Name 'passwdviewonly' -PropertyType Binary -Value (Convert-To-UVNCPass 'meinPW') -Force | Out-Null
    }

    # sinnvolle Defaults
    New-ItemProperty -Path $rk -Name 'DisableTrayIcon' -PropertyType DWord -Value 1 -Force | Out-Null
    New-ItemProperty -Path $rk -Name 'AuthRequired'     -PropertyType DWord -Value 1 -Force | Out-Null
    New-ItemProperty -Path $rk -Name 'QuerySetting'     -PropertyType DWord -Value 2 -Force | Out-Null  # annehmen/ablehnen erlauben

    # Dienst aktivieren & starten
    sc.exe config uvnc_service start= auto | Out-Null
    Start-Service uvnc_service -ErrorAction SilentlyContinue
}

function Activate-WindowsFromMak {
    [CmdletBinding()]
    param(
        [string]$Name,
        [string]$MakFile = $Global:MakFile,
        [string]$LogPath = $Global:LogPath
    )

    # --- Log vorbereiten ---
    if (-not (Test-Path $LogPath)) {
        try { New-Item -ItemType Directory -Path $LogPath -Force | Out-Null } catch {}
    }
    $baseName = if ($Name) { "$Name-Activation" } else { ("Activation-{0:yyyyMMdd_HHmmss}" -f (Get-Date)) }
    $LogFile = Join-Path $LogPath ("$baseName.log")

    function Write-ActLog([string]$msg, [string]$lvl="INFO") {
        $line = ("{0} [{1}] {2}" -f (Get-Date -Format "s"), $lvl, $msg)
        Add-Content -Encoding UTF8 -Path $LogFile -Value $line
        Write-HostLog $line -ForegroundColor (@{INFO="Gray";WARN="Yellow";ERROR="Red";SUCCESS="Green"}[$lvl])
    }

    Write-ActLog "Start Activate-WindowsFromMak (MakFile=$MakFile)"

    if (-not (Test-Path $MakFile)) {
        Write-ActLog "FEHLER: MAK-Datei nicht gefunden: $MakFile" "ERROR"
        return $false
    }

    $key = Get-Content -Path $MakFile -ErrorAction SilentlyContinue |
           ForEach-Object { $_.Trim() } |
           Where-Object { $_ -ne "" } |
           Select-Object -First 1

    if (-not $key) {
        Write-ActLog "FEHLER: Keine gültige MAK-Zeile in $MakFile gefunden." "ERROR"
        return $false
    }

    $slmgr = Join-Path $env:windir "system32\slmgr.vbs"
    if (-not (Test-Path $slmgr)) {
        Write-ActLog "FEHLER: slmgr.vbs nicht gefunden unter $slmgr" "ERROR"
        return $false
    }

    # --- Hilfsfunktion: slmgr ausführen + Output loggen ---
    function Run-Slmgr([string]$args) {
        $cmd = "cscript.exe //nologo `"$slmgr`" $args"
        Write-ActLog "RUN: $cmd"
        $out = & cmd.exe /c $cmd 2>&1
        if ($out) { ($out | ForEach-Object { Write-ActLog $_ "INFO" }) | Out-Null }
        return $LASTEXITCODE
    }

    # --- Admin Check (wichtig) ---
    if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
        ).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
        Write-ActLog "FEHLER: Muss als Administrator laufen." "ERROR"
        return $false
    }

    # --- sppsvc sicherstellen ---
    try {
        $svc = Get-Service sppsvc -ErrorAction SilentlyContinue
        if ($svc -and $svc.Status -ne "Running") {
            Write-ActLog "Starte Dienst sppsvc..." "INFO"
            Start-Service sppsvc -ErrorAction SilentlyContinue
        }
    } catch {}

    # --- OS/Edition Logging (hilft bei 'Edition mismatch') ---
    try {
        $cap = (Get-CimInstance Win32_OperatingSystem).Caption
        Write-ActLog "OS: $cap" "INFO"
        $ed = (& dism.exe /online /Get-CurrentEdition 2>$null) -join "`n"
        if ($ed) { Write-ActLog "DISM CurrentEdition:`n$ed" "INFO" }
    } catch {}

    # --- 1) Alte Keys entfernen (best effort) ---
    Write-ActLog "Entferne alte Keys (best effort): /upk + /cpky" "INFO"
    Run-Slmgr "/upk" | Out-Null
    Run-Slmgr "/cpky" | Out-Null

    Start-Sleep -Seconds 2

    # --- 2) Key installieren ---
    Write-ActLog ("Installiere MAK (gekürzter Key): {0}..." -f $key.Substring(0,[Math]::Min(8,$key.Length))) "INFO"
    $rcIpk = Run-Slmgr "/ipk $key"
    if ($rcIpk -ne 0) {
        Write-ActLog "FEHLER: /ipk ExitCode=$rcIpk (siehe Output im Log)" "ERROR"
        return $false
    }

    Start-Sleep -Seconds 2

    # --- 3) Online aktivieren ---
    Write-ActLog "Starte Online-Aktivierung (/ato)..." "INFO"
    $rcAto = Run-Slmgr "/ato"
    if ($rcAto -ne 0) {
        Write-ActLog "WARN: /ato ExitCode=$rcAto (prüfe trotzdem Status)" "WARN"
    }

    Start-Sleep -Seconds 8

    # --- 4) Status prüfen (verlässlich) ---
    Write-ActLog "Prüfe Status (/xpr + /dlv)..." "INFO"
    Run-Slmgr "/xpr" | Out-Null
    Run-Slmgr "/dlv" | Out-Null

    $licensed = $false
    try {
        $lic = Get-CimInstance SoftwareLicensingProduct -Filter "PartialProductKey is not null" -ErrorAction SilentlyContinue |
               Where-Object { $_.ApplicationID -eq '55c92734-d682-4d71-983e-d6ec3f16059f' } |
               Sort-Object LicenseStatus -Descending |
               Select-Object -First 1

        # LicenseStatus 1 = Licensed
        if ($lic -and $lic.LicenseStatus -eq 1) { $licensed = $true }
        Write-ActLog ("LicenseStatus={0} (1=Licensed)" -f ($lic.LicenseStatus)) "INFO"
    } catch {
        Write-ActLog "WARN: Konnte LicenseStatus nicht lesen: $($_.Exception.Message)" "WARN"
    }

    if ($licensed) {
        Write-ActLog "Windows ist aktiviert ?" "SUCCESS"
        return $true
    } else {
        Write-ActLog "Windows ist NICHT aktiviert ? (siehe /dlv im Log für Fehlercode/Reason)" "ERROR"
        return $false
    }
}

function Get-CimSafe {
    param(
        [Parameter(Mandatory)][string]$ClassName
    )
    try {
        return Get-CimInstance -ClassName $ClassName -ErrorAction Stop
    } catch {
        return $null
    }
}

function Reset-WindowsUpdateComponents {
    [CmdletBinding()]
    param(
        [switch]$ForceRename,   # optional: wenn .old schon existiert -> dann umbenennen mit Timestamp
        [string]$LogFile
    )

    function _Log([string]$msg) {
        $ts = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
        $line = "[$ts] [WU-RESET] $msg"
        Write-HostLog $line -ForegroundColor Yellow
        if ($LogFile) { Add-Content -Path $LogFile -Value $line }
    }

    # Admin-Check (falls du die Funktion mal solo nutzt)
    if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
        ).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
        throw "Reset-WindowsUpdateComponents muss als Administrator ausgeführt werden."
    }

    $sd  = Join-Path $env:SystemRoot "SoftwareDistribution"
    $sdO = "$sd.old"

    $cr  = Join-Path $env:SystemRoot "System32\catroot2"
    $crO = "$cr.old"

    # Falls .old bereits existiert -> optional Timestamp
    if ($ForceRename) {
        if (Test-Path $sdO) { $sdO = "$sd.old.$(Get-Date -Format 'yyyyMMdd_HHmmss')" }
        if (Test-Path $crO) { $crO = "$cr.old.$(Get-Date -Format 'yyyyMMdd_HHmmss')" }
    }

    _Log "Stoppe Dienste: wuauserv, bits, cryptsvc, msiserver"
    foreach ($svc in @("wuauserv","bits","cryptsvc","msiserver")) {
        try {
            Stop-Service -Name $svc -Force -ErrorAction SilentlyContinue
        } catch {}
        try {
            & sc.exe stop $svc 2>$null | Out-Null
        } catch {}
    }

    Start-Sleep -Seconds 2

    _Log "Benenne Ordner um:"
    _Log " - $sd -> $sdO"
    _Log " - $cr -> $crO"

    try {
        if (Test-Path $sd) { Rename-Item -Path $sd -NewName (Split-Path $sdO -Leaf) -ErrorAction Stop }
        else { _Log "Hinweis: $sd nicht gefunden (ok)." }
    } catch {
        _Log "WARN: Konnte $sd nicht umbenennen: $($_.Exception.Message)"
    }

    try {
        if (Test-Path $cr) { Rename-Item -Path $cr -NewName (Split-Path $crO -Leaf) -ErrorAction Stop }
        else { _Log "Hinweis: $cr nicht gefunden (ok)." }
    } catch {
        _Log "WARN: Konnte $cr nicht umbenennen: $($_.Exception.Message)"
    }

    _Log "Starte Dienste: msiserver, cryptsvc, bits, wuauserv"
    foreach ($svc in @("msiserver","cryptsvc","bits","wuauserv")) {
        try { Start-Service -Name $svc -ErrorAction SilentlyContinue } catch {}
        try { & sc.exe start $svc 2>$null | Out-Null } catch {}
    }

    _Log "WU-Reset abgeschlossen."
}

function Get-7ZipPath {
    # Passe ggf. deine Pfade an (oder lass es so + installiere 7-Zip)
    $candidates = @(
        "C:\Program Files\7-Zip\7z.exe",
        "C:\Program Files (x86)\7-Zip\7z.exe",
        "D:\Datein\Skripte\7zr.exe"
    )
    foreach ($p in $candidates) { if (Test-Path $p) { return $p } }
    return $null
}

function Test-ExtractedInf {
    param([Parameter(Mandatory)][string]$Folder)
    try {
        $inf = Get-ChildItem -Path $Folder -Recurse -Filter *.inf -File -ErrorAction SilentlyContinue | Select-Object -First 1
        return [bool]$inf
    } catch { return $false }
}

function Install-DriversFromFolder {
    param(
        [Parameter(Mandatory)][string]$Folder,
        [string]$LogFile = "C:\Temp\pnputil-install.log"
    )

    if (-not (Test-Path $Folder)) { throw "Folder not found: $Folder" }
    $logDir = Split-Path -Parent $LogFile
    if ($logDir -and -not (Test-Path $logDir)) { New-Item -ItemType Directory -Path $logDir -Force | Out-Null }

    $cmd = "pnputil /add-driver `"$Folder\*.inf`" /subdirs /install"
    $out = & cmd.exe /c $cmd 2>&1
    $out | Out-File -FilePath $LogFile -Encoding UTF8
    return $out
}

function Try-ExtractDriverPackage {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$SourceExe,
        [Parameter(Mandatory)][string]$DestFolder,
        [string]$LogFile = "C:\Temp\driver-extract.log"
    )

    $null = New-Item -ItemType Directory -Path $DestFolder -Force -ErrorAction SilentlyContinue

    function Log([string]$msg) {
        $ts = (Get-Date).ToString("s")
        $line = "[$ts] [DRV-EXTRACT] $msg"
        Write-HostLog $line -ForegroundColor Gray
        Add-Content -Encoding UTF8 -Path $LogFile -Value $line
    }

    Log "=== Extract Start: $SourceExe -> $DestFolder ==="

    # 1) 7-Zip zuerst (beste Quote)
    $seven = Get-7ZipPath
    if ($seven) {
        try {
            Log "Try 7z: $seven x -y -o`"$DestFolder`" `"$SourceExe`""
            $p = Start-Process -FilePath $seven -ArgumentList @("x","-y","-o$DestFolder",$SourceExe) -Wait -PassThru -WindowStyle Hidden -ErrorAction Stop
            Log "7z ExitCode=$($p.ExitCode)"

            if (Test-ExtractedInf -Folder $DestFolder) {
                Log "INF found after 7z extraction."
                return [pscustomobject]@{ Success=$true; Method="7z"; ExitCode=$p.ExitCode; Dest=$DestFolder }
            }
        } catch {
            Log "7z failed: $($_.Exception.Message)"
        }
    } else {
        Log "7z not found -> skipping 7z method."
    }

    # 2) Fallback: typische Extract-Schalter (best effort)
    $argCandidates = @(
        "/extract `"$DestFolder`" /quiet",
        "/extract=`"$DestFolder`" /quiet",
        "/S /E=`"$DestFolder`"",
        "/S /E `"$DestFolder`"",
        "/S /EXTRACT=`"$DestFolder`"",
        "/S /x /b`"$DestFolder`"",
        "/s /x /b`"$DestFolder`"",
        "/a /s /v`"/qn TARGETDIR=`"$DestFolder`"`"",
        "/VERYSILENT /SUPPRESSMSGBOXES /NORESTART /DIR=`"$DestFolder`""
    ) | Select-Object -Unique

    foreach ($args in $argCandidates) {
        try {
            Log "Try args: `"$SourceExe`" $args"
            $p = Start-Process -FilePath $SourceExe -ArgumentList $args -Wait -PassThru -WindowStyle Hidden -ErrorAction Stop
            Log "ExitCode=$($p.ExitCode) args=$args"

            if (Test-ExtractedInf -Folder $DestFolder) {
                Log "INF found in dest."
                return [pscustomobject]@{ Success=$true; Method="Args"; ExitCode=$p.ExitCode; Dest=$DestFolder; Args=$args }
            }
        } catch {
            Log "Args failed ($args): $($_.Exception.Message)"
        }
    }

    Log "=== Extract FAILED ==="
    return [pscustomobject]@{ Success=$false; Method="None"; ExitCode=$null; Dest=$DestFolder }
}

function Invoke-DriverPackageWorkflow {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$SourceFolder,    # Ordner mit Downloads
        [Parameter(Mandatory)][string]$TargetFolder,    # Zielordner
        [ValidateSet("ExtractOnly","ExtractAndInstall","InstallOnly")][string]$Mode = "ExtractAndInstall",
        [string]$LogFile = (Join-Path $Global:LogPath "TreiberEntpacken.log")
    )

    if (-not (Test-Path $SourceFolder)) { throw "SourceFolder not found: $SourceFolder" }
    $null = New-Item -ItemType Directory -Path $TargetFolder -Force -ErrorAction SilentlyContinue

    $logDir = Split-Path -Parent $LogFile
    if ($logDir -and -not (Test-Path $logDir)) { New-Item -ItemType Directory -Path $logDir -Force | Out-Null }

    Add-Content -Encoding UTF8 $LogFile ("`n=== DriverWorkflow Start {0} | Mode={1} ===" -f (Get-Date), $Mode)

    $files = Get-ChildItem -Path $SourceFolder -File -ErrorAction SilentlyContinue |
             Where-Object { $_.Extension -in ".exe",".msi",".zip",".cab" } |
             Sort-Object LastWriteTime -Descending

    if (-not $files) {
        Write-Warning "Keine .exe/.msi/.zip/.cab im SourceFolder gefunden: $SourceFolder"
        return
    }

    foreach ($f in $files) {
        Write-HostLog "`n--- Paket: $($f.Name) ---" -ForegroundColor Cyan
        Add-Content -Encoding UTF8 $LogFile ("[{0}] Package: {1}" -f (Get-Date -Format s), $f.FullName)

        $pkgDest = Join-Path $TargetFolder ($f.BaseName)
        $null = New-Item -ItemType Directory -Path $pkgDest -Force -ErrorAction SilentlyContinue

        if ($f.Extension -eq ".msi") {
            if ($Mode -in @("InstallOnly","ExtractAndInstall")) {
                $msiLog = Join-Path $pkgDest "msi-install.log"
                Start-Process msiexec.exe -ArgumentList "/i `"$($f.FullName)`" /qn REBOOT=ReallySuppress /L*v `"$msiLog`"" -Wait
            } else {
                Start-Process msiexec.exe -ArgumentList "/a `"$($f.FullName)`" /qn TARGETDIR=`"$pkgDest`"" -Wait
            }
            continue
        }

        if ($f.Extension -in ".zip",".cab") {
            try {
                if ($f.Extension -eq ".zip") {
                    Expand-Archive -Path $f.FullName -DestinationPath $pkgDest -Force -ErrorAction Stop
                } else {
                    & expand.exe -F:* $f.FullName $pkgDest | Out-Null
                }
            } catch {
                Write-Warning "Entpacken fehlgeschlagen: $($_.Exception.Message)"
            }

            if ($Mode -eq "ExtractAndInstall" -and (Test-ExtractedInf -Folder $pkgDest)) {
                $pnplog = Join-Path $pkgDest "pnputil-install.log"
                Install-DriversFromFolder -Folder $pkgDest -LogFile $pnplog | Out-Null
            }
            continue
        }

        # EXE
        if ($Mode -eq "InstallOnly") {
            # simple silent-try
            $silentArgs = @('/S','/silent','/verysilent','/quiet','/passive','/s /v"/qn REBOOT=ReallySuppress"')
            foreach ($a in $silentArgs) {
                try {
                    Write-HostLog "Try install: $a" -ForegroundColor Gray
                    $p = Start-Process -FilePath $f.FullName -ArgumentList $a -Wait -PassThru -WindowStyle Hidden
                    if ($p.ExitCode -in 0,1641,3010) { break }
                } catch {}
            }
            continue
        }

        $res = Try-ExtractDriverPackage -SourceExe $f.FullName -DestFolder $pkgDest -LogFile $LogFile
        if (-not $res.Success) {
            Write-Warning "Extraktion fehlgeschlagen: $($f.Name)"
            continue
        }

        if ($Mode -eq "ExtractAndInstall") {
            if (Test-ExtractedInf -Folder $pkgDest) {
                $pnplog = Join-Path $pkgDest "pnputil-install.log"
                Install-DriversFromFolder -Folder $pkgDest -LogFile $pnplog | Out-Null
                Write-HostLog "pnputil Install: OK" -ForegroundColor Green
            } else {
                Write-Warning "Extrahiert, aber keine INF gefunden: $pkgDest"
            }
        }
    }

    Add-Content -Encoding UTF8 $LogFile ("=== DriverWorkflow End {0} ===" -f (Get-Date))
}

function Invoke-NativeQuiet {
    param([Parameter(Mandatory)][string]$CommandLine)

    # über cmd.exe ausführen und ALLES wegredirecten
    & cmd.exe /c "$CommandLine >nul 2>nul"
    return $LASTEXITCODE
}

#endregion

#region Gemeinsamer Ablauf fuer Desktop-Geraete & Laptops
function Setup-BaseSystem {
    param(
        [Parameter(Mandatory)][string]$Name,
        [string]$HWId,
        [string]$TID,
        [switch]$MitTreibern
    )
	$logFile = Join-Path $Global:LogPath "$Name.log"
	# Session auf $Name umstellen (damit Haupt-/Teil-Logs konsistent sind)
	Switch-ToNamedMainLog -Name $Name
	$script:LOG = $logFile
    $current = $env:COMPUTERNAME
	# Altes Log loeschen
	# Log NICHT löschen – immer anhängen (append-only)
	Initialize-LogFile -Path $logFile
	Write-Log -Message "=== SCRIPT START: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') ===" -Level INFO -Path $logFile

	# Transcript starten

	# Live-Log-Job starten
	$job = Start-Job -ScriptBlock {
		param($file)
		Write-HostLog "[LIVE] Live-Log gestartet fuer $file ..." -ForegroundColor Yellow
		Get-Content -Path $file -Wait
	} -ArgumentList $logFile
    

    # 1. Rechnername & Kommentar
	if ($current -ne $Name) {
		Rename-Computer -NewName $Name -Force -ErrorAction Stop
	}
    reg add HKLM\SYSTEM\CurrentControlSet\Services\lanmanserver\parameters /v srvcomment /d "$Name" /f | Out-Null

    # 2. Treiber installieren
	$drvFolder = Resolve-DriverFolder
	if ($drvFolder) {
		$drvLog = Join-Path $Global:LogPath "$Name-Treiber.log"
		Install-Treiber -Pfad $drvFolder -LogDatei $drvLog
	} else {
		Write-Warning "[WARN] Kein passender Treiber-Ordner gefunden (Resolve-DriverFolder)."
	}


    # 3. Firewall & IPv6
    Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False
    Disable-NetAdapterBinding -Name Ethernet -ComponentID ms_tcpip6 -PassThru -ErrorAction SilentlyContinue | Out-Null

    # 4. Drucker entfernen
    Drucker

    # 5. Fonts
    Fonts

    # 6. Layout-Datei
    if (Test-Path $Global:LayoutXml) {
        Copy-Item $Global:LayoutXml "C:\Users\Default\AppData\Local\Microsoft\Windows\Shell" -Force
    }

    # 7. Netzwerk und Energiesparplan
    Netzwerk
    Energiesparplan

    # 8. Wiederherstellungspunkt
    Configure-RestorePoint
    # 9. Benutzer (aktuellen interaktiv angemeldeten Benutzer nach Logoff per Task entfernen)
    net user Administrator /active:yes | Out-Null
    net user Administrator $script:AdminPassword | Out-Null

    $cleanupResult = Invoke-UserCleanupWithLogoff
    if ($cleanupResult) {
        $script:UserCleanupActive = $true
    }

# 10. Logdatei schreiben
    $macs = Get-MacAddresses
@"
PC :          $Name

Mainboard: $(Get-MBShort)

HardwareID :  $HWId
TicketID :    $TID

$macs
"@ | Out-File (Join-Path $Global:LogPath "$Name.txt")

    # 11. Abschluss - Cleanup mit zentraler Helper-Funktion
    Stop-SessionCleanup -Job $job
}

function Setup-NUC {
    param(
        [Parameter(Mandatory)][string]$Name,
        [string]$HWId,
        [string]$TID,
        [Parameter(Mandatory)][string]$Modell,
        [ValidateSet("Bochum","Hattingen","Linden","Extern")] [string]$Standort = "Bochum"
    )

    $logFile = Join-Path $Global:LogPath "$Name.log"
    # Session auf $Name umstellen (damit Haupt-/Teil-Logs konsistent sind)
    Switch-ToNamedMainLog -Name $Name
    $script:LOG = $logFile

    # Altes Log löschen
    # Log NICHT löschen – immer anhängen (append-only)
    Initialize-LogFile -Path $logFile
    Write-Log -Message "=== SCRIPT START: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') ===" -Level INFO -Path $logFile

    # Transcript starten (alles wird live in Konsole + Datei ausgegeben)
    Write-HostLog "[LIVE] Live-Log laeuft direkt in der Konsole ..." -ForegroundColor Yellow

    # 1. Rechnername setzen
    $current = $env:COMPUTERNAME

    if ($current -ne $Name) {
        Rename-Computer -NewName $Name -Force -ErrorAction Stop
    }
    reg add HKLM\SYSTEM\CurrentControlSet\Services\lanmanserver\parameters /v srvcomment /d "$Name" /f | Out-Null

    # 2. Treiber (NUC\<Modell*>)
    $folder = Get-NucFolder -Modell $Modell
    if ($folder) {
        $drvLog = Join-Path $Global:LogPath "$Name-Treiber.log"
        Install-Treiber -Pfad $folder -LogDatei $drvLog
    }

    # 3. Firewall & IPv6
    Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False
    Disable-NetAdapterBinding -Name Ethernet -ComponentID ms_tcpip6 -PassThru -ErrorAction SilentlyContinue | Out-Null

    # 4. Drucker
    Drucker

    # 5. Fonts
    Fonts

    # 6. Layout-Datei
    if (Test-Path $Global:LayoutXml) {
        Copy-Item $Global:LayoutXml "C:\Users\Default\AppData\Local\Microsoft\Windows\Shell" -Force
    }

    # 7. Netzwerk & Energiesparplan
    Netzwerk
    Energiesparplan

    # 8. WLAN-Adapter-Settings
    $wlan = Get-NetAdapter | Where-Object { $_.InterfaceDescription -match "Wireless|WLAN" -and $_.Status -eq "Up" } | Select-Object -First 1
    if ($wlan) {
        $wlanSettings = @{"Wireless Mode"="IEEE 802.11a/n/ac";"Roaming Sensitivity Level"="Middle";"Preferred Band"="Prefer 5GHz"}
        foreach ($key in $wlanSettings.Keys) {
            $prop = Get-NetAdapterAdvancedProperty -Name $wlan.Name -DisplayName $key -ErrorAction SilentlyContinue
            if ($prop) { Set-NetAdapterAdvancedProperty -Name $wlan.Name -DisplayName $key -DisplayValue $wlanSettings[$key] -ErrorAction SilentlyContinue }
        }
    }

    # 9. WLAN-Profile je nach Standort
    netsh wlan add filter permission=denyall networktype=infrastructure | Out-Null
    netsh wlan add filter permission=denyall networktype=adhoc | Out-Null
    switch ($Standort) {
        "Bochum"   { netsh wlan add filter permission=allow ssid="208" networktype=infrastructure | Out-Null; Add-WlanProfile -SSID "208" }
        "Hattingen"{ netsh wlan add filter permission=allow ssid="208" networktype=infrastructure | Out-Null; netsh wlan add filter permission=allow ssid="209" networktype=infrastructure | Out-Null; Add-WlanProfile -SSID "208"; Add-WlanProfile -SSID "209" }
        "Linden"   { netsh wlan add filter permission=allow ssid="208" networktype=infrastructure | Out-Null; netsh wlan add filter permission=allow ssid="210" networktype=infrastructure | Out-Null; Add-WlanProfile -SSID "208"; Add-WlanProfile -SSID "210" }
        "Extern"   { netsh wlan add filter permission=block ssid="201" networktype=infrastructure | Out-Null; netsh wlan add filter permission=block ssid="205" networktype=infrastructure | Out-Null; netsh wlan add filter permission=block ssid="208" networktype=infrastructure | Out-Null; netsh wlan add filter permission=block ssid="209" networktype=infrastructure | Out-Null; netsh wlan add filter permission=block ssid="210" networktype=infrastructure | Out-Null; netsh wlan add filter permission=block ssid="medtech" networktype=infrastructure | Out-Null; netsh wlan add filter permission=block ssid="medtech_hat" networktype=infrastructure | Out-Null; netsh wlan add filter permission=block ssid="telemetrie" networktype=infrastructure | Out-Null; netsh wlan add filter permission=block ssid="spotmessung" networktype=infrastructure | Out-Null; netsh wlan add filter permission=block ssid="motara" networktype=infrastructure | Out-Null; netsh wlan add filter permission=block ssid="mortara" networktype=infrastructure | Out-Null; netsh wlan add filter permission=block ssid="swisslog" networktype=infrastructure | Out-Null; netsh wlan add filter permission=block ssid="ExtConf" networktype=infrastructure | Out-Null; netsh wlan add filter permission=block ssid="akademie-wlan" networktype=infrastructure | Out-Null; Add-WlanProfile -SSID "IInternet" }
    }

    # 10. Wiederherstellungspunkt
    Configure-RestorePoint

    # 11. Benutzer
    net user Administrator /active:yes | Out-Null
    net user Administrator $script:AdminPassword | Out-Null

    $cleanupResult = Invoke-UserCleanupWithLogoff
    if ($cleanupResult) {
        $script:UserCleanupActive = $true
    }

# 12. Logdatei (Zusatz)
    $macs = Get-MacAddresses
@"
PC :          $Name
Modell:       $Modell
HardwareID :  $HWId
TicketID :    $TID

$macs
"@ | Out-File (Join-Path $Global:LogPath "$Name.txt")

    # 13. Abschluss
    Stop-Transcript

    Write-HostLog "? Setup-NUC abgeschlossen." -ForegroundColor Green
}

function Setup-Laptop {
    param(
        [Parameter(Mandatory)][string]$Name,
        [string]$HWId,
        [string]$TID,
        [Parameter(Mandatory)][string]$Modell,
        [ValidateSet("Bochum","Hattingen","Linden")] [string]$Standort = "Bochum"
    )
	$logFile = Join-Path $Global:LogPath "$Name.log"
	# Session auf $Name umstellen (damit Haupt-/Teil-Logs konsistent sind)
	Switch-ToNamedMainLog -Name $Name
	$script:LOG = $logFile

	# Altes Log loeschen
	# Log NICHT löschen – immer anhängen (append-only)
	Initialize-LogFile -Path $logFile
	Write-Log -Message "=== SCRIPT START: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') ===" -Level INFO -Path $logFile

	# Transcript starten

	# Live-Log-Job starten
	$job = Start-Job -ScriptBlock {
		param($file)
		Write-HostLog "[LIVE] Live-Log gestartet fuer $file ..." -ForegroundColor Yellow
		Get-Content -Path $file -Wait
	} -ArgumentList $logFile
    
    $current = $env:COMPUTERNAME

    # 1. Rechnername & Kommentar
	if ($current -ne $Name) {
		Rename-Computer -NewName $Name -Force -ErrorAction Stop
	}
    reg add HKLM\SYSTEM\CurrentControlSet\Services\lanmanserver\parameters /v srvcomment /d "$Name" /f | Out-Null

    # 2. Treiber (Notebook\<Hersteller>\<Modell*>)
    $vendor = Get-Manufacturer
    $root = Join-Path $Global:TreiberNotebookPath ("$vendor")
    if (-not (Test-Path $root)) { $root = $Global:TreiberNotebookPath }
    $folder = Get-ChildItem -Path $root -Directory -ErrorAction SilentlyContinue | Where-Object { $_.Name -like "$Modell*" } | Select-Object -First 1
    $folder = Get-LaptopFolder -Modell $Modell
	if ($folder) {
		$drvLog = Join-Path $Global:LogPath "$Name-Treiber.log"
		Install-Treiber -Pfad $folder -LogDatei $drvLog
	}


    # 3. Firewall & IPv6
    Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False
    Disable-NetAdapterBinding -Name Ethernet -ComponentID ms_tcpip6 -PassThru -ErrorAction SilentlyContinue | Out-Null
    Disable-NetAdapterBinding -Name WLAN -ComponentID ms_tcpip6 -PassThru -ErrorAction SilentlyContinue | Out-Null

    # 4. Drucker
    Drucker

    # 5. Fonts
    Fonts

    # 6. Layout-Datei
    if (Test-Path $Global:LayoutXml) {
        Copy-Item $Global:LayoutXml "C:\Users\Default\AppData\Local\Microsoft\Windows\Shell" -Force
    }

    # 7. Netzwerk & Energiesparplan
    Netzwerk
    Energiesparplan

    # 8. WLAN-Adapter-Settings
    $wlan = Get-NetAdapter | Where-Object { $_.InterfaceDescription -match "Wireless|WLAN" -and $_.Status -eq "Up" } | Select-Object -First 1
    if ($wlan) {
        $wlanSettings = @{"Wireless Mode"="IEEE 802.11a/n/ac";"Roaming Sensitivity Level"="Middle";"Preferred Band"="Prefer 5GHz"}
        foreach ($key in $wlanSettings.Keys) {
            $prop = Get-NetAdapterAdvancedProperty -Name $wlan.Name -DisplayName $key -ErrorAction SilentlyContinue
            if ($prop) { Set-NetAdapterAdvancedProperty -Name $wlan.Name -DisplayName $key -DisplayValue $wlanSettings[$key] -ErrorAction SilentlyContinue }
        }
    }

    # 9. WLAN-Profile je nach Standort
    netsh wlan add filter permission=denyall networktype=infrastructure | Out-Null
    netsh wlan add filter permission=denyall networktype=adhoc | Out-Null
    switch ($Standort) {
        "Bochum"   { netsh wlan add filter permission=allow ssid="208" networktype=infrastructure | Out-Null; Add-WlanProfile -SSID "208" }
        "Hattingen"{ netsh wlan add filter permission=allow ssid="208" networktype=infrastructure | Out-Null; netsh wlan add filter permission=allow ssid="209" networktype=infrastructure | Out-Null; Add-WlanProfile -SSID "208"; Add-WlanProfile -SSID "209" }
        "Linden"   { netsh wlan add filter permission=allow ssid="208" networktype=infrastructure | Out-Null; netsh wlan add filter permission=allow ssid="210" networktype=infrastructure | Out-Null; Add-WlanProfile -SSID "208"; Add-WlanProfile -SSID "210" }
    }

    # 10. Wiederherstellungspunkt
    Configure-RestorePoint

    # 11. Benutzer
    net user Administrator /active:yes | Out-Null
    net user Administrator $script:AdminPassword | Out-Null

    $cleanupResult = Invoke-UserCleanupWithLogoff
    if ($cleanupResult) {
        $script:UserCleanupActive = $true
    }

# 12. Logdatei
    $macs = Get-MacAddresses
@"
PC :          $Name

Mainboard: $(Get-MBShort)

HardwareID :  $HWId
TicketID :    $TID

$macs
"@ | Out-File (Join-Path $Global:LogPath "$Name.txt")

    # 13. Abschluss - Cleanup mit zentraler Helper-Funktion
    Stop-SessionCleanup -Job $job
}

function Setup-VPN {
    param(
        [Parameter(Mandatory)][string]$Name,
        [string]$HWId,
        [string]$TID,
        [Parameter(Mandatory)][string]$Modell,
        [Parameter(Mandatory)][SecureString]$VpnPasswort
    )
	$logFile = Join-Path $Global:LogPath "$Name.log"
	# Session auf $Name umstellen (damit Haupt-/Teil-Logs konsistent sind)
	Switch-ToNamedMainLog -Name $Name
	$script:LOG = $logFile

	# Altes Log loeschen
	# Log NICHT löschen – immer anhängen (append-only)
	Initialize-LogFile -Path $logFile
	Write-Log -Message "=== SCRIPT START: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') ===" -Level INFO -Path $logFile

	# Transcript starten

	# Live-Log-Job starten
	$job = Start-Job -ScriptBlock {
		param($file)
		Write-HostLog "[LIVE] Live-Log gestartet fuer $file ..." -ForegroundColor Yellow
		Get-Content -Path $file -Wait
	} -ArgumentList $logFile

    # 1. Rechnername
    $current = $env:COMPUTERNAME
	if ($current -ne $Name) {
		Rename-Computer -NewName $Name -Force -ErrorAction Stop
	}
    reg add HKLM\SYSTEM\CurrentControlSet\Services\lanmanserver\parameters /v srvcomment /d "$Name" /f | Out-Null

    # ==========================================================
    # 2) UAC- und Datenschutz-Policies (Registry-Pfade automatisch anlegen)
    # ==========================================================
    try {
        # Pfad zu den System-Policies
        $path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"

        # Pr?fen, ob Pfad existiert & wenn nicht, per reg.exe manuell anlegen (funktioniert auch, wenn PowerShell blockiert)
        if (-not (Test-Path $path)) {
            Write-HostLog "[INFO] Registry-Pfad fehlt, wird angelegt: $path" -ForegroundColor Yellow
            Start-Process -FilePath "reg.exe" -ArgumentList 'add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /f' -Verb RunAs -Wait
        }

        # Wenn der Pfad jetzt existiert, fortfahren
        if (Test-Path $path) {
            New-ItemProperty -Path $path -Name 'ConsentPromptBehaviorAdmin'  -Value 4 -PropertyType DWORD -Force | Out-Null
            New-ItemProperty -Path $path -Name 'ConsentPromptBehaviorUser'   -Value 1 -PropertyType DWORD -Force | Out-Null
            New-ItemProperty -Path $path -Name 'EnableInstallerDetection'    -Value 1 -PropertyType DWORD -Force | Out-Null
            New-ItemProperty -Path $path -Name 'EnableLUA'                   -Value 1 -PropertyType DWORD -Force | Out-Null
            New-ItemProperty -Path $path -Name 'EnableVirtualization'        -Value 1 -PropertyType DWORD -Force | Out-Null
            New-ItemProperty -Path $path -Name 'PromptOnSecureDesktop'       -Value 0 -PropertyType DWORD -Force | Out-Null
            New-ItemProperty -Path $path -Name 'ValidateAdminCodeSignatures' -Value 1 -PropertyType DWORD -Force | Out-Null
            New-ItemProperty -Path $path -Name 'FilterAdministratorToken'    -Value 1 -PropertyType DWORD -Force | Out-Null
        } else {
            Write-Warning "? Der Pfad $path konnte nicht angelegt werden. Bitte PowerShell als Administrator ausführen."
        }

        # Datenschutz-Policies (App-Zugriff Kamera/Mikrofon)
        $appPriv = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy"
        if (-not (Test-Path $appPriv)) {
            Write-HostLog "[INFO] Lege Registry-Pfad an: $appPriv" -ForegroundColor Yellow
            Start-Process -FilePath "reg.exe" -ArgumentList 'add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /f' -Verb RunAs -Wait
        }

        if (Test-Path $appPriv) {
            New-ItemProperty -Path $appPriv -Name 'LetAppsAccessCamera'    -Value 0 -PropertyType DWORD -Force | Out-Null
            New-ItemProperty -Path $appPriv -Name 'LetAppsAccessMicrophone' -Value 0 -PropertyType DWORD -Force | Out-Null
        } else {
            Write-Warning "? Der Pfad $appPriv konnte nicht angelegt werden. Bitte PowerShell als Administrator ausführen."
        }

        Write-HostLog "? Registry-Policies erfolgreich gesetzt." -ForegroundColor Green
    }
    catch {
        Write-Warning "[ERROR] Fehler beim Setzen der Policies: $($_.Exception.Message)"
    }


    # 3. Treiber
    $vendor = Get-Manufacturer
    $root = Join-Path $Global:TreiberNotebookPath ("$vendor")
    if (-not (Test-Path $root)) { $root = $Global:TreiberNotebookPath }
    $folder = Get-LaptopFolder -Modell $Modell
	if ($folder) {
		$drvLog = Join-Path $Global:LogPath "$Name-Treiber.log"
		Install-Treiber -Pfad $folder -LogDatei $drvLog
	}

    # 4. Drucker
    Drucker

    # 5. Energiesparplan
    Energiesparplan
	
    # ==========================================================
    # 6) AVK Client + G DATA Agent installieren (silent, ohne Neustart)
    # ==========================================================
    try {
        # Pfade vorbereiten
        $avkReg = Join-Path $Global:BaseFilePath "AVKCLIENT.reg"
        $agent  = Join-Path $Global:ProgramPath "__windowsfullagent.exe"

        # ----------------------------------------------------------
        # 6.1) AVK Registry-Import still (ohne Nachfrage)
        # ----------------------------------------------------------
        if (Test-Path $avkReg) {
            Write-HostLog "[INFO] Importiere AVKCLIENT.reg..." -ForegroundColor Yellow
            Start-Process -FilePath "reg.exe" -ArgumentList "import `"$avkReg`"" -Wait -WindowStyle Hidden
            Write-HostLog "? AVKCLIENT.reg erfolgreich importiert." -ForegroundColor Green
        } else {
            Write-Warning "? AVKCLIENT.reg nicht gefunden unter $avkReg"
        }

        # ----------------------------------------------------------
        # 6.2) G DATA Agent still installieren (ohne Neustart)
        # ----------------------------------------------------------
        if (Test-Path $agent) {
            Write-HostLog "[INFO] Installiere G DATA Agent (__windowsfullagent.exe)..." -ForegroundColor Yellow

            # Silent-Parameter für G DATA-Installationen
            # /VERYSILENT           -> keine Benutzeroberfl?che
            # /NORESTART            -> kein automatischer Neustart
            # /SUPPRESSMSGBOXES     -> unterdr?ckt Messageboxen
            # /FORCECLOSEAPPLICATIONS -> beendet ggf. laufende Anwendungen
            # /LOG="Pfad"           -> optionales Logfile
            $logFileGD = Join-Path $Global:LogPath "GDATA-Agent-Install.log"
            $silentArgs = "/VERYSILENT /NORESTART /SUPPRESSMSGBOXES /FORCECLOSEAPPLICATIONS /LOG=`"$logFileGD`""

            # Prozess still und wartend starten
            $process = Start-Process -FilePath $agent -ArgumentList $silentArgs -Wait -PassThru -WindowStyle Hidden

            # Exitcode pr?fen
            if ($process.ExitCode -eq 0) {
                Write-HostLog "? G DATA Agent wurde erfolgreich still installiert (kein Neustart)." -ForegroundColor Green
            } else {
                Write-Warning "[WARN] G DATA Agent-Installer meldete ExitCode $($process.ExitCode). Siehe Log: $logFileGD"
            }
        } else {
            Write-Warning "? G DATA Agent Setup nicht gefunden unter $agent"
        }
    }
    catch {
        Write-Warning "[ERROR] Fehler beim Installieren von AVK/G DATA: $($_.Exception.Message)"
    }

    # 7. WLAN-Adapter Settings
    $adapter = (Get-NetAdapter -Name "WLAN" -ErrorAction SilentlyContinue)
    if (-not $adapter) { $adapter = Get-NetAdapter | Where-Object {$_.InterfaceDescription -match "Wireless|WLAN"} | Select-Object -First 1 }
    if ($adapter) {
        $wlanSettings = @{"Wireless Mode"="IEEE 802.11a/n/ac";"Roaming Sensitivity Level"="Middle";"Preferred Band"="Prefer 5GHz"}
        foreach ($key in $wlanSettings.Keys) {
            $prop = Get-NetAdapterAdvancedProperty -Name $adapter.Name -DisplayName $key -ErrorAction SilentlyContinue
            if ($prop) { Set-NetAdapterAdvancedProperty -Name $adapter.Name -DisplayName $key -DisplayValue $wlanSettings[$key] -NoRestart -ErrorAction SilentlyContinue }
        }
    }

    # 8. Firewall & IPv6
    Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False
    Disable-NetAdapterBinding -Name Ethernet -ComponentID ms_tcpip6 -PassThru -ErrorAction SilentlyContinue | Out-Null
    Disable-NetAdapterBinding -Name WLAN    -ComponentID ms_tcpip6 -PassThru -ErrorAction SilentlyContinue | Out-Null

    # 9. SSIDs blocken + Profil
    foreach ($ssid in @("201","205","208","209","210","medtech","medtech_hat","telemetrie","spotmessung","motara","mortara","swisslog","ExtConf","akademie-wlan")) {
        netsh wlan add filter permission=block ssid=$ssid networktype=infrastructure | Out-Null
    }
    Add-WlanProfile -SSID "IInternet"

    # 10. Cleanup
    UninstallWinProg

    # 10a. Windows aktivieren (MAK) & immer versuchen bei VPN-Setups
	$actOk = $false
	try {
		$actOk = Activate-WindowsFromMak -Name $Name
	} catch {
		Write-Warning "Windows-Aktivierung: Exception: $($_.Exception.Message)"
	}

	# Direkt nachprüfen (GUI kann cachen -> wir prüfen maschinenlesbar)
	try {
		$lic = Get-CimInstance SoftwareLicensingProduct -Filter "PartialProductKey is not null" -ErrorAction SilentlyContinue |
			   Where-Object { $_.ApplicationID -eq '55c92734-d682-4d71-983e-d6ec3f16059f' } |
			   Sort-Object LicenseStatus -Descending |
			   Select-Object -First 1

		if ($lic -and $lic.LicenseStatus -eq 1) {
			Write-HostLog "? Windows ist aktiviert (LicenseStatus=1)" -ForegroundColor Green
			$actOk = $true
		} else {
			Write-Warning "Windows ist NICHT aktiviert (LicenseStatus=$($lic.LicenseStatus)). Siehe Activation-Log im LogPath."
		}
	} catch {
		Write-Warning "Konnte LicenseStatus nicht lesen: $($_.Exception.Message)"
	}

	# Optional: Wenn Aktivierung fehlschlägt, einmal sppsvc neu starten (hilft manchmal)
	if (-not $actOk) {
		try {
			Write-Warning "Versuche sppsvc Restart und nochmal /ato..."
			Restart-Service sppsvc -Force -ErrorAction SilentlyContinue
			$slmgr = Join-Path $env:windir "system32\slmgr.vbs"
			& cmd.exe /c "cscript.exe //nologo `"$slmgr`" /ato" 2>&1 | Out-Null
		} catch {}
	}


    # 11. Benutzer
    net user Administrator /active:yes | Out-Null
    net user Administrator $script:AdminPassword | Out-Null
    try {
        New-LocalUser -Name $Name -Password $VpnPasswort -FullName $Name -Description "VPN-User" -PasswordNeverExpires:$true -UserMayNotChangePassword:$true | Out-Null
        Add-LocalGroupMember -Group "Benutzer" -Member $Name | Out-Null
    } catch { Write-Warning "Konnte VPN-User nicht anlegen: $_" }

    $cleanupResult = Invoke-UserCleanupWithLogoff
    if ($cleanupResult) {
        $script:UserCleanupActive = $true
    }

# 12. Logdatei
    $macs = Get-MacAddresses
@"
PC :          $Name

Mainboard: $(Get-MBShort)

HardwareID :  $HWId
TicketID :    $TID

$macs
"@ | Out-File (Join-Path $Global:LogPath "$Name.txt")

	# ==========================================================
	# 13) Fix für OOBE / Erstanmeldung (OOBSETTINGSMULTIPAGE)
	# ==========================================================
	try {
		Write-HostLog "[INFO] Setze OOBE- und Erstlogin-Parameter korrekt..." -ForegroundColor Yellow

		# Sicherstellen, dass UAC aktiv bleibt, aber OOBE-Setup nicht blockiert
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -Value 1 -Force
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Value 5 -Force
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "PromptOnSecureDesktop" -Value 1 -Force

		# Aktiviert den OOBE-Dienst, falls er deaktiviert wurde
		sc.exe config "wlidsvc" start= demand | Out-Null  # Microsoft Account Anmeldung
		sc.exe config "tiledatamodelsvc" start= demand | Out-Null  # App-Registrierung
		sc.exe config "UserManager" start= auto | Out-Null
		sc.exe config "StateRepository" start= auto | Out-Null

		# Optional: Telemetrie & Standortdienste auf Standard
		reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Privacy" /v "OemPrivacySettings" /t REG_DWORD /d 0 /f | Out-Null
		reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "AllowLocation" /t REG_DWORD /d 1 /f | Out-Null

		Write-HostLog "? OOBE- und Datenschutzdienste korrigiert. Administrator-Login wird fehlerfrei funktionieren." -ForegroundColor Green
	}
	catch {
		Write-Warning "[ERROR] Konnte OOBE-Fix nicht anwenden: $($_.Exception.Message)"
	}
		
    # 14. Abschluss - Cleanup mit zentraler Helper-Funktion
    Stop-SessionCleanup -Job $job
}

function Setup-Einstellen {
    param(
        [string]$Name,
        [string]$HWId,
        [string]$TID,
        [ValidateSet("Rechner","Laptop","NUC","VPN","Baaske","ImportRechner")]
        [string]$Geraetetyp,
        [string]$Modell,
        [ValidateSet("Bochum","Hattingen","Linden","Extern")]
        [string]$Standort
    )
    $current = $env:COMPUTERNAME
    # --- Grunddaten abfragen (nur falls nicht schon ?bergeben) ---
    if (-not $Geraetetyp) {
        $map = @{
            '1'='Rechner'; '2'='NUC'; '3'='Baaske'; '4'='Laptop'; '5'='ImportRechner'; '6'='VPN'
        }
        $sel = Read-Host "Für welches Ger?t Einstellungen vornehmen? (1=Rechner, 2=NUC, 3=Baaske, 4=Laptop, 5=ImportRechner, 6=VPN)"
        $Geraetetyp = $map[$sel]; if (-not $Geraetetyp) { Write-Warning "Ungültige Auswahl."; return }
    }

    if ($Geraetetyp -in @('Laptop','VPN','NUC') -and (-not $Modell)) {
        $Modell = Read-Host "Modell-Reihe (z.B. UN62, NUC11TNHi3, V15 IIL, V15 G4 AMN)"
    }
    if ($Geraetetyp -in @('Laptop','NUC') -and (-not $Standort)) {
        $Standort = Read-Host "Standort (Bochum / Hattingen / Linden / Extern)"
        if (-not $Standort) { $Standort = "Bochum" }
    }

    # --- Logging wie bei den Setups ---
    $logFile = Join-Path $Global:LogPath "$Name-Einstellen.log"
    # Log NICHT löschen – immer anhängen (append-only)
    Initialize-LogFile -Path $logFile
    Write-Log -Message "=== SCRIPT START: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') ===" -Level INFO -Path $logFile

    Write-HostLog "`n>>> Einstellen-Modus für $Geraetetyp gestartet." -ForegroundColor Cyan

    # ---- 1) Rechnername & Kommentar -----------------------------------------
    if (Ask-YesNo "Rechner umbenennen und Serverkommentar setzen?" -DefaultYes) {
        $current = $env:COMPUTERNAME
        if ($current -ne $Name -and $Name) {
            try { Rename-Computer -NewName $Name -Force -ErrorAction Stop; Write-Host "Rechnername -> $Name" -ForegroundColor Green }
            catch { Write-Warning "Rename-Computer fehlgeschlagen: $_" }
        }
        try { reg add HKLM\SYSTEM\CurrentControlSet\Services\lanmanserver\parameters /v srvcomment /d "$Name" /f | Out-Null } catch {}
    }

    # ---- 2) Treiberinstallation ---------------------------------------------
    if (Ask-YesNo "Treiber installieren?" -DefaultYes) {
        $drvLog = Join-Path $Global:LogPath "$Name-Treiber.log"
        switch ($Geraetetyp) {
            'Rechner' { $drvFolder = Resolve-DriverFolder; if ($drvFolder) { Install-Treiber -Pfad $drvFolder -LogDatei $drvLog } else { Write-Warning "Kein Treiber-Ordner gefunden (Resolve-DriverFolder)." } }
            'Baaske'  { $drvFolder = Resolve-DriverFolder; if ($drvFolder) { Install-Treiber -Pfad $drvFolder -LogDatei $drvLog } else { Write-Warning "Kein Treiber-Ordner gefunden (Resolve-DriverFolder)." } }
            'ImportRechner' { Write-Host "ImportRechner: Treiberinstallation i. d. R. ?bersprungen." -ForegroundColor Yellow }
            default   {
                $folder = $null
                if ($Modell) { $folder = switch ($Geraetetyp) {
                    'Laptop' { Get-LaptopFolder -Modell $Modell }
                    'NUC'    { Get-NucFolder    -Modell $Modell }
                    'VPN'    { Get-LaptopFolder -Modell $Modell }
                } }
                if ($folder) { Install-Treiber -Pfad $folder -LogDatei $drvLog } else { Write-Warning "Kein passender Treiberordner gefunden." }
            }
        }
    }

    # ---- 3) Firewall deaktivieren & IPv6 binden? ----------------------------
    if (Ask-YesNo "Firewall (alle Profile) deaktivieren und IPv6 an NIC(s) deaktivieren?" ) {
        try { Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False } catch {}
        try { Disable-NetAdapterBinding -Name Ethernet -ComponentID ms_tcpip6 -PassThru -ErrorAction SilentlyContinue | Out-Null } catch {}
        if ($Geraetetyp -in @('Laptop','NUC','VPN')) {
            try { Disable-NetAdapterBinding -Name WLAN -ComponentID ms_tcpip6 -PassThru -ErrorAction SilentlyContinue | Out-Null } catch {}
        }
    }

    # ---- 4) Drucker entfernen (Microsoft Print to PDF) ----------------------
    if (Ask-YesNo "Standarddrucker 'Microsoft Print to PDF' entfernen?") { Drucker }

    # ---- 5) Fonts installieren ----------------------------------------------
    if (Ask-YesNo "Fonts aus $Global:FontsPath installieren?") { Fonts }

    # ---- 6) Layout-Datei kopieren -------------------------------------------
    if (Ask-YesNo "LayoutModification.xml nach Default-Profil kopieren?") {
        if (Test-Path $Global:LayoutXml) {
            Copy-Item $Global:LayoutXml "C:\Users\Default\AppData\Local\Microsoft\Windows\Shell" -Force
        } else { Write-Warning "Layout-XML nicht gefunden: $Global:LayoutXml" }
    }

    # ---- 7) Netzwerk- und Energieeinstellungen ------------------------------
    if (Ask-YesNo "Netzwerk (Energiemgmt Registry) anwenden?") { Netzwerk }
    if (Ask-YesNo "Energiesparplan 'H?hstleistung/Ausbalanciert' + Zeitlimits deaktivieren?" -DefaultYes) { Energiesparplan }
    if (Ask-YesNo "Wake-on-LAN konfigurieren?") { WakeonLan }

    # ---- 8) WLAN-Adapter-Feintuning (sofern vorhanden) ----------------------
    if ($Geraetetyp -in @('Laptop','NUC','VPN')) {
        if (Ask-YesNo "WLAN-Adapter-Advanced-Properties (Band/Mode/Roaming) setzen?") {
            $wlan = Get-NetAdapter | Where-Object { $_.InterfaceDescription -match "Wireless|WLAN" } | Select-Object -First 1
            if ($wlan) {
                $wlanSettings = @{"Wireless Mode"="IEEE 802.11a/n/ac";"Roaming Sensitivity Level"="Middle";"Preferred Band"="Prefer 5GHz"}
                foreach ($key in $wlanSettings.Keys) {
                    $prop = Get-NetAdapterAdvancedProperty -Name $wlan.Name -DisplayName $key -ErrorAction SilentlyContinue
                    if ($prop) { Set-NetAdapterAdvancedProperty -Name $wlan.Name -DisplayName $key -DisplayValue $wlanSettings[$key] -ErrorAction SilentlyContinue }
                }
            } else { Write-Host "Kein WLAN-Adapter gefunden." -ForegroundColor Yellow }
        }
    }

    # ---- 9) WLAN-Profile/Filter nach Standort -------------------------------
    if ($Geraetetyp -in @('Laptop','NUC')) {
        if (Ask-YesNo "WLAN-Filter/Profil je Standort setzen? (SSID-Whitelist)") {
            netsh wlan add filter permission=denyall networktype=infrastructure | Out-Null
            netsh wlan add filter permission=denyall networktype=adhoc | Out-Null
            switch ($Standort) {
                "Bochum"   { netsh wlan add filter permission=allow ssid="208" networktype=infrastructure | Out-Null; Add-WlanProfile -SSID "208" }
                "Hattingen"{ netsh wlan add filter permission=allow ssid="208" networktype=infrastructure | Out-Null; netsh wlan add filter permission=allow ssid="209" networktype=infrastructure | Out-Null; Add-WlanProfile -SSID "208"; Add-WlanProfile -SSID "209" }
                "Linden"   { netsh wlan add filter permission=allow ssid="208" networktype=infrastructure | Out-Null; netsh wlan add filter permission=allow ssid="210" networktype=infrastructure | Out-Null; Add-WlanProfile -SSID "208"; Add-WlanProfile -SSID "210" }
                default    { Write-Host "Unbekannter Standort: $Standort" -ForegroundColor Yellow }
            }
        }
    }
    if ($Geraetetyp -eq 'VPN') {
        if (Ask-YesNo "VPN-Ger?t: SSIDs blocken und Profil 'IInternet' hinzuf?gen?") {
            foreach ($ssid in @("201","205","208","209","210","medtech","medtech_hat","telemetrie","spotmessung","motara","mortara","swisslog","ExtConf","akademie-wlan")) {
                netsh wlan add filter permission=block ssid=$ssid networktype=infrastructure | Out-Null
            }
            Add-WlanProfile -SSID "IInternet"
        }
    }

    # ---- 10) Wiederherstellungspunkt ----------------------------------------
    if (Ask-YesNo "Wiederherstellungspunkt konfigurieren (C: ~3%)?") { Configure-RestorePoint }

    # ---- 11) Windows-Apps/Cleanup -------------------------------------------
    if (Ask-YesNo "Windows-Bloatware/Apps bereinigen (UninstallWinProg)?" ) { UninstallWinProg }

	# ---- 12) Windows-Apps/Cleanup -------------------------------------------
	if (Ask-YesNo "Windows mit MAK aus $Global:MakFile aktivieren?") { Activate-WindowsFromMak -Name $Name}

    # ---- 13) Benutzerkonten-Tasks -------------------------------------------
    if (Ask-YesNo "Lokalen Administrator aktivieren & Passwort setzen?" ) {
        net user Administrator /active:yes | Out-Null
        net user Administrator $script:AdminPassword | Out-Null
    }
    if (Ask-YesNo "Aktuell angemeldeten lokalen Benutzer entfernen (nach Abmeldung)?") {
        $cleanupResult = Invoke-UserCleanupWithLogoff
        if ($cleanupResult) {
            $script:UserCleanupActive = $true
        }
    }

    # ---- 14) Log/Info-Datei schreiben ---------------------------------------
    if (Ask-YesNo "Info-/Log-Textdatei für dieses Gerät erzeugen?" -DefaultYes) {
        try {
            # Zielpfad wird in Switch-ToNamedMainLog/Set-LogSessionName gesetzt: $script:InfoPath
            Write-InfoFile -Name $Name -HWId $HWId -TID $TID
        } catch {
            Write-Log -Message ("Info-Datei konnte nicht erstellt werden: {0}" -f $_.Exception.Message) -Level ERROR
        }
    }
# --- Abschluss / Neustart -------------------------------------------------
    Stop-Transcript
    if (Ask-YesNo "Neustart jetzt durchf?hren?" -DefaultYes) {
        Restart-Immediate -DelaySeconds 0 -Force
    } else {
        Write-HostLog "Einstellen-Modus beendet (kein Neustart)." -ForegroundColor Green
    }
}

function Setup-TreiberEntpacken {
    [CmdletBinding()]
    param(
        [string]$Vendor,
        [string]$Modell
    )

    Write-HostLog "`n>>> Treiber-Entpacken/Installieren gestartet" -ForegroundColor Cyan

    if (-not $Vendor) { $Vendor = Read-Host "Hersteller (z.B. Lenovo/Dell/HP)" }
    if (-not $Modell) { $Modell = Read-Host "Modell-Reihe (z.B. V15 G4 AMN)" }

    $modeSel = Read-Host "Was soll passieren? (1=Nur entpacken, 2=Entpacken+Install via pnputil, 3=Nur silent installieren)"
    $mode = switch ($modeSel) {
        '1' { 'ExtractOnly' }
        '2' { 'ExtractAndInstall' }
        '3' { 'InstallOnly' }
        default { 'ExtractAndInstall' }
    }

    $src = Read-Host "Quellordner mit Treiber-Downloads (z.B. C:\Users\...\Downloads)"
    if (-not $src) { Write-Warning "Kein Quellordner angegeben."; return }

    # Ziel in deiner Struktur:
    $targetRoot = Join-Path $Global:TreiberNotebookPath $Vendor
    $target     = Join-Path $targetRoot ($Modell + "\_Extracted")
    $log        = Join-Path $Global:LogPath ("TreiberEntpacken-{0}-{1}.log" -f $Vendor,$Modell)

    Invoke-DriverPackageWorkflow -SourceFolder $src -TargetFolder $target -Mode $mode -LogFile $log

    Write-HostLog "`nFertig. Ziel: $target" -ForegroundColor Green
    Write-HostLog "Log:   $log" -ForegroundColor Green
}

#endregion

# ==================================================================
# Einstiegspunkt: Auswahlmenü für die Installation
# ==================================================================

#Clear-Host
Write-HostLog "==============================================="
Write-HostLog "        Installations-Tool (Konsole)"
Write-HostLog "        Version: 2.0.0"
Write-HostLog "==============================================="

# -------------------------------------------------------------------------
# Unattended-Modus: Parameter direkt übernehmen
# -------------------------------------------------------------------------
if ($Unattended) {
    $modus = $Modus
    $Name = $ComputerName
    $HWId = $HardwareID
    $TID = $TicketID
    # Modell und Standort werden direkt aus Parametern übernommen
    $vpnPw = $VpnPasswort

    Write-HostLog "[UNATTENDED] Modus: $modus, Name: $Name" -ForegroundColor Cyan
}
# -------------------------------------------------------------------------
# Interaktiver Modus: Benutzer nach Eingaben fragen
# -------------------------------------------------------------------------
else {
    # Robust: Nicht bei leerer Eingabe sofort beenden
    do {
        $typ = Read-Host "Was wollen Sie aufsetzen?
(1=Rechner, 2=Baaske, 3=ImportRechner, 4=NUC, 5=Laptop, 6=VPN, 7=Einstellen, 8=TreiberEntpacken, 9=WindowsUpdateReset)"
        switch ($typ) {
            '1' { $modus = "Rechner" }
            '2' { $modus = "Baaske" }
            '3' { $modus = "ImportRechner" }
            '4' { $modus = "NUC" }
            '5' { $modus = "Laptop" }
            '6' { $modus = "VPN" }
            '7' { $modus = "Einstellen" }
            '8' { $modus = "TreiberEntpacken" }
            '9' { $modus = "WindowsUpdateReset" }
            default {
                $modus = $null
                Write-HostLog "Ungültige Auswahl (bitte 1-9 eingeben)." -ForegroundColor Yellow
            }
        }
    } until ($modus)

    do {
        $Name = Read-Host "Neuer Rechnername"
        if (-not $Name) {
            Write-HostLog "Rechnername darf nicht leer sein." -ForegroundColor Yellow
            continue
        }

        # Validiere den Computernamen
        $validation = Test-ValidComputerName -Name $Name
        if (-not $validation.Valid) {
            Write-HostLog "Ungültiger Rechnername: $($validation.Reason)" -ForegroundColor Red
            $Name = $null
        }
    } until ($Name)

    $HWId = Read-Host "HardwareID eingeben"
    $TID  = Read-Host "TicketID eingeben"

    if ($modus -eq "Laptop" -or $modus -eq "VPN" -or $modus -eq "NUC") {
        $Modell = Read-Host "Modell Reihe (z.B. UN62 oder NUC11TNHi3 oder V15 IIL oder V15 G4 AMN)"
    }

    if ($modus -eq "Laptop" -or $modus -eq "NUC") {
        $Standort = Read-Host "Standort (Bochum / Hattingen / Linden / Extern)"
    }

    if ($modus -eq "VPN") {
        $vpnPw = Read-Host "Passwort für VPN-User" -AsSecureString
    }
}

# --- Logging: ab hier auf $Name.log umschalten (inkl. Transcript) ---
try { Switch-ToNamedMainLog -Name $Name } catch { Write-Warning "Konnte Log nicht umschalten: $_" }

# --- Inventar-Report (Name.txt + CSVs) ---
try { Export-InventoryReport -Name $Name -HardwareID $HWId -TicketID $TID } catch { Write-Log -Message "Inventar-Export fehlgeschlagen: $($_.Exception.Message)" -Level "WARN" -Tag "CORE" }



Write-HostLog "`nStarte Installation für $modus..." -ForegroundColor Cyan
Write-Progress -Activity "Installation $modus" -Status "Bitte warten..." -PercentComplete 5

# Variable um zu tracken ob User-Cleanup durchgeführt wird (dann KEIN Restart hier!)
$script:UserCleanupActive = $false

switch ($modus) {
    "Rechner"       { Setup-BaseSystem -Name $Name -HWId $HWId -TID $TID -MitTreibern }
    "Baaske"         { Setup-BaseSystem -Name $Name -HWId $HWId -TID $TID -MitTreibern }
    "ImportRechner" { Setup-BaseSystem -Name $Name -HWId $HWId -TID $TID -MitTreibern:$false; Install-UltraVNCServer }
    "NUC" 			{ Setup-NUC -Name $Name -HWId $HWId -TID $TID -Modell $Modell -Standort $Standort }
    "Laptop"         { Setup-Laptop -Name $Name -HWId $HWId -TID $TID -Modell $Modell -Standort $Standort }
    "VPN"             { Setup-VPN -Name $Name -HWId $HWId -TID $TID -Modell $Modell -VpnPasswort $vpnPw }
    "Einstellen"     { Setup-Einstellen -Name $Name -HWId $HWId -TID $TID }
	"TreiberEntpacken"   { Setup-TreiberEntpacken }
	"WindowsUpdateReset" { $wuLog = Join-Path $Global:LogPath ("WU-Reset-{0:yyyyMMdd_HHmmss}.log" -f (Get-Date)); Reset-WindowsUpdateComponents -ForceRename -LogFile $wuLog }
}

Write-Progress -Activity "Installation $modus" -Completed
Write-HostLog "`n[OK] Installation abgeschlossen." -ForegroundColor Green

# WhatIf-Modus: Kein Neustart
if ($script:WhatIfMode) {
    Write-HostLog "[WHATIF] Würde jetzt neustarten - aber WhatIf-Modus aktiv." -ForegroundColor Cyan
    Write-Log "WhatIf-Modus: Neustart übersprungen" "INFO"
    exit $script:CurrentExitCode
}

# Nur Neustart wenn KEIN User-Cleanup aktiv ist (der Task macht dann den Neustart)
if (-not $script:UserCleanupActive) {
    Write-Log "Kein User-Cleanup aktiv - starte Neustart direkt..." "INFO"
    if ($Unattended) {
        # Im Unattended-Modus Exit-Code setzen bevor Neustart
        Write-Log "Exit-Code: $($script:CurrentExitCode)" "INFO"
    }
    Restart-Immediate -DelaySeconds 0 -Force
} else {
    Write-Log "User-Cleanup aktiv - Neustart erfolgt durch Scheduled Task nach User-Löschung." "INFO"
    Write-HostLog "Neustart erfolgt automatisch nach User-Löschung..." -ForegroundColor Yellow
}

# Exit-Code setzen (für Unattended/Automatisierung)
exit $script:CurrentExitCode