# ============================================================================
# AutoDetect-Drivers.ps1 - Automatische Hardware-Erkennung & Treiber-Zuordnung
# ============================================================================
# Erkennt automatisch:
#   - Geraetetyp (Desktop, Laptop, NUC, All-in-One, Medizin-PC, Mini-PC)
#   - Hersteller & Mainboard/Modell
#   - Passendes Treiber-Verzeichnis auf dem ausfuehrenden Laufwerk
#
# Verwendung:
#   .\AutoDetect-Drivers.ps1                        # Interaktiv
#   .\AutoDetect-Drivers.ps1 -AutoInstall           # Vollautomatisch
#   .\AutoDetect-Drivers.ps1 -ReportOnly            # Nur Bericht
#   .\AutoDetect-Drivers.ps1 -WhatIf                # Trockenlauf
#
# Erweiterbar ueber: AutoDetect.Config.psd1
# ============================================================================

#requires -Version 5.1
#requires -RunAsAdministrator

[CmdletBinding(SupportsShouldProcess)]
param(
    # Vollautomatische Installation ohne Rueckfragen
    [switch]$AutoInstall,

    # Nur Hardware-Bericht ausgeben, keine Installation
    [switch]$ReportOnly,

    # Computername (optional - wird sonst aus Config/Eingabe geholt)
    [string]$ComputerName,

    # Manueller Override: Geraetetyp erzwingen
    [ValidateSet('Desktop','Laptop','NUC','AllinOnePC','MiniPC','MedizinPC','Server','Unbekannt')]
    [string]$ForceDeviceType,

    # Manueller Override: Treiberpfad direkt angeben
    [string]$ForceDriverPath,

    # Standort (fuer WLAN-Konfiguration)
    [ValidateSet('Bochum','Hattingen','Linden','Extern')]
    [string]$Standort,

    # Ausfuehrliches Logging
    [switch]$VerboseOutput
)

# ============================================================================
# REGION: Initialisierung
# ============================================================================
#region Init

try { chcp 65001 | Out-Null } catch {}
try { [Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false) } catch {}

$ErrorActionPreference = 'Continue'
$script:ScriptVersion = '1.0.0'
$script:ScriptStartTime = Get-Date

# Laufwerk ermitteln, auf dem dieses Skript liegt
$script:ScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Definition
$script:ScriptDrive = (Split-Path -Qualifier $script:ScriptRoot)

# Konfiguration laden
$configPath = Join-Path $script:ScriptRoot 'AutoDetect.Config.psd1'
if (Test-Path $configPath) {
    $script:Config = Import-PowerShellDataFile -Path $configPath
} else {
    Write-Warning "Konfigurationsdatei nicht gefunden: $configPath - verwende Standardwerte"
    $script:Config = @{}
}

# BasePath: Verzeichnis 'Datein' auf dem Skript-Laufwerk (oder Skript-Root selbst)
$dateinPath = Join-Path $script:ScriptDrive '\Datein'
if (Test-Path $dateinPath) {
    $script:BasePath = $dateinPath
} else {
    $script:BasePath = $script:ScriptRoot
}

# Treiber-Pfade dynamisch vom Skript-Laufwerk ableiten
$treiberRoot = if ($script:Config.Paths -and $script:Config.Paths.TreiberSubPath) {
    Join-Path $script:BasePath $script:Config.Paths.TreiberSubPath
} else {
    Join-Path $script:BasePath 'treiber'
}

$script:Paths = @{
    BasePath       = $script:BasePath
    TreiberRoot    = $treiberRoot
    Mainboard      = Join-Path $treiberRoot 'Mainboard'
    Notebook       = Join-Path $treiberRoot 'Notebook'
    NUC            = Join-Path $treiberRoot 'NUC'
    AllinOnePC     = Join-Path $treiberRoot 'AllinOnePC'
    MedizinPC      = Join-Path $treiberRoot 'MedizinPC'
    MiniPC         = Join-Path $treiberRoot 'MiniPC'
    LogPath        = Join-Path $script:BasePath 'Macs_und_Mainboards_Logs'
}

# Log-Verzeichnis sicherstellen
if (-not (Test-Path $script:Paths.LogPath)) {
    New-Item -ItemType Directory -Path $script:Paths.LogPath -Force | Out-Null
}
$script:LogFile = Join-Path $script:Paths.LogPath ("AutoDetect-{0:yyyyMMdd_HHmmss}.log" -f (Get-Date))

#endregion

# ============================================================================
# REGION: Logging
# ============================================================================
#region Logging

function Write-Log {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position=0)]
        [string]$Message,

        [ValidateSet('INFO','WARN','ERROR','SUCCESS','DEBUG')]
        [string]$Level = 'INFO'
    )

    $ts = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $line = "[$ts] [$Level] $Message"

    # In Logdatei schreiben
    $line | Out-File -FilePath $script:LogFile -Append -Encoding UTF8

    # Auf Konsole ausgeben
    $color = switch ($Level) {
        'ERROR'   { 'Red' }
        'WARN'    { 'Yellow' }
        'SUCCESS' { 'Green' }
        'DEBUG'   { 'DarkGray' }
        default   { 'Gray' }
    }
    Write-Host $line -ForegroundColor $color
}

#endregion

# ============================================================================
# REGION: Hardware-Erkennung
# ============================================================================
#region HardwareDetection

function Get-HardwareInfo {
    <#
    .SYNOPSIS
        Sammelt alle relevanten Hardware-Informationen per WMI/CIM.
    .DESCRIPTION
        Gibt ein PSCustomObject mit allen Feldern zurueck, die fuer die
        Geraeteklassifizierung und Treiberzuordnung benoetigt werden.
    #>
    [CmdletBinding()]
    param()

    Write-Log "Sammle Hardware-Informationen..." -Level INFO

    # --- Basis-Daten ---
    $cs   = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction SilentlyContinue
    $bb   = Get-CimInstance -ClassName Win32_BaseBoard -ErrorAction SilentlyContinue
    $bios = Get-CimInstance -ClassName Win32_BIOS -ErrorAction SilentlyContinue
    $os   = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction SilentlyContinue
    $enc  = Get-CimInstance -ClassName Win32_SystemEnclosure -ErrorAction SilentlyContinue

    # --- Chassis-Typ (entscheidend fuer Desktop vs Laptop) ---
    # https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/win32-systemenclosure
    # ChassisTypes Array - wir nehmen den ersten Wert
    $chassisTypes = @()
    if ($enc.ChassisTypes) {
        $chassisTypes = @($enc.ChassisTypes)
    }

    # --- Battery vorhanden? (Laptop-Indikator) ---
    $hasBattery = $false
    try {
        $bat = Get-CimInstance -ClassName Win32_Battery -ErrorAction SilentlyContinue
        if ($bat) { $hasBattery = $true }
    } catch {}

    # --- WLAN-Adapter vorhanden? ---
    $hasWlan = $false
    try {
        $wlanAdapter = Get-NetAdapter -ErrorAction SilentlyContinue |
            Where-Object { $_.InterfaceDescription -match 'Wireless|WLAN|Wi-Fi|WiFi|802\.11' }
        if ($wlanAdapter) { $hasWlan = $true }
    } catch {}

    # --- PCI-Geraete fuer spezielle Erkennung ---
    $pciDevices = @()
    try {
        $pciDevices = Get-CimInstance -ClassName Win32_PnPEntity -ErrorAction SilentlyContinue |
            Where-Object { $_.PNPDeviceID -match '^PCI\\' } |
            Select-Object Name, PNPDeviceID, Manufacturer -First 50
    } catch {}

    # --- Hersteller normalisieren ---
    $manufacturer = Get-NormalizedManufacturer -RawCS $cs.Manufacturer -RawBB $bb.Manufacturer

    # --- Mainboard-Produkt bereinigen ---
    $bbProduct = if ($bb.Product) { $bb.Product.Trim() } else { '' }

    # ASUS: "PRIME" Praefix entfernen
    if ($manufacturer -eq 'ASUS' -and $bbProduct -match '^PRIME\s*') {
        $bbProduct = ($bbProduct -replace '^PRIME\s*', '').Trim()
    }

    $info = [PSCustomObject]@{
        # System
        ComputerName       = $env:COMPUTERNAME
        Manufacturer       = $manufacturer
        Model              = if ($cs.Model) { $cs.Model.Trim() } else { '' }
        SystemFamily       = if ($cs.SystemFamily) { $cs.SystemFamily.Trim() } else { '' }
        SystemSKU          = if ($cs.SystemSKUNumber) { $cs.SystemSKUNumber.Trim() } else { '' }
        PCSystemType       = if ($cs.PCSystemType) { [int]$cs.PCSystemType } else { 0 }

        # Mainboard
        BoardManufacturer  = if ($bb.Manufacturer) { $bb.Manufacturer.Trim() } else { '' }
        BoardProduct       = $bbProduct
        BoardSerial        = if ($bb.SerialNumber) { $bb.SerialNumber.Trim() } else { '' }

        # BIOS
        BIOSVersion        = if ($bios.SMBIOSBIOSVersion) { $bios.SMBIOSBIOSVersion } else { '' }
        BIOSSerial         = if ($bios.SerialNumber) { $bios.SerialNumber.Trim() } else { '' }

        # OS
        OSCaption          = if ($os.Caption) { $os.Caption } else { '' }
        OSBuild            = if ($os.BuildNumber) { $os.BuildNumber } else { '' }
        OSArch             = if ([Environment]::Is64BitOperatingSystem) { 'x64' } else { 'x86' }

        # Chassis
        ChassisTypes       = $chassisTypes
        ChassisTypePrimary = if ($chassisTypes.Count -gt 0) { [int]$chassisTypes[0] } else { 0 }

        # Erkennung
        HasBattery         = $hasBattery
        HasWlan            = $hasWlan
        PciDeviceCount     = $pciDevices.Count

        # Roh-Daten (fuer Erweiterungen)
        RawComputerSystem  = $cs
        RawBaseBoard       = $bb
        RawBIOS            = $bios
        RawEnclosure       = $enc
    }

    Write-Log ("Hardware: {0} {1} | Board: {2} {3} | Chassis: {4}" -f
        $info.Manufacturer, $info.Model,
        $info.BoardManufacturer, $info.BoardProduct,
        ($info.ChassisTypes -join ',')) -Level INFO

    return $info
}

function Get-NormalizedManufacturer {
    <#
    .SYNOPSIS
        Normalisiert den Herstellernamen aus verschiedenen WMI-Quellen.
    #>
    param(
        [string]$RawCS,
        [string]$RawBB
    )

    $combined = ("$RawCS $RawBB").Trim().ToUpperInvariant()

    # Reihenfolge: spezifische Matches zuerst
    $map = [ordered]@{
        'LENOVO'            = 'Lenovo'
        'DELL'              = 'Dell'
        'HEWLETT|HP INC|HP' = 'HP'
        'ASUSTeK|ASUS'      = 'ASUS'
        'ACER'              = 'Acer'
        'MSI'               = 'MSI'
        'GIGABYTE'          = 'Gigabyte'
        'INTEL'             = 'Intel'
        'BAASKE'            = 'Baaske'
        'SHUTTLE'           = 'Shuttle'
        'FUJITSU'           = 'Fujitsu'
        'KONTRON'           = 'Kontron'
        'ADVANTECH'         = 'Advantech'
        'BECKHOFF'          = 'Beckhoff'
        'SIEMENS'           = 'Siemens'
        'ONYX'              = 'Onyx'
        'TANGENT'           = 'Tangent'
        'CYBERNET'          = 'Cybernet'
        'WINCOMM'           = 'Wincomm'
    }

    foreach ($pattern in $map.Keys) {
        if ($combined -match $pattern) {
            return $map[$pattern]
        }
    }

    return 'Unknown'
}

function Get-DeviceType {
    <#
    .SYNOPSIS
        Klassifiziert das Geraet anhand der gesammelten Hardware-Informationen.
    .DESCRIPTION
        Prueft mehrere Merkmale (Chassis, Batterie, Modellname, Hersteller,
        Board-Produkt) um den Geraetetyp zu bestimmen.
        Gibt ein Objekt mit DeviceType, Confidence und Reason zurueck.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject]$HardwareInfo
    )

    $hw = $HardwareInfo

    # --- Chassis-Typ-Gruppen ---
    # Desktop:       3, 4, 5, 6, 7, 15, 16, 24
    # Laptop:        8, 9, 10, 11, 14, 30, 31, 32
    # Mini-PC/NUC:   35 (Mini PC)
    # All-in-One:    13
    # Tablet:        30, 31, 32
    # Server:        17, 23
    $chassisDesktop = @(3, 4, 5, 6, 7, 15, 16, 24)
    $chassisLaptop  = @(8, 9, 10, 11, 14, 30, 31, 32)
    $chassisMiniPC  = @(35)
    $chassisAiO     = @(13)
    $chassisServer  = @(17, 23)

    $ct = $hw.ChassisTypePrimary
    $model = $hw.Model.ToUpperInvariant()
    $product = $hw.BoardProduct.ToUpperInvariant()
    $family = $hw.SystemFamily.ToUpperInvariant()
    $mfr = $hw.Manufacturer

    # --- PCSystemType (Win32_ComputerSystem.PCSystemType) ---
    # 0=Unspecified, 1=Desktop, 2=Mobile, 3=Workstation, 4=Enterprise Server, 5=SOHO Server, 7=Performance Server, 8=Slate/Tablet
    $pcType = $hw.PCSystemType

    # ====== Erkennungs-Regeln (Prioritaet von oben nach unten) ======

    # 1. Konfigurierte Hardware-Aliase pruefen
    if ($script:Config.HardwareAliases) {
        $aliasKey = "{0}_{1}" -f $mfr, $hw.BoardProduct
        if ($script:Config.HardwareAliases.ContainsKey($aliasKey)) {
            $alias = $script:Config.HardwareAliases[$aliasKey]
            if ($alias.DeviceType) {
                return [PSCustomObject]@{
                    DeviceType = $alias.DeviceType
                    Confidence = 100
                    Reason     = "Hardware-Alias: $aliasKey -> $($alias.DeviceType)"
                }
            }
        }
    }

    # 2. Konfigurierte Geraete-Regeln pruefen
    if ($script:Config.DeviceRules) {
        foreach ($rule in $script:Config.DeviceRules) {
            $match = $true
            if ($rule.Manufacturer -and $mfr -ne $rule.Manufacturer) { $match = $false }
            if ($rule.ModelPattern -and $model -notmatch $rule.ModelPattern) { $match = $false }
            if ($rule.BoardPattern -and $product -notmatch $rule.BoardPattern) { $match = $false }
            if ($rule.ChassisType -and $ct -ne $rule.ChassisType) { $match = $false }

            if ($match) {
                return [PSCustomObject]@{
                    DeviceType = $rule.DeviceType
                    Confidence = 95
                    Reason     = "Konfig-Regel: $($rule.Description)"
                }
            }
        }
    }

    # 3. Medizin-PC Erkennung (spezielle Hersteller / Modellnamen)
    $medPcManufacturers = @('Onyx','Tangent','Cybernet','Wincomm','Kontron','Advantech','Beckhoff')
    $medPcPatterns = @('MEDICAL','MED-PC','MEDPC','MEDI','CLINIC','PATIENT','KIOSK')
    if ($mfr -in $medPcManufacturers) {
        return [PSCustomObject]@{
            DeviceType = 'MedizinPC'
            Confidence = 90
            Reason     = "Medizin-PC Hersteller erkannt: $mfr"
        }
    }
    foreach ($pattern in $medPcPatterns) {
        if ($model -match $pattern -or $product -match $pattern -or $family -match $pattern) {
            return [PSCustomObject]@{
                DeviceType = 'MedizinPC'
                Confidence = 85
                Reason     = "Medizin-PC Muster erkannt: $pattern in Modell/Board/Family"
            }
        }
    }

    # 4. Baaske (spezieller Hersteller)
    if ($mfr -eq 'Baaske') {
        return [PSCustomObject]@{
            DeviceType = 'Desktop'
            Confidence = 95
            Reason     = "Baaske-Geraet erkannt (wird als Desktop behandelt)"
            SubType    = 'Baaske'
        }
    }

    # 5. All-in-One erkennen
    if ($ct -in $chassisAiO) {
        return [PSCustomObject]@{
            DeviceType = 'AllinOnePC'
            Confidence = 95
            Reason     = "Chassis-Typ 13 (All-in-One)"
        }
    }
    # Lenovo AiO: Produkt 3780 oder Modellname enthaelt "Neo 50a" etc.
    if ($model -match 'ALL[\s\-]?IN[\s\-]?ONE|AIO|NEO\s*50A' -or $family -match 'ALL[\s\-]?IN[\s\-]?ONE') {
        return [PSCustomObject]@{
            DeviceType = 'AllinOnePC'
            Confidence = 90
            Reason     = "All-in-One im Modellnamen/Family erkannt"
        }
    }

    # 6. NUC erkennen (Intel NUC / Mini-PC Chassis 35)
    if ($ct -in $chassisMiniPC) {
        # Unterscheidung NUC vs. generischer Mini-PC
        if ($model -match 'NUC|UN\d{2}' -or $mfr -eq 'Intel') {
            return [PSCustomObject]@{
                DeviceType = 'NUC'
                Confidence = 95
                Reason     = "Chassis 35 (Mini PC) + Intel/NUC-Modell: $($hw.Model)"
            }
        }
        return [PSCustomObject]@{
            DeviceType = 'MiniPC'
            Confidence = 85
            Reason     = "Chassis 35 (Mini PC) - kein Intel NUC"
        }
    }
    # NUC ohne Chassis 35 (aeltere Modelle)
    if ($model -match '^NUC\d|^UN\d{2}' -or $product -match '^NUC\d') {
        return [PSCustomObject]@{
            DeviceType = 'NUC'
            Confidence = 90
            Reason     = "NUC-Modellname erkannt: $($hw.Model) / $($hw.BoardProduct)"
        }
    }

    # 7. Server
    if ($ct -in $chassisServer -or $pcType -in @(4, 5, 7)) {
        return [PSCustomObject]@{
            DeviceType = 'Server'
            Confidence = 90
            Reason     = "Server-Chassis oder PCSystemType"
        }
    }

    # 8. Laptop erkennen (Chassis + Batterie)
    if ($ct -in $chassisLaptop) {
        return [PSCustomObject]@{
            DeviceType = 'Laptop'
            Confidence = 95
            Reason     = "Chassis-Typ $ct (Laptop/Portable)"
        }
    }
    if ($hw.HasBattery -and $pcType -eq 2) {
        return [PSCustomObject]@{
            DeviceType = 'Laptop'
            Confidence = 90
            Reason     = "Batterie vorhanden + PCSystemType=Mobile"
        }
    }
    if ($hw.HasBattery) {
        return [PSCustomObject]@{
            DeviceType = 'Laptop'
            Confidence = 75
            Reason     = "Batterie vorhanden (aber Chassis-Typ $ct nicht eindeutig)"
        }
    }

    # 9. Desktop (Fallback fuer bekannte Chassis-Typen)
    if ($ct -in $chassisDesktop -or $pcType -in @(1, 3)) {
        return [PSCustomObject]@{
            DeviceType = 'Desktop'
            Confidence = 85
            Reason     = "Chassis-Typ $ct / PCSystemType $pcType (Desktop/Workstation)"
        }
    }

    # 10. Absoluter Fallback
    return [PSCustomObject]@{
        DeviceType = 'Unbekannt'
        Confidence = 0
        Reason     = "Kein Muster erkannt (Chassis=$ct, PCType=$pcType, Batterie=$($hw.HasBattery))"
    }
}

#endregion

# ============================================================================
# REGION: Treiber-Aufloesung
# ============================================================================
#region DriverResolution

function Resolve-DriverPath {
    <#
    .SYNOPSIS
        Findet den passenden Treiber-Ordner fuer die erkannte Hardware.
    .DESCRIPTION
        Sucht in der konfigurierten Treiber-Ordnerstruktur nach einem
        passenden Verzeichnis basierend auf Geraetetyp, Hersteller und Modell.
    .OUTPUTS
        PSCustomObject mit Path, MatchType und MatchDetail
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject]$HardwareInfo,

        [Parameter(Mandatory)]
        [string]$DeviceType
    )

    $hw = $HardwareInfo
    $result = [PSCustomObject]@{
        Path        = $null
        MatchType   = 'None'
        MatchDetail = ''
        SearchPaths = @()
    }

    Write-Log "Suche Treiber fuer DeviceType=$DeviceType, Hersteller=$($hw.Manufacturer), Board=$($hw.BoardProduct)" -Level INFO

    # --- 1. Hardware-Aliase pruefen (hoechste Prioritaet) ---
    if ($script:Config.HardwareAliases) {
        $aliasKey = "{0}_{1}" -f $hw.Manufacturer, $hw.BoardProduct
        if ($script:Config.HardwareAliases.ContainsKey($aliasKey)) {
            $alias = $script:Config.HardwareAliases[$aliasKey]
            $aliasPath = Join-Path $script:Paths.TreiberRoot $alias.Path
            if (Test-Path $aliasPath) {
                Write-Log "Hardware-Alias Treffer: $aliasKey -> $aliasPath" -Level SUCCESS
                $result.Path = $aliasPath
                $result.MatchType = 'Alias'
                $result.MatchDetail = $aliasKey
                return $result
            } else {
                Write-Log "Alias-Pfad existiert nicht: $aliasPath" -Level WARN
            }
        }
    }

    # --- 2. Je nach Geraetetyp den richtigen Suchpfad waehlen ---
    switch ($DeviceType) {
        'Desktop' {
            $searchRoot = $script:Paths.Mainboard
            $result.SearchPaths += $searchRoot
            $found = Find-DriverFolderByBoard -SearchRoot $searchRoot -BoardProduct $hw.BoardProduct
            if ($found) {
                $result.Path = $found
                $result.MatchType = 'Mainboard'
                $result.MatchDetail = $hw.BoardProduct
            }
        }

        'Laptop' {
            $vendorRoot = Join-Path $script:Paths.Notebook $hw.Manufacturer
            $result.SearchPaths += $vendorRoot
            if (-not (Test-Path $vendorRoot)) {
                # Fallback: direkt im Notebook-Ordner suchen
                $vendorRoot = $script:Paths.Notebook
                $result.SearchPaths += $vendorRoot
            }
            $found = Find-DriverFolderByModel -SearchRoot $vendorRoot -Model $hw.Model
            if (-not $found) {
                # Zweiter Versuch mit Board-Produkt
                $found = Find-DriverFolderByModel -SearchRoot $vendorRoot -Model $hw.BoardProduct
            }
            if ($found) {
                $result.Path = $found
                $result.MatchType = 'Notebook-Modell'
                $result.MatchDetail = $hw.Model
            }
        }

        'NUC' {
            $searchRoot = $script:Paths.NUC
            $result.SearchPaths += $searchRoot
            $found = Find-DriverFolderByModel -SearchRoot $searchRoot -Model $hw.Model
            if (-not $found) {
                $found = Find-DriverFolderByModel -SearchRoot $searchRoot -Model $hw.BoardProduct
            }
            if ($found) {
                $result.Path = $found
                $result.MatchType = 'NUC-Modell'
                $result.MatchDetail = $hw.Model
            }
        }

        'AllinOnePC' {
            $vendorRoot = Join-Path $script:Paths.AllinOnePC $hw.Manufacturer
            $result.SearchPaths += $vendorRoot
            if (Test-Path $vendorRoot) {
                $found = Find-DriverFolderByModel -SearchRoot $vendorRoot -Model $hw.Model
                if (-not $found) {
                    $found = Find-DriverFolderByModel -SearchRoot $vendorRoot -Model $hw.BoardProduct
                }
            }
            if (-not $found) {
                # Fallback: AllinOnePC-Root
                $result.SearchPaths += $script:Paths.AllinOnePC
                $found = Find-DriverFolderByModel -SearchRoot $script:Paths.AllinOnePC -Model $hw.Model
            }
            if ($found) {
                $result.Path = $found
                $result.MatchType = 'AllInOne-Modell'
                $result.MatchDetail = "$($hw.Manufacturer)/$($hw.Model)"
            }
        }

        'MedizinPC' {
            $searchRoot = $script:Paths.MedizinPC
            $result.SearchPaths += $searchRoot
            if (Test-Path $searchRoot) {
                # Erst nach Hersteller-Unterordner suchen
                $vendorRoot = Join-Path $searchRoot $hw.Manufacturer
                if (Test-Path $vendorRoot) {
                    $found = Find-DriverFolderByModel -SearchRoot $vendorRoot -Model $hw.Model
                }
                if (-not $found) {
                    $found = Find-DriverFolderByModel -SearchRoot $searchRoot -Model $hw.Model
                }
            }
            if (-not $found) {
                # Fallback: Mainboard-Suche
                $result.SearchPaths += $script:Paths.Mainboard
                $found = Find-DriverFolderByBoard -SearchRoot $script:Paths.Mainboard -BoardProduct $hw.BoardProduct
            }
            if ($found) {
                $result.Path = $found
                $result.MatchType = 'MedizinPC'
                $result.MatchDetail = "$($hw.Manufacturer)/$($hw.Model)"
            }
        }

        'MiniPC' {
            $searchRoot = $script:Paths.MiniPC
            $result.SearchPaths += $searchRoot
            if (Test-Path $searchRoot) {
                $found = Find-DriverFolderByModel -SearchRoot $searchRoot -Model $hw.Model
            }
            if (-not $found) {
                # Fallback: Mainboard
                $result.SearchPaths += $script:Paths.Mainboard
                $found = Find-DriverFolderByBoard -SearchRoot $script:Paths.Mainboard -BoardProduct $hw.BoardProduct
            }
            if ($found) {
                $result.Path = $found
                $result.MatchType = 'MiniPC'
                $result.MatchDetail = $hw.Model
            }
        }

        default {
            # Fallback: Mainboard-Suche
            $searchRoot = $script:Paths.Mainboard
            $result.SearchPaths += $searchRoot
            $found = Find-DriverFolderByBoard -SearchRoot $searchRoot -BoardProduct $hw.BoardProduct
            if ($found) {
                $result.Path = $found
                $result.MatchType = 'Mainboard-Fallback'
                $result.MatchDetail = $hw.BoardProduct
            }
        }
    }

    if ($result.Path) {
        Write-Log "Treiber gefunden: $($result.Path) (Match: $($result.MatchType))" -Level SUCCESS
    } else {
        Write-Log "KEIN Treiber-Ordner gefunden! Durchsuchte Pfade: $($result.SearchPaths -join ', ')" -Level WARN
    }

    return $result
}

function Find-DriverFolderByBoard {
    <#
    .SYNOPSIS
        Sucht im Mainboard-Treiberordner nach passendem Unterverzeichnis.
    #>
    param(
        [string]$SearchRoot,
        [string]$BoardProduct
    )

    if (-not (Test-Path $SearchRoot)) { return $null }
    if ([string]::IsNullOrWhiteSpace($BoardProduct)) { return $null }

    # Normalisieren: PRIME entfernen, Leerzeichen raus, Sonderzeichen raus
    $clean = $BoardProduct -replace '^PRIME\s*', '' -replace '\s+', '' -replace '[^A-Za-z0-9\-_]', ''

    # 1. Exakter Treffer
    $exact = Join-Path $SearchRoot $clean
    if (Test-Path $exact) { return $exact }

    # 2. Normalisierter Vergleich
    $dirs = Get-ChildItem -Path $SearchRoot -Directory -ErrorAction SilentlyContinue |
        Where-Object {
            $normalized = ($_.Name -replace '^(Asus|ASUS|PRIME)\s*', '' -replace '\s+', '' -replace '[^A-Za-z0-9\-_]', '')
            $normalized -like "$clean*"
        }

    if ($dirs -and $dirs.Count -ge 1) {
        # Bei eindeutigem Match direkt zurueckgeben
        if ($dirs.Count -eq 1) {
            return $dirs[0].FullName
        }
        # Mehrere Treffer: besten Score berechnen
        $best = $dirs | Sort-Object {
            $normalized = ($_.Name -replace '^(Asus|ASUS|PRIME)\s*', '' -replace '\s+', '')
            # Kuerzerer Name = naeher am Suchbegriff = besser
            [Math]::Abs($normalized.Length - $clean.Length)
        } | Select-Object -First 1
        return $best.FullName
    }

    return $null
}

function Find-DriverFolderByModel {
    <#
    .SYNOPSIS
        Sucht im angegebenen Verzeichnis nach einem Ordner, der zum Modell passt.
    #>
    param(
        [string]$SearchRoot,
        [string]$Model
    )

    if (-not (Test-Path $SearchRoot)) { return $null }
    if ([string]::IsNullOrWhiteSpace($Model)) { return $null }

    $clean = $Model.Trim()

    # 1. Exakter Treffer
    $exact = Join-Path $SearchRoot $clean
    if (Test-Path $exact) { return $exact }

    # 2. Prefix-Match
    $dirs = Get-ChildItem -Path $SearchRoot -Directory -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -like "$clean*" }

    if ($dirs -and $dirs.Count -ge 1) {
        return ($dirs | Select-Object -First 1).FullName
    }

    # 3. Fuzzy: Modellname als Teil des Ordnernamens
    $dirs = Get-ChildItem -Path $SearchRoot -Directory -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -match [regex]::Escape($clean) }

    if ($dirs -and $dirs.Count -ge 1) {
        return ($dirs | Select-Object -First 1).FullName
    }

    # 4. Token-basiert: Modellname in einzelne Woerter aufteilen und matchen
    $tokens = $clean -split '\s+' | Where-Object { $_.Length -ge 2 }
    if ($tokens.Count -ge 2) {
        $dirs = Get-ChildItem -Path $SearchRoot -Directory -ErrorAction SilentlyContinue |
            Where-Object {
                $name = $_.Name
                $matchCount = ($tokens | Where-Object { $name -match [regex]::Escape($_) }).Count
                $matchCount -ge [Math]::Ceiling($tokens.Count * 0.7)  # 70% der Token muessen matchen
            }
        if ($dirs -and $dirs.Count -ge 1) {
            return ($dirs | Select-Object -First 1).FullName
        }
    }

    return $null
}

#endregion

# ============================================================================
# REGION: Netzwerk-Info
# ============================================================================
#region NetworkInfo

function Get-NetworkSummary {
    <#
    .SYNOPSIS
        Sammelt Netzwerk-Informationen (MAC, IP, Adapter).
    #>
    [CmdletBinding()]
    param()

    $adapters = @()
    try {
        $adapters = Get-NetAdapter -Physical -ErrorAction Stop | ForEach-Object {
            $ip = $null
            try {
                $ip = (Get-NetIPAddress -InterfaceIndex $_.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue |
                    Select-Object -First 1).IPAddress
            } catch {}

            [PSCustomObject]@{
                Name       = $_.Name
                Status     = $_.Status
                LinkSpeed  = $_.LinkSpeed
                MacAddress = $_.MacAddress
                IPv4       = $ip
                Type       = if ($_.InterfaceDescription -match 'Wireless|WLAN|Wi-Fi') { 'WLAN' } else { 'Ethernet' }
            }
        }
    } catch {
        Write-Log "Netzwerk-Erkennung fehlgeschlagen: $($_.Exception.Message)" -Level WARN
    }

    return $adapters
}

#endregion

# ============================================================================
# REGION: Bericht & Ausgabe
# ============================================================================
#region Report

function Show-DetectionReport {
    <#
    .SYNOPSIS
        Zeigt einen formatierten Bericht der Erkennung an.
    #>
    param(
        [PSCustomObject]$HardwareInfo,
        [PSCustomObject]$DeviceClassification,
        [PSCustomObject]$DriverResolution,
        $NetworkAdapters
    )

    $hw = $HardwareInfo
    $dc = $DeviceClassification
    $dr = $DriverResolution

    Write-Host ""
    Write-Host ("=" * 65) -ForegroundColor Cyan
    Write-Host "       AUTO-DETECT HARDWARE & TREIBER - ERGEBNIS" -ForegroundColor Cyan
    Write-Host ("=" * 65) -ForegroundColor Cyan
    Write-Host ""

    # System
    Write-Host "  SYSTEM" -ForegroundColor Yellow
    Write-Host ("  {0,-24} {1}" -f "Computername:", $hw.ComputerName)
    Write-Host ("  {0,-24} {1}" -f "Hersteller:", $hw.Manufacturer)
    Write-Host ("  {0,-24} {1}" -f "Modell:", $hw.Model)
    Write-Host ("  {0,-24} {1}" -f "System-Familie:", $hw.SystemFamily)
    Write-Host ""

    # Mainboard
    Write-Host "  MAINBOARD" -ForegroundColor Yellow
    Write-Host ("  {0,-24} {1}" -f "Hersteller:", $hw.BoardManufacturer)
    Write-Host ("  {0,-24} {1}" -f "Produkt:", $hw.BoardProduct)
    Write-Host ("  {0,-24} {1}" -f "Seriennummer:", $hw.BoardSerial)
    Write-Host ""

    # BIOS
    Write-Host "  BIOS" -ForegroundColor Yellow
    Write-Host ("  {0,-24} {1}" -f "Version:", $hw.BIOSVersion)
    Write-Host ("  {0,-24} {1}" -f "Seriennummer:", $hw.BIOSSerial)
    Write-Host ""

    # OS
    Write-Host "  BETRIEBSSYSTEM" -ForegroundColor Yellow
    Write-Host ("  {0,-24} {1}" -f "OS:", $hw.OSCaption)
    Write-Host ("  {0,-24} {1}" -f "Build:", $hw.OSBuild)
    Write-Host ("  {0,-24} {1}" -f "Architektur:", $hw.OSArch)
    Write-Host ""

    # Erkennung
    Write-Host "  ERKENNUNG" -ForegroundColor Yellow
    $typeColor = if ($dc.Confidence -ge 80) { 'Green' } elseif ($dc.Confidence -ge 50) { 'Yellow' } else { 'Red' }
    Write-Host ("  {0,-24} " -f "Geraetetyp:") -NoNewline
    Write-Host $dc.DeviceType -ForegroundColor $typeColor
    Write-Host ("  {0,-24} {1}%" -f "Konfidenz:", $dc.Confidence)
    Write-Host ("  {0,-24} {1}" -f "Grund:", $dc.Reason)
    Write-Host ("  {0,-24} {1}" -f "Chassis-Typ:", ($hw.ChassisTypes -join ', '))
    Write-Host ("  {0,-24} {1}" -f "Batterie:", $(if ($hw.HasBattery) { 'Ja' } else { 'Nein' }))
    Write-Host ("  {0,-24} {1}" -f "WLAN:", $(if ($hw.HasWlan) { 'Ja' } else { 'Nein' }))
    Write-Host ""

    # Treiber
    Write-Host "  TREIBER" -ForegroundColor Yellow
    if ($dr.Path) {
        Write-Host ("  {0,-24} " -f "Treiber-Ordner:") -NoNewline
        Write-Host $dr.Path -ForegroundColor Green
        Write-Host ("  {0,-24} {1}" -f "Match-Typ:", $dr.MatchType)
        Write-Host ("  {0,-24} {1}" -f "Match-Detail:", $dr.MatchDetail)
    } else {
        Write-Host ("  {0,-24} " -f "Treiber-Ordner:") -NoNewline
        Write-Host "NICHT GEFUNDEN" -ForegroundColor Red
        Write-Host ("  {0,-24} {1}" -f "Durchsucht:", ($dr.SearchPaths -join ', '))
    }
    Write-Host ""

    # Netzwerk
    if ($NetworkAdapters -and $NetworkAdapters.Count -gt 0) {
        Write-Host "  NETZWERK" -ForegroundColor Yellow
        foreach ($nic in $NetworkAdapters) {
            $statusColor = if ($nic.Status -eq 'Up') { 'Green' } else { 'DarkGray' }
            Write-Host ("  {0,-20} {1,-8} MAC: {2}  IPv4: {3}" -f $nic.Name, $nic.Status, $nic.MacAddress, $nic.IPv4) -ForegroundColor $statusColor
        }
        Write-Host ""
    }

    # Pfade
    Write-Host "  PFADE" -ForegroundColor Yellow
    Write-Host ("  {0,-24} {1}" -f "Skript-Laufwerk:", $script:ScriptDrive)
    Write-Host ("  {0,-24} {1}" -f "Basis-Pfad:", $script:Paths.BasePath)
    Write-Host ("  {0,-24} {1}" -f "Treiber-Root:", $script:Paths.TreiberRoot)
    Write-Host ("  {0,-24} {1}" -f "Log-Datei:", $script:LogFile)
    Write-Host ""

    Write-Host ("-" * 65) -ForegroundColor DarkGray
}

function Export-DetectionReport {
    <#
    .SYNOPSIS
        Exportiert den Erkennungsbericht als JSON fuer Automatisierung.
    #>
    param(
        [PSCustomObject]$HardwareInfo,
        [PSCustomObject]$DeviceClassification,
        [PSCustomObject]$DriverResolution,
        $NetworkAdapters
    )

    $report = [ordered]@{
        Timestamp        = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
        ScriptVersion    = $script:ScriptVersion
        ScriptDrive      = $script:ScriptDrive

        Hardware = [ordered]@{
            ComputerName      = $HardwareInfo.ComputerName
            Manufacturer      = $HardwareInfo.Manufacturer
            Model             = $HardwareInfo.Model
            SystemFamily      = $HardwareInfo.SystemFamily
            BoardManufacturer = $HardwareInfo.BoardManufacturer
            BoardProduct      = $HardwareInfo.BoardProduct
            BoardSerial       = $HardwareInfo.BoardSerial
            BIOSVersion       = $HardwareInfo.BIOSVersion
            OSCaption         = $HardwareInfo.OSCaption
            OSBuild           = $HardwareInfo.OSBuild
            OSArch            = $HardwareInfo.OSArch
            ChassisTypes      = $HardwareInfo.ChassisTypes
            HasBattery        = $HardwareInfo.HasBattery
            HasWlan           = $HardwareInfo.HasWlan
        }

        Detection = [ordered]@{
            DeviceType = $DeviceClassification.DeviceType
            Confidence = $DeviceClassification.Confidence
            Reason     = $DeviceClassification.Reason
        }

        Driver = [ordered]@{
            Path        = $DriverResolution.Path
            MatchType   = $DriverResolution.MatchType
            MatchDetail = $DriverResolution.MatchDetail
            Found       = [bool]$DriverResolution.Path
        }

        Network = @(
            if ($NetworkAdapters) {
                $NetworkAdapters | ForEach-Object {
                    [ordered]@{
                        Name       = $_.Name
                        Status     = $_.Status
                        MacAddress = $_.MacAddress
                        IPv4       = $_.IPv4
                        Type       = $_.Type
                    }
                }
            }
        )
    }

    $jsonPath = Join-Path $script:Paths.LogPath ("AutoDetect-{0}-{1:yyyyMMdd_HHmmss}.json" -f $env:COMPUTERNAME, (Get-Date))
    $report | ConvertTo-Json -Depth 5 | Out-File -FilePath $jsonPath -Encoding UTF8
    Write-Log "Bericht exportiert: $jsonPath" -Level SUCCESS

    return $jsonPath
}

#endregion

# ============================================================================
# REGION: Integrations-Schnittstelle (fuer Installation.ps1)
# ============================================================================
#region Integration

function Get-AutoDetectResult {
    <#
    .SYNOPSIS
        Hauptfunktion: Erkennung ausfuehren und Ergebnis-Objekt zurueckgeben.
    .DESCRIPTION
        Kann von Installation.ps1 aufgerufen werden, um die automatische
        Erkennung in den bestehenden Workflow zu integrieren.
    .EXAMPLE
        $detect = & .\AutoDetect-Drivers.ps1 -ReportOnly
        $detect = Get-AutoDetectResult
        if ($detect.DriverPath) { Install-Treiber -Pfad $detect.DriverPath -LogDatei $log }
    #>
    [CmdletBinding()]
    param()

    $hwInfo     = Get-HardwareInfo
    $deviceType = Get-DeviceType -HardwareInfo $hwInfo
    $driverRes  = Resolve-DriverPath -HardwareInfo $hwInfo -DeviceType $deviceType.DeviceType
    $network    = Get-NetworkSummary

    return [PSCustomObject]@{
        HardwareInfo    = $hwInfo
        DeviceType      = $deviceType.DeviceType
        DeviceSubType   = if ($deviceType.PSObject.Properties['SubType']) { $deviceType.SubType } else { $null }
        Confidence      = $deviceType.Confidence
        Reason          = $deviceType.Reason
        DriverPath      = $driverRes.Path
        DriverMatchType = $driverRes.MatchType
        NetworkAdapters = $network

        # Mapping auf bestehende Installation.ps1 Modi
        InstallationModus = switch ($deviceType.DeviceType) {
            'Desktop'    { 'Rechner' }
            'Laptop'     { 'Laptop' }
            'NUC'        { 'NUC' }
            'AllinOnePC' { 'Rechner' }  # AiO wird wie Rechner behandelt
            'MiniPC'     { 'Rechner' }
            'MedizinPC'  { 'Rechner' }
            'Server'     { 'Rechner' }
            default      { 'Rechner' }
        }
    }
}

#endregion

# ============================================================================
# REGION: Hauptprogramm
# ============================================================================
#region Main

Write-Host ""
Write-Host ("=" * 65) -ForegroundColor DarkCyan
Write-Host "    AUTOMATISCHE HARDWARE-ERKENNUNG & TREIBER-ZUORDNUNG v$($script:ScriptVersion)" -ForegroundColor DarkCyan
Write-Host ("=" * 65) -ForegroundColor DarkCyan
Write-Host ""
Write-Log "Skript gestartet auf Laufwerk: $($script:ScriptDrive)" -Level INFO
Write-Log "BasePath: $($script:Paths.BasePath)" -Level INFO
Write-Log "TreiberRoot: $($script:Paths.TreiberRoot)" -Level INFO

# 1. Hardware erkennen
$hwInfo = Get-HardwareInfo

# 2. Geraetetyp klassifizieren
if ($ForceDeviceType) {
    $classification = [PSCustomObject]@{
        DeviceType = $ForceDeviceType
        Confidence = 100
        Reason     = "Manuell erzwungen: -ForceDeviceType $ForceDeviceType"
    }
    Write-Log "Geraetetyp manuell erzwungen: $ForceDeviceType" -Level WARN
} else {
    $classification = Get-DeviceType -HardwareInfo $hwInfo
}

# 3. Treiber-Ordner suchen
if ($ForceDriverPath) {
    $driverResult = [PSCustomObject]@{
        Path        = $ForceDriverPath
        MatchType   = 'ManuellerPfad'
        MatchDetail = 'Per -ForceDriverPath angegeben'
        SearchPaths = @($ForceDriverPath)
    }
    Write-Log "Treiber-Pfad manuell erzwungen: $ForceDriverPath" -Level WARN
} else {
    $driverResult = Resolve-DriverPath -HardwareInfo $hwInfo -DeviceType $classification.DeviceType
}

# 4. Netzwerk-Info sammeln
$networkInfo = Get-NetworkSummary

# 5. Bericht anzeigen
Show-DetectionReport -HardwareInfo $hwInfo -DeviceClassification $classification `
    -DriverResolution $driverResult -NetworkAdapters $networkInfo

# 6. Bericht als JSON exportieren
$jsonReport = Export-DetectionReport -HardwareInfo $hwInfo -DeviceClassification $classification `
    -DriverResolution $driverResult -NetworkAdapters $networkInfo

# 7. Nur Bericht? Dann hier aufhoeren.
if ($ReportOnly) {
    Write-Host ""
    Write-Host "Nur-Bericht-Modus: Keine Aenderungen vorgenommen." -ForegroundColor Yellow
    Write-Host "JSON-Bericht: $jsonReport" -ForegroundColor DarkGray
    Write-Host ""
    exit 0
}

# 8. Interaktiv: Bestaetigung oder Korrektur
if (-not $AutoInstall) {
    Write-Host ""

    # Geraetetyp bestaetigen
    if ($classification.Confidence -lt 80) {
        Write-Host "ACHTUNG: Erkennung unsicher (Konfidenz: $($classification.Confidence)%)" -ForegroundColor Yellow
    }

    Write-Host "Erkannter Geraetetyp: " -NoNewline
    Write-Host $classification.DeviceType -ForegroundColor Cyan
    Write-Host ""

    $confirm = Read-Host "Ist der Geraetetyp korrekt? (J/N, Enter=Ja)"
    if ($confirm -and $confirm.ToUpper() -ne 'J' -and $confirm.ToUpper() -ne 'Y' -and $confirm -ne '') {
        Write-Host ""
        Write-Host "Verfuegbare Geraetetypen:" -ForegroundColor Cyan
        Write-Host "  [1] Desktop       - Standard-PC/Workstation"
        Write-Host "  [2] Laptop        - Notebook/Portable"
        Write-Host "  [3] NUC           - Intel NUC"
        Write-Host "  [4] AllinOnePC    - All-in-One PC"
        Write-Host "  [5] MiniPC        - Mini-PC (nicht NUC)"
        Write-Host "  [6] MedizinPC     - Medizinischer PC"
        Write-Host "  [7] Server        - Server"
        Write-Host ""

        do {
            $sel = Read-Host "Geraetetyp waehlen (1-7)"
            $newType = switch ($sel) {
                '1' { 'Desktop' }
                '2' { 'Laptop' }
                '3' { 'NUC' }
                '4' { 'AllinOnePC' }
                '5' { 'MiniPC' }
                '6' { 'MedizinPC' }
                '7' { 'Server' }
                default { $null }
            }
        } until ($newType)

        $classification = [PSCustomObject]@{
            DeviceType = $newType
            Confidence = 100
            Reason     = "Manuell korrigiert durch Benutzer"
        }

        # Treiber-Pfad neu aufloesen
        $driverResult = Resolve-DriverPath -HardwareInfo $hwInfo -DeviceType $newType
        Write-Log "Geraetetyp manuell korrigiert: $newType" -Level INFO
    }

    # Treiber-Pfad bestaetigen
    if ($driverResult.Path) {
        Write-Host ""
        Write-Host "Treiber-Ordner: " -NoNewline
        Write-Host $driverResult.Path -ForegroundColor Green
        $confirmDrv = Read-Host "Treiber aus diesem Ordner installieren? (J/N, Enter=Ja)"
        if ($confirmDrv -and $confirmDrv.ToUpper() -notin @('J','Y','')) {
            Write-Host "Treiber-Installation uebersprungen." -ForegroundColor Yellow
            $driverResult.Path = $null
        }
    } else {
        Write-Host ""
        Write-Host "Kein passender Treiber-Ordner gefunden." -ForegroundColor Yellow
        $manualPath = Read-Host "Manuellen Treiber-Pfad eingeben (oder Enter zum Ueberspringen)"
        if ($manualPath -and (Test-Path $manualPath)) {
            $driverResult.Path = $manualPath
            $driverResult.MatchType = 'ManuellEingegeben'
        }
    }
}

# 9. Ergebnis-Objekt fuer Integration bereitstellen
$script:DetectionResult = [PSCustomObject]@{
    HardwareInfo        = $hwInfo
    DeviceType          = $classification.DeviceType
    Confidence          = $classification.Confidence
    DriverPath          = $driverResult.Path
    DriverMatchType     = $driverResult.MatchType
    NetworkAdapters     = $networkInfo
    InstallationModus   = switch ($classification.DeviceType) {
        'Desktop'    { 'Rechner' }
        'Laptop'     { 'Laptop' }
        'NUC'        { 'NUC' }
        'AllinOnePC' { 'Rechner' }
        'MiniPC'     { 'Rechner' }
        'MedizinPC'  { 'Rechner' }
        'Server'     { 'Rechner' }
        default      { 'Rechner' }
    }
    Standort            = $Standort
    JsonReportPath      = $jsonReport
}

# 10. Zusammenfassung
$elapsed = (Get-Date) - $script:ScriptStartTime

Write-Host ""
Write-Host ("=" * 65) -ForegroundColor DarkCyan
Write-Host "       ERKENNUNG ABGESCHLOSSEN" -ForegroundColor DarkCyan
Write-Host ("=" * 65) -ForegroundColor DarkCyan
Write-Host ""
Write-Host ("  Geraetetyp:     {0}" -f $classification.DeviceType) -ForegroundColor White
Write-Host ("  Konfidenz:      {0}%" -f $classification.Confidence) -ForegroundColor White
Write-Host ("  Treiber-Pfad:   {0}" -f $(if ($driverResult.Path) { $driverResult.Path } else { '(keiner)' })) -ForegroundColor White
Write-Host ("  Inst.-Modus:    {0}" -f $script:DetectionResult.InstallationModus) -ForegroundColor White
Write-Host ("  Dauer:          {0:N1}s" -f $elapsed.TotalSeconds) -ForegroundColor DarkGray
Write-Host ""
Write-Host ("-" * 65) -ForegroundColor DarkGray

Write-Log "Erkennung abgeschlossen in $([math]::Round($elapsed.TotalSeconds, 1))s" -Level SUCCESS

# Rueckgabe fuer Pipeline / Aufrufer
return $script:DetectionResult

#endregion
