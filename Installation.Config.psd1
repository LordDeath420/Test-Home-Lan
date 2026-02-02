# ============================================================================
# Installation.ps1 - Zentrale Konfigurationsdatei
# ============================================================================
# Diese Datei enthält alle konfigurierbaren Parameter für das Installationsskript.
# Änderungen hier vermeiden Änderungen am Hauptskript.
# ============================================================================

@{
    # -------------------------------------------------------------------------
    # Basis-Pfade
    # -------------------------------------------------------------------------
    Paths = @{
        BasePath                = 'D:\Datein'
        LogSubPath              = 'Macs_und_Mainboards_Logs'
        InstallationSubPath     = 'Installation\Dokumente'
        FontsSubPath            = 'fonts'
        TreiberSubPath          = 'treiber'
        ProgramSubPath          = 'Installation\Dokumente\Installation von Programmen'
        TreiberMainboardSubPath = 'treiber\Mainboard'
        TreiberNotebookSubPath  = 'treiber\Notebook'
        TreiberNucSubPath       = 'treiber\NUC'
        TreiberAllinOnePCSubPath= 'treiber\AllinOnePC'
    }

    # -------------------------------------------------------------------------
    # Dateien
    # -------------------------------------------------------------------------
    Files = @{
        LayoutXml   = 'LayoutModification.xml'
        WlanPwFile  = 'wlan.txt'
        MakFile     = 'win10Ent-mak.txt'
        AvkReg      = 'AVKCLIENT.reg'
        GDataAgent  = '__windowsfullagent.exe'
        UltraVNC    = 'UltraVNC_1_5_8_X64_Setup.exe'
    }

    # -------------------------------------------------------------------------
    # WLAN-Konfiguration nach Standort
    # -------------------------------------------------------------------------
    WlanProfiles = @{
        Bochum = @{
            AllowedSSIDs  = @('208')
            BlockedSSIDs  = @()
        }
        Hattingen = @{
            AllowedSSIDs  = @('208', '209')
            BlockedSSIDs  = @()
        }
        Linden = @{
            AllowedSSIDs  = @('208', '210')
            BlockedSSIDs  = @()
        }
        Extern = @{
            AllowedSSIDs  = @('IInternet')
            BlockedSSIDs  = @('201', '205', '208', '209', '210', 'medtech', 'medtech_hat',
                             'telemetrie', 'spotmessung', 'motara', 'mortara', 'swisslog',
                             'ExtConf', 'akademie-wlan')
        }
        VPN = @{
            AllowedSSIDs  = @('IInternet')
            BlockedSSIDs  = @('201', '205', '208', '209', '210', 'medtech', 'medtech_hat',
                             'telemetrie', 'spotmessung', 'motara', 'mortara', 'swisslog',
                             'ExtConf', 'akademie-wlan')
        }
    }

    # -------------------------------------------------------------------------
    # Bloatware / Apps zum Entfernen
    # -------------------------------------------------------------------------
    BlockedApps = @(
        'Microsoft.Windows.NarratorQuickStart'
        'Microsoft.BingNews'
        'Microsoft.BingWeather'
        'Microsoft.PowerAutomateDesktop'
        'Microsoft.Windows.Photos'
        'Microsoft.WindowsAlarms'
        'Microsoft.WindowsFeedbackHub'
        'Microsoft.WindowsSoundRecorder'
        'Microsoft.MicrosoftOfficeHub'
        'Microsoft.Xbox.TCUI'
        'Microsoft.XboxGamingOverlay'
        'Microsoft.XboxGameOverlay'
        'Microsoft.XboxGameCallableUI'
        'Microsoft.XboxIdentityProvider'
        'Microsoft.XboxSpeechToTextOverlay'
        'MicrosoftCorporationII.QuickAssist'
        'Microsoft.Windows.Copilot'
        'Clipchamp.Clipchamp'
        'Microsoft.Xbox*'
        'Microsoft.GamingApp'
        'Microsoft.Todos'
        'Microsoft.ScreenSketch'
        'Microsoft.GetHelp'
        'Microsoft.Getstarted'
        'Microsoft.People'
        'Microsoft.YourPhone'
        'Microsoft.WindowsMaps'
        'Microsoft.ZuneMusic'
        'Microsoft.ZuneVideo'
        'Microsoft.MicrosoftSolitaireCollection'
        'Microsoft.MicrosoftStickyNotes'
        'Microsoft.OfficeHub'
        'Microsoft.OutlookForWindows'
        'Microsoft.Teams'
        'Microsoft.CommsPhone'
        'Microsoft.WindowsCommunicationsApps'
        'Microsoft.549981C3F5F10'
        'DolbyLaboratories.DolbyAccess'
        'MicrosoftTeams*'
        'MSTeams*'
        'Microsoft.OneDriveSync'
        'RealtekSemiconductorCorp.RealtekAudioControl*'
        'RealtekSemiconductorCorp.RealtekAudioConsole*'
        'DolbyLaboratories.DolbyAudio*'
        'DolbyLaboratories.Dolby*'
    )

    # -------------------------------------------------------------------------
    # WLAN-Adapter-Einstellungen
    # -------------------------------------------------------------------------
    WlanAdapterSettings = @{
        'Wireless Mode'           = 'IEEE 802.11a/n/ac'
        'Roaming Sensitivity Level' = 'Middle'
        'Preferred Band'          = 'Prefer 5GHz'
    }

    # -------------------------------------------------------------------------
    # Treiberinstallation
    # -------------------------------------------------------------------------
    DriverInstallation = @{
        # Priorität der Installer-Dateien (von hoch zu niedrig)
        InstallerPriority = @('setup.exe', 'driversetup.exe', 'asussetup.exe', 'setup.cmd', 'dpinst.exe')

        # Silent-Argumente für verschiedene Installer-Typen
        SilentArguments = @(
            '/S'
            '/silent'
            '/verysilent'
            '/quiet'
            '/quiet /norestart'
            '/passive'
            '/passive /norestart'
            '/s /v"/qn REBOOT=ReallySuppress"'
            '/v"/qn REBOOT=ReallySuppress"'
            '/qn REBOOT=ReallySuppress'
            '/norestart /quiet'
            '/install /quiet /norestart'
        )

        # Timeout in Sekunden
        TimeoutSeconds = 1200
    }

    # -------------------------------------------------------------------------
    # Logging-Konfiguration
    # -------------------------------------------------------------------------
    Logging = @{
        MaxLogSizeMB     = 5
        KeepLogRotations = 3
        LogLevels        = @('INFO', 'WARN', 'ERROR', 'SUCCESS')
    }

    # -------------------------------------------------------------------------
    # Spezielle Hardware-Aliase
    # -------------------------------------------------------------------------
    HardwareAliases = @{
        # Lenovo All-in-One PCs
        'Lenovo_3780' = @{
            Path = 'AllinOnePC\Lenovo\Neo 50a 24 G5'
            Description = 'Lenovo Neo 50a 24 G5 All-in-One'
        }
    }

    # -------------------------------------------------------------------------
    # Geschützte Benutzerkonten (niemals löschen)
    # -------------------------------------------------------------------------
    ProtectedUsers = @(
        'Administrator'
        'DefaultAccount'
        'Guest'
        'WDAGUtilityAccount'
        'SYSTEM'
        'LocalService'
        'NetworkService'
    )

    # -------------------------------------------------------------------------
    # UltraVNC-Einstellungen
    # -------------------------------------------------------------------------
    UltraVNC = @{
        DisableTrayIcon    = $true
        AuthRequired       = $true
        QuerySetting       = 2  # Benutzer kann annehmen/ablehnen
    }

    # -------------------------------------------------------------------------
    # Version und Metadaten
    # -------------------------------------------------------------------------
    Version = '2.0.0'
    LastModified = '2026-02-01'
    Author = 'IT-Administration'
}
