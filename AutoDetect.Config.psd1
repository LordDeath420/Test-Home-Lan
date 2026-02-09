# ============================================================================
# AutoDetect.Config.psd1 - Konfiguration fuer automatische Hardware-Erkennung
# ============================================================================
# Diese Datei steuert:
#   - Pfadstrukturen fuer Treiber
#   - Hardware-Aliase (bekannte Sonderfaelle)
#   - Geraete-Regeln (Pattern-basierte Erkennung)
#   - Medizin-PC Hersteller und Muster
#   - Erweiterbare Zuordnungstabellen
#
# Aenderungen hier vermeiden Aenderungen am Hauptskript.
# ============================================================================

@{
    # -------------------------------------------------------------------------
    # Pfade (relativ zu BasePath, werden vom Skript automatisch aufgeloest)
    # -------------------------------------------------------------------------
    Paths = @{
        TreiberSubPath          = 'treiber'
        TreiberMainboardSubPath = 'treiber\Mainboard'
        TreiberNotebookSubPath  = 'treiber\Notebook'
        TreiberNucSubPath       = 'treiber\NUC'
        TreiberAllinOnePCSubPath= 'treiber\AllinOnePC'
        TreiberMedizinPCSubPath = 'treiber\MedizinPC'
        TreiberMiniPCSubPath    = 'treiber\MiniPC'
        LogSubPath              = 'Macs_und_Mainboards_Logs'
    }

    # -------------------------------------------------------------------------
    # Hardware-Aliase: Exakte Zuordnung von Hersteller+BoardProduct zu Treiberpfad
    # Format: 'Hersteller_BoardProduct' = @{ Path = '...'; Description = '...'; DeviceType = '...' }
    #
    # ERWEITERUNG: Neue Geraete hier eintragen!
    # -------------------------------------------------------------------------
    HardwareAliases = @{
        # Lenovo All-in-One PCs
        'Lenovo_3780' = @{
            Path        = 'AllinOnePC\Lenovo\Neo 50a 24 G5'
            Description = 'Lenovo Neo 50a 24 G5 All-in-One'
            DeviceType  = 'AllinOnePC'
        }

        # Beispiel: Spezieller Medizin-PC
        # 'Onyx_MEDI-19' = @{
        #     Path        = 'MedizinPC\Onyx\MEDI-19'
        #     Description = 'Onyx Healthcare MEDI-19 Medical Panel PC'
        #     DeviceType  = 'MedizinPC'
        # }

        # Beispiel: Baaske Medical
        # 'Baaske_MPC-5100' = @{
        #     Path        = 'MedizinPC\Baaske\MPC-5100'
        #     Description = 'Baaske Medical PC MPC-5100'
        #     DeviceType  = 'MedizinPC'
        # }
    }

    # -------------------------------------------------------------------------
    # Geraete-Regeln: Pattern-basierte Erkennung (geprueft in Reihenfolge!)
    # Felder: Manufacturer, ModelPattern, BoardPattern, ChassisType, DeviceType, Description
    # Leere Felder = wird nicht geprueft (Wildcard)
    #
    # ERWEITERUNG: Neue Erkennungs-Regeln hier eintragen!
    # -------------------------------------------------------------------------
    DeviceRules = @(
        # Intel NUC Modelle (bekannte Muster)
        @{
            Manufacturer = 'Intel'
            ModelPattern = '^NUC'
            BoardPattern = ''
            ChassisType  = $null
            DeviceType   = 'NUC'
            Description  = 'Intel NUC (Modellname beginnt mit NUC)'
        }
        @{
            Manufacturer = ''
            ModelPattern = '^UN\d{2}'
            BoardPattern = ''
            ChassisType  = $null
            DeviceType   = 'NUC'
            Description  = 'NUC mit UN-Modellbezeichnung (z.B. UN62)'
        }

        # Baaske Geraete
        @{
            Manufacturer = 'Baaske'
            ModelPattern = ''
            BoardPattern = ''
            ChassisType  = $null
            DeviceType   = 'Desktop'
            Description  = 'Baaske Medical Geraet (als Desktop)'
        }

        # Shuttle Mini-PCs
        @{
            Manufacturer = 'Shuttle'
            ModelPattern = ''
            BoardPattern = ''
            ChassisType  = $null
            DeviceType   = 'MiniPC'
            Description  = 'Shuttle Mini-PC / Barebone'
        }

        # Lenovo ThinkCentre Tiny (Mini-PC)
        @{
            Manufacturer = 'Lenovo'
            ModelPattern = 'THINKCENTRE.*TINY|THINKSTATION.*TINY'
            BoardPattern = ''
            ChassisType  = $null
            DeviceType   = 'MiniPC'
            Description  = 'Lenovo ThinkCentre/ThinkStation Tiny'
        }
    )

    # -------------------------------------------------------------------------
    # Medizin-PC Hersteller (automatische Erkennung als MedizinPC)
    # Hersteller in dieser Liste werden IMMER als MedizinPC klassifiziert.
    #
    # ERWEITERUNG: Neue Medizin-PC Hersteller hier eintragen!
    # -------------------------------------------------------------------------
    MedizinPCManufacturers = @(
        'Onyx'
        'Tangent'
        'Cybernet'
        'Wincomm'
        'Kontron'
        'Advantech'
        'Beckhoff'
        # 'Elo'           # Elo Touch (wenn als Medizin-PC genutzt)
        # 'MiTAC'         # MiTAC embedded systems
        # 'Arbor'         # Arbor Technology
    )

    # -------------------------------------------------------------------------
    # Medizin-PC Muster: Wenn Modell/Board/Family eines dieser Muster enthaelt
    # wird das Geraet als MedizinPC erkannt.
    #
    # ERWEITERUNG: Neue Muster hier eintragen!
    # -------------------------------------------------------------------------
    MedizinPCPatterns = @(
        'MEDICAL'
        'MED-PC'
        'MEDPC'
        'MEDI'
        'CLINIC'
        'PATIENT'
        'KIOSK'
        'POC'           # Point of Care
        'DENTAL'
        # 'PANEL'       # Zu generisch - auskommentiert
    )

    # -------------------------------------------------------------------------
    # Chassis-Typ Zuordnung (Referenz fuer Erweiterungen)
    # https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/win32-systemenclosure
    # -------------------------------------------------------------------------
    ChassisTypeReference = @{
        Desktop   = @(3, 4, 5, 6, 7, 15, 16, 24)
        Laptop    = @(8, 9, 10, 11, 14, 30, 31, 32)
        MiniPC    = @(35)
        AllInOne  = @(13)
        Server    = @(17, 23)
        Tablet    = @(30, 31, 32)
    }

    # -------------------------------------------------------------------------
    # Hersteller-Normalisierung: Pattern -> Anzeigename
    # -------------------------------------------------------------------------
    ManufacturerPatterns = @{
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

    # -------------------------------------------------------------------------
    # ASUS Board-Normalisierung: Praefixe die entfernt werden
    # -------------------------------------------------------------------------
    BoardPrefixRemoval = @(
        'PRIME'
        'ROG STRIX'
        'TUF GAMING'
        'ProArt'
    )

    # -------------------------------------------------------------------------
    # Treiberinstallation - Installer-Prioritaeten und Silent-Argumente
    # (Identisch mit Installation.Config.psd1 fuer Kompatibilitaet)
    # -------------------------------------------------------------------------
    DriverInstallation = @{
        InstallerPriority = @('setup.exe', 'driversetup.exe', 'asussetup.exe', 'setup.cmd', 'dpinst.exe')

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

        TimeoutSeconds = 1200
    }

    # -------------------------------------------------------------------------
    # Version und Metadaten
    # -------------------------------------------------------------------------
    Version      = '1.0.0'
    LastModified = '2026-02-09'
    Author       = 'IT-Administration'
}
