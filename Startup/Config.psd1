# ============================================================================
# Startup/Config.psd1 - Konfiguration fuer Autostart & Monitor-Verwaltung
# ============================================================================
# Dieses File enthaelt KEINE Passwoerter.
# Credentials werden einmalig ueber Setup-Credentials.ps1 im
# Windows Credential Manager (DPAPI-verschluesselt) gespeichert.
# ============================================================================

@{
    # ========================================================================
    # Benutzerkonten (NUR Benutzernamen - KEIN Passwort!)
    # ========================================================================
    ADMUser = 'DOMAIN\adm-benutzername'   # ADM-Konto fuer AD.msc anpassen
    T1User  = 'DOMAIN\t1-benutzername'    # T1-Konto fuer DHCP.msc anpassen

    # ========================================================================
    # Pfade zu den Management-Konsolen (.msc Dateien)
    # ========================================================================
    ADConsolePath   = 'C:\AdminTools\AD.msc'     # Pfad zur AD-Konsole anpassen
    DHCPConsolePath = 'C:\AdminTools\DHCP.msc'   # Pfad zur DHCP-Konsole anpassen

    # ========================================================================
    # Monitor-Zuweisung fuer Management-Konsolen
    # 0 = primaerer Monitor, 1 = zweiter Monitor, 2 = dritter Monitor
    # Monitore ermitteln: [System.Windows.Forms.Screen]::AllScreens | Select DeviceName,Bounds,Primary
    # ========================================================================
    ADMonitor   = 1   # AD-Konsole auf Monitor 2
    DHCPMonitor = 1   # DHCP-Konsole auf Monitor 2

    # Sekunden warten bis Fenster erscheint (Netzwerk-Ladezeit beruecksichtigen)
    WindowWaitSeconds = 6

    # ========================================================================
    # Weitere Autostart-Programme mit Monitor-Zuweisung
    # Prozessname (ohne .exe) -> Ziel-Monitor-Index
    # Fenster werden immer maximiert auf dem Ziel-Monitor
    # ========================================================================
    AutostartMonitors = @{
        # Beispiele - nach Bedarf anpassen:
        # 'chrome'   = 0   # Google Chrome -> Monitor 1 (primaer)
        # 'outlook'  = 0   # Outlook        -> Monitor 1 (primaer)
        # 'teams'    = 1   # MS Teams       -> Monitor 2
        # 'slack'    = 1   # Slack          -> Monitor 2
    }

    # Sekunden nach Login warten, bevor Fenster positioniert werden
    AutostartWaitSeconds = 10
}
