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
    ADMUser    = 'DOMAIN\adm-benutzername'   # ADM-Konto fuer AD.msc anpassen
    T1User     = 'DOMAIN\t1-benutzername'    # T1-Konto fuer DHCP.msc anpassen

    # DHCP-Server Hostname/IP (fuer zweiten Credential-Eintrag im Snap-In)
    DHCPServer = 'srv-dhcp01'                # DHCP-Server-Name anpassen

    # ========================================================================
    # Pfade zu den Management-Konsolen (.msc Dateien)
    # ========================================================================
    ADConsolePath   = 'C:\AdminTools\AD.msc'     # Pfad zur AD-Konsole anpassen
    DHCPConsolePath = 'C:\AdminTools\DHCP.msc'   # Pfad zur DHCP-Konsole anpassen

    # ========================================================================
    # Monitor-Zuweisung fuer Management-Konsolen
    # 0 = primaerer Monitor, 1 = zweiter Monitor, 2 = dritter Monitor
    # ========================================================================
    ADMonitor   = 1   # AD-Konsole auf Monitor 2
    DHCPMonitor = 1   # DHCP-Konsole auf Monitor 2

    # Fenstergroesse der Konsolen (Pixel)
    WindowWidth  = 1400
    WindowHeight = 900

    # Sekunden warten bis Fenster erscheint (Netzwerk-Ladezeit beruecksichtigen)
    WindowWaitSeconds = 6

    # ========================================================================
    # Weitere Autostart-Programme mit Monitor-Zuweisung
    # Prozessname (ohne .exe) -> Ziel-Monitor-Index
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
