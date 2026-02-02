# ============================================================================
# Installation.Credentials.ps1 - Sichere Passwort-Verwaltung
# ============================================================================
# WICHTIG: Diese Datei enthält sensible Daten!
# - Nicht in Versionskontrolle einchecken (.gitignore)
# - Zugriffsrechte auf Administratoren beschränken
# - Regelmäßig Passwörter rotieren
# ============================================================================

# -------------------------------------------------------------------------
# Option 1: Verschlüsselte Passwörter (empfohlen für Produktion)
# -------------------------------------------------------------------------
# Passwörter können mit folgendem Befehl verschlüsselt werden:
# "MeinPasswort" | ConvertTo-SecureString -AsPlainText -Force | ConvertFrom-SecureString | Set-Clipboard
# Das verschlüsselte Passwort kann dann hier eingefügt werden.
# HINWEIS: Verschlüsselung ist maschinenspezifisch (DPAPI)!

# -------------------------------------------------------------------------
# Option 2: Klartext-Passwörter (nur für Entwicklung/Test)
# -------------------------------------------------------------------------
# WARNUNG: Nur verwenden wenn die Datei sicher geschützt ist!

$script:Credentials = @{
    # Administrator-Passwort
    AdminPassword = '@aka@'

    # VNC-Passwort
    VncPassword = 'qakaqq'

    # Verschlüsselte Variante (Beispiel - muss auf dem Zielsystem generiert werden):
    # AdminPasswordSecure = '01000000d08c9ddf0115d1118c7a00c04fc297eb...'
}

# -------------------------------------------------------------------------
# Funktionen zum Abrufen der Credentials
# -------------------------------------------------------------------------
function Get-InstallationCredential {
    <#
        Ruft ein Passwort aus der Credentials-Konfiguration ab.
        Unterstützt sowohl Klartext als auch verschlüsselte Passwörter.
    #>
    param(
        [Parameter(Mandatory)]
        [ValidateSet('Admin', 'VNC')]
        [string]$CredentialType,

        [switch]$AsSecureString
    )

    $password = switch ($CredentialType) {
        'Admin' { $script:Credentials.AdminPassword }
        'VNC'   { $script:Credentials.VncPassword }
    }

    if (-not $password) {
        Write-Warning "Kein Passwort für '$CredentialType' konfiguriert!"
        return $null
    }

    if ($AsSecureString) {
        return (ConvertTo-SecureString -String $password -AsPlainText -Force)
    }

    return $password
}

# -------------------------------------------------------------------------
# Funktion zum Erstellen verschlüsselter Passwörter (für Admins)
# -------------------------------------------------------------------------
function New-EncryptedPassword {
    <#
        Erstellt ein verschlüsseltes Passwort für die Konfigurationsdatei.
        HINWEIS: Verschlüsselung ist maschinenspezifisch!
    #>
    param(
        [Parameter(Mandatory)]
        [string]$PlainPassword
    )

    $secure = ConvertTo-SecureString -String $PlainPassword -AsPlainText -Force
    $encrypted = ConvertFrom-SecureString -SecureString $secure

    Write-Host "Verschlüsseltes Passwort (für diese Maschine):" -ForegroundColor Cyan
    Write-Host $encrypted -ForegroundColor Green
    Write-Host ""
    Write-Host "Diesen String in die Credentials-Datei einfügen." -ForegroundColor Yellow

    return $encrypted
}

# -------------------------------------------------------------------------
# Export der Funktionen
# -------------------------------------------------------------------------
Export-ModuleMember -Function Get-InstallationCredential, New-EncryptedPassword -ErrorAction SilentlyContinue
