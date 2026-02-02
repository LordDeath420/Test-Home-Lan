<#
.SYNOPSIS
    Installation_GUI.ps1 - Grafische Oberfläche für das Installationsskript
.DESCRIPTION
    WPF-basierte GUI für Installation.ps1
    Bietet eine benutzerfreundliche Oberfläche für alle Installationsoptionen.
.NOTES
    Version: 1.0.0
    Encoding: UTF-8 mit BOM für Umlaut-Unterstützung
#>

#region Admin-Check
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]"Administrator")) {
    Write-Host "[INFO] Starte das Script erneut als Administrator..." -ForegroundColor Yellow
    $argList = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$PSCommandPath`"")
    try {
        Start-Process -FilePath 'powershell.exe' -ArgumentList $argList -Verb RunAs -WindowStyle Hidden
    } catch {
        [System.Windows.MessageBox]::Show("Konnte nicht als Administrator starten: $($_.Exception.Message)", "Fehler", "OK", "Error")
    }
    return
}
#endregion

#region UTF-8 Encoding
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8
#endregion

#region WPF Assembly laden
Add-Type -AssemblyName PresentationFramework
Add-Type -AssemblyName PresentationCore
Add-Type -AssemblyName WindowsBase
Add-Type -AssemblyName System.Windows.Forms
#endregion

#region Pfade und Konfiguration
$script:ScriptRoot = $PSScriptRoot
$script:MainScript = Join-Path $PSScriptRoot "Installation.ps1"
$script:LogRoot = 'D:\Datein\Macs_und_Mainboards_Logs'
$script:ConfigPath = Join-Path $PSScriptRoot 'Installation.Config.psd1'

# Prüfen ob Hauptskript existiert
if (-not (Test-Path $script:MainScript)) {
    [System.Windows.MessageBox]::Show(
        "Installation.ps1 nicht gefunden!`n`nErwartet unter:`n$($script:MainScript)",
        "Fehler - Hauptskript fehlt",
        "OK",
        "Error"
    )
    exit 1
}
#endregion

#region XAML GUI Definition
[xml]$xaml = @"
<Window
    xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
    xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
    Title="Windows Installation Tool v2.0"
    Height="700" Width="900"
    WindowStartupLocation="CenterScreen"
    Background="#1E1E1E"
    Foreground="White"
    ResizeMode="CanResizeWithGrip">

    <Window.Resources>
        <!-- Button Style -->
        <Style TargetType="Button">
            <Setter Property="Background" Value="#0078D4"/>
            <Setter Property="Foreground" Value="White"/>
            <Setter Property="FontSize" Value="14"/>
            <Setter Property="FontWeight" Value="SemiBold"/>
            <Setter Property="Padding" Value="20,12"/>
            <Setter Property="Margin" Value="5"/>
            <Setter Property="BorderThickness" Value="0"/>
            <Setter Property="Cursor" Value="Hand"/>
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="Button">
                        <Border Background="{TemplateBinding Background}"
                                CornerRadius="4"
                                Padding="{TemplateBinding Padding}">
                            <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/>
                        </Border>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
            <Style.Triggers>
                <Trigger Property="IsMouseOver" Value="True">
                    <Setter Property="Background" Value="#106EBE"/>
                </Trigger>
                <Trigger Property="IsEnabled" Value="False">
                    <Setter Property="Background" Value="#555555"/>
                    <Setter Property="Foreground" Value="#888888"/>
                </Trigger>
            </Style.Triggers>
        </Style>

        <!-- TextBox Style -->
        <Style TargetType="TextBox">
            <Setter Property="Background" Value="#2D2D2D"/>
            <Setter Property="Foreground" Value="White"/>
            <Setter Property="BorderBrush" Value="#3F3F3F"/>
            <Setter Property="BorderThickness" Value="1"/>
            <Setter Property="Padding" Value="8,6"/>
            <Setter Property="FontSize" Value="14"/>
        </Style>

        <!-- ComboBox Style -->
        <Style TargetType="ComboBox">
            <Setter Property="Background" Value="#2D2D2D"/>
            <Setter Property="Foreground" Value="White"/>
            <Setter Property="BorderBrush" Value="#3F3F3F"/>
            <Setter Property="FontSize" Value="14"/>
            <Setter Property="Padding" Value="8,6"/>
        </Style>

        <!-- Label Style -->
        <Style TargetType="Label">
            <Setter Property="Foreground" Value="#CCCCCC"/>
            <Setter Property="FontSize" Value="13"/>
            <Setter Property="Margin" Value="0,5,0,2"/>
        </Style>

        <!-- GroupBox Style -->
        <Style TargetType="GroupBox">
            <Setter Property="BorderBrush" Value="#3F3F3F"/>
            <Setter Property="Foreground" Value="#0078D4"/>
            <Setter Property="FontSize" Value="14"/>
            <Setter Property="FontWeight" Value="SemiBold"/>
            <Setter Property="Margin" Value="10"/>
            <Setter Property="Padding" Value="10"/>
        </Style>
    </Window.Resources>

    <Grid>
        <Grid.RowDefinitions>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="*"/>
            <RowDefinition Height="Auto"/>
        </Grid.RowDefinitions>

        <!-- Header -->
        <Border Grid.Row="0" Background="#0078D4" Padding="20">
            <StackPanel>
                <TextBlock Text="Windows Installation Tool"
                           FontSize="28" FontWeight="Bold" Foreground="White"/>
                <TextBlock Text="Automatisierte Windows-Einrichtung für Desktop, Laptop, NUC und VPN"
                           FontSize="12" Foreground="#B3FFFFFF" Margin="0,5,0,0"/>
            </StackPanel>
        </Border>

        <!-- Main Content -->
        <Grid Grid.Row="1" Margin="10">
            <Grid.ColumnDefinitions>
                <ColumnDefinition Width="*"/>
                <ColumnDefinition Width="*"/>
            </Grid.ColumnDefinitions>

            <!-- Linke Spalte: Gerätetyp und Einstellungen -->
            <StackPanel Grid.Column="0" Margin="10">

                <!-- Gerätetyp Auswahl -->
                <GroupBox Header="🖥️ Gerätetyp">
                    <StackPanel>
                        <RadioButton x:Name="rbRechner" Content="Rechner (Desktop PC)"
                                     Foreground="White" FontSize="14" Margin="5" IsChecked="True" GroupName="DeviceType"/>
                        <RadioButton x:Name="rbBaaske" Content="Baaske (Desktop PC)"
                                     Foreground="White" FontSize="14" Margin="5" GroupName="DeviceType"/>
                        <RadioButton x:Name="rbImportRechner" Content="Import-Rechner (ohne Treiber)"
                                     Foreground="White" FontSize="14" Margin="5" GroupName="DeviceType"/>
                        <RadioButton x:Name="rbNUC" Content="NUC (Intel Mini-PC)"
                                     Foreground="White" FontSize="14" Margin="5" GroupName="DeviceType"/>
                        <RadioButton x:Name="rbLaptop" Content="Laptop / Notebook"
                                     Foreground="White" FontSize="14" Margin="5" GroupName="DeviceType"/>
                        <RadioButton x:Name="rbVPN" Content="VPN-Gerät"
                                     Foreground="White" FontSize="14" Margin="5" GroupName="DeviceType"/>
                    </StackPanel>
                </GroupBox>

                <!-- Rechnerdaten -->
                <GroupBox Header="📝 Rechnerdaten">
                    <StackPanel>
                        <Label Content="Rechnername (max. 15 Zeichen):"/>
                        <TextBox x:Name="txtComputerName" MaxLength="15"/>
                        <TextBlock x:Name="lblNameValidation" Foreground="#FF6B6B" FontSize="11" Margin="5,2,0,0"/>

                        <Label Content="Hardware-ID (z.B. MAC oder SN):"/>
                        <TextBox x:Name="txtHardwareID"/>

                        <Label Content="Ticket-ID:"/>
                        <TextBox x:Name="txtTicketID"/>
                    </StackPanel>
                </GroupBox>

                <!-- Laptop/NUC/VPN spezifisch -->
                <GroupBox x:Name="grpLaptopOptions" Header="📱 Laptop / NUC / VPN Optionen" Visibility="Collapsed">
                    <StackPanel>
                        <Label Content="Modell (z.B. V15 G4 AMN, NUC11TNHi3):"/>
                        <TextBox x:Name="txtModell"/>

                        <Label x:Name="lblStandort" Content="Standort:"/>
                        <ComboBox x:Name="cboStandort">
                            <ComboBoxItem Content="Bochum" IsSelected="True"/>
                            <ComboBoxItem Content="Hattingen"/>
                            <ComboBoxItem Content="Linden"/>
                            <ComboBoxItem Content="Extern"/>
                        </ComboBox>

                        <Label x:Name="lblVpnPassword" Content="VPN-Passwort:" Visibility="Collapsed"/>
                        <PasswordBox x:Name="txtVpnPassword" Background="#2D2D2D" Foreground="White"
                                     BorderBrush="#3F3F3F" Padding="8,6" FontSize="14" Visibility="Collapsed"/>
                    </StackPanel>
                </GroupBox>
            </StackPanel>

            <!-- Rechte Spalte: System-Info und Optionen -->
            <StackPanel Grid.Column="1" Margin="10">

                <!-- System-Info -->
                <GroupBox Header="ℹ️ System-Informationen">
                    <StackPanel>
                        <Grid>
                            <Grid.ColumnDefinitions>
                                <ColumnDefinition Width="Auto"/>
                                <ColumnDefinition Width="*"/>
                            </Grid.ColumnDefinitions>
                            <Grid.RowDefinitions>
                                <RowDefinition Height="Auto"/>
                                <RowDefinition Height="Auto"/>
                                <RowDefinition Height="Auto"/>
                                <RowDefinition Height="Auto"/>
                                <RowDefinition Height="Auto"/>
                            </Grid.RowDefinitions>

                            <TextBlock Grid.Row="0" Grid.Column="0" Text="Aktueller Name:" Foreground="#888" Margin="0,3"/>
                            <TextBlock Grid.Row="0" Grid.Column="1" x:Name="lblCurrentName" Foreground="White" Margin="10,3"/>

                            <TextBlock Grid.Row="1" Grid.Column="0" Text="Hersteller:" Foreground="#888" Margin="0,3"/>
                            <TextBlock Grid.Row="1" Grid.Column="1" x:Name="lblManufacturer" Foreground="White" Margin="10,3"/>

                            <TextBlock Grid.Row="2" Grid.Column="0" Text="Modell:" Foreground="#888" Margin="0,3"/>
                            <TextBlock Grid.Row="2" Grid.Column="1" x:Name="lblModel" Foreground="White" Margin="10,3"/>

                            <TextBlock Grid.Row="3" Grid.Column="0" Text="Mainboard:" Foreground="#888" Margin="0,3"/>
                            <TextBlock Grid.Row="3" Grid.Column="1" x:Name="lblMainboard" Foreground="White" Margin="10,3"/>

                            <TextBlock Grid.Row="4" Grid.Column="0" Text="OS:" Foreground="#888" Margin="0,3"/>
                            <TextBlock Grid.Row="4" Grid.Column="1" x:Name="lblOS" Foreground="White" Margin="10,3"/>
                        </Grid>
                    </StackPanel>
                </GroupBox>

                <!-- Optionen -->
                <GroupBox Header="⚙️ Optionen">
                    <StackPanel>
                        <CheckBox x:Name="chkWhatIf" Content="WhatIf-Modus (nur Simulation)"
                                  Foreground="White" FontSize="13" Margin="5"/>
                        <CheckBox x:Name="chkVerbose" Content="Ausführliche Ausgabe (Verbose)"
                                  Foreground="White" FontSize="13" Margin="5"/>
                    </StackPanel>
                </GroupBox>

                <!-- Letzte Rechnernamen -->
                <GroupBox Header="📋 Letzte Rechnernamen">
                    <ListBox x:Name="lstRecentNames" Height="120"
                             Background="#2D2D2D" Foreground="White" BorderThickness="0"
                             SelectionMode="Single">
                    </ListBox>
                </GroupBox>

                <!-- Weitere Tools -->
                <GroupBox Header="🔧 Weitere Tools">
                    <WrapPanel>
                        <Button x:Name="btnEinstellen" Content="⚙️ Einstellen" Width="130" Padding="10,8"/>
                        <Button x:Name="btnTreiberEntpacken" Content="📦 Treiber entpacken" Width="160" Padding="10,8"/>
                        <Button x:Name="btnWindowsUpdate" Content="🔄 WU Reset" Width="120" Padding="10,8"/>
                    </WrapPanel>
                </GroupBox>
            </StackPanel>
        </Grid>

        <!-- Footer mit Start-Button -->
        <Border Grid.Row="2" Background="#252525" Padding="20">
            <Grid>
                <Grid.ColumnDefinitions>
                    <ColumnDefinition Width="*"/>
                    <ColumnDefinition Width="Auto"/>
                    <ColumnDefinition Width="Auto"/>
                </Grid.ColumnDefinitions>

                <TextBlock x:Name="lblStatus" Grid.Column="0"
                           VerticalAlignment="Center" Foreground="#888888" FontSize="12"/>

                <Button x:Name="btnCancel" Grid.Column="1" Content="Abbrechen"
                        Background="#555555" Width="120" Margin="10,0"/>

                <Button x:Name="btnStart" Grid.Column="2" Content="▶️ Installation starten"
                        Background="#107C10" Width="200">
                    <Button.Style>
                        <Style TargetType="Button" BasedOn="{StaticResource {x:Type Button}}">
                            <Setter Property="Background" Value="#107C10"/>
                            <Style.Triggers>
                                <Trigger Property="IsMouseOver" Value="True">
                                    <Setter Property="Background" Value="#0E6B0E"/>
                                </Trigger>
                            </Style.Triggers>
                        </Style>
                    </Button.Style>
                </Button>
            </Grid>
        </Border>
    </Grid>
</Window>
"@
#endregion

#region Window erstellen
$reader = New-Object System.Xml.XmlNodeReader $xaml
$window = [Windows.Markup.XamlReader]::Load($reader)

# Controls referenzieren
$rbRechner = $window.FindName("rbRechner")
$rbBaaske = $window.FindName("rbBaaske")
$rbImportRechner = $window.FindName("rbImportRechner")
$rbNUC = $window.FindName("rbNUC")
$rbLaptop = $window.FindName("rbLaptop")
$rbVPN = $window.FindName("rbVPN")

$txtComputerName = $window.FindName("txtComputerName")
$lblNameValidation = $window.FindName("lblNameValidation")
$txtHardwareID = $window.FindName("txtHardwareID")
$txtTicketID = $window.FindName("txtTicketID")

$grpLaptopOptions = $window.FindName("grpLaptopOptions")
$txtModell = $window.FindName("txtModell")
$cboStandort = $window.FindName("cboStandort")
$lblStandort = $window.FindName("lblStandort")
$lblVpnPassword = $window.FindName("lblVpnPassword")
$txtVpnPassword = $window.FindName("txtVpnPassword")

$lblCurrentName = $window.FindName("lblCurrentName")
$lblManufacturer = $window.FindName("lblManufacturer")
$lblModel = $window.FindName("lblModel")
$lblMainboard = $window.FindName("lblMainboard")
$lblOS = $window.FindName("lblOS")

$chkWhatIf = $window.FindName("chkWhatIf")
$chkVerbose = $window.FindName("chkVerbose")

$lstRecentNames = $window.FindName("lstRecentNames")

$btnEinstellen = $window.FindName("btnEinstellen")
$btnTreiberEntpacken = $window.FindName("btnTreiberEntpacken")
$btnWindowsUpdate = $window.FindName("btnWindowsUpdate")

$btnCancel = $window.FindName("btnCancel")
$btnStart = $window.FindName("btnStart")
$lblStatus = $window.FindName("lblStatus")
#endregion

#region Hilfsfunktionen
function Update-DeviceOptions {
    $isLaptopNucVpn = $rbLaptop.IsChecked -or $rbNUC.IsChecked -or $rbVPN.IsChecked
    $isVPN = $rbVPN.IsChecked

    if ($isLaptopNucVpn) {
        $grpLaptopOptions.Visibility = "Visible"
    } else {
        $grpLaptopOptions.Visibility = "Collapsed"
    }

    # Standort nur für Laptop und NUC
    if ($rbLaptop.IsChecked -or $rbNUC.IsChecked) {
        $lblStandort.Visibility = "Visible"
        $cboStandort.Visibility = "Visible"
    } else {
        $lblStandort.Visibility = "Collapsed"
        $cboStandort.Visibility = "Collapsed"
    }

    # VPN-Passwort nur für VPN
    if ($isVPN) {
        $lblVpnPassword.Visibility = "Visible"
        $txtVpnPassword.Visibility = "Visible"
    } else {
        $lblVpnPassword.Visibility = "Collapsed"
        $txtVpnPassword.Visibility = "Collapsed"
    }
}

function Test-ComputerNameValid {
    param([string]$Name)

    if ([string]::IsNullOrWhiteSpace($Name)) {
        return @{ Valid = $false; Reason = "Name darf nicht leer sein" }
    }
    if ($Name.Length -gt 15) {
        return @{ Valid = $false; Reason = "Max. 15 Zeichen (aktuell: $($Name.Length))" }
    }
    if ($Name -notmatch '^[a-zA-Z0-9][a-zA-Z0-9\-]{0,13}[a-zA-Z0-9]$' -and $Name.Length -gt 1) {
        return @{ Valid = $false; Reason = "Nur A-Z, 0-9, Bindestrich erlaubt" }
    }
    $reserved = @('LOCALHOST', 'CON', 'PRN', 'AUX', 'NUL', 'COM1', 'COM2', 'COM3', 'COM4', 'LPT1', 'LPT2', 'LPT3')
    if ($reserved -contains $Name.ToUpper()) {
        return @{ Valid = $false; Reason = "Reservierter Name" }
    }
    return @{ Valid = $true; Reason = "" }
}

function Get-SelectedDeviceType {
    if ($rbRechner.IsChecked) { return "Rechner" }
    if ($rbBaaske.IsChecked) { return "Baaske" }
    if ($rbImportRechner.IsChecked) { return "ImportRechner" }
    if ($rbNUC.IsChecked) { return "NUC" }
    if ($rbLaptop.IsChecked) { return "Laptop" }
    if ($rbVPN.IsChecked) { return "VPN" }
    return "Rechner"
}

function Load-RecentComputerNames {
    $lstRecentNames.Items.Clear()

    if (-not (Test-Path $script:LogRoot)) { return }

    $exclude = '(?i)-(Treiber|Fonts|transcript|userdelete|Einstellen)$'
    $files = Get-ChildItem -Path $script:LogRoot -Filter "*.log" -ErrorAction SilentlyContinue |
        Where-Object {
            $_.BaseName -ne 'Installation' -and
            $_.BaseName -notmatch $exclude
        } |
        Sort-Object LastWriteTime -Descending |
        Group-Object BaseName |
        ForEach-Object { $_.Group | Select-Object -First 1 } |
        Select-Object -First 10

    foreach ($file in $files) {
        $item = New-Object System.Windows.Controls.ListBoxItem
        $item.Content = "$($file.BaseName)  ($($file.LastWriteTime.ToString('dd.MM.yyyy HH:mm')))"
        $item.Tag = $file.BaseName
        $lstRecentNames.Items.Add($item)
    }
}

function Load-SystemInfo {
    try {
        $lblCurrentName.Text = $env:COMPUTERNAME

        $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction SilentlyContinue
        $bb = Get-CimInstance -ClassName Win32_BaseBoard -ErrorAction SilentlyContinue
        $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction SilentlyContinue

        if ($cs) {
            $lblManufacturer.Text = $cs.Manufacturer
            $lblModel.Text = $cs.Model
        }
        if ($bb) {
            $lblMainboard.Text = "$($bb.Manufacturer) $($bb.Product)"
        }
        if ($os) {
            $lblOS.Text = "$($os.Caption) (Build $($os.BuildNumber))"
        }
    } catch {
        $lblCurrentName.Text = $env:COMPUTERNAME
        $lblManufacturer.Text = "Fehler beim Laden"
    }
}

function Start-Installation {
    param(
        [string]$Modus,
        [string]$ComputerName,
        [string]$HardwareID,
        [string]$TicketID,
        [string]$Modell,
        [string]$Standort,
        [securestring]$VpnPasswort,
        [switch]$WhatIf,
        [switch]$Verbose
    )

    # Argumente aufbauen
    $args = @(
        "-NoProfile"
        "-ExecutionPolicy", "Bypass"
        "-File", "`"$($script:MainScript)`""
        "-Unattended"
        "-Modus", $Modus
        "-ComputerName", "`"$ComputerName`""
    )

    if ($HardwareID) { $args += @("-HardwareID", "`"$HardwareID`"") }
    if ($TicketID) { $args += @("-TicketID", "`"$TicketID`"") }
    if ($Modell) { $args += @("-Modell", "`"$Modell`"") }
    if ($Standort) { $args += @("-Standort", $Standort) }
    if ($WhatIf) { $args += "-WhatIf" }
    if ($Verbose) { $args += "-VerboseOutput" }

    # Starten
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = "powershell.exe"
    $psi.Arguments = $args -join " "
    $psi.UseShellExecute = $true
    $psi.Verb = "runas"
    $psi.WorkingDirectory = $script:ScriptRoot

    try {
        [System.Diagnostics.Process]::Start($psi) | Out-Null
        $window.Close()
    } catch {
        [System.Windows.MessageBox]::Show(
            "Fehler beim Starten der Installation:`n$($_.Exception.Message)",
            "Fehler",
            "OK",
            "Error"
        )
    }
}
#endregion

#region Event Handler
# Gerätetyp Radio Buttons
$rbRechner.Add_Checked({ Update-DeviceOptions })
$rbBaaske.Add_Checked({ Update-DeviceOptions })
$rbImportRechner.Add_Checked({ Update-DeviceOptions })
$rbNUC.Add_Checked({ Update-DeviceOptions })
$rbLaptop.Add_Checked({ Update-DeviceOptions })
$rbVPN.Add_Checked({ Update-DeviceOptions })

# Rechnername Validierung
$txtComputerName.Add_TextChanged({
    $validation = Test-ComputerNameValid -Name $txtComputerName.Text
    if ($validation.Valid) {
        $lblNameValidation.Text = "[ok] Name gueltig"
        $lblNameValidation.Foreground = "#4CAF50"
    } else {
        $lblNameValidation.Text = "[Error] $($validation.Reason)"
        $lblNameValidation.Foreground = "#FF6B6B"
    }
})

# Doppelklick auf letzte Namen übernimmt diesen
$lstRecentNames.Add_MouseDoubleClick({
    if ($lstRecentNames.SelectedItem) {
        $txtComputerName.Text = $lstRecentNames.SelectedItem.Tag
    }
})

# Tool-Buttons
$btnEinstellen.Add_Click({
    $args = @(
        "-NoProfile"
        "-ExecutionPolicy", "Bypass"
        "-File", "`"$($script:MainScript)`""
        "-Unattended"
        "-Modus", "Einstellen"
        "-ComputerName", "`"$($txtComputerName.Text)`""
    )
    Start-Process powershell.exe -ArgumentList ($args -join " ") -Verb RunAs
})

$btnTreiberEntpacken.Add_Click({
    $args = @(
        "-NoProfile"
        "-ExecutionPolicy", "Bypass"
        "-File", "`"$($script:MainScript)`""
        "-Unattended"
        "-Modus", "TreiberEntpacken"
    )
    Start-Process powershell.exe -ArgumentList ($args -join " ") -Verb RunAs
})

$btnWindowsUpdate.Add_Click({
    $args = @(
        "-NoProfile"
        "-ExecutionPolicy", "Bypass"
        "-File", "`"$($script:MainScript)`""
        "-Unattended"
        "-Modus", "WindowsUpdateReset"
    )
    Start-Process powershell.exe -ArgumentList ($args -join " ") -Verb RunAs
})

# Abbrechen
$btnCancel.Add_Click({
    $window.Close()
})

# Start-Button
$btnStart.Add_Click({
    # Validierung
    $name = $txtComputerName.Text.Trim()
    $validation = Test-ComputerNameValid -Name $name

    if (-not $validation.Valid) {
        [System.Windows.MessageBox]::Show(
            "Ungültiger Rechnername:`n$($validation.Reason)",
            "Validierungsfehler",
            "OK",
            "Warning"
        )
        return
    }

    $deviceType = Get-SelectedDeviceType

    # Modell für Laptop/NUC/VPN prüfen
    if ($deviceType -in @('Laptop', 'NUC', 'VPN')) {
        if ([string]::IsNullOrWhiteSpace($txtModell.Text)) {
            [System.Windows.MessageBox]::Show(
                "Bitte Modell angeben für $deviceType!",
                "Validierungsfehler",
                "OK",
                "Warning"
            )
            return
        }
    }

    # VPN-Passwort prüfen
    if ($deviceType -eq 'VPN') {
        if ($txtVpnPassword.SecurePassword.Length -eq 0) {
            [System.Windows.MessageBox]::Show(
                "Bitte VPN-Passwort angeben!",
                "Validierungsfehler",
                "OK",
                "Warning"
            )
            return
        }
    }

    # Bestätigung
    $standort = ""
    if ($cboStandort.SelectedItem) {
        $standort = $cboStandort.SelectedItem.Content
    }

    $confirmMsg = "Installation starten mit folgenden Einstellungen?`n`n"
    $confirmMsg += "Modus: $deviceType`n"
    $confirmMsg += "Rechnername: $name`n"
    if ($txtHardwareID.Text) { $confirmMsg += "Hardware-ID: $($txtHardwareID.Text)`n" }
    if ($txtTicketID.Text) { $confirmMsg += "Ticket-ID: $($txtTicketID.Text)`n" }
    if ($txtModell.Text) { $confirmMsg += "Modell: $($txtModell.Text)`n" }
    if ($standort -and $deviceType -in @('Laptop', 'NUC')) { $confirmMsg += "Standort: $standort`n" }
    if ($chkWhatIf.IsChecked) { $confirmMsg += "`n⚠️ WHATIF-MODUS (Nur Simulation!)" }

    $result = [System.Windows.MessageBox]::Show(
        $confirmMsg,
        "Installation bestätigen",
        "YesNo",
        "Question"
    )

    if ($result -eq "Yes") {
        $params = @{
            Modus = $deviceType
            ComputerName = $name
            HardwareID = $txtHardwareID.Text
            TicketID = $txtTicketID.Text
        }

        if ($txtModell.Text) { $params.Modell = $txtModell.Text }
        if ($standort -and $deviceType -in @('Laptop', 'NUC')) { $params.Standort = $standort }
        if ($deviceType -eq 'VPN') { $params.VpnPasswort = $txtVpnPassword.SecurePassword }
        if ($chkWhatIf.IsChecked) { $params.WhatIf = $true }
        if ($chkVerbose.IsChecked) { $params.Verbose = $true }

        Start-Installation @params
    }
})

# Window Loaded Event
$window.Add_Loaded({
    Load-SystemInfo
    Load-RecentComputerNames
    Update-DeviceOptions
    $lblStatus.Text = "Bereit - Wählen Sie einen Gerätetyp und geben Sie die Daten ein"
})
#endregion

#region Window anzeigen
$window.ShowDialog() | Out-Null
#endregion