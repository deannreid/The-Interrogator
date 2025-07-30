<#
.SYNOPSIS
    Interrogator - AD CUG Checker

.DESCRIPTION
    A lightweight PowerShell script for querying Active Directory users, groups, and computers.
    Works even on non-domain joined machines, as long as DNS and LDAP ports are accessible.
    
    Allows you to:
    - Inspect AD accounts and assets with readable formatting.
    - Highlight key AD properties like admin rights and logon permissions.
    - Save named presets of users, groups, or computers to run checks quickly in future.
    - Supports different check types (User, Group, Asset) and smart domain selection.
    - [Planned] Detect weak ACLs such as GenericAll or GenericWrite.

.PARAMETER None
    The script is interactive and does not require command-line parameters.

.NOTES
    Author  : Dean
    Version : 1.0
    License : Who?

.LINK
    https://github.com/deannreid/TheInterrogator
#>

#===========#
# Variables #
#===========#
$MIN_POWERSHELL_VERSION = "7.0"
$ADMIN_REQUIRED = $false  # Set this to $false if admin privileges are not required
$jsonFilePath = "$env:USERPROFILE\.ADChecker5000\config.json"  # Updated to use environment variable
Clear-Host
$BANNER = @"
___________.__             .___        __                                           __                  _______________  _______  ____ 
\__    ___/|  |__   ____   |   | _____/  |_  __________________  ____   _________ _/  |_  ___________  /   __   \   _  \ \   _  \/_   |
  |    |   |  |  \_/ __ \  |   |/    \   __\/ __ \_  __ \_  __ \/  _ \ / ___\__  \\   __\/  _ \_  __ \ \____    /  /_\  \/  /_\  \|   |
  |    |   |   Y  \  ___/  |   |   |  \  | \  ___/|  | \/|  | \(  <_> ) /_/  > __ \|  | (  <_> )  | \/    /    /\  \_/   \  \_/   \   |
  |____|   |___|  /\___  > |___|___|  /__|  \___  >__|   |__|   \____/\___  (____  /__|  \____/|__|      /____/  \_____  /\_____  /___|
                \/     \/           \/          \/                   /_____/     \/                                    \/       \/                                         
                                        The Interrogator 9001 - Irn Bru Edition
                                It's just a script, that does things with Active Directory
                                --------------------------------------------------
                                ::         %INSERT RELEVANT DISCORD HERE        ::
                                :: https://github.com/deannreid/TheInterrogator ::
                                --------------------------------------------------
"@

$BLURBS = @(
    "	  		Enumerating services: Like snooping through your neighbor's Wi-Fi, but legal.`n`n",
    "	  		Exploring services: The geek's way of saying 'I'm just curious!'`n`n",
    "		  	Discovering endpoints: Like a treasure hunt, but with more IP addresses.`n`n",
    "		  	Probing the depths: Finding the juicy bits your network's been hiding.`n`n",
    "		  	Scanning the landscape: Seeking out vulnerabilities like a digital archaeologist.`n`n",
    "		  	Uncovering paths: It's like finding secret doors in your favorite video game.`n`n",
    "		  	Shining a flashlight: Because every network has its dark corners.`n`n",
    "	  		Looking under the hood: What's powering this thing, anyway?`n`n",
    "		  	Investigating ports: Is it a door or a trap? Only one way to find out!`n`n",
    "		  	Mapping the maze: The only labyrinth where every wrong turn could be enlightening.`n`n",
    "		  	Cracking the code: Every endpoint is a puzzle waiting to be solved.`n`n",
    "		  	Poking the firewall: Let's see if it's really as tough as it claims.`n`n",
    "	  		Scanning quietly: Shhh… Don't wake up the IDS!`n`n",
    "		  	Going undercover: Like a ninja, but with packets.`n`n",
    "		  	Breaking down barriers: Who said firewalls are impassable?`n`n",
    "		  	Interpreting signals: Turning noise into insight, one packet at a time.`n`n"
)

#===========#
# Functions #
#===========#

function fncPrintMessage {
    param (
        [string]$message,
        [ValidateSet("info", "success", "warning", "error", "disabled", "default")]
        [string]$type = "info"
    )

    switch ($type) {
        "info"     { Write-Host "[~] $message" -ForegroundColor Cyan }
        "success"  { Write-Host "[OK] $message" -ForegroundColor Green }
        "warning"  { Write-Host "[!] $message" -ForegroundColor Yellow }
        "error"    { Write-Host "[FAIL] $message" -ForegroundColor Red }
        "disabled" { Write-Host "[#] $message" -ForegroundColor DarkGray }
        default    { Write-Host "[-] $message" -ForegroundColor White }
    }
}


function fncPrintBanner {
    # Print Banner and Version Information
    Write-Host $BANNER -ForegroundColor Cyan
    
    # Print Random Blurb from $BLURBS
    $randomBlurb = Get-Random -InputObject $BLURBS
    Write-Host $randomBlurb
}

function fncCheckPSVersion {

    $psVersion = [version]$PSVersionTable.PSVersion
    $minRequired = [version]$MIN_POWERSHELL_VERSION

    fncPrintMessage "PowerShell Version Detected: $($psVersion.ToString())" "info"

    $IsPS5 = ($psVersion.Major -lt 7)

    if ($psVersion -lt $minRequired) {
        fncPrintMessage "This script requires PowerShell $MIN_POWERSHELL_VERSION or higher." "error"

        if ($IsPS5) {
            fncPrintMessage "You're running in Windows PowerShell 5.x. This script is designed for PowerShell 7+." "warning"

            $pwshPath = Get-Command pwsh.exe -ErrorAction SilentlyContinue

            if (-not $pwshPath) {
                fncPrintMessage "PowerShell 7 not found on this system." "warning"
                $install = Read-Host "Would you like to install PowerShell 7 now? (Y/N)"
                if ($install -match "^(Y|y)") {
                    fncInstallPS7
                    fncPrintMessage "Please rerun the script using PowerShell 7 (`pwsh.exe`). Exiting now." "info"
                    Exit 0
                } else {
                    fncPrintMessage "Cannot proceed without PowerShell 7. Exiting." "error"
                    Exit 1
                }
            } else {
                fncPrintMessage "PowerShell 7 is installed. Relaunching the script in PowerShell 7..." "info"
                Start-Process -FilePath $pwshPath.Source -ArgumentList "-NoExit", "-File", "`"$PSCommandPath`""
                Exit 0
            }
        } else {
            fncPrintMessage "Unexpected version state. Cannot continue." "error"
            Exit 1
        }
    }
}

function fncCheckGodMode {
	function fncCheckIsAdmin {
		$isAdmin = [Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
		return $isAdmin.IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
	}
    if ($ADMIN_REQUIRED) {
        if (-not (fncCheckIsAdmin)) {
            fncPrintMessage "This script requires administrative privileges. Please run it as an administrator or with elevated permissions." "error"
            Exit 1
        }
    } else {
        fncPrintMessage "Admin privileges are not required for this script." "info"
    }
}

function fncInstallPS7 {
    fncPrintMessage "Installing PowerShell 7..." "info"

    $arch = if ([Environment]::Is64BitOperatingSystem) { "x64" } else { "x86" }
    $installerURL = "https://github.com/PowerShell/PowerShell/releases/latest/download/PowerShell-7.4.0-win-$arch.msi"
    $installerPath = "$env:TEMP\pwsh7-install.msi"

    try {
        fncPrintMessage "Downloading PowerShell 7 MSI from $installerURL" "info"
        Invoke-WebRequest -Uri $installerURL -OutFile $installerPath -UseBasicParsing -ErrorAction Stop
        fncPrintMessage "Installing MSI..." "info"
        Start-Process "msiexec.exe" -ArgumentList "/i `"$installerPath`" /quiet /norestart" -Wait -NoNewWindow
        fncPrintMessage "PowerShell 7 installed successfully." "success"
    } catch {
        fncPrintMessage "Installation failed. Reason: $_" "error"
        fncPrintMessage "This may be due to a proxy, firewall, or permissions issue." "warning"

        $tryBrowse = Read-Host "Do you want to manually browse to an installed pwsh.exe file? (Y/N)"
        if ($tryBrowse -match "^(Y|y)") {
            Add-Type -AssemblyName System.Windows.Forms

            $fileDialog = New-Object System.Windows.Forms.OpenFileDialog
            $fileDialog.Title = "Select pwsh.exe"
            $fileDialog.Filter = "PowerShell Executable|pwsh.exe"
            $fileDialog.InitialDirectory = "C:\Program Files\PowerShell"

            if ($fileDialog.ShowDialog() -eq "OK" -and (Test-Path $fileDialog.FileName)) {
                fncPrintMessage "Found pwsh.exe at $($fileDialog.FileName). Relaunching script..." "success"
                Start-Process -FilePath $fileDialog.FileName -ArgumentList "-NoExit", "-File", "`"$PSCommandPath`""
                Exit 0
            } else {
                fncPrintMessage "No valid pwsh.exe selected. Cannot continue." "error"
                Exit 1
            }
        } else {
            fncPrintMessage "Cannot continue without PowerShell 7. Exiting." "error"
            Exit 1
        }
    }
}

function fncCheckModules {
    fncPrintMessage "Checking required PowerShell modules..." "info"

    #========================#
    #--- ActiveDirectory ----#
    #========================#
    fncPrintMessage "Checking for Active Directory module..." "info"

    # First, try importing from previously saved path
    if ($global:config.ADModulePath -and (Test-Path (Join-Path $global:config.ADModulePath 'ActiveDirectory.psd1'))) {
        try {
            $psd1Path = Join-Path $global:config.ADModulePath 'ActiveDirectory.psd1'
            Import-Module -Name $psd1Path -ErrorAction Stop
            fncPrintMessage "✔ Loaded AD module from saved path in config." "success"
            return
        } catch {
            fncPrintMessage "⚠ Failed to import AD module from saved path: $_" "warning"
        }
    }

    # Check if module is available normally
    $adModule = Get-Module -ListAvailable -Name ActiveDirectory
    if ($adModule) {
        try {
            Import-Module ActiveDirectory -ErrorAction Stop
            fncPrintMessage "✔ Active Directory module imported successfully." "success"

            $global:config.ADModulePath = $adModule.Path
            fncSaveConfig -jsonFilePath $jsonFilePath -config $global:config
            return
        } catch {
            fncPrintMessage "⚠ Module found but failed to load: $_" "warning"
        }
    }

    fncPrintMessage "⚠ Active Directory module not found. Attempting to install..." "warning"

    try {
        if (Get-Command Add-WindowsCapability -ErrorAction SilentlyContinue) {
            Add-WindowsCapability -Online -Name "Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0" -ErrorAction Stop
            Import-Module ActiveDirectory -ErrorAction Stop

            $global:config.ADModulePath = (Get-Module -Name ActiveDirectory).Path
            fncPrintMessage "✔ Installed and imported Active Directory module via RSAT." "success"
            fncSaveConfig -jsonFilePath $jsonFilePath -config $global:config
            return

        } elseif (Get-Command Install-WindowsFeature -ErrorAction SilentlyContinue) {
            Install-WindowsFeature -Name "RSAT-AD-PowerShell" -IncludeAllSubFeature -IncludeManagementTools -ErrorAction Stop
            Import-Module ActiveDirectory -ErrorAction Stop

            $global:config.ADModulePath = (Get-Module -Name ActiveDirectory).Path
            fncPrintMessage "✔ Installed and imported AD module on server." "success"
            fncSaveConfig -jsonFilePath $jsonFilePath -config $global:config
            return
        } else {
            throw "No supported method to install Active Directory module found."
        }
    } catch {
        fncPrintMessage "❌  Failed to install AD module: $_" "error"
        $tryLocal = Read-Host "Use local .\Modules\ActiveDirectory instead? (Y/N)"
        if ($tryLocal -match "^(Y|y)$") {
            # Robust detection of script path
            if ($MyInvocation.MyCommand.Path) {
                $scriptRoot = Split-Path -Path $MyInvocation.MyCommand.Path
            } elseif ($PSScriptRoot) {
                $scriptRoot = $PSScriptRoot
            } else {
                $scriptRoot = (Get-Location).Path
                fncPrintMessage "[WARN] Script path could not be detected. Using current directory: $scriptRoot" "warning"
            }

            $localSource = Join-Path -Path $scriptRoot -ChildPath "Modules\ActiveDirectory"
            $userModulePath = Join-Path -Path "$env:USERPROFILE\Documents\WindowsPowerShell\Modules" -ChildPath "ActiveDirectory"

            if (Test-Path (Join-Path $localSource 'ActiveDirectory.psd1')) {
                try {
                    if (-not (Test-Path $userModulePath)) {
                        fncPrintMessage "Copying local AD module to your user module folder..." "info"
                        New-Item -Path $userModulePath -ItemType Directory -Force | Out-Null
                        Copy-Item -Path "$localSource\*" -Destination $userModulePath -Recurse -Force
                    }

                    $psd1Path = Join-Path -Path $userModulePath -ChildPath "ActiveDirectory.psd1"
                    Import-Module -Name $psd1Path -ErrorAction Stop
                    fncPrintMessage "✔  Loaded AD module from: $userModulePath" "success"

                    $global:config.ADModulePath = $userModulePath
                    fncSaveConfig -jsonFilePath $jsonFilePath -config $global:config
                    return
                } catch {
                    fncPrintMessage "❌  Failed to move or import local module: $_" "error"
                    Exit 1
                }
            } else {
                fncPrintMessage "❌  Local module not found at: $localSource" "error"
                Exit 1
            }
        } else {
            fncPrintMessage "❌  Cannot continue without Active Directory module. Exiting." "error"
            Exit 1
        }
    }

    #========================#
    #--- Placeholder: Cloud Modules ---#
    #========================#
    $enableCloudModules = $false
    if ($enableCloudModules) {
        fncPrintMessage "Checking for AzureAD/Entra ID modules... (Not enabled)" "disabled"
        fncPrintMessage "Checking for AWS modules... (Not enabled)" "disabled"
        fncPrintMessage "Checking for GCP modules... (Not enabled)" "disabled"
    }
}

function fncSaveConfig {
    param (
        [string]$jsonFilePath,
        [hashtable]$config
    )
    try {
        $jsonContent = $config | ConvertTo-Json -Depth 10
        $jsonContent | Out-File -FilePath $jsonFilePath -Encoding UTF8
        fncPrintMessage "Configuration saved successfully." "success"
    } catch {
        fncPrintMessage "Error saving configuration. Details: $_" "error"
    }
}

function fncLoadConfig {
    param (
        [string]$jsonFilePath
    )

    if (Test-Path -Path $jsonFilePath) {
        try {
            $jsonRaw = Get-Content -Path $jsonFilePath -Raw
            $jsonContent = $jsonRaw | ConvertFrom-Json
            fncPrintMessage "Configuration loaded successfully." "success"

            # Convert PSCustomObject to Hashtable
            $hashtable = @{}
            $jsonContent.PSObject.Properties | ForEach-Object {
                $hashtable[$_.Name] = $_.Value
            }
            return $hashtable
        } catch {
            fncPrintMessage "Error loading configuration. Loading default settings." "warning"
            return $null
        }
    } else {
        fncPrintMessage "No config file found. Initializing with default values." "warning"
        return $null
    }
}

function fncConfigureAdminNaming {
    Write-Host "`n[+] Admin Naming Configuration" -ForegroundColor Cyan

    # --- Local Admin Group Naming ---
    $deviceAdminGroups = @()

    $hasNamingScheme = Read-Host "Do you have a naming scheme for Local Admin Groups? (Y/N)"
    if ($hasNamingScheme -match "^(Y|y)$") {
        Write-Host "`nExample: GRP_HOSTNAME_LAdmin or GRP_HOSTNAME_SAdmin" -ForegroundColor Yellow
        Write-Host "IMPORTANT: You *must* use the keyword 'HOSTNAME' in your group naming scheme." -ForegroundColor Red

        while ($true) {
            $inputPattern = Read-Host "Enter a group name pattern with 'HOSTNAME' (Leave blank to finish)"
            if ([string]::IsNullOrWhiteSpace($inputPattern)) { break }

            if ($inputPattern -notmatch "HOSTNAME") {
                Write-Host "❌ Pattern must contain the keyword 'HOSTNAME'!" -ForegroundColor Red
            } else {
                $deviceAdminGroups += $inputPattern
                Write-Host "✔ Added: $inputPattern" -ForegroundColor Green
            }
        }
    }

    # --- Tiered Admin Accounts ---
    $adminAccounts = @()
    $hasTiered = Read-Host "`nDo you use tiered admin accounts? (e.g., _A0, _A1, _A2) (Y/N)"
    if ($hasTiered -match "^(Y|y)$") {
        $position = Read-Host "Does the tier suffix/prefix go BEFORE or AFTER the user ID? (Enter 'before' or 'after')"
        while ($true) {
            $tier = Read-Host "Enter a tier identifier (e.g., _A0 or T0_) (Leave blank to finish)"
            if ([string]::IsNullOrWhiteSpace($tier)) { break }

            if ($position -match "before") {
                $adminAccounts += "$tier*"
            } elseif ($position -match "after") {
                $adminAccounts += "*$tier"
            } else {
                Write-Host "❌ Invalid position specified. Please restart the function and enter 'before' or 'after'." -ForegroundColor Red
                break
            }

            Write-Host "✔ Added match pattern: $($adminAccounts[-1])" -ForegroundColor Green
        }
    }

    # Output summary
    Write-Host "`n[✓] Final Configuration Summary:" -ForegroundColor Cyan
    Write-Host "Device Admin Group Patterns:" -ForegroundColor Yellow
    $deviceAdminGroups | ForEach-Object { Write-Host " - $_" -ForegroundColor DarkCyan }

    Write-Host "Tiered Admin Account Patterns:" -ForegroundColor Yellow
    $adminAccounts | ForEach-Object { Write-Host " - $_" -ForegroundColor DarkCyan }

    # Return result
    return @{
        DeviceAdminGroups = $deviceAdminGroups
        AdminAccounts     = $adminAccounts
    }
}

function fncConfigurePrivilegedGroups {
    Write-Host "`n[+] Custom High Privileged Group Configuration" -ForegroundColor Cyan
    Write-Host "You can define corporate high-priv groups in addition to defaults like 'Domain Admins'." -ForegroundColor Yellow
    Write-Host "Examples: 'CyberSec Admins', 'Server Operators', 'Tier 0 Teams'"

    $customGroups = @()

    while ($true) {
        $groupInput = Read-Host "Enter a high-priv group name (Leave blank to finish)"
        if ([string]::IsNullOrWhiteSpace($groupInput)) { break }

        $customGroups += $groupInput
        Write-Host "✔ Added: $groupInput" -ForegroundColor Green
    }

    if ($customGroups.Count -eq 0) {
        Write-Host "[~] No custom groups added." -ForegroundColor DarkGray
    } else {
        Write-Host "`n[✓] Custom High Priv Groups:" -ForegroundColor Cyan
        $customGroups | ForEach-Object { Write-Host " - $_" -ForegroundColor DarkCyan }
    }

    return $customGroups
}


function fncInitConfig {
    fncPrintMessage "Initializing configuration..." "info"

    $global:config = fncLoadConfig -jsonFilePath $jsonFilePath

    if (-not $global:config) {
        $deviceAdminGroups = @()
        $adminAccounts = @()




        $global:config = @{
            DEBUG_ENABLED      = $false
            IS_SETUP           = $false
            ADVANCED_MODE      = $false
            deviceAdminGroups  = $deviceAdminGroups
            adminAccounts      = $adminAccounts
            modulePath         = ""
            cloudModulesEnabled = $false
            LAST_KWN_DOM       = ""
            LAST_KWN_USR       = ""
            userItems = @{
                userGroupPreset1 = @("")
            }
        }

        fncSaveConfig -jsonFilePath $jsonFilePath -config $global:config
        fncPrintMessage "Default configuration created and saved." "success"
    }

    return $global:config
}

#================#
#   Main Logic   #
#================#

fncPrintBanner
fncCheckPSVersion
fncCheckGodMode

# Load or initialize configuration
$config = fncInitConfig -jsonFilePath $jsonFilePath
if (-not $config) {
    fncPrintMessage "Failed to load or initialize config. Exiting." "error"
    exit 1
}

# Prompt user for admin naming schemes
$adminConfig = fncConfigureAdminNaming
$global:config.deviceAdminGroups = $adminConfig.DeviceAdminGroups
$global:config.adminAccounts     = $adminConfig.AdminAccounts

# Prompt for custom high-priv groups
$privGroups = fncConfigurePrivilegedGroups
$global:config.privilegedGroups = $privGroups

fncSaveConfig -jsonFilePath $jsonFilePath -config $global:config


# Check and install modules if needed
fncCheckModules

# Mark setup complete
$global:config["IS_SETUP"] = $true
fncSaveConfig -jsonFilePath $jsonFilePath -config $global:config

fncPrintMessage "Setup complete. You may now run 'The Interrogator'." "success"
