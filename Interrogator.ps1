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
    "	 	Enumerating services: Like snooping through your neighbor's Wi-Fi, but legal.`n`n",
    "	 	Exploring services: The geek's way of saying 'I'm just curious!'`n`n",
    "	 	Discovering endpoints: Like a treasure hunt, but with more IP addresses.`n`n",
    "	  	Probing the depths: Finding the juicy bits your network's been hiding.`n`n",
    "	  	Scanning the landscape: Seeking out vulnerabilities like a digital archaeologist.`n`n",
    "	  	Uncovering paths: It's like finding secret doors in your favorite video game.`n`n",
    "	  	Shining a flashlight: Because every network has its dark corners.`n`n",
    "		Looking under the hood: What's powering this thing, anyway?`n`n",
    "     	Investigating ports: Is it a door or a trap? Only one way to find out!`n`n",
    "	  	Mapping the maze: The only labyrinth where every wrong turn could be enlightening.`n`n",
    "	  	Cracking the code: Every endpoint is a puzzle waiting to be solved.`n`n",
    "	  	Poking the firewall: Let's see if it's really as tough as it claims.`n`n",
    "  		Scanning quietly: Shhh… Don't wake up the IDS!`n`n",
    "	  	Going undercover: Like a ninja, but with packets.`n`n",
    "	  	Breaking down barriers: Who said firewalls are impassable?`n`n",
    "	  	Interpreting signals: Turning noise into insight, one packet at a time.`n`n"
)

#===========#
# Functions #
#===========#

function fncPrintMessage {
    param (
        [string]$message,
        [ValidateSet("info", "success", "warning", "error", "disabled", "debug", "default")]
        [string]$type = "info"
    )

    switch ($type) {
        "info"     { Write-Host "[~] $message" -ForegroundColor Cyan }
        "success"  { Write-Host "[✓] $message" -ForegroundColor Green }
        "warning"  { Write-Host "[!] $message" -ForegroundColor Yellow }
        "error"    { Write-Host "[X] $message" -ForegroundColor Red }
        "disabled" { Write-Host "[#] $message" -ForegroundColor DarkGray }
        "debug"    {
            if ($global:config.DEBUG_ENABLED -eq $true) {
                Write-Host "[#] [DEBUG] $message" -ForegroundColor DarkGray
            }
        }
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

function fncInitConfig {
    param (
        [string]$jsonFilePath
    )

    if (Test-Path $jsonFilePath) {
        fncPrintMessage "Config file detected at '$jsonFilePath'" "debug"

        try {
            $json = Get-Content $jsonFilePath -Raw | ConvertFrom-Json
            $global:config = $json

            # Debug print size of config file
            $configSize = (Get-Item $jsonFilePath).Length
            fncPrintMessage "Loaded config file (${configSize} bytes)" "debug"

            # Backward compatibility: define globals if present
            if ($json.LAST_KWN_DOM) {
                $global:LAST_KWN_DOM = $json.LAST_KWN_DOM
                fncPrintMessage "LAST_KWN_DOM set to '$($global:LAST_KWN_DOM)'" "debug"
            }

            if ($json.LAST_KWN_USR) {
                $global:LAST_KWN_USR = $json.LAST_KWN_USR
                fncPrintMessage "LAST_KWN_USR set to '$($global:LAST_KWN_USR)'" "debug"
            }

            fncPrintMessage "Configuration successfully loaded." "debug"
            return $json
        } catch {
            fncPrintMessage "Failed to parse config file: $_" "error"
            exit 1
        }
    } else {
        fncPrintMessage "Configuration file not found at $jsonFilePath" "error"
        exit 1
    }
}

function fncSaveConfig {
    param (
        [string]$jsonFilePath = $global:jsonFilePath,
        $config
    )

    if (-not $jsonFilePath -or [string]::IsNullOrWhiteSpace($jsonFilePath)) {
        if ($global:jsonFilePath) {
            $jsonFilePath = $global:jsonFilePath
        } else {
            throw "No valid jsonFilePath provided or found in global scope."
        }
    }

    try {
        # Fallback if jsonFilePath not passed
        if (-not $jsonFilePath) {
            if ($global:jsonFilePath) {
                $jsonFilePath = $global:jsonFilePath
            } elseif ($script:jsonFilePath) {
                $jsonFilePath = $script:jsonFilePath
            } else {
                throw "No valid path for config file provided."
            }
        }

        # Force userItems into a hashtable if not already
        if ($config.PSObject.Properties.Name -contains 'userItems') {
            if ($config.userItems -isnot [hashtable]) {
                $converted = @{}
                foreach ($prop in $config.userItems.PSObject.Properties) {
                    $converted[$prop.Name] = $prop.Value
                }
                $config.userItems = $converted
            }
        } else {
            $config | Add-Member -MemberType NoteProperty -Name userItems -Value @{}
        }

        # Convert and write JSON
        $json = $config | ConvertTo-Json -Depth 10
        Set-Content -Path $jsonFilePath -Value $json -Encoding UTF8

        if ($config.DEBUG) {
            fncPrintMessage "Saved config to $jsonFilePath" "debug"
        }
    } catch {
        fncPrintMessage "Failed to save config: $_" "error"
    }
}

function fncCheckPSVersion {
    # Detect and Check PowerShell Version
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
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object Security.Principal.WindowsPrincipal($identity)
        $isAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

        fncPrintMessage "[DEBUG] Current user: $($identity.Name)" "debug"
        fncPrintMessage "[DEBUG] Is admin: $isAdmin" "debug"
        return $isAdmin
    }

    fncPrintMessage "[DEBUG] ADMIN_REQUIRED is set to '$ADMIN_REQUIRED'" "debug"

    if ($ADMIN_REQUIRED) {
        if (-not (fncCheckIsAdmin)) {
            fncPrintMessage "This script requires administrative privileges. Please run it as an administrator or with elevated permissions." "error"
            Exit 1
        } else {
            fncPrintMessage "Running with administrative privileges." "info"
        }
    } else {
        fncPrintMessage "Admin privileges are not required for this script." "info"
    }
}

function fncCheckModules {
    fncPrintMessage "Checking for required PowerShell modules..." "info"

    $enableCloudModules = $false

    if ($enableCloudModules) {
        fncPrintMessage "Checking for AzureAD/Entra ID modules... (Not enabled)" "disabled"
        fncPrintMessage "Checking for AWS modules...              (Not enabled)" "disabled"
        fncPrintMessage "Checking for GCP modules...              (Not enabled)" "disabled"
    }

    # Check if AD module is already loaded
    if (Get-Module -Name ActiveDirectory) {
        fncPrintMessage "Active Directory module already loaded." "success"
        return
    }

    fncPrintMessage "AD module not yet loaded, checking config path..." "debug"

    # Attempt to import from config-defined path
    if ($global:config.ADModulePath -and (Test-Path $global:config.ADModulePath)) {
        fncPrintMessage "Found AD module path in config: $($global:config.ADModulePath)" "debug"
        try {
            Import-Module -Name $global:config.ADModulePath -ErrorAction Stop
            fncPrintMessage "Loaded AD module from saved config path." "success"
            return
        } catch {
            fncPrintMessage "Failed to import AD module from saved path: $($_.Exception.Message)" "warning"
        }
    }

    # Check user profile path
    $moduleRoot = "$env:USERPROFILE\Documents\WindowsPowerShell\Modules\ActiveDirectory"
    $psd1Path = Join-Path -Path $moduleRoot -ChildPath "ActiveDirectory.psd1"
    fncPrintMessage "Checking user profile module path: $psd1Path" "debug"

    if (Test-Path $psd1Path) {
        try {
            Import-Module -Name $psd1Path -ErrorAction Stop
            fncPrintMessage "Loaded AD module from user profile modules directory." "success"
            $global:config.ADModulePath = $psd1Path
            fncSaveConfig -jsonFilePath $jsonFilePath -config $global:config
            return
        } catch {
            fncPrintMessage "Failed to load module from user modules dir: $($_.Exception.Message)" "error"
        }
    } else {
        fncPrintMessage "AD module not found in user profile directory." "debug"
    }

    # Final fallback
    fncPrintMessage "Attempting fallback import from system module path..." "debug"
    try {
        Import-Module ActiveDirectory -ErrorAction Stop
        fncPrintMessage "Active Directory module loaded from system." "success"
        $global:config.ADModulePath = (Get-Module -Name ActiveDirectory).Path
        fncSaveConfig -jsonFilePath $jsonFilePath -config $global:config
        return
    } catch {
        fncPrintMessage "Active Directory module is missing or failed to load." "error"
        fncPrintMessage "Please run 'installer.ps1' to install and configure required modules." "warning"
        Exit 1
    }
}

function fncLoadPSDrive {
    fncPrintMessage "Attempting to load config from $jsonFilePath" "info"

    $configPath = $jsonFilePath
    $config = if (Test-Path $configPath) {
        fncPrintMessage "Config file found at $configPath" "debug"
        Get-Content $configPath -Raw | ConvertFrom-Json -AsHashtable
    } else {
        fncPrintMessage "Config file not found. Using empty config." "debug"
        @{ }
    }

    $useAlways = $false
    $DOMAIN = ""
    $username = ""

    if ($config.USR_ALWAYS_REMEMBER -eq $true -and $config.LAST_KWN_DOM -and $config.LAST_KWN_USR) {
        fncPrintMessage "Using saved credentials (USR_ALWAYS_REMEMBER is true)" "debug"
        $DOMAIN = $config.LAST_KWN_DOM
        $username = $config.LAST_KWN_USR
        $useAlways = $true
    } else {
        # Ask to reuse domain
        if ($config.LAST_KWN_DOM) {
            $reuseDom = Read-Host "Do you want to use the last known domain ($($config.LAST_KWN_DOM))? (Y/N)"
            $DOMAIN = if ($reuseDom -match "^(Y|y)$|^$") {
                $config.LAST_KWN_DOM
            } else {
                Read-Host "Please enter the expected domain name (e.g., DOMAIN.COM)"
            }
        } else {
            $DOMAIN = Read-Host "Please enter the expected domain name (e.g., DOMAIN.COM)"
        }

        if ([string]::IsNullOrWhiteSpace($DOMAIN)) {
            fncPrintMessage "No domain provided. Exiting AD connectivity check." "error"
            return
        }

        if ($config.LAST_KWN_USR) {
            $reuseUser = Read-Host "Do you want to use the last known username ($($config.LAST_KWN_USR))? (Y/N)"
            $username = if ($reuseUser -match "^(Y|y)$|^$") {
                $config.LAST_KWN_USR
            } else {
                Read-Host "Enter your domain username"
            }
        } else {
            $username = Read-Host "Enter your domain username"
        }
    }

    # Discover DC
    fncPrintMessage "Attempting nltest /dsgetdc:$DOMAIN" "debug"
    $nltestOutput = nltest /dsgetdc:$DOMAIN 2>&1
    $dcHost = ($nltestOutput | Where-Object { $_ -match 'DC:' }) -replace '.*DC:\s*',''
    $dcHost = $dcHost -replace '^\\\\', ''

    if (-not $dcHost) {
        fncPrintMessage "Failed to find a Domain Controller for $DOMAIN." "error"
        return
    }

    fncPrintMessage "Extracted DC Host: $dcHost" "debug"
    fncPrintMessage "Resolving DC hostname: $dcHost" "info"
    $nslookup = nslookup $dcHost 2>&1
    if ($nslookup -match 'Name:|Address:') {
        fncPrintMessage "DC hostname resolved successfully." "success"
    } else {
        fncPrintMessage "Failed to resolve DC hostname using nslookup." "error"
        return
    }

    # Login retry logic
    $authenticated = $false
    $attempts = 0
    $maxAttempts = 5

    while (-not $authenticated -and $attempts -lt $maxAttempts) {
        $attempts++
        $securePassword = Read-Host "Enter password for $DOMAIN\$username" -AsSecureString
        $cred = New-Object System.Management.Automation.PSCredential ("$DOMAIN\$username", $securePassword)

        try {
            $driveName = ($DOMAIN.Split('.')[0])
            fncPrintMessage "Attempting PSDrive mount: $driveName@$dcHost" "debug"
            New-PSDrive -Name $driveName -PSProvider ActiveDirectory -Root "//RootDSE/" -Credential $cred -Server $dcHost -ErrorAction Stop | Out-Null

            fncPrintMessage "Connected to $DOMAIN successfully." "success"
            $authenticated = $true

            # Ask to save settings if not already remembered
            if (-not $useAlways) {
                $remember = Read-Host "Do you want to remember this configuration and auto-load it in future? (Y/n)"
                if ($remember -match "^(Y|y)$|^$") {
                    $config.LAST_KWN_DOM = $DOMAIN
                    $config.LAST_KWN_USR = $username
                    $config.USR_ALWAYS_REMEMBER = $true
                    fncPrintMessage "Settings will be remembered for future use." "info"
                } else {
                    fncPrintMessage "Settings not remembered." "info"
                }

                $config | ConvertTo-Json -Depth 10 | Out-File -FilePath $configPath -Encoding UTF8
            }

            # Set globals
            $global:dcHost = $dcHost
            $global:domainMap = @{ }
            $global:domainMap[$DOMAIN] = $dcHost

            fncPrintMessage "Global DC host set: $dcHost" "debug"
        }
        catch {
            fncPrintMessage "[X] Authentication failed: Username or Password is incorrect." "error"
            if ($attempts -lt $maxAttempts) {
                $retry = Read-Host "Try again? (Y/n)"
                if ($retry -match "^(N|n)$") {
                    fncPrintMessage "Authentication aborted by user." "warn"
                    return
                }
            } else {
                fncPrintMessage "[!] Multiple failed login attempts. Your account may become locked out if this continues." "warn"
                return
            }
        }
    }
}

function fncUpdateDomainSettings {
    fncPrintMessage "Resolving domain controller for current domain..." "debug"

    $domain = $global:config.LAST_KWN_DOM
    if (-not $domain) {
        fncPrintMessage "Current domain not set in config." "error"
        return
    }

    try {
        fncPrintMessage "Running nltest to get DC for $domain" "debug"

        $nltestOutput = nltest /dsgetdc:$domain 2>&1
        $dcHost = ($nltestOutput | Where-Object { $_ -match 'DC:' }) -replace '.*DC:\s*',''
        $dcHost = $dcHost -replace '^\\\\', ''

        if (-not $dcHost) {
            fncPrintMessage "Failed to resolve domain controller for $domain." "error"
            return
        }

        fncPrintMessage "Parsed DC host: $dcHost" "debug"

        # Save to global map
        $global:domainMap = @{}
        $global:domainMap[$domain] = $dcHost
        fncPrintMessage "Setting domain map and updating config" "debug"

        $global:config.LAST_KWN_DOM = $domain
        if (-not $global:config.LAST_KWN_USR) {
            $global:config.LAST_KWN_USR = ""
        }

        fncPrintMessage "Resolved existing domain in config: $domain | DC Host: $dcHost" "debug"

        # Save config
        fncSaveConfig -jsonFilePath $jsonFilePath -config $global:config
    } catch {
        fncPrintMessage "Error resolving domain controller: $_" "error"
    }
}

function fncPresetRunner {
    # Ensure userItems is a hashtable
    if ($global:config.userItems -isnot [hashtable]) {
        $global:config.userItems = @{} + $global:config.userItems
    }

    $presets = $global:config.userItems.Keys | Where-Object {
        $_ -notmatch '_TYPE$' -and
        $global:config.userItems[$_] -is [System.Collections.IEnumerable] -and
        $global:config.userItems[$_].Count -gt 0
    }

    if (-not $presets -or $presets.Count -eq 0) {
        fncPrintMessage "No preset groups available to select." "warning"
        return
    }

    Write-Host "`nAvailable Presets:" -ForegroundColor Cyan
    $index = 1
    $menuMap = @{}
    foreach ($preset in $presets) {
        $typeKey = "${preset}_TYPE"
        $type = if ($global:config.userItems.ContainsKey($typeKey)) { 
            $global:config.userItems[$typeKey] 
        } else { 
            "Unknown" 
        }
        Write-Host ("{0}. {1} ({2})" -f $index, $preset, $type) -ForegroundColor Yellow
        $menuMap[$index] = $preset
        $index++
    }

    $selection = Read-Host "`nChoose a preset to view (1-$($menuMap.Count))"
    if ($selection -notmatch '^\d+$' -or -not $menuMap.ContainsKey([int]$selection)) {
        fncPrintMessage "Invalid selection." "error"
        return
    }

    $selectedPreset = $menuMap[[int]$selection]
    $runnerKey = "${selectedPreset}_TYPE"

    if (-not $global:config.userItems.ContainsKey($runnerKey)) {
        fncPrintMessage "Preset '$selectedPreset' has no associated function type." "error"
        return
    }

    $runner = $global:config.userItems[$runnerKey]
    $items = $global:config.userItems[$selectedPreset]

    fncPrintMessage "Resolving preset '$selectedPreset' using '$runner'" "info"

    $resolvedItems = @()
    $itemIndex = 1
    foreach ($item in $items) {
        if ([string]::IsNullOrWhiteSpace($item)) { continue }

        try {
            switch ($runner) {
                'fncGetUserInfo' {
                    $user = Get-ADUser -Identity $item -Server $global:dcHost -Properties GivenName, Surname
                    Write-Host "$itemIndex. $($user.SamAccountName) ($($user.GivenName) $($user.Surname))" -ForegroundColor Green
                }
                'fncCheckComputerInfo' {
                    $comp = Get-ADComputer -Identity $item -Server $global:dcHost
                    Write-Host "$itemIndex. $($comp.Name) [Computer]" -ForegroundColor Yellow
                }
                'fncGetGroupInfo' {
                    $group = Get-ADGroup -Identity $item -Server $global:dcHost
                    Write-Host "$itemIndex. $($group.Name) [Group]" -ForegroundColor Cyan
                }
                default {
                    Write-Host "$itemIndex. $item" -ForegroundColor Magenta
                }
            }
            $resolvedItems += $item
            $itemIndex++
        } catch {
            Write-Host "$itemIndex. $item (lookup failed)" -ForegroundColor DarkGray
            $resolvedItems += $item
            $itemIndex++
        }
    }

    if ($resolvedItems.Count -eq 0) {
        fncPrintMessage "No valid items to run." "warning"
        return
    }

    $itemChoice = Read-Host "`nSelect an item to run (1-$($resolvedItems.Count))"
    if ($itemChoice -notmatch '^\d+$' -or [int]$itemChoice -lt 1 -or [int]$itemChoice -gt $resolvedItems.Count) {
        fncPrintMessage "Invalid item selection." "error"
        return
    }

    $selectedItem = $resolvedItems[[int]$itemChoice - 1]
    fncPrintMessage "→ Running '$runner' on: $selectedItem" "info"

    try {
        switch ($runner) {
            'fncGetUserInfo'        { fncGetUserInfo -user $selectedItem }
            'fncCheckComputerInfo'  { fncCheckComputerInfo -device $selectedItem }
            'fncGetGroupInfo'       { fncGetGroupInfo -group $selectedItem }
            default {
                fncPrintMessage "Unknown function type: $runner" "error"
                return
            }
        }
    } catch {
        fncPrintMessage "Error running $runner on $selectedItem : $_" "error"
    }

    fncPrintMessage "✔ Completed execution on: $selectedItem" "success"
}

##############################
### Main Application Logic ###
##############################

############################################################
#### Get User Info
function fncGetUserInfo {
    param (
        [string]$user
    )

    try {
        # Hardcoded privileged groups
        $builtinPrivilegedGroups = @(
            "Domain Admins",
            "Enterprise Admins",
            "Administrators",
            "Schema Admins",
            "Account Operators",
            "Server Operators",
            "Backup Operators"
        )

        # Optional user-defined privileged groups from config
        $userDefinedPrivilegedGroups = @()
        if ($global:config.PSObject.Properties.Name -contains "privilegedGroups") {
            $userDefinedPrivilegedGroups = $global:config.privilegedGroups
        }

        # Combined privilege group list
        $privilegedGroups = $builtinPrivilegedGroups + $userDefinedPrivilegedGroups
 
        # Fuzzy matching patterns
        $privilegedPatterns = @("admin", "super admin", "sudo", "root", "priv", "power", "cyberark", "restricted", "elevateduser", "rdp")

        # Retrieve user details
        $userDetails = Get-ADUser -Server $global:dcHost -Identity $user -Properties DistinguishedName, Name, GivenName, Surname, ObjectClass, SamAccountName, UserPrincipalName, LastLogonDate, Enabled, BadPwdCount, Manager, Secretary, LockedOut

        if (-not $userDetails) {
            fncPrintMessage "User not found." "error"
            return
        }

        # Display basic info
        Write-Host "====================================="
        Write-Host -NoNewline "User: " -ForegroundColor Green; Write-Host "$($userDetails.Name)"
        Write-Host -NoNewline "Name: " -ForegroundColor Green; Write-Host "$($userDetails.GivenName) $($userDetails.Surname)"
        Write-Host -NoNewline "DistinguishedName: " -ForegroundColor Green; Write-Host "$($userDetails.DistinguishedName)"
        Write-Host -NoNewline "ObjectClass: " -ForegroundColor Green; Write-Host "$($userDetails.ObjectClass)"
        Write-Host -NoNewline "SamAccountName: " -ForegroundColor Green; Write-Host "$($userDetails.SamAccountName)"
        Write-Host -NoNewline "UserPrincipalName: " -ForegroundColor Green; Write-Host "$($userDetails.UserPrincipalName)"
        Write-Host -NoNewline "Last Logon Date: " -ForegroundColor Green; Write-Host "$($userDetails.LastLogonDate)"
        Write-Host -NoNewline "Enabled: " -ForegroundColor Green; Write-Host "$($userDetails.Enabled)"
        Write-Host -NoNewline "Locked: " -ForegroundColor Green; Write-Host "$($userDetails.LockedOut)"
        Write-Host -NoNewline "Failed Password Attempts: " -ForegroundColor Green; Write-Host "$($userDetails.BadPwdCount)"
        Write-Host ""

        # Manager and Secretary
        Write-Host -NoNewline "Managed By: " -ForegroundColor Green
        if ($userDetails.Manager) {
            $managerDetails = Get-ADUser -Server $global:dcHost -Identity $userDetails.Manager -Properties Name, GivenName, Surname
            Write-Host "$($managerDetails.GivenName) $($managerDetails.Surname) - $($managerDetails.Name)"
        } else {
            Write-Host "No manager assigned"
        }

        Write-Host -NoNewline "Deputy Manager: " -ForegroundColor Green
        if ($userDetails.Manager) {
            $managerDetails = Get-ADUser -Server $global:dcHost -Identity $userDetails.Manager -Properties Name, GivenName, Surname, Manager
            if ($managerDetails.Manager) {
                $deputyDetails = Get-ADUser -Server $global:dcHost -Identity $managerDetails.Manager -Properties Name, GivenName, Surname
                if ($deputyDetails) {
                    Write-Host "$($deputyDetails.GivenName) $($deputyDetails.Surname) - $($deputyDetails.Name)"
                } else {
                    Write-Host "Deputy manager not found"
                }
            } else {
                Write-Host "Deputy manager not found"
            }
        } else {
            Write-Host "No manager assigned, so no deputy"
        }

        do {
            Write-Host "===================================================" -ForegroundColor Cyan
            Write-Host ""

            Write-Host "===================================================" -ForegroundColor Cyan
            Write-Host "            🔧 Advanced User Tools Menu           " -ForegroundColor Cyan
            Write-Host "                Target User:" -ForegroundColor Yellow -NoNewline
            Write-Host " $($userDetails.Name)" -ForegroundColor Red
            Write-Host "===================================================" -ForegroundColor Cyan

            Write-Host ""
            Write-Host " 1) 🔥 Kerberoast this user"
            Write-Host " 2) 🧾 AS-REP Roasting check"
            Write-Host " 3) 🔐 Generate AES Keys (AES128/AES256)"
            Write-Host " 4) 🎭 View SPNs for this user"
            Write-Host ""
            Write-Host " 5) 📔 View Group Memberships"
            Write-Host " 6) 🧬 View Nested Membershiops"
            Write-Host " 6) 🎛️ Check Delegation (Unconstrained, Constrained, RBCD)"
            Write-Host " 7) 👑 Find Admin Account Variants (e.g. *_ADM, *_T1)"
            Write-Host ""
            Write-Host " 8) 🏛️ Check if user owns/modifies privileged groups"
            Write-Host " 9) 🧾 View Effective Group Token SIDs"
            Write-Host "10) 🔁 Reset password path check (who can reset this user)"
            Write-Host "11) 💉 Pass-The-Hash / Ticket simulation (offline only)"
            Write-Host "12) 📚 Dump full group DN tree"
            Write-Host ""

            Write-Host ""
            $userToolChoice = Read-Host "Select an option or press [Enter] to return to main menu"

            switch ($userToolChoice) {
                '1' {
                    fncCheckASRepRoast -user $userDetails.SamAccountName
                }
                '2' {
                    try {
                        fncPrintMessage "Checking AS-REP roasting eligibility for user: $user" "info"

                        # Get the user object and check the 'DoesNotRequirePreAuth' flag
                        $userObject = Get-ADUser -Server $global:dcHost -Identity $userDetails.SamAccountName -Properties DoesNotRequirePreAuth, UserPrincipalName, SamAccountName

                        if (-not $userObject) {
                            fncPrintMessage "User not found: $user" "error"
                            return
                        }

                        fncPrintMessage "UserPrincipalName: $($userObject.UserPrincipalName)" "debug"
                        fncPrintMessage "SamAccountName:    $($userObject.SamAccountName)" "debug"
                        fncPrintMessage "DoesNotRequirePreAuth: $($userObject.DoesNotRequirePreAuth)" "debug"

                        if ($userObject.DoesNotRequirePreAuth) {
                            Write-Host "[!] 🔥 User '$($userObject.SamAccountName)' is vulnerable to AS-REP Roasting!" -ForegroundColor Red
                            Write-Host "Use tools like Rubeus or GetNPUsers to request an AS-REP hash." -ForegroundColor Yellow
                        } else {
                            Write-Host "[+] ✅ User '$($userObject.SamAccountName)' does NOT have DONT_REQ_PREAUTH set." -ForegroundColor Green
                        }
                    }
                    catch {
                        fncPrintMessage "Error while checking AS-REP roast eligibility: $_" "error"
                    }                   
                }
                "3" {
                    try {
                        Write-Host "`n[🔐] Kerberos Key Cracker Selected" -ForegroundColor Cyan
                        # Pass the user’s samAccountName and UPN domain to the function
                        $sam = $userDetails.SamAccountName
                        $domainName = ($userDetails.UserPrincipalName -split '@')[-1]

                        # Ask if it's a computer account
                        $isHost = $false
                        if ($sam.EndsWith('$')) {
                            $askHost = Read-Host "Looks like a computer account. Treat as host? (Y/N)"
                            if ($askHost -match '^(Y|y)') {
                                $isHost = $true
                            }
                        }

                        # Ask if user wants to enter password or use wordlist
                        Write-Host "`nHow would you like to input the password?" -ForegroundColor Cyan
                        Write-Host "1) Manual input"
                        Write-Host "2) Select a wordlist file"
                        $pwChoice = Read-Host "Choose an option (1/2)"

                        $passwords = @()
                        if ($pwChoice -eq "1") {
                            $plainPW = Read-Host "Enter cleartext password"
                            if ($plainPW) { $passwords += $plainPW }
                        }
                        elseif ($pwChoice -eq "2") {
                            Add-Type -AssemblyName System.Windows.Forms
                            $fileDialog = New-Object System.Windows.Forms.OpenFileDialog
                            $fileDialog.Filter = "Text files (*.txt)|*.txt|All files (*.*)|*.*"
                            $fileDialog.Title = "Select Wordlist File"
                            if ($fileDialog.ShowDialog() -eq "OK") {
                                $passwords = Get-Content $fileDialog.FileName
                            }
                        }

                        foreach ($pw in $passwords) {
                            fncGenerateKerberosAESKeys -domain $domainName -username $sam -password $pw -isHost:$isHost
                        }

                    } catch {
                        fncPrintMessage "Error in AES Key Generation: $_" "error"
                    }

                    Read-Host "Press Enter to return to the menu..."
                }
                '4' {
                    fncViewSPNs -identity $userDetails.SamAccountName
                    return
                }
                '5' {
                    # Group Membership Breakdown
                    Write-Host "-------------------------------------"
                    Write-Host "Currently Applied Groups:`n"
                    Write-Host "Key:"
                    Write-Host "Group Name             - Yellow" -ForegroundColor Yellow
                    Write-Host "Domain Component (DC)  - DarkBlue" -ForegroundColor DarkBlue
                    Write-Host "Organisational Unit    - White"
                    Write-Host ""
                    Write-Host "Mailbox/Distribution Group    - [~] + Cyan" -ForegroundColor Cyan
                    Write-Host "High Priv Group               - [!] + Red" -ForegroundColor Red
                    Write-Host "-------------------------------------"

                    $userGroupsDN = Get-ADUser -Server $global:dcHost -Identity $user -Properties MemberOf | Select-Object -ExpandProperty MemberOf

                    $groupObjects = @()
                    foreach ($groupDN in $userGroupsDN) {
                        $parts = $groupDN -split ','
                        $groupName = ($parts[0] -replace '^CN=')
                        $groupNameLower = $groupName.ToLower()

                        $isPrivGroup = $false
                        if ($privilegedGroups -contains $groupName) {
                            $isPrivGroup = $true
                        } elseif ($privilegedPatterns | Where-Object { $groupNameLower -like "*$($_.ToLower())*" }) {
                            $isPrivGroup = $true
                        }

                        $isMailOrDL = (
                            ($groupDN -match 'OU=Distribution Groups') -or
                            ($groupName -like '*$*') -or
                            ($groupName -like '*distribution*')
                        )

                        $groupObjects += [PSCustomObject]@{
                            Name         = $groupName
                            DN           = $groupDN
                            IsPrivileged = $isPrivGroup
                            IsMailGroup  = $isMailOrDL
                        }
                    }

                    $sortedPriv   = $groupObjects | Where-Object { $_.IsPrivileged } | Sort-Object Name
                    $sortedNormal = $groupObjects | Where-Object { (-not $_.IsPrivileged) -and (-not $_.IsMailGroup) } | Sort-Object Name
                    $mailGroups   = $groupObjects | Where-Object { $_.IsMailGroup } | Sort-Object Name

                    if ($sortedPriv.Count -gt 0) {
                        Write-Host "`n[!] High Privilege Groups:" -ForegroundColor Red
                        Write-Host "================================================"
                        foreach ($group in $sortedPriv) {
                            $parts = $group.DN -split ','
                            foreach ($part in $parts) {
                                if ($part -like "CN=*") {
                                    Write-Host "[!] $($group.Name)" -ForegroundColor Red -NoNewline
                                } elseif ($part -like "DC=*") {
                                    Write-Host ",$part" -ForegroundColor DarkBlue -NoNewline
                                } else {
                                    Write-Host ",$part" -ForegroundColor White -NoNewline
                                }
                            }
                            Write-Host ""
                        }
                    }

                    if ($sortedNormal.Count -gt 0) {
                        Write-Host "`n[-] Standard Groups:" -ForegroundColor Yellow
                        Write-Host "================================================"
                        foreach ($group in $sortedNormal) {
                            $parts = $group.DN -split ','
                            foreach ($part in $parts) {
                                if ($part -like "CN=*") {
                                    Write-Host "$($group.Name)" -ForegroundColor Yellow -NoNewline
                                } elseif ($part -like "DC=*") {
                                    Write-Host ",$part" -ForegroundColor DarkBlue -NoNewline
                                } else {
                                    Write-Host ",$part" -ForegroundColor White -NoNewline
                                }
                            }
                            Write-Host ""
                        }
                    } else {
                        Write-Host "`n[-] No standard groups found." -ForegroundColor DarkGray
                    }

                    if ($mailGroups.Count -gt 0) {
                        Write-Host "`n[~] Mailboxes and Distribution Lists:" -ForegroundColor Cyan
                        foreach ($g in $mailGroups) {
                            foreach ($p in $g.DN -split ',') {
                                if ($p -like "CN=*") {
                                    Write-Host "[~] $($g.Name)" -ForegroundColor Cyan -NoNewline
                                } elseif ($p -like "DC=*") {
                                    Write-Host ",$p" -ForegroundColor DarkBlue -NoNewline
                                } else {
                                    Write-Host ",$p" -ForegroundColor White -NoNewline
                                }
                            }
                            Write-Host ""
                        }
                    }
                }
                '6' {
                }
                '7' {
                # Admin account discovery (based on config.adminAccounts)
                if ($global:config.PSObject.Properties.Name -contains 'adminAccounts' -and $global:config.adminAccounts.Count -gt 0) {
                    Write-Host "`n[🔎] Searching for matching admin accounts..." -ForegroundColor Cyan

                    $foundAdminAccounts = @()
                    foreach ($suffix in $global:config.adminAccounts) {
                        $pattern = "$($userDetails.SamAccountName)$suffix"
                        try {
                            $adminAccount = Get-ADUser -Server $global:dcHost -Filter "SamAccountName -like '$pattern'" -Properties SamAccountName, DisplayName, Enabled, LastLogonDate, MemberOf

                            if ($adminAccount) {
                                $foundAdminAccounts += $adminAccount
                            }
                        } catch {
                            Write-Host "[-] Failed to query admin account pattern: $pattern" -ForegroundColor DarkGray
                        }
                    }

                    if ($foundAdminAccounts.Count -gt 0) {
                        foreach ($acc in $foundAdminAccounts) {
                            Write-Host "`n[!] Admin Account Found:" -ForegroundColor Green
                            Write-Host "   SamAccountName : $($acc.SamAccountName)"
                            Write-Host "   Display Name   : $($acc.DisplayName)"
                            Write-Host "   Enabled        : $($acc.Enabled)"
                            Write-Host "   Last Logon     : $($acc.LastLogonDate)"

                            # Group memberships
                            if ($acc.MemberOf.Count -gt 0) {
                                Write-Host "   Group Memberships:"
                                foreach ($groupDN in $acc.MemberOf) {
                                    $groupName = ($groupDN -split ',')[0] -replace '^CN='
                                    Write-Host "      - $groupName" -ForegroundColor Yellow
                                }
                            } else {
                                Write-Host "   Group Memberships: None found." -ForegroundColor DarkGray
                            }
                        }
                    } else {
                        Write-Host "[~] No admin accounts found using defined suffixes." -ForegroundColor DarkGray
                    }
                }
                }
                '8' {
                    try {
                        Write-Host "`n[🏛️] Checking if $($userDetails.SamAccountName) manages or deputies any groups..." -ForegroundColor Cyan

                        # Get all groups with ManagedBy set
                        $allGroups = Get-ADGroup -Server $global:dcHost -Filter * -Properties ManagedBy | Where-Object { $_.ManagedBy }
                        $total = $allGroups.Count
                        if ($total -eq 0) {
                            Write-Host "[~] No groups with ManagedBy set in this domain." -ForegroundColor DarkGray
                            return
                        }

                        # Cache all users once
                        $allUsers = Get-ADUser -Server $global:dcHost -Filter * -Properties SamAccountName, Manager |
                                    Select-Object DistinguishedName, SamAccountName, Manager

                        # Show initial status
                        Write-Progress -Activity "Scanning AD Groups" -Status "[0/$total] Initialising ..." -PercentComplete 0

                        # Run in parallel but don’t handle progress inside threads
                        $results = $allGroups | ForEach-Object -Parallel {
                            param($grp, $allUsers, $userSam)

                            $output = $null
                            $manager = $allUsers | Where-Object { $_.DistinguishedName -eq $grp.ManagedBy }
                            if ($manager) {
                                if ($manager.SamAccountName -eq $userSam) {
                                    $output = [PSCustomObject]@{ GroupName = $grp.Name; Type = "Direct" }
                                }
                                elseif ($manager.Manager) {
                                    $deputy = $allUsers | Where-Object { $_.DistinguishedName -eq $manager.Manager }
                                    if ($deputy.SamAccountName -eq $userSam) {
                                        $output = [PSCustomObject]@{ GroupName = $grp.Name; Type = "Deputy" }
                                    }
                                }
                            }
                            return $output
                        } -ThrottleLimit 20 -ArgumentList $allUsers, $userDetails.SamAccountName

                        # Now update progress in parent as we process results
                        $count = 0
                        foreach ($grp in $allGroups) {
                            $count++
                            $percent = [math]::Round(($count / $total) * 100, 2)
                            Write-Progress -Activity "Scanning AD Groups" -Status "[$count/$total] Processing $($grp.Name)" -PercentComplete $percent
                        }

                        # Clear progress
                        Write-Progress -Activity "Scanning AD Groups" -Completed

                        # Split results
                        $directGroups = $results | Where-Object { $_.Type -eq "Direct" }
                        $deputyGroups = $results | Where-Object { $_.Type -eq "Deputy" }

                        # Output results
                        if ($directGroups.Count -gt 0) {
                            Write-Host "`n[✔] Directly Managed Groups:" -ForegroundColor Green
                            foreach ($g in $directGroups) { Write-Host "   - $($g.GroupName)" -ForegroundColor Yellow }
                        } else {
                            Write-Host "`n[~] No groups directly managed by this user." -ForegroundColor DarkGray
                        }

                        if ($deputyGroups.Count -gt 0) {
                            Write-Host "`n[✔] Deputy Managed Groups (manages the manager of these groups):" -ForegroundColor Cyan
                            foreach ($g in $deputyGroups) { Write-Host "   - $($g.GroupName)" -ForegroundColor Yellow }
                        } else {
                            Write-Host "`n[~] No deputy group manager relationships found." -ForegroundColor DarkGray
                        }
                    } catch {
                        fncPrintMessage "Error while checking group management: $_" "error"
                    }

                    Read-Host "Press Enter to return to the menu..."
                }
                '9' {

                }
                '10' {
                    fncCheckPasswordResetPaths -targetUser $userDetails.SamAccountName
                }
                '11' {

                }
                '12' {

                }
                '13' {

                }
                '14' {

                }
                default {
                    Write-Host "`nReturning to main menu..." -ForegroundColor Cyan
                    Start-Sleep -Seconds 1
                }
            }
        } while ($userToolChoice)   # loop until blank input
    } catch {
        fncPrintMessage "Error retrieving information for user: $user" "error"
    }
}

############################################################
##### group Info
function fncGetGroupInfo {
    param (
        [string]$groupName
    )

    $groupName = $groupName.Trim()
    $domainsFound = @()

    # Primary domain from LAST_KWN_DOM
    $primaryDomain = $global:config.LAST_KWN_DOM
    $primaryDcHost = $global:domainMap[$primaryDomain] -replace '^\\\\', ''

    fncPrintMessage "Starting group search for '$groupName'" "debug"
    fncPrintMessage "Primary domain: $primaryDomain, DC: $primaryDcHost" "debug"

    function Search-GroupOnDomain {
        param (
            [string]$domain,
            [string]$dcHost
        )

        fncPrintMessage "Querying '$groupName' on DC: $dcHost (Domain: $domain)" "debug"

        try {
            $group = Get-ADGroup -Server $dcHost -Identity $groupName -Properties Member, Description, ManagedBy, Secretary, GroupCategory, GroupScope, WhenCreated, WhenChanged -ErrorAction Stop
        } catch {
            fncPrintMessage "Get-ADGroup failed on $domain : $_" "error"
            return $null
        }

        if ($null -ne $group) {
            $domainsFound += $domain
            Write-Host "`n[+] Group '$groupName' found in domain '$domain'" -ForegroundColor Cyan
            Write-Host "Group Name        : $($group.Name)" -ForegroundColor Yellow
            Write-Host "Description       : $($group.Description)" -ForegroundColor White
            Write-Host "Group Category    : $($group.GroupCategory)" -ForegroundColor White
            Write-Host "Group Scope       : $($group.GroupScope)" -ForegroundColor White
            Write-Host "Created On        : $($group.WhenCreated)" -ForegroundColor White
            Write-Host "Last Modified On  : $($group.WhenChanged)" -ForegroundColor White

            Write-Host -NoNewline "Manager           : " -ForegroundColor Green
            if ($group.ManagedBy) {
                try {
                    $manager = Get-ADUser -Server $dcHost -Identity $group.ManagedBy -Properties GivenName, Surname, SamAccountName -ErrorAction Stop
                    Write-Host "$($manager.GivenName) $($manager.Surname) ($($manager.SamAccountName))"
                } catch {
                    Write-Host "(Manager object not found)" -ForegroundColor Yellow
                }
            } else {
                Write-Host "Not specified" -ForegroundColor Yellow
            }

            Write-Host -NoNewline "Deputy Manager    : " -ForegroundColor Green
            if ($group.Secretary) {
                try {
                    $dn = $group.Secretary
                    $deputy = Get-ADUser -Server $dcHost -Filter "DistinguishedName -eq '$dn'" -Properties GivenName, Surname, SamAccountName -ErrorAction Stop
                    Write-Host "$($deputy.GivenName) $($deputy.Surname) ($($deputy.SamAccountName))"
                } catch {
                    Write-Host "(Deputy manager not found)" -ForegroundColor Yellow
                }
            } else {
                Write-Host "Not specified" -ForegroundColor Yellow
            }

            Write-Host "`nMembers:" -ForegroundColor Cyan
            try {
                $members = Get-ADGroupMember -Server $dcHost -Identity $groupName -ErrorAction Stop
                foreach ($member in $members) {
                    if ($member.objectClass -eq "user") {
                        try {
                            $user = Get-ADUser -Server $dcHost -Identity $member.DistinguishedName -Properties GivenName, Surname, SamAccountName -ErrorAction Stop
                            Write-Host " - $($user.SamAccountName) ($($user.GivenName) $($user.Surname))" -ForegroundColor Green
                        } catch {
                            Write-Host " - $($member.SamAccountName) (Details not found)" -ForegroundColor Yellow
                        }
                    } else {
                        Write-Host " - $($member.Name) {$($member.objectClass)}" -ForegroundColor Yellow
                    }
                }
            } catch {
                Write-Host "Unable to retrieve group members: $_" -ForegroundColor Red
            }

            return $true
        }

        return $false
    }

    # First search the primary domain
    if ($primaryDomain -and $global:domainMap.ContainsKey($primaryDomain)) {
        Search-GroupOnDomain -domain $primaryDomain -dcHost $primaryDcHost | Out-Null
    } else {
        fncPrintMessage "Primary domain '$primaryDomain' not mapped to a DC." "warning"
    }

    # Then search other domains
    $remainingDomains = $global:domainList | Where-Object { $_ -ne $primaryDomain }

    foreach ($domain in $remainingDomains) {
        if (-not $global:domainMap.ContainsKey($domain)) {
            fncPrintMessage "No other DC hostname found for domain $domain. Skipping..." "warning"
            continue
        }

        $dcHost = $global:domainMap[$domain] -replace '^\\\\', ''
        Search-GroupOnDomain -domain $domain -dcHost $dcHost | Out-Null
    }

    if ($domainsFound.Count -eq 0) {
        fncPrintMessage "No other domains found in array." "debug"
        fncPrintMessage "Group '$groupName' was not found in any other domain." "info"
    }


        Write-Host "===================================================" -ForegroundColor Cyan
        Write-Host "            🔧 Advanced Group Tools Menu           " -ForegroundColor Cyan
        Write-Host "===================================================" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "Target Group: $groupName" -ForegroundColor Yellow
        Write-Host ""
        Write-Host " 1) 🧬 View Nested Group Memberships"
        Write-Host " 2) 👤 List All Users (Recursively)"
        Write-Host " 3) 🛡️  Check for Privileged ACLs (GenericAll, WriteDACL)"
        Write-Host " 4) 🚪 Find Members with External Access (e.g. VPN, RDP)"
        Write-Host " 5) 📜 Show Group Description and Metadata"
        Write-Host " 6) 📤 Dump Group Members to CSV"
        Write-Host " 7) 🔍 Search for Users by Pattern (wildcards supported)"
        Write-Host " 8) 🧪 Check Group Delegations or Shadow Admins"
        Write-Host " 9) 🧼 Find and Remove Disabled/Expired Users"
        Write-Host "10) ❌ Identify Orphaned Groups (no members)"
        Write-Host "11) 🧾 Export Group ACLs and Metadata to File"
        Write-Host "12) 🚫 Check if Group Has Deny Permissions Assigned"
        Write-Host "13) ⏰ Check When Group Was Last Modified"
        Write-Host "14) ↩️ Return to Previous Menu"
        Write-Host ""

        $choice = Read-Host "Select an option or press [Enter] to return"

        switch ($choice) {
            '1'  { fncViewNestedGroups -groupName $groupName }
            '2'  { fncListGroupUsersRecursive -groupName $groupName }
            '3'  { fncCheckGroupACLs -groupName $groupName }
            '4'  { fncFindExternalAccessMembers -groupName $groupName }
            '5'  { fncShowGroupDetails -groupName $groupName }
            '6'  { fncExportGroupMembers -groupName $groupName }
            '7'  { fncSearchUsersInGroup -groupName $groupName }
            '8'  { fncCheckDelegatedGroupControl -groupName $groupName }
            '9'  { fncFindDisabledUsersInGroup -groupName $groupName }
            '10' { fncCheckIfGroupEmpty -groupName $groupName }
            '11' { fncExportGroupACLReport -groupName $groupName }
            '12' { fncCheckGroupDenyACLs -groupName $groupName }
            '13' { fncCheckGroupLastModified -groupName $groupName }
            default { return }
        }

        Pause
   
}

############################################################
### Computer Info
function fncCheckComputerInfo {
    param (
        [string]$device
    )

    fncPrintMessage "Gathering asset information for device $device..." "info"

    try {
        $deviceInfo = Get-ADComputer -Server $dcHost -Identity $device -Properties Name, OperatingSystem, OperatingSystemVersion, LastLogonDate, IPv4Address, Enabled, PasswordLastSet, DNSHostName, Description, Location, ManagedBy
        if (-not $deviceInfo) {
            fncPrintMessage "Device $device not found in Active Directory." "error"
            return
        }

        # Basic AD Info
        Write-Host "====================================="
        Write-Host "Device Name         : $($deviceInfo.Name)" -ForegroundColor Green
        Write-Host "IP Address          : $($deviceInfo.IPv4Address)"
        Write-Host "DNS Hostname        : $($deviceInfo.DNSHostName)"
        Write-Host "Operating System    : $($deviceInfo.OperatingSystem)"
        Write-Host "OS Version          : $($deviceInfo.OperatingSystemVersion)"
        Write-Host "Last Logon Date     : $($deviceInfo.LastLogonDate)"
        Write-Host "Password Last Set   : $($deviceInfo.PasswordLastSet)"
        Write-Host "Enabled             : $($deviceInfo.Enabled)"
        Write-Host "Description         : $($deviceInfo.Description)"
        Write-Host "Managed By          : $($deviceInfo.ManagedBy)"
        Write-Host "====================================="

        # Admin Groups Check
        Write-Host ""
        Write-Host "---- Admin Group Check ----" -ForegroundColor Cyan

        $adminGroupTemplates = @() + $global:config.deviceAdminGroups
        $validTemplates = $adminGroupTemplates | Where-Object { $_ -like '*HOSTNAME*' }

        if (-not $validTemplates) {
            fncPrintMessage "Invalid config: No '*HOSTNAME*' placeholder in deviceAdminGroups." "warning"
            Write-Host "UNABLE TO FIND ADMIN GROUPS" -ForegroundColor Red
        } else {
            foreach ($template in $validTemplates) {
                $groupName = $template -replace 'HOSTNAME', $device
                fncPrintMessage "Checking admin group '$groupName' on $dcHost" "debug"

                try {
                    $group = Get-ADGroup -Server $dcHost -Identity $groupName -Properties Member, Description, ManagedBy, GroupCategory, GroupScope, WhenCreated, WhenChanged -ErrorAction Stop

                    Write-Host ""
                    Write-Host "---- Admin Group: $groupName ----" -ForegroundColor Cyan
                    Write-Host "Description       : $($group.Description)"
                    Write-Host "Group Category    : $($group.GroupCategory)"
                    Write-Host "Group Scope       : $($group.GroupScope)"
                    Write-Host "Created On        : $($group.WhenCreated)"
                    Write-Host "Last Modified     : $($group.WhenChanged)"

                    # Manager
                    Write-Host -NoNewline "Manager           : " -ForegroundColor Green
                    if ($group.ManagedBy) {
                        try {
                            $manager = Get-ADUser -Server $dcHost -Identity $group.ManagedBy -Properties GivenName, Surname, SamAccountName
                            Write-Host "$($manager.GivenName) $($manager.Surname) ($($manager.SamAccountName))"
                        } catch {
                            Write-Host "(Manager object not found)" -ForegroundColor Yellow
                        }
                    } else {
                        Write-Host "Not specified" -ForegroundColor Yellow
                    }

                    # Members
                    Write-Host "`nMembers:" -ForegroundColor Cyan
                    try {
                        $members = Get-ADGroupMember -Server $dcHost -Identity $groupName -ErrorAction Stop
                        foreach ($member in $members) {
                            if ($member.objectClass -eq "user") {
                                try {
                                    $user = Get-ADUser -Server $dcHost -Identity $member.DistinguishedName -Properties GivenName, Surname, SamAccountName
                                    Write-Host " - $($user.SamAccountName) ($($user.GivenName) $($user.Surname))" -ForegroundColor Green
                                } catch {
                                    Write-Host " - $($member.SamAccountName) (Details not found)" -ForegroundColor Yellow
                                }
                            } else {
                                Write-Host " - $($member.Name) {$($member.objectClass)}" -ForegroundColor Yellow
                            }
                        }
                    } catch {
                        Write-Host "Unable to retrieve group members: $_" -ForegroundColor Red
                    }

                } catch {
                    fncPrintMessage "Admin Group not found or inaccessible: $groupName" "error"
                }
            }
        }
        # Group Membership
        Write-Host ""
        Write-Host "---- Group Membership ----" -ForegroundColor Cyan
        $groups = Get-ADComputer -Server $dcHost -Identity $device -Properties MemberOf | Select-Object -ExpandProperty MemberOf
        if ($groups) {
            foreach ($groupDN in $groups) {
                $parts = $groupDN -split ','
                foreach ($part in $parts) {
                    if ($part -like "CN=*") {
                        Write-Host $part -ForegroundColor Yellow -NoNewline
                    } elseif ($part -like "DC=*") {
                        Write-Host ",$part" -ForegroundColor Red -NoNewline
                    } else {
                        Write-Host ",$part" -ForegroundColor White -NoNewline
                    }
                }
                Write-Host ""
            }
        } else {
            Write-Host "No groups found." -ForegroundColor Yellow
        }

    # ---- Network Reachability ----
    Write-Host ""
    Write-Host "---- Network Reachability ----" -ForegroundColor Cyan
    $targetHost = $deviceInfo.DNSHostName

    # Resolve to IP if DNSHostName fails
    if (-not $targetHost) {
        fncPrintMessage "No DNS hostname found for $($deviceInfo.Name). Trying to resolve..." "warning"
        $nslookupResult = nslookup $deviceInfo.Name 2>&1
        $resolvedIP = ($nslookupResult | Where-Object { $_ -match '^Address:' }) -replace 'Address:\s+', ''
        
        if ($resolvedIP -match '^\d{1,3}(\.\d{1,3}){3}$') {
            $targetHost = $resolvedIP
            fncPrintMessage "Resolved $($deviceInfo.Name) to $targetHost via nslookup." "success"
        } else {
            fncPrintMessage "Failed to resolve IP address for $($deviceInfo.Name)." "error"
            return
        }
    }

    # Function: Test port with timeout
        function Test-Port {
        param (
            [string]$ipOrHost,
            [int]$port
        )
        try {
            $client = New-Object System.Net.Sockets.TcpClient
            $asyncResult = $client.BeginConnect($ipOrHost, $port, $null, $null)
            $success = $asyncResult.AsyncWaitHandle.WaitOne(5000, $false)  # 5-second timeout
            if ($success -and $client.Connected) {
                $client.EndConnect($asyncResult)
                $client.Close()
                return $true
            } else {
                $client.Close()
                return $false
            }
        } catch {
            return $false
        }
    }

    # Run port tests
    $rdpOpen = Test-Port -ipOrHost $targetHost -port 3389
    $sshOpen = Test-Port -ipOrHost $targetHost -port 22

    if ($rdpOpen) {
        fncPrintMessage "RDP (3389) is open." "success"
    } else {
        fncPrintMessage "RDP (3389) is closed or timed out." "error"
    }

    if ($sshOpen) {
        fncPrintMessage "SSH (22) is open." "success"
    } else {
        fncPrintMessage "SSH (22) is closed or timed out." "error"
    }

    # Interactive connect option
    if ($rdpOpen -or $sshOpen) {
        $choice = Read-Host "Connect via (R)DP, (S)SH, or (M)ain menu?"
        switch ($choice.ToUpper()) {
            'R' { Start-Process "mstsc" "/v:$targetHost" }
            'S' { Start-Process "powershell" "-Command ssh $targetHost" }
            default { fncPrintMessage "Returning to main menu." "info" }
        }
    } else {
        fncPrintMessage "No available remote services to connect." "warning"
    }
    } catch {
        fncPrintMessage "Unexpected error while retrieving group info: $_" "error"
    }
}










# ================================================================
# Function: fncCheckASRepRoast
# Purpose : Check if a user has 'Does not require Kerberos preauthentication' enabled
# Notes   : Used to identify accounts vulnerable to AS-REP Roasting
# ================================================================
function fncCheckASRepRoast {
    param (
        [Parameter(Mandatory = $true)]
        [string]$user
    )


}


# ================================================================
# Function: fncViewNestedGroups
# Purpose : Recursively displays all nested group memberships for 
#           a given AD group, with clear indentation and formatting.
# Notes   : - Uses Get-ADGroup and Get-ADObject to traverse members.
#          - Avoids circular references using a visited hashset.
#          - Indents using '|-' and '|--' to show hierarchy.
#          - Supports both users and group objects.
# ================================================================
function fncViewNestedGroups {
    param (
        [Parameter(Mandatory = $true)]
        [string]$groupName,

        [int]$level = 0,

        [ref]$visited = $(New-Object System.Collections.Generic.HashSet[string])
    )

    try {
        # Get the group object
        $group = Get-ADGroup -Identity $groupName -Server $global:dcHost -Properties Member

        if (-not $group) {
            fncPrintMessage "Group not found: $groupName" "error"
            return
        }

        # Avoid loops due to circular memberships
        if ($visited.Value.Contains($group.DistinguishedName)) {
            return
        } else {
            $visited.Value.Add($group.DistinguishedName) | Out-Null
        }

        # Indentation
        $indent = "|  " * $level
        if ($level -eq 0) {
            Write-Host "$($group.Name)"
        } else {
            Write-Host "$indent|-  $($group.Name)"
        }

        # Check if group has members
        if (-not $group.Member) {
            return
        }

        # Loop through members
        foreach ($memberDN in $group.Member) {
            try {
                $member = Get-ADObject -Identity $memberDN -Server $global:dcHost -Properties objectClass, Name

                if ($member.ObjectClass -eq "group") {
                    # Recursive call
                    fncViewNestedGroups -groupName $member.Name -level ($level + 1) -visited $visited
                } else {
                    # Print user or non-group
                    $userIndent = "|  " * ($level + 1)
                    Write-Host "$userIndent|--  $($member.Name)" -ForegroundColor DarkGray
                }
            } catch {
                fncPrintMessage "Error resolving member: $memberDN" "debug"
            }
        }
    } catch {
        fncPrintMessage "Error retrieving nested groups for: $groupName" "error"
    }
}

# ================================================================
# Function: fncCheckPasswordResetPaths
# Purpose : Identify users/groups that can reset the password of a specific user
# Notes   : Does not use PSDrive; uses ADSI for ACL enumeration
# ================================================================
function fncCheckPasswordResetPaths {
    param (
        [string]$targetUser
    )

    try {
        Write-Host "🔍 Checking who can reset the password for: $targetUser" -ForegroundColor Cyan

        $userObject = Get-ADUser -Server $global:dcHost -Identity $targetUser -Properties DistinguishedName
        if (-not $userObject -or -not $userObject.DistinguishedName) {
            fncPrintMessage "User not found or missing DN: $targetUser" "error"
            return
        }

        $dn = $userObject.DistinguishedName
        fncPrintMessage "Resolved DN: $dn" "debug"

        # Safety check: detect if the DN looks like a domain root (not a user DN)
        if ($dn -notmatch '^CN=.*?,') {
            fncPrintMessage "Warning: The DN does not appear to belong to a user object (DN: $dn)" "debug"
        }

        $directoryEntry = [ADSI]"LDAP://$dn"
        $acl = $directoryEntry.ObjectSecurity
        fncPrintMessage "Retrieved ACL for: $dn" "debug"

        $resetRights = @("ResetPassword", "ExtendedRight", "WriteProperty", "GenericAll", "GenericWrite")
        fncPrintMessage "Rights being checked: $($resetRights -join ', ')" "debug"

        $results = @()

        foreach ($ace in $acl.Access) {
            $rightStr = $ace.ActiveDirectoryRights.ToString()
            fncPrintMessage "ACE: $($ace.IdentityReference) => $rightStr" "debug"

            if (
                ($resetRights -contains $rightStr) -or
                ($rightStr -match "ResetPassword|GenericAll|GenericWrite")
            ) {
                if ($ace.IdentityReference -notmatch "SELF|NT AUTHORITY|Everyone") {
                    fncPrintMessage "MATCH: $($ace.IdentityReference) has $rightStr" "debug"
                    $results += [PSCustomObject]@{
                        Identity     = $ace.IdentityReference
                        AccessType   = $ace.AccessControlType
                        Rights       = $ace.ActiveDirectoryRights
                        Inherited    = $ace.IsInherited
                    }
                } else {
                    fncPrintMessage "Skipping built-in identity: $($ace.IdentityReference)" "debug"
                }
            }
        }

        if ($results.Count -eq 0) {
            Write-Host "[~] No users/groups found with ResetPassword-like rights." -ForegroundColor DarkGray
        } else {
            Write-Host "`n[+] The following users/groups can reset the password for $targetUser :`n" -ForegroundColor Yellow
            $results | Sort-Object Identity | Format-Table -AutoSize
        }

    } catch {
        fncPrintMessage "Error while checking password reset paths: $_" "error"
    }
}

# ================================================================
# Function: fncViewSPNs
# Purpose : Displays Service Principal Names (SPNs) for a user or computer
# Notes   : Uses Get-ADUser or Get-ADComputer depending on input
# ================================================================
function fncViewSPNs {
    param (
        [string]$identity
    )

    try {
        # Try as a user
        $user = Get-ADUser -Server $global:dcHost -Identity $identity -Properties ServicePrincipalName
        if ($user) {
            Write-Host "=============================="
            Write-Host " SPNs for User: $($user.SamAccountName)" -ForegroundColor Cyan
            Write-Host "=============================="

            if ($user.ServicePrincipalName.Count -gt 0) {
                foreach ($spn in $user.ServicePrincipalName) {
                    Write-Host "  $spn" -ForegroundColor Yellow
                }
            } else {
                Write-Host "  [~] No SPNs found for this user." -ForegroundColor DarkGray
            }
            return
        }

        # Try as a computer
        $computer = Get-ADComputer -Server $global:dcHost -Identity $identity -Properties ServicePrincipalName
        if ($computer) {
            Write-Host "=============================="
            Write-Host " SPNs for Computer: $($computer.Name)" -ForegroundColor Cyan
            Write-Host "=============================="

            if ($computer.ServicePrincipalName.Count -gt 0) {
                foreach ($spn in $computer.ServicePrincipalName) {
                    Write-Host "  $spn" -ForegroundColor Yellow
                }
            } else {
                Write-Host "  [~] No SPNs found for this computer." -ForegroundColor DarkGray
            }
            return
        }

        # If both lookups fail
        fncPrintMessage "No user or computer found with identity: $identity" "error"

    } catch {
        fncPrintMessage "An error occurred while retrieving SPNs for: $identity" "error"
        fncPrintMessage "$($_.Exception.Message)" "debug"
    }
}

# ================================================================
# Function: fncDumpUserGroups
# Purpose : Extracts all AD groups a user belongs to and exports details.
# Notes   : Includes group description, scope, OU, manager, and deputy info in CSV.
# ================================================================
function fncDumpUserGroups {
    param (
        [string]$username
    )

    if (-not $username) {
        $username = Read-Host "Enter username to dump groups for"
        if (-not $username) {
            Write-Host "[-] No username provided. Aborting." -ForegroundColor Red
            return
        }
    }

    try {
        $dcHost = $global:dcHost

        Write-Host "`n[+] Dumping groups for user: $username" -ForegroundColor Cyan

        $user = Get-ADUser -Server $dcHost -Identity $username -Properties MemberOf
        if (-not $user) {
            Write-Host "[-] User not found." -ForegroundColor Red
            return
        }

        $groups = $user.MemberOf
        if (-not $groups) {
            Write-Host "[-] No groups found for $username." -ForegroundColor Yellow
            return
        }

        $output = @()

        foreach ($groupDN in $groups) {
            Write-Host "[*] Processing: $groupDN" -ForegroundColor Gray

            $groupObj = Get-ADGroup -Server $dcHost -Identity $groupDN -Properties Name, Description, DistinguishedName, GroupCategory, GroupScope, whenCreated, whenChanged, ManagedBy

            $cn = ($groupObj.DistinguishedName -split ',')[0] -replace '^CN='
            $ouParts = ($groupObj.DistinguishedName -split ',') | Where-Object { $_ -like 'OU=*' }
            $ou = ($ouParts -join '/')
            if (-not $ou) { $ou = "NO INFO" }

            $manager = "NO INFO"
            $deputy = "NO INFO"

            if ($groupObj.ManagedBy) {
                try {
                    $mgr = Get-ADUser -Server $dcHost -Identity $groupObj.ManagedBy -Properties Name, GivenName, Surname, Manager
                    $manager = "$($mgr.GivenName) $($mgr.Surname) - $($mgr.Name)"

                    if ($mgr.Manager) {
                        $deputyObj = Get-ADUser -Server $dcHost -Identity $mgr.Manager -Properties Name, GivenName, Surname
                        $deputy = "$($deputyObj.GivenName) $($deputyObj.Surname) - $($deputyObj.Name)"
                    }
                } catch {
                    $manager = "NO INFO"
                    $deputy = "NO INFO"
                }
            }

            $output += [PSCustomObject]@{
                "Application CN"     = if ($cn) { $cn } else { "NO INFO" }
                "Application Name"   = if ($groupObj.Description) { $groupObj.Description } else { "NO INFO" }
                "Application OU"     = $ou
                "Category"           = if ($groupObj.GroupCategory) { $groupObj.GroupCategory } else { "NO INFO" }
                "Scope"              = if ($groupObj.GroupScope) { $groupObj.GroupScope } else { "NO INFO" }
                "Created"            = if ($groupObj.whenCreated) { $groupObj.whenCreated } else { "NO INFO" }
                "Modified"           = if ($groupObj.whenChanged) { $groupObj.whenChanged } else { "NO INFO" }
                "Manager"            = $manager
                "Deputy Manager"     = $deputy
            }
        }

        $csvPath = "$PWD\Dump_UserGroups_$($username)_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
        $output | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $csvPath

        Write-Host "`n[+] Dump complete! CSV saved to:" -ForegroundColor Green
        Write-Host $csvPath -ForegroundColor Yellow
    }
    catch {
        Write-Host "[-] Error: $_" -ForegroundColor Red
    }
}

# ================================================================
# Function: fncDumpComputerGroups
# Purpose : Extracts all AD groups a computer belongs to and exports details.
# Notes   : Outputs group description, OU, scope, and manager info to CSV.
# ================================================================
function fncDumpComputerGroups {
    param (
        [string]$computerName
    )

    # Prompt if not supplied
    if (-not $computerName) {
        $computerName = Read-Host "Enter computer name to dump groups for"
        if (-not $computerName) {
            Write-Host "[-] No computer name provided. Aborting." -ForegroundColor Red
            return
        }
    }

    try {
        $dcHost = $global:dcHost

        Write-Host "`n[+] Dumping groups for computer: $computerName" -ForegroundColor Cyan

        $groups = Get-ADComputer -Server $dcHost -Identity $computerName -Properties MemberOf | Select-Object -ExpandProperty MemberOf
        if (-not $groups) {
            Write-Host "[-] No groups found for $computerName." -ForegroundColor Yellow
            return
        }

        $output = @()

        foreach ($groupDN in $groups) {
            $groupObj = Get-ADGroup -Server $dcHost -Identity $groupDN -Properties Name, Description, DistinguishedName, GroupCategory, GroupScope, whenCreated, whenChanged, ManagedBy
            Write-Host "[~] Processing group: $groupDN" -ForegroundColor DarkGray
            $cn = ($groupObj.DistinguishedName -split ',')[0] -replace '^CN='

            $ouParts = ($groupObj.DistinguishedName -split ',') | Where-Object { $_ -like 'OU=*' }
            $ou = if ($ouParts) { $ouParts -join '/' } else { "NO INFO" }

            $manager = "NO INFO"
            $deputy = "NO INFO"

            if ($groupObj.ManagedBy) {
                try {
                    $mgr = Get-ADUser -Server $dcHost -Identity $groupObj.ManagedBy -Properties Name, GivenName, Surname, Manager
                    if ($mgr) {
                        $manager = "$($mgr.GivenName) $($mgr.Surname) - $($mgr.Name)"
                    }

                    if ($mgr.Manager) {
                        $deputyObj = Get-ADUser -Server $dcHost -Identity $mgr.Manager -Properties Name, GivenName, Surname
                        if ($deputyObj) {
                            $deputy = "$($deputyObj.GivenName) $($deputyObj.Surname) - $($deputyObj.Name)"
                        }
                    }
                } catch {
                    $manager = "NO INFO"
                    $deputy = "NO INFO"
                }
            }

            $output += [PSCustomObject]@{
                "Application Name"   = if ($groupObj.Description) { $groupObj.Description } else { "NO INFO" }
                "Application CN"     = $groupObj.Name
                "Application OU"     = $ou
                "Category"           = if ($groupObj.GroupCategory) { $groupObj.GroupCategory } else { "NO INFO" }
                "Scope"              = if ($groupObj.GroupScope) { $groupObj.GroupScope } else { "NO INFO" }
                "Created"            = if ($groupObj.whenCreated) { $groupObj.whenCreated } else { "NO INFO" }
                "Modified"           = if ($groupObj.whenChanged) { $groupObj.whenChanged } else { "NO INFO" }
                "Manager"            = $manager
                "Deputy Manager"     = $deputy
            }
        }

        $csvPath = "$PWD\Dump_ComputerGroups_$($computerName)_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
        $output | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $csvPath

        Write-Host "`n[+] Dump complete! CSV saved to:" -ForegroundColor Green
        Write-Host $csvPath -ForegroundColor Yellow
    }
    catch {
        Write-Host "[-] Error: $_" -ForegroundColor Red
    }
}

# ================================================================
# Function: fncDumpGroupMembers
# Purpose : Dumps members of a specified AD group into a detailed CSV.
# Notes   : Includes SAML, name, email, and manager; supports export for audit.
# ================================================================
function fncDumpGroupMembers {
    param (
        [string]$groupName
    )

    # Ask for group name if not supplied
    if (-not $groupName) {
        $groupName = Read-Host "Enter AD group name to dump members for"
        if (-not $groupName) {
            Write-Host "[-] No group name provided. Aborting." -ForegroundColor Red
            return
        }
    }

    try {
        Write-Host "`n[+] Dumping members of group: $groupName" -ForegroundColor Cyan

        $dcHost = $global:dcHost  # Uses your domain controller context
        $group = Get-ADGroup -Server $dcHost -Identity $groupName -ErrorAction Stop
        $members = Get-ADGroupMember -Server $dcHost -Identity $group.DistinguishedName -Recursive | Where-Object { $_.objectClass -eq 'user' }

        if (-not $members) {
            Write-Host "[-] No user members found in $groupName." -ForegroundColor Yellow
            return
        }

        $output = @()

        foreach ($member in $members) {
            Write-Host "[*] Processing: $($member.SamAccountName)" -ForegroundColor DarkGray

            $user = Get-ADUser -Server $dcHost -Identity $member.SamAccountName -Properties GivenName, Surname, EmailAddress, Manager

            $managerName = "NO INFO"
            if ($user.Manager) {
                try {
                    $mgr = Get-ADUser -Server $dcHost -Identity $user.Manager -Properties GivenName, Surname
                    $managerName = "$($mgr.GivenName) $($mgr.Surname)"
                } catch {
                    $managerName = "NO INFO"
                }
            }

            $output += [PSCustomObject]@{
                "Group Name"    = $group.Name
                "SAML"          = $user.SamAccountName
                "First Name"    = if ($user.GivenName) { $user.GivenName } else { "NO INFO" }
                "Surname"       = if ($user.Surname) { $user.Surname } else { "NO INFO" }
                "Email"         = if ($user.EmailAddress) { $user.EmailAddress } else { "NO INFO" }
                "Manager Name"  = $managerName
            }
        }

        $csvPath = "$PWD\Dump_GroupMembers_$($group.Name)_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
        $output | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $csvPath

        Write-Host "`n[+] Dump complete! CSV saved to:" -ForegroundColor Green
        Write-Host $csvPath -ForegroundColor Yellow
    }
    catch {
        Write-Host "[-] Error: $_" -ForegroundColor Red
    }
}

# ================================================================
# Function: fncCheckWeakACLs
# Purpose : Identifies risky ACEs on an AD user object that could allow privilege escalation.
# Notes   : Flags rights like GenericAll, WriteDACL, and WriteOwner using Get-Acl.
# ================================================================
function fncCheckWeakACLs {
    param (
        [Microsoft.ActiveDirectory.Management.ADUser]$userDetails
    )

    Write-Host "====================================="
    Write-Host "`n[+] Checking for weak ACLs on user object..." -ForegroundColor Cyan
    Write-Host "====================================="

    try {
        $dn = $userDetails.DistinguishedName

        # Use PSDrive name (default AD or from config)
        $driveName = if ($global:config.PSObject.Properties.Name -contains "driveName") {
            $global:config.driveName
        } else {
            "AD"
        }

        $path = "$driveName\$dn"
        $acl = Get-Acl -Path $path

        $riskyRights = @(
            "GenericAll", "GenericWrite", "WriteOwner", "WriteDACL",
            "CreateChild", "DeleteChild", "WriteProperty", "Self"
        )

        $weakEntries = @()

        foreach ($entry in $acl.Access) {
            foreach ($right in $riskyRights) {
                if ($entry.ActiveDirectoryRights.HasFlag([System.DirectoryServices.ActiveDirectoryRights]::$right)) {
                    $weakEntries += $entry
                    break
                }
            }
        }

        $weakEntries = $weakEntries | Sort-Object IdentityReference, ActiveDirectoryRights -Unique

        if (-not ($global:config.PSObject.Properties.Name -contains "suppressSelfACE")) {
            $global:config | Add-Member -MemberType NoteProperty -Name suppressSelfACE -Value $false
        }

        if ($weakEntries.Count -gt 0) {
            Write-Host "`n[!] Weak permissions found on user object:" -ForegroundColor Red
            foreach ($entry in $weakEntries) {
                if ($global:config.suppressSelfACE -and $entry.IdentityReference -like "*SELF*") {
                    continue
                }

                if ($entry.ActiveDirectoryRights -match 'GenericAll|WriteDACL|WriteOwner') {
                    Write-Host "⚠️  HIGH RISK: $($entry.IdentityReference) - $($entry.ActiveDirectoryRights)" -ForegroundColor Red
                } else {
                    Write-Host "    Trustee   : $($entry.IdentityReference)" -ForegroundColor Yellow
                    Write-Host "    Right     : $($entry.ActiveDirectoryRights)"
                    Write-Host "    Type      : $($entry.AccessControlType)"
                    Write-Host "    Inherited : $($entry.IsInherited)"
                    Write-Host ""
                }
            }
        } else {
            Write-Host "[✓] No weak ACEs found." -ForegroundColor Green
        }
    } catch {
        Write-Host "[X] Failed to retrieve ACL: $_" -ForegroundColor Red
    }
}

# ================================================================
# Function: fncCheckSACLS
# Purpose : Retrieves and displays the SACL (audit permissions) 
# Notes   : Useful for identifying what actions on the object are audited,
#           including who is audited, for what rights, and whether for
#           success, failure, or both.
# ================================================================
function fncCheckSACL {
    param (
        [Microsoft.ActiveDirectory.Management.ADUser]$userDetails
    )
    Write-Host "====================================="
    Write-Host "`n[+] Checking SACL (auditing permissions) for user object..." -ForegroundColor Cyan
    Write-Host "====================================="
    try {
        $dn = $userDetails.DistinguishedName

        # Use DirectoryEntry to get underlying object
        $entry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$dn")

        # Get security descriptor with SACL (requires SeSecurityPrivilege!)
        $flags = [System.DirectoryServices.SecurityMasks]::Sacl
        $entry.Options.SecurityMasks = $flags
        $descriptor = $entry.ObjectSecurity

        $sacl = $descriptor.GetAuditRules($true, $true, [System.Security.Principal.NTAccount])

        if ($sacl.Count -gt 0) {
            Write-Host "`n[!] Auditing Rules Found in SACL:" -ForegroundColor Yellow

            foreach ($rule in $sacl) {
                Write-Host "------------------------------------"
                Write-Host "Identity      : $($rule.IdentityReference)"
                Write-Host "Access Type   : $($rule.AuditFlags)"
                Write-Host "Inherited     : $($rule.IsInherited)"
                Write-Host "Rights        : $($rule.ActiveDirectoryRights)"
                Write-Host ""
            }
        } else {
            Write-Host "[✓] No auditing rules (SACL entries) found." -ForegroundColor Green
        }
    } catch {
        Write-Host "[X] Failed to retrieve SACL. You may lack SeSecurityPrivilege." -ForegroundColor Red
        Write-Host "Error: $_"
    }
}

# ================================================================
# Function: fncGetDomainInfo
# Purpose : Displays details about the current domain
# Notes   : Uses Get-ADDomain and Get-ADDomainController
# ================================================================
function fncGetDomainInfo {
    Write-Host "`n[+] Retrieving Domain Information..." -ForegroundColor Cyan
    Write-Host "==========================================="

    try {
        $domain = Get-ADDomain -Server $global:dcHost
        $dc = Get-ADDomainController -Server $global:dcHost

        Write-Host ("Domain Name              : $($domain.Name)")
        Write-Host ("NetBIOS Name             : $($domain.NetBIOSName)")
        Write-Host ("Domain Mode              : $($domain.DomainMode)")
        Write-Host ("Infrastructure Master    : $($domain.InfrastructureMaster)")
        Write-Host ("RID Master               : $($domain.RIDMaster)")
        Write-Host ("PDC Emulator             : $($domain.PDCEmulator)")

        Write-Host ("Default OU               : $($domain.ComputersContainer)")
        Write-Host ("Users Container          : $($domain.UsersContainer)")
        Write-Host ("DC Hostname              : $($dc.HostName)")
        Write-Host ("DC IPv4 Address          : $($dc.IPv4Address)")
        Write-Host ("DC Site                  : $($dc.Site)")
        Write-Host ("Is Global Catalog        : $($dc.IsGlobalCatalog)")
        Write-Host ("Is Read Only             : $($dc.IsReadOnly)")
        Write-Host ("Operating System         : $($dc.OperatingSystem)")

        if ($null -ne $domain.AllowedDNSSuffixes -and $domain.AllowedDNSSuffixes.Count -gt 0) {
            Write-Host ("Allowed DNS Suffixes     : $($domain.AllowedDNSSuffixes -join ', ')")
        } else {
            Write-Host "Allowed DNS Suffixes     : None"
        }

        Write-Host "==========================================="
    } catch {
        Write-Host "[X] Failed to retrieve domain info: $_" -ForegroundColor Red
    }

    Pause
}

# ================================================================
# Function: fncGetForestInfo
# Purpose : Displays detailed information about the AD forest
# Notes   : Formats sites on separate lines and adds more metadata
# ================================================================
function fncGetForestInfo {
    Write-Host "`n[+] Retrieving Forest Information..." -ForegroundColor Cyan
    Write-Host "=============================================="

    try {
        $forest = Get-ADForest -Server $global:dcHost

        Write-Host ("Forest Root Domain       : $($forest.RootDomain)")
        Write-Host ("Forest Mode              : $($forest.ForestMode)")
        Write-Host ("Global Catalogs          :")
        foreach ($gc in $forest.GlobalCatalogs) {
            Write-Host ("    - $gc")
        }

        Write-Host ("Application Partitions   :")
        if ($null -ne $forest.ApplicationPartitions -and $forest.ApplicationPartitions.Count -gt 0) {
            foreach ($ap in $forest.ApplicationPartitions) {
                Write-Host ("    - $ap")
            }
        } else {
            Write-Host "    None"
        }

        Write-Host ("UPNs Suffixes            :")
        if ($null -ne $forest.UPNSuffixes -and $forest.UPNSuffixes.Count -gt 0) {
            foreach ($upn in $forest.UPNSuffixes) {
                Write-Host ("    - $upn")
            }
        } else {
            Write-Host "    None"
        }

        Write-Host ("Sites in Forest          :")
        if ($null -ne $forest.Sites -and $forest.Sites.Count -gt 0) {
            foreach ($site in $forest.Sites) {
                Write-Host ("    - $site")
            }
        } else {
            Write-Host "    None"
        }

        Write-Host ("Domains in Forest        :")
        if ($null -ne $forest.Domains -and $forest.Domains.Count -gt 0) {
            foreach ($domain in $forest.Domains) {
                Write-Host ("    - $domain")
            }
        } else {
            Write-Host "    None"
        }

        Write-Host ("Trusts in Forest         :")
        if ($null -ne $forest.DomainNamingMaster -and (Get-ADTrust -Filter * -Server $global:dcHost -ErrorAction SilentlyContinue)) {
            $trusts = Get-ADTrust -Filter * -Server $global:dcHost
            foreach ($trust in $trusts) {
                Write-Host ("    - $($trust.Name) [$($trust.TrustType)] - $($trust.TrustDirection)")
            }
        } else {
            Write-Host "    None found or insufficient permissions"
        }

        Write-Host "=============================================="
    } catch {
        Write-Host "[X] Failed to retrieve forest info: $_" -ForegroundColor Red
    }

    Pause
}

# ================================================================
# Function: fncListDomainControllers
# Purpose : Lists all domain controllers in the current domain with details
# Notes   : Includes OS, site, IPv4/IPv6, roles, status, and replication info
# ================================================================
function fncListDomainControllers {
    Write-Host "`n[+] Listing Domain Controllers in Domain..." -ForegroundColor Cyan
    Write-Host "=============================================="

    try {
        $dcs = Get-ADDomainController -Filter * -Server $global:dcHost

        if (-not $dcs) {
            Write-Host "[!] No domain controllers found." -ForegroundColor Yellow
            return
        }

        foreach ($dc in $dcs) {
            Write-Host "----------------------------------------------"
            Write-Host ("Hostname              : $($dc.HostName)")
            Write-Host ("IPv4 Address          : $($dc.IPv4Address)")
            Write-Host ("IPv6 Address          : $($dc.IPv6Address)")
            Write-Host ("Site Name             : $($dc.Site)")
            Write-Host ("Domain Name           : $($dc.Domain)")
            Write-Host ("Forest                : $($dc.Forest)")
            Write-Host ("Is Global Catalog     : $($dc.IsGlobalCatalog)")
            Write-Host ("Is Read-Only DC       : $($dc.IsReadOnly)")
            Write-Host ("Operating System      : $($dc.OperatingSystem)")
            Write-Host ("OS Version            : $($dc.OperatingSystemVersion)")
            Write-Host ("OS Service Pack       : $($dc.OperatingSystemServicePack)")
            Write-Host ("Last Logon Time       : $($dc.LastLogonTime)")
            Write-Host ("Server Object DN      : $($dc.ServerObjectDN)")

            # FSMO Roles (only printed if roles exist on this DC)
            $domain = Get-ADDomain -Server $dc.HostName
            $fsmoRoles = @()
            if ($domain.InfrastructureMaster -eq $dc.HostName) { $fsmoRoles += "Infrastructure Master" }
            if ($domain.PDCEmulator -eq $dc.HostName) { $fsmoRoles += "PDC Emulator" }
            if ($domain.RIDMaster -eq $dc.HostName) { $fsmoRoles += "RID Master" }

            $forest = Get-ADForest -Server $dc.HostName
            if ($forest.SchemaMaster -eq $dc.HostName) { $fsmoRoles += "Schema Master" }
            if ($forest.DomainNamingMaster -eq $dc.HostName) { $fsmoRoles += "Domain Naming Master" }

            if ($fsmoRoles.Count -gt 0) {
                Write-Host "FSMO Roles            : $($fsmoRoles -join ', ')" -ForegroundColor Yellow
            }

            # Replication Status (Optional)
            try {
                $repStatus = repadmin /showrepl $dc.HostName /errorsonly
                if ($repStatus) {
                    Write-Host "Replication Errors     : Possible issues detected!" -ForegroundColor Red
                } else {
                    Write-Host "Replication Status     : Healthy"
                }
            } catch {
                Write-Host "Replication Status     : Unable to check (repadmin not available)"
            }

            Write-Host "----------------------------------------------`n"
        }

        Write-Host "[✓] Domain Controller enumeration completed." -ForegroundColor Green
    } catch {
        Write-Host "[X] Error retrieving domain controllers: $_" -ForegroundColor Red
    }

    Pause
}

# ================================================================
# Function: fncGetTrusts
# Purpose : Enumerates domain and forest trusts with details
# Notes   : Requires Domain Admin or appropriate rights
# ================================================================
function fncGetTrusts {
    Write-Host "`n[+] Enumerating Domain and Forest Trusts..." -ForegroundColor Cyan
    Write-Host "=============================================="

    try {
        $trusts = Get-ADTrust -Filter * -Server $global:dcHost

        if (-not $trusts -or $trusts.Count -eq 0) {
            Write-Host "[!] No trusts found." -ForegroundColor Yellow
            return
        }

        foreach ($trust in $trusts) {
            Write-Host "----------------------------------------------"
            Write-Host "Trusted Domain        : $($trust.Name)"
            Write-Host "Trust Type            : $($trust.TrustType)"         # Forest / External / Realm / Kerberos
            Write-Host "Direction             : $($trust.Direction)"         # Inbound / Outbound / Bidirectional
            Write-Host "Transitive            : $($trust.Transitive)"
            Write-Host "Trust Attributes      : $($trust.TrustAttributes)"
            Write-Host "Trust Partner         : $($trust.TrustedDomain)"
            Write-Host "Selective Auth?       : $($trust.SelectiveAuthentication)"
            Write-Host "SID Filtering Enabled : $($trust.SIDFilteringEnabled)"
            Write-Host "Trust Forest?         : $($trust.IsForest)"
            Write-Host "----------------------------------------------`n"
        }

        Write-Host "[✓] Trust enumeration complete." -ForegroundColor Green
    } catch {
        Write-Host "[X] Failed to retrieve trusts: $_" -ForegroundColor Red
    }

    Pause
}

# ================================================================
# Function: fncGetFSMORoles
# Purpose : Retrieves and displays all FSMO role holders
# Notes   : Requires domain connectivity; uses Get-ADDomain & Get-ADForest
# ================================================================
function fncGetFSMORoles {
    Write-Host "`n[+] Retrieving FSMO Role Holders..." -ForegroundColor Cyan
    Write-Host "====================================="

    try {
        $domain = Get-ADDomain -Server $global:dcHost
        $forest = Get-ADForest -Server $global:dcHost

        Write-Host "`n==== Domain FSMO Roles ====" -ForegroundColor Yellow
        Write-Host "PDC Emulator      : $($domain.PDCEmulator)"
        Write-Host "RID Master        : $($domain.RIDMaster)"
        Write-Host "Infrastructure    : $($domain.InfrastructureMaster)"

        Write-Host "`n==== Forest FSMO Roles ====" -ForegroundColor Yellow
        Write-Host "Schema Master     : $($forest.SchemaMaster)"
        Write-Host "Domain Naming     : $($forest.DomainNamingMaster)"

        Write-Host "`n[✓] FSMO role enumeration complete." -ForegroundColor Green
    } catch {
        Write-Host "[X] Failed to retrieve FSMO roles: $_" -ForegroundColor Red
    }

    Pause
}

# ================================================================
# Function: fncCheckSPN
# Purpose : Check if a user has any SPNs assigned
# Notes   : Useful for Kerberoasting enumeration
# ================================================================
function fncCheckSPN {
    param (
        [string]$user
    )

    Write-Host "=====================================" -ForegroundColor Cyan
    Write-Host "[+] Checking for SPNs on user: $user" -ForegroundColor Cyan
    Write-Host "====================================="

    try {
        $userDetails = Get-ADUser -Server $global:dcHost -Identity $user -Properties ServicePrincipalName, SamAccountName, Name

        if ($null -eq $userDetails) {
            Write-Host "[-] User not found." -ForegroundColor Red
            return
        }

        if ($userDetails.ServicePrincipalName -and $userDetails.ServicePrincipalName.Count -gt 0) {
            Write-Host "`n[!] SPNs found for user $($userDetails.SamAccountName) - $($userDetails.Name):" -ForegroundColor Yellow
            $userDetails.ServicePrincipalName | ForEach-Object {
                Write-Host "    $_" -ForegroundColor Magenta
            }
        } else {
            Write-Host "[✓] No SPNs assigned to this user." -ForegroundColor Green
        }

    } catch {
        Write-Host "[X] Error checking SPNs: $_" -ForegroundColor Red
    }
}

# ================================================================
# Function: fncCheckSIDHistory
# Purpose : Check if a user has any SID History values
# Notes   : Useful for identifying legacy/migrated accounts or SID injection
# ================================================================
function fncCheckSIDHistory {
    param (
        [string]$user
    )

    Write-Host "=====================================" -ForegroundColor Cyan
    Write-Host "[+] Checking SID History for user: $user" -ForegroundColor Cyan
    Write-Host "====================================="

    try {
        $userDetails = Get-ADUser -Server $global:dcHost -Identity $user -Properties SIDHistory, SamAccountName, Name

        if ($null -eq $userDetails) {
            Write-Host "[-] User not found." -ForegroundColor Red
            return
        }

        if ($userDetails.SIDHistory -and $userDetails.SIDHistory.Count -gt 0) {
            Write-Host "`n[!] SID History entries found for user $($userDetails.SamAccountName) - $($userDetails.Name):" -ForegroundColor Yellow
            $userDetails.SIDHistory | ForEach-Object {
                Write-Host "    $_" -ForegroundColor Magenta
            }
        } else {
            Write-Host "[✓] No SID History entries found." -ForegroundColor Green
        }

    } catch {
        Write-Host "[X] Error checking SID History: $_" -ForegroundColor Red
    }
}

# ================================================================
# Function: fncListTokenGroups
# Purpose : List all token groups (including transitive) for a user
# Notes   : Includes both resolved group names and SID values
# ================================================================
function fncListTokenGroups {
    param (
        [string]$user
    )

    Write-Host "=====================================" -ForegroundColor Cyan
    Write-Host "[+] Listing Token Groups for user: $user" -ForegroundColor Cyan
    Write-Host "====================================="

    try {
        $userObject = Get-ADUser -Server $global:dcHost -Identity $user -Properties TokenGroups

        if ($null -eq $userObject) {
            Write-Host "[-] User not found." -ForegroundColor Red
            return
        }

        if ($userObject.TokenGroups.Count -eq 0) {
            Write-Host "[✓] No token groups found for this user." -ForegroundColor Green
            return
        }

        foreach ($sid in $userObject.TokenGroups) {
            try {
                $group = New-Object System.Security.Principal.SecurityIdentifier($sid)
                $resolved = $group.Translate([System.Security.Principal.NTAccount])
                Write-Host "✔ $resolved ($sid)" -ForegroundColor Yellow
            } catch {
                Write-Host "⚠ Could not resolve SID: $sid" -ForegroundColor DarkYellow
            }
        }

    } catch {
        Write-Host "[X] Error retrieving token groups: $_" -ForegroundColor Red
    }
}

# ================================================================
# Function: fncCheckUserDelegation
# Purpose : Check if a user is configured for Kerberos delegation
# Notes   : Detects unconstrained, constrained, and RBCD
# ================================================================
function fncCheckUserDelegation {
    param (
        [string]$user
    )

    Write-Host "=====================================" -ForegroundColor Cyan
    Write-Host "[+] Checking delegation for user: $user" -ForegroundColor Cyan
    Write-Host "====================================="

    try {
        $props = @(
            "TrustedForDelegation", 
            "TrustedToAuthForDelegation", 
            "msDS-AllowedToDelegateTo", 
            "msDS-AllowedToActOnBehalfOfOtherIdentity"
        )

        $userObj = Get-ADUser -Server $global:dcHost -Identity $user -Properties $props

        if ($null -eq $userObj) {
            Write-Host "[-] User not found." -ForegroundColor Red
            return
        }

        $delegationSet = $false

        if ($userObj.TrustedForDelegation) {
            Write-Host "[!] Unconstrained Delegation is enabled." -ForegroundColor Red
            $delegationSet = $true
        }

        if ($userObj.TrustedToAuthForDelegation) {
            Write-Host "[!] Constrained Delegation to services using S4U2Proxy is enabled." -ForegroundColor Yellow
            $delegationSet = $true
        }

        if ($userObj.'msDS-AllowedToDelegateTo') {
            Write-Host "[!] Constrained Delegation to the following SPNs:" -ForegroundColor Yellow
            foreach ($spn in $userObj.'msDS-AllowedToDelegateTo') {
                Write-Host "    → $spn"
            }
            $delegationSet = $true
        }

        if ($userObj.'msDS-AllowedToActOnBehalfOfOtherIdentity') {
            Write-Host "[!] Resource-Based Constrained Delegation (RBCD) is configured." -ForegroundColor Yellow
            Write-Host "    → DN: $($userObj.'msDS-AllowedToActOnBehalfOfOtherIdentity'.DistinguishedName)"
            $delegationSet = $true
        }

        if (-not $delegationSet) {
            Write-Host "[✓] No delegation settings found for this user." -ForegroundColor Green
        }

    } catch {
        Write-Host "[X] Error while checking delegation: $_" -ForegroundColor Red
    }
}

# ================================================================
# Function: fncCheckGroupACLs
# Purpose : Check weak ACLs on a specified AD group object
# Notes   : Looks for risky ACEs like GenericAll, WriteDACL, etc.
# ================================================================
function fncCheckGroupACLs {
    param (
        [string]$group
    )

    Write-Host "=====================================" -ForegroundColor Cyan
    Write-Host "[+] Checking weak ACLs on group: $group" -ForegroundColor Cyan
    Write-Host "====================================="

    try {
        $groupDetails = Get-ADGroup -Server $global:dcHost -Identity $group -Properties DistinguishedName

        if (-not $groupDetails) {
            Write-Host "[-] Group not found." -ForegroundColor Red
            return
        }

        $dn = $groupDetails.DistinguishedName
        $path = "AD:\$dn"

        if (-not (Test-Path $path)) {
            Write-Host "[-] Cannot find AD path: $path" -ForegroundColor Red
            return
        }

        $acl = Get-Acl -Path $path

        $riskyRights = @(
            "GenericAll", "GenericWrite", "WriteOwner", "WriteDACL",
            "CreateChild", "DeleteChild", "WriteProperty", "Self"
        )

        $weakEntries = @()

        foreach ($entry in $acl.Access) {
            foreach ($right in $riskyRights) {
                if ($entry.ActiveDirectoryRights.HasFlag([System.DirectoryServices.ActiveDirectoryRights]::$right)) {
                    $weakEntries += $entry
                    break
                }
            }
        }

        $weakEntries = $weakEntries | Sort-Object IdentityReference, ActiveDirectoryRights -Unique

        # Default config suppress check
        if (-not ($global:config.PSObject.Properties.Name -contains "suppressSelfACE")) {
            $global:config | Add-Member -MemberType NoteProperty -Name suppressSelfACE -Value $false
        }

        if ($weakEntries.Count -gt 0) {
            Write-Host "`n[!] Weak permissions found on group object:" -ForegroundColor Red
            foreach ($entry in $weakEntries) {
                if ($global:config.suppressSelfACE -and $entry.IdentityReference -like "*SELF*") {
                    continue
                }

                if ($entry.ActiveDirectoryRights -match 'GenericAll|WriteDACL|WriteOwner') {
                    Write-Host "⚠️  HIGH RISK: $($entry.IdentityReference) - $($entry.ActiveDirectoryRights)" -ForegroundColor Red
                } else {
                    Write-Host "    Trustee   : $($entry.IdentityReference)" -ForegroundColor Yellow
                    Write-Host "    Right     : $($entry.ActiveDirectoryRights)"
                    Write-Host "    Type      : $($entry.AccessControlType)"
                    Write-Host "    Inherited : $($entry.IsInherited)"
                    Write-Host ""
                }
            }
        } else {
            Write-Host "[✓] No weak ACEs found on group." -ForegroundColor Green
        }
    } catch {
        Write-Host "[X] Failed to retrieve group ACL: $_" -ForegroundColor Red
    }
}

# ================================================================
# Function: fncCheckComputerACLs
# Purpose : Check weak ACLs on a specified AD computer object
# Notes   : Identifies risky ACEs like GenericAll, WriteDACL, etc.
# ================================================================
function fncCheckComputerACLs {
    param (
        [string]$computer
    )

    Write-Host "=====================================" -ForegroundColor Cyan
    Write-Host "[+] Checking weak ACLs on computer: $computer" -ForegroundColor Cyan
    Write-Host "====================================="

    try {
        $computerDetails = Get-ADComputer -Server $global:dcHost -Identity $computer -Properties DistinguishedName

        if (-not $computerDetails) {
            Write-Host "[-] Computer not found." -ForegroundColor Red
            return
        }

        $dn = $computerDetails.DistinguishedName
        $path = "AD:\$dn"

        if (-not (Test-Path $path)) {
            Write-Host "[-] Cannot find AD path: $path" -ForegroundColor Red
            return
        }

        $acl = Get-Acl -Path $path

        $riskyRights = @(
            "GenericAll", "GenericWrite", "WriteOwner", "WriteDACL",
            "CreateChild", "DeleteChild", "WriteProperty", "Self"
        )

        $weakEntries = @()

        foreach ($entry in $acl.Access) {
            foreach ($right in $riskyRights) {
                if ($entry.ActiveDirectoryRights.HasFlag([System.DirectoryServices.ActiveDirectoryRights]::$right)) {
                    $weakEntries += $entry
                    break
                }
            }
        }

        $weakEntries = $weakEntries | Sort-Object IdentityReference, ActiveDirectoryRights -Unique

        # Default config suppress check
        if (-not ($global:config.PSObject.Properties.Name -contains "suppressSelfACE")) {
            $global:config | Add-Member -MemberType NoteProperty -Name suppressSelfACE -Value $false
        }

        if ($weakEntries.Count -gt 0) {
            Write-Host "`n[!] Weak permissions found on computer object:" -ForegroundColor Red
            foreach ($entry in $weakEntries) {
                if ($global:config.suppressSelfACE -and $entry.IdentityReference -like "*SELF*") {
                    continue
                }

                if ($entry.ActiveDirectoryRights -match 'GenericAll|WriteDACL|WriteOwner') {
                    Write-Host "⚠️  HIGH RISK: $($entry.IdentityReference) - $($entry.ActiveDirectoryRights)" -ForegroundColor Red
                } else {
                    Write-Host "    Trustee   : $($entry.IdentityReference)" -ForegroundColor Yellow
                    Write-Host "    Right     : $($entry.ActiveDirectoryRights)"
                    Write-Host "    Type      : $($entry.AccessControlType)"
                    Write-Host "    Inherited : $($entry.IsInherited)"
                    Write-Host ""
                }
            }
        } else {
            Write-Host "[✓] No weak ACEs found on computer." -ForegroundColor Green
        }
    } catch {
        Write-Host "[X] Failed to retrieve computer ACL: $_" -ForegroundColor Red
    }
}

# ================================================================
# Function: fncGetPasswordPolicy
# Purpose : Displays default and FGPP password policy for current user
# Notes   : Uses Get-ADDefaultDomainPasswordPolicy + Get-ADUserResultantPasswordPolicy
# ================================================================
function fncGetPasswordPolicy {
    Write-Host "`n[+] Retrieving password policy..." -ForegroundColor Cyan
    Write-Host "==============================================="

    try {
        # Ensure AD module
        if (-not (Get-Module -Name ActiveDirectory)) {
            Import-Module ActiveDirectory -ErrorAction Stop
        }

        # Get user and domain from DC host and identity
        $user = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
        $domain = ($global:dcHost -split '\.')[0].ToUpper()

        Write-Host "[*] Connected Domain : $domain"
        Write-Host "[*] Current User     : $user"
        Write-Host "-----------------------------------------------"

        # Default domain password policy
        $defaultPolicy = Get-ADDefaultDomainPasswordPolicy -Server $global:dcHost
        if ($null -ne $defaultPolicy) {
            Write-Host "`n[✓] Default Domain Password Policy" -ForegroundColor Green
            Write-Host "-----------------------------------------------"
            Write-Host "Minimum Password Length      : $($defaultPolicy.MinPasswordLength)"
            Write-Host "Password History Count       : $($defaultPolicy.PasswordHistoryCount)"
            Write-Host "Maximum Password Age         : $($defaultPolicy.MaxPasswordAge.Days) days"
            Write-Host "Minimum Password Age         : $($defaultPolicy.MinPasswordAge.Days) days"
            Write-Host "Password Complexity Enabled  : $($defaultPolicy.ComplexityEnabled)"
            Write-Host "Reversible Encryption Allowed: $($defaultPolicy.ReversibleEncryptionEnabled)"
            Write-Host "Lockout Threshold            : $($defaultPolicy.LockoutThreshold)"
            Write-Host "Lockout Duration             : $($defaultPolicy.LockoutDuration.TotalMinutes) minutes"
            Write-Host "Lockout Observation Window   : $($defaultPolicy.LockoutObservationWindow.TotalMinutes) minutes"
        }

        # Check if FGPP applies to current user
        $samAccount = $user.Split('\')[-1]
        $fgpp = Get-ADUserResultantPasswordPolicy -Identity $samAccount -Server $global:dcHost -ErrorAction SilentlyContinue

        if ($fgpp) {
            Write-Host "`n[✓] Fine-Grained Password Policy (FGPP) Applies" -ForegroundColor Cyan
            Write-Host "-----------------------------------------------"
            Write-Host "Minimum Password Length      : $($fgpp.MinPasswordLength)"
            Write-Host "Password History Count       : $($fgpp.PasswordHistoryCount)"
            Write-Host "Maximum Password Age         : $($fgpp.MaxPasswordAge.Days) days"
            Write-Host "Minimum Password Age         : $($fgpp.MinPasswordAge.Days) days"
            Write-Host "Password Complexity Enabled  : $($fgpp.ComplexityEnabled)"
            Write-Host "Reversible Encryption Allowed: $($fgpp.ReversibleEncryptionEnabled)"
            Write-Host "Lockout Threshold            : $($fgpp.LockoutThreshold)"
            Write-Host "Lockout Duration             : $($fgpp.LockoutDuration.TotalMinutes) minutes"
            Write-Host "Lockout Observation Window   : $($fgpp.LockoutObservationWindow.TotalMinutes) minutes"
        } else {
            Write-Host "`n[✓] No Fine-Grained Password Policy found for this user." -ForegroundColor DarkGray
        }

    } catch {
        Write-Host "[X] Failed to retrieve password policy: $_" -ForegroundColor Red
    }

    Write-Host ""
    Read-Host -Prompt "Press [Enter] to return to the menu"
}

# ================================================================
# Function: fncGetGroupsByPattern
# Purpose : Search AD groups by name pattern and summarise members
# Notes   : Includes group owner, deputy, and description output
# ================================================================
function fncGetGroupsByPattern {
    param(
        [string]$dcHost = $null
    )

    $raw = Read-Host "Enter group name pattern (e.g. *Admin or Admin*)"
    if (-not $raw) {
        Write-Host "[!] No pattern entered. Aborting." -ForegroundColor Yellow
        return
    }

    $pattern = if ($raw -notmatch '\*') { "*$raw*" } else { $raw }
    fncPrintMessage "Search pattern: $pattern" "debug"

    $params = @{}
    if ($dcHost) {
        $params['Server'] = $dcHost
        fncPrintMessage "Using DC host override: $dcHost" "debug"
    }

    try {
        fncPrintMessage "Running Get-ADGroup query..." "debug"
        $groups = Get-ADGroup -Filter "Name -like '$pattern'" -Properties Description, ManagedBy @params | Sort-Object Name

        if (-not $groups) {
            Write-Host "[i] No groups matched '$pattern'." -ForegroundColor Yellow
            return
        }

        fncPrintMessage ("Matched {0} group(s) using pattern: {1}" -f $groups.Count, $pattern) "debug"
        Write-Host "`n[=] Processing $($groups.Count) group(s)..." -ForegroundColor Cyan

        $uniqueUsers = New-Object 'System.Collections.Generic.HashSet[string]'
        $groupRows   = New-Object 'System.Collections.Generic.List[object]'
        $dupTotal = 0
        $emptyGroups = 0

        $total = $groups.Count
        $i = 0
        $sw = [System.Diagnostics.Stopwatch]::StartNew()

        foreach ($g in $groups) {
            $i++
            $percent = [math]::Round(($i / $total) * 100)
            Write-Progress -Activity "Processing Groups..." -Status "[$i/$total] $($g.Name)" -PercentComplete $percent

            fncPrintMessage "Processing group: $($g.Name)" "debug"
            try {
                $gm = @(Get-ADGroupMember -Identity $g.DistinguishedName -Recursive -ErrorAction Stop @params)
                fncPrintMessage (" -> Get-ADGroupMember returned {0} object(s)" -f $gm.Count) "debug"
            } catch {
                Write-Host "[!] Failed to get members for group: $($g.Name)" -ForegroundColor Yellow
                fncPrintMessage $_.Exception.Message "debug"
                continue
            }

            $userMembers = @($gm | Where-Object { $_.objectClass -eq 'user' })
            fncPrintMessage " -> Filtered to $($userMembers.Count) user(s)" "debug"

            if ($userMembers.Count -eq 0) {
                $emptyGroups++
                fncPrintMessage " -> Group is empty (0 user members)." "debug"
            }

            $dupTotal += $userMembers.Count

            foreach ($u in $userMembers) {
                try {
                    $dn = $u | Select-Object -ExpandProperty DistinguishedName
                    if ($dn) { [void]$uniqueUsers.Add([string]$dn) }
                } catch {
                    fncPrintMessage " -> Failed to extract DN: $($_.Exception.Message)" "debug"
                }
            }

            # Owner and Deputy lookup
            $ownerName = "Unassigned"
            $deputyName = "Unassigned"
            if ($g.ManagedBy) {
                try {
                    $manager = Get-ADUser -Identity $g.ManagedBy -Properties GivenName, Surname, Manager @params
                    $ownerName = "$($manager.GivenName) $($manager.Surname)"
                    if ($manager.Manager) {
                        $deputy = Get-ADUser -Identity $manager.Manager -Properties GivenName, Surname @params
                        $deputyName = "$($deputy.GivenName) $($deputy.Surname)"
                    }
                } catch {
                    fncPrintMessage "Failed to retrieve owner/deputy: $($_.Exception.Message)" "debug"
                }
            }

            # Determine if high privilege group (same as user function)
            $highPriv = ($g.Name -match 'admin|domain|enterprise|privileged|schema|account|backup|group policy|dns' -or
                         $g.DistinguishedName -match 'OU=Admin|OU=Privileged|OU=Tier|OU=High|OU=Protected')

            $groupRows.Add([PSCustomObject]@{
                GroupID      = $g.Name
                UserCount    = $userMembers.Count
                Owner        = $ownerName
                Deputy       = $deputyName
                Description  = $g.Description
                HighPriv     = $highPriv
            }) | Out-Null
        }

        $sw.Stop()
        Write-Progress -Activity "Done" -Completed

        Write-Host ("[✓] Total groups matched: {0}" -f $total) -ForegroundColor Green
        Write-Host ("[=] Total user memberships (with duplicates): {0}" -f $dupTotal) -ForegroundColor Cyan
        Write-Host ("[=] Total unique users:                       {0}" -f $uniqueUsers.Count) -ForegroundColor Cyan
        Write-Host ("[=] Groups with zero user members:            {0}" -f $emptyGroups) -ForegroundColor Yellow

        fncPrintMessage "UniqueUsers Count: $($uniqueUsers.Count)" "debug"
        fncPrintMessage "GroupRows Count:   $($groupRows.Count)" "debug"
        fncPrintMessage "Duplicates Count:  $dupTotal" "debug"
        fncPrintMessage "Empty Groups:      $emptyGroups" "debug"

        if ($total -le 20) {
            do {
                Write-Host "[=] Matching Groups (Select one to view details)" -ForegroundColor Cyan

                $indexed = $groupRows | Select-Object @{Name="Index";Expression={[array]::IndexOf($groupRows, $_)}}, *
                $indexed | ForEach-Object {
                    $color = if ($_.HighPriv) { "Magenta" } else { "White" }
                    Write-Host ("[{0}] {1,-30} | Users: {2,-3} | Owner: {3,-20} | Deputy: {4,-20} | {5}" -f
                        $_.Index, $_.GroupID, $_.UserCount, $_.Owner, $_.Deputy, $_.Description) -ForegroundColor $color
                }

                $selection = Read-Host "`nEnter index of group to view details, or press [Enter] to return"
                if ($selection -match '^\d+$' -and [int]$selection -lt $groupRows.Count) {
                    $selectedGroup = $groupRows[$selection].GroupID
                    fncPrintMessage "Selected group: $selectedGroup — calling fncGetGroupInfo" "debug"
                    fncGetGroupInfo -GroupName $selectedGroup
                    Write-Host ""
                    Read-Host -Prompt "Press [Enter] to return to group list"
                } elseif ($selection -eq '') {
                    break
                } else {
                    Write-Host "[!] Invalid selection." -ForegroundColor Yellow
                    Start-Sleep -Seconds 1.5
                }
            } while ($true)
        } else {
            Write-Host "[i] Too many groups to show detailed table. Use a narrower pattern." -ForegroundColor Yellow
        }

    } catch {
        Write-Host "[X] Error in fncGetGroupsByPattern: $($_.Exception.Message)" -ForegroundColor Red
        if ($global:config.DEBUG_MODE -eq $true) {
            Write-Host ($_.Exception | Format-List * -Force | Out-String) -ForegroundColor DarkGray
            Write-Host ("[DEBUG] StackTrace:`n{0}" -f ($_.ScriptStackTrace)) -ForegroundColor DarkGray
        }
    }
}

# ================================================================
# Function: fncGenerateKerberosAESKeys
# Purpose : Generate AES128/256 Kerberos keys for an AD user or host account
# Notes   : Supports current or custom domain, manual or wordlist input
# ================================================================
function fncGenerateKerberosAESKeys {
    param (
        [string]$domain,
        [string]$username,
        [string]$password,
        [bool]$isHost = $false
    )

    # Constants
    $AES256_CONSTANT = [byte[]](0x6B,0x65,0x72,0x62,0x65,0x72,0x6F,0x73,0x7B,0x9B,0x5B,0x2B,0x93,0x13,0x2B,0x93,0x5C,0x9B,0xDC,0xDA,0xD9,0x5C,0x98,0x99,0xC4,0xCA,0xE4,0xDE,0xE6,0xD6,0xCA,0xE4)
    $AES128_CONSTANT = $AES256_CONSTANT[0..15]
    $IV = [byte[]](0..15 | ForEach-Object { 0x00 })
    $ITERATION = 4096

    try {
        # Salt
        if ($isHost) {
            $hostname = $username.TrimEnd('$').ToLower()
            $salt = "$domain" + "host" + "$hostname.$($domain.ToLower())"
        } else {
            $salt = "$domain$username"
        }

        fncPrintMessage "[*] Kerberos Salt: $salt" "info"

        $saltBytes = [System.Text.Encoding]::UTF8.GetBytes($salt)

        try {
            $passwordBytes = [System.Text.Encoding]::UTF8.GetBytes($password)
        } catch {
            fncPrintMessage "[-] Failed to encode password." "error"
            return
        }

        # Derive AES256 key using PBKDF2
        $aes256PBKDF2 = [System.Security.Cryptography.Rfc2898DeriveBytes]::new($passwordBytes, $saltBytes, $ITERATION)
        $aes256Key = $aes256PBKDF2.GetBytes(32)
        $aes128Key = $aes256Key[0..15]

        # AES 256
        $aes = [System.Security.Cryptography.Aes]::Create()
        $aes.Mode = "CBC"
        $aes.Padding = "None"
        $aes.Key = $aes256Key
        $aes.IV = $IV
        $encryptor = $aes.CreateEncryptor()
        $key1 = $encryptor.TransformFinalBlock($AES256_CONSTANT, 0, $AES256_CONSTANT.Length)

        $aes = [System.Security.Cryptography.Aes]::Create()
        $aes.Mode = "CBC"
        $aes.Padding = "None"
        $aes.Key = $aes256Key
        $aes.IV = $IV
        $encryptor2 = $aes.CreateEncryptor()
        $key2 = $encryptor2.TransformFinalBlock($key1, 0, $key1.Length)

        $aes256Final = $key1[0..15] + $key2[0..15]
        $aes256Hex = ($aes256Final | ForEach-Object { $_.ToString("X2") }) -join ""

        # AES 128
        $aes = [System.Security.Cryptography.Aes]::Create()
        $aes.Mode = "CBC"
        $aes.Padding = "None"
        $aes.Key = $aes128Key
        $aes.IV = $IV
        $encryptor128 = $aes.CreateEncryptor()
        $aes128Final = $encryptor128.TransformFinalBlock($AES128_CONSTANT, 0, $AES128_CONSTANT.Length)
        $aes128Hex = ($aes128Final | ForEach-Object { $_.ToString("X2") }) -join ""

        # Output
        Write-Host "`n[+] AES256 Key: $aes256Hex" -ForegroundColor Green
        Write-Host "[+] AES128 Key: $aes128Hex" -ForegroundColor Yellow
        Write-Host "[X] Key is not valid for using as a Kerberos Ticket" -ForegroundColor Red
    }
    catch {
        fncPrintMessage "[-] AES key generation failed: $_" "error"
    }
}

# ================================================================
# Function: fncCheckComputerAccess
# Purpose : Given a TXT of hostnames (one per line), resolve IP,
#           RDP/SSH status, and pull detailed AD computer info.
# Notes   : Each line in the TXT must be a hostname
# ================================================================
function fncCheckComputerAccess {
    Add-Type -AssemblyName System.Windows.Forms

    $OpenFileDialog = New-Object System.Windows.Forms.OpenFileDialog
    $OpenFileDialog.InitialDirectory = [Environment]::GetFolderPath("Desktop")
    $OpenFileDialog.Filter = "Text files (*.txt)|*.txt"
    $OpenFileDialog.Title = "Select TXT of Hostnames"
    
    if ($OpenFileDialog.ShowDialog() -ne "OK") {
        fncPrintMessage "Cancelled file selection." "warn"
        return
    }

    $txtPath = $OpenFileDialog.FileName
    if (-not (Test-Path $txtPath)) {
        fncPrintMessage "File not found: $txtPath" "error"
        return
    }

    fncPrintMessage "Loading hostnames from TXT: $txtPath" "debug"

    try {
        $computers = Get-Content $txtPath | Where-Object { $_.Trim() -ne "" }
        fncPrintMessage "Imported $($computers.Count) host entries from TXT." "debug"
    } catch {
        fncPrintMessage "Failed to read TXT: $_" "error"
        return
    }

    # 🔑 Show current domain info
    try {
        $domainCtx = (Get-ADDomain -Server $global:dcHost).DNSRoot
        fncPrintMessage "Using DC host: $global:dcHost (Domain: $domainCtx)" "debug"
    } catch {
        fncPrintMessage "Could not resolve domain context for $global:dcHost ($_)" "warn"
    }

    $output = @()

    foreach ($hostname in $computers) {
        $hostname = $hostname.Trim()
        if (-not $hostname) { continue }

        Write-Host "`n🔍 Checking: $hostname" -ForegroundColor Cyan
        fncPrintMessage "Starting checks for $hostname" "debug"

        # DNS resolution
        $ip = try {
            $resolved = [System.Net.Dns]::GetHostAddresses($hostname)[0].IPAddressToString
            fncPrintMessage "$hostname resolved to $resolved" "debug"
            $resolved
        } catch {
            fncPrintMessage "DNS resolution failed for $hostname" "debug"
            "Resolution Failed"
        }

        # Port status
        $rdpOpen = $false
        $sshOpen = $false

        if ($ip -ne "Resolution Failed") {
            try {
                $rdpOpen = Test-NetConnection -ComputerName $ip -Port 3389 -InformationLevel Quiet
                fncPrintMessage "RDP port 3389 on $hostname ($ip) open: $rdpOpen" "debug"

                $sshOpen = Test-NetConnection -ComputerName $ip -Port 22 -InformationLevel Quiet
                fncPrintMessage "SSH port 22 on $hostname ($ip) open: $sshOpen" "debug"
            } catch {
                fncPrintMessage "Connection test failed for $ip" "debug"
            }
        }

        # AD lookup
        $adGroups = "N/A"
        $owner = "N/A"
        $site = ""
        $dnsName = ""
        $canonical = ""
        $os = ""
        $osVer = ""
        $spack = ""
        $desc = ""

        try {
    fncPrintMessage "Querying AD for $hostname on $global:dcHost" "debug"

    $adComputer = Get-ADComputer -Server $global:dcHost -Identity $hostname -Properties `
        MemberOf, ManagedBy, CanonicalName, Description, DNSHostName, OperatingSystem, OperatingSystemVersion, OperatingSystemServicePack

    if ($adComputer) {
        fncPrintMessage "AD object found for $hostname" "debug"

        # Get groups
        if ($adComputer.MemberOf) {
            $groupNames = $adComputer.MemberOf | ForEach-Object {
                ($_ -split ',')[0] -replace '^CN='
            }
            $adGroups = $groupNames -join '; '
            fncPrintMessage "$hostname is a member of groups: $adGroups" "debug"
        }

        # Owner
        if ($adComputer.ManagedBy) {
            $ownerObj = Get-ADUser -Server $global:dcHost -Identity $adComputer.ManagedBy -Properties DisplayName, SamAccountName
            if ($ownerObj) {
                $owner = "$($ownerObj.DisplayName) ($($ownerObj.SamAccountName))"
                fncPrintMessage "Device owner for $hostname resolved to $owner" "debug"
            }
        }

        # Other attributes
        $dnsName   = $adComputer.DNSHostName
        $canonical = $adComputer.CanonicalName
        $desc      = $adComputer.Description
        $os        = $adComputer.OperatingSystem
        $osVer     = $adComputer.OperatingSystemVersion
        $spack     = $adComputer.OperatingSystemServicePack

        fncPrintMessage "OS: $os ($osVer) SP: $spack" "debug"
    }
} catch {
    fncPrintMessage "AD lookup failed for $hostname ($_)" "debug"
}


        # Add result row
        $output += [PSCustomObject]@{
            Hostname                         = $hostname
            IPAddress                        = $ip
            'RDP Port Open'                  = $rdpOpen
            'SSH Port Open'                  = $sshOpen
            DNS_Name                         = $dnsName
            Canonical_Name                   = $canonical
            Site                             = $site
            Description                      = $desc
            Operating_System                 = $os
            OS_Version                       = $osVer
            Service_Pack                     = $spack
            'AD Groups'                      = $adGroups
            'Device Owner'                   = $owner
            'The Interrogator Device Dumper' = '✅'
        }
    }

    # Show results to screen
    fncPrintMessage "Displaying results on screen..." "debug"
    $output | Sort-Object Hostname | Format-Table -AutoSize

    # Export
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $outfile = "$PSScriptRoot\ComputerAccess_$timestamp.csv"
    fncPrintMessage "Exporting results to $outfile" "debug"

    $output | Export-Csv -NoTypeInformation -Path $outfile

    Write-Host "`n✅ Scan complete. Results saved to: $outfile" -ForegroundColor Green
}






##################
### Menu Logic ###
##################
function fncMainMenu {
    while ($true) {
        $line = "=" * 70
        $user = $global:config.LAST_KWN_USR
        $domain = $global:config.LAST_KWN_DOM
        $dcHost = $global:domainMap[$domain]

        if (-not $global:config.DEBUG_ENABLED) {
            Clear-Host
            fncPrintBanner
            Write-Host $line -ForegroundColor DarkCyan
            Write-Host ("   Welcome! You are logged in as: " + $user) -ForegroundColor Green
            Write-Host ("   Current Domain: " + $domain) -ForegroundColor Yellow
            Write-Host ("   Domain Controller: " + $dcHost) -ForegroundColor Yellow
            Write-Host $line -ForegroundColor DarkCyan
            Write-Host ""
        } else {
            Write-Host $line -ForegroundColor Blue -BackgroundColor Red
            Write-Host ("   Welcome! You are logged in as: " + $user) -ForegroundColor Green
            Write-Host ("   Current Domain: " + $domain) -ForegroundColor Yellow
            Write-Host ("   Domain Controller: " + $dcHost) -ForegroundColor Yellow
            Write-Host ("              DEBUG MODE ENABLED                       ") -ForegroundColor Blue
            Write-Host $line -ForegroundColor Blue -BackgroundColor Red
            Write-Host ""
        }
        
        Write-Host "Main Menu:" -ForegroundColor Cyan
        Write-Host "  [ 1] Search for User"
        Write-Host "  [ 2] Search for Group"
        Write-Host "  [22]     Search Wildcard Group"
        Write-Host "  [ 3] Search for Computer"
        Write-Host ""
        # Display Preset Menu Option if any exist
        if ($global:config.userItems -and $global:config.userItems.Count -gt 0) {
            $availablePresets = $global:config.userItems.Keys | Where-Object {
                $_ -and ($_ -notmatch '_TYPE$') -and
                ($global:config.userItems[$_] -is [System.Collections.IEnumerable]) -and
                ($global:config.userItems[$_].Count -gt 0)
            }

            if ($availablePresets.Count -gt 0) {
                Write-Host "  [4] Presets" -ForegroundColor Green
                Write-Host "  [N] Add New Preset" -ForegroundColor Cyan
            } else {
                Write-Host "  [X] No Presets Set" -ForegroundColor Red
                Write-Host "  [N] Add New Preset" -ForegroundColor Cyan
            }
        } else {
            Write-Host "  [X]  No Presets Set" -ForegroundColor Red
        }
        Write-Host ""
        if ($global:config.ADVANCED_MODE) {
            Write-Host "  [7] Super Secret Menu." -ForegroundColor Red
        } else {
			Write-Host "  [X] Super Secret Menu." -ForegroundColor Red
		}
		Write-Host "  [8] The Dumper"
		Write-Host ""
        Write-Host "9. Settings"
        Write-Host "Q. Exit"
        Write-Host ""

        
        $choice = Read-Host "Enter your selection (1-9)"

        switch ($choice) {
            "1" {
                $user = Read-Host "Enter the SamAccountName or full DistinguishedName of the user"
                if (![string]::IsNullOrWhiteSpace($user)) {
                    fncGetUserInfo -user $user
                } else {
                    fncPrintMessage "No user input provided. Returning to menu." "warning"
                }
                Pause
            }
            "2" {
                $group = Read-Host "Enter the name of the group"
                if (![string]::IsNullOrWhiteSpace($group)) {
                    fncGetGroupInfo -groupName $group
                } else {
                    fncPrintMessage "No group name provided. Returning to menu." "warning"
                }
                Pause
            }
            '22' {
                fncPrintBanner
                Write-Host "`n[>] Running Group Search by Pattern..." -ForegroundColor Green
                fncGetGroupsByPattern -dcHost $global:dcHost
                Pause
            }
            "3" {
                $device = Read-Host "Enter the device hostname"
                if (![string]::IsNullOrWhiteSpace($device)) {
                    fncCheckComputerInfo -device $device
                } else {
                    fncPrintMessage "No device name provided. Returning to menu." "warning"
                }
                Pause
            }

            '4' {
                fncPresetRunner
                Pause
            }
            '7' {
				if ($global:config.ADVANCED_MODE) {
					fncAdvancedMenu
					Pause
				} else {
					fncPrintMessage "Advanced Mode is Disabled" "warning"
				}
            }
            '8' {
                fncTheDumper
                Pause
            }
            "9" {
                fncSettingsMenu
            }
            'N' {
                fncPrintMessage "Create a new Preset Group" "info"

                $presetName = Read-Host "Name the Preset Group (e.g., userGroupPreset77 or groupASSETS)"
                if ([string]::IsNullOrWhiteSpace($presetName)) {
                    fncPrintMessage "Invalid group name. Returning to menu." "error"
                    fncMainMenu
                }
                $presetName = $presetName.Trim()

                # Convert PSCustomObject to Hashtable if needed
                if ($global:config.userItems -isnot [hashtable]) {
                    $newUserItems = @{}
                    foreach ($key in $global:config.userItems.PSObject.Properties.Name) {
                        $newUserItems[$key] = $global:config.userItems.$key
                    }
                    $global:config.userItems = $newUserItems
                }

                # Check if the preset already exists
                if ($global:config.userItems.ContainsKey($presetName)) {
                    fncPrintMessage "This preset already exists. Please choose a new name or remove the existing one manually." "error"
                    fncMainMenu
                }

                Write-Host ""
                Write-Host "Select the type of items to include in this group:" -ForegroundColor Cyan
                Write-Host "U = Users (fncGetUserInfo)" -ForegroundColor Yellow
                Write-Host "G = Groups (fncGetGroupInfo)" -ForegroundColor Yellow
                Write-Host "C = Computers (fncCheckComputerInfo)" -ForegroundColor Yellow
                $typeChoice = Read-Host "Your choice (U/G/C)"

                switch ($typeChoice.ToUpper()) {
                    'U' { $presetType = 'User'; $runner = 'fncGetUserInfo' }
                    'G' { $presetType = 'Group'; $runner = 'fncGetGroupInfo' }
                    'C' { $presetType = 'Computer'; $runner = 'fncCheckComputerInfo' }
                    default {
                        fncPrintMessage "Invalid selection. Must be U, G, or C." "error"
                        fncMainMenu
                        return
                    }
                }

                $entryList = @()
                while ($true) {
                    $item = Read-Host "Enter a $presetType to add (or press Enter to finish)"
                    if ([string]::IsNullOrWhiteSpace($item)) { break }
                    $entryList += $item.Trim()
                    fncPrintMessage "Added: $item" "success"
                }

                if ($entryList.Count -eq 0) {
                    fncPrintMessage "No entries added. Preset not saved." "warning"
                    fncMainMenu
                    return
                }

                # Save to config
                $global:config.userItems[$presetName] = $entryList
                $global:config.userItems["${presetName}_TYPE"] = $runner

                try {
                    fncPrintMessage "Saving updated config to: $global:jsonFilePath" "debug"

                    # Confirm it's serializable
                    $jsonOut = $global:config | ConvertTo-Json -Depth 10
                    $jsonOut | Out-File -FilePath $global:jsonFilePath -Encoding UTF8

                    fncPrintMessage "Preset group '$presetName' created with type '$presetType' and saved." "success"
                } catch {
                    fncPrintMessage "Failed to save updated config: $_" "error"
                }


                try {
                    fncSaveConfig -config $global:config -jsonFilePath $global:jsonFilePath
                    fncPrintMessage "Preset group '$presetName' created with type '$presetType'." "success"
                } catch {
                    fncPrintMessage "ERROR: Failed to save preset group '$presetName': $_" "error"
                    Read-Host "Press Enter to return to main menu"
                }
                fncMainMenu
            }

            "Q" {
            }
            default {
                fncPrintMessage "Invalid selection. Please choose a valid option" "error"
                Start-Sleep -Seconds 1.5
            }
        }
    }
}

function fncSettingsMenu {
    Clear-Host
    fncPrintBanner
    fncPrintMessage "Settings Menu" "info"
    Write-Host ""
    Write-Host "=========== Settings Options ===========" -ForegroundColor Cyan
    Write-Host " 1. View Loaded Config" -ForegroundColor Yellow
    Write-Host " 2. Reload Config" -ForegroundColor Yellow
    Write-Host " 3. Reconnect to AD (PSDrive)" -ForegroundColor Yellow
    Write-Host " 4. Change Domain" -ForegroundColor Yellow
    Write-Host ""
    
    Write-Host ""
    Write-Host " 0. Return to Main Menu" -ForegroundColor Red
    Write-Host "========================================" -ForegroundColor Cyan

    $choice = Read-Host "Please select a settings option"
    switch ($choice) {
        '1' {
            fncPrintMessage "Loaded Config:" "info"
            $global:config | ConvertTo-Json -Depth 5 | Out-String | Write-Host
            Pause
            fncSettingsMenu
        }
        '2' {
            fncPrintMessage "Reloading configuration..." "info"
            $global:config = fncInitConfig -jsonFilePath $global:jsonFilePath
            fncPrintMessage "Configuration reloaded." "success"
            Pause
            fncSettingsMenu
        }
        '3' {
            fncLoadPSDrive
            Pause
            fncSettingsMenu
        }
        '4' {
            $newDomain = Read-Host "Enter new domain (e.g., BOBSDOMAIN.com)"
            if (-not [string]::IsNullOrWhiteSpace($newDomain)) {
                $newDomain = $newDomain.ToUpper()

                # Unmount old domain if it's mounted
                if (Get-PSDrive -Name $global:config.LAST_KWN_DOM -ErrorAction SilentlyContinue) {
                    try {
                        Remove-PSDrive -Name $global:config.LAST_KWN_DOM -Force -ErrorAction Stop
                        fncPrintMessage "Removed old PSDrive: $($global:config.LAST_KWN_DOM)" "info"
                    } catch {
                        fncPrintMessage "Failed to remove old PSDrive: $_" "error"
                    }
                }

                # Attempt to mount new domain
                $mountResult = fncMountPSDrive -domain $newDomain
                if ($mountResult) {
                    $global:config.LAST_KWN_DOM = $newDomain
                    fncPrintMessage "Domain updated and PSDrive mounted: $newDomain" "success"
                    fncSaveConfig -config $global:config -jsonFilePath $global:jsonFilePath
                } else {
                    fncPrintMessage "Failed to mount PSDrive for domain: $newDomain" "error"
                }
            } else {
                fncPrintMessage "Invalid domain input. No changes made." "error"
            }
            Pause
            fncSettingsMenu
        }
        '0' {
            fncMainMenu
        }
        default {
            fncPrintMessage "Invalid option. Please try again." "error"
            Pause
            fncSettingsMenu
        }
    }
}

function fncTheDumper {
    Write-Host ""
    Write-Host "==== THE DUMPER ====" -ForegroundColor Cyan
    Write-Host "[1] Dump Computer Groups"
    Write-Host "[2] Dump User Groups"
    Write-Host "[3] Dump Group Members"
    $choice = Read-Host "Select an option (1 or 2)"

    switch ($choice) {
        '1' {
			Clear-Host
			fncPrintBanner	
            fncDumpComputerGroups
        }
        '2' {
			Clear-Host
			fncPrintBanner			
            fncDumpUserGroups
        }
        '3' {
			Clear-Host
			fncPrintBanner	
            fncDumpGroupMembers
        }
        default {
            fncPrintMessage "Invalid option." "error"
        }
    }
}

function fncAdvancedMenu {
    if (-not $global:config.ADVANCED_MODE) {
        Write-Host "[X] Advanced Mode is not enabled. Pentester Menu unavailable." -ForegroundColor Red
        return
    }

    while ($true) {
		Clear-Host
		fncPrintBanner	
        Write-Host "=======================" -ForegroundColor Cyan
        Write-Host "   Super Secret Menu"
        Write-Host "=======================" -ForegroundColor Cyan
        Write-Host ""

        Write-Host "==== DC / Forest Commands ====" -ForegroundColor DarkCyan
        Write-Host "1.  Get Domain Information"
        Write-Host "2.  Get Forest Information"
        Write-Host "3.  List Domain Controllers"
        Write-Host "4.  Get Trust Relationships"
        Write-Host "5.  Get FSMO Role Holders"
		Write-Host "6.  Get Current Domain Password Policy"
        Write-Host ""

        Write-Host "==== User Commands ====" -ForegroundColor DarkGreen
        Write-Host "7.  Check Weak ACLs on User"
        Write-Host "8.  Check SACLS on User"
        Write-Host "9.  Check if User has SPN"
        Write-Host "10.  Check if User has SID History"
        Write-Host "11. List User's Token Groups"
        Write-Host "12. Check if User has Delegation Rights"
        Write-Host ""

        Write-Host "==== Group Commands ====" -ForegroundColor DarkYellow
        Write-Host "13. Dump Group Members"
        Write-Host "14. Check Group Managers"
        Write-Host "15. Check Group Delegated Permissions"
        Write-Host ""

        Write-Host "==== Computer Commands ====" -ForegroundColor DarkMagenta
        Write-Host "16. Dump Computer Group Membership"
        Write-Host "17. Bulk Dump Computer Information."
        Write-Host "18. Check Admin Rights on Computer (via ACLs)"
        Write-Host ""

        Write-Host "==== Other Commands ====" -ForegroundColor DarkMagenta
        Write-Host "99. Bloodhound Dumper" -ForegroundColor Red
        Write-Host "==== Misc ====" -ForegroundColor Gray
        Write-Host "0. Exit Advanced Menu"
        Write-Host ""

        $choice = Read-Host "Select an option"

        switch ($choice) {
            # ==== DC Commands ====
            '1'  { 
				Clear-Host
				fncPrintBanner	
				fncGetDomainInfo 
			}
            '2'  {
				Clear-Host
				fncPrintBanner	
				fncGetForestInfo 
			}
            '3'  {
				Clear-Host
				fncPrintBanner	 
				fncListDomainControllers 
			}
            '4'  {
				Clear-Host
				fncPrintBanner	 
				fncGetTrusts 
			}
            '5'  {
				Clear-Host
				fncPrintBanner				
				fncGetFSMORoles
			}
            '6' {
				Clear-Host
				fncPrintBanner
                fncGetPasswordPolicy 
				break
            }
            # ==== User Commands ====
            '7'  {
				Clear-Host
				fncPrintBanner
                $user = Read-Host "Enter the username (samAccountName) to check ACLs for"
                fncCheckWeakACLs -user $user
            }

            '8'  {
				Clear-Host
				fncPrintBanner
                $user = Read-Host "Enter the username (samAccountName) to check SACLS for"
                fncCheckSACLS -user $user
            }

            '9'  {
				Clear-Host
				fncPrintBanner				
                $user = Read-Host "Enter the username (samAccountName) to check SPNs for"
                fncCheckSPN -user $user
            }

            '10'  {
				Clear-Host
				fncPrintBanner				
                $user = Read-Host "Enter the username (samAccountName) to check SID History for"
                fncCheckSIDHistory -user $user
            }

            '11' {
				Clear-Host
				fncPrintBanner				
                $user = Read-Host "Enter the username (samAccountName) to list token groups"
                fncListTokenGroups -user $user
            }

            '12' {
				Clear-Host
				fncPrintBanner				
                $user = Read-Host "Enter the username (samAccountName) to check delegation settings"
                fncCheckUserDelegation -user $user
            }

            '13' {
				Clear-Host
				fncPrintBanner				
                $group = Read-Host "Enter the group name (samAccountName or CN)"
                fncDumpGroupMembers -group $group
            }

            '14' {
				Clear-Host
				fncPrintBanner				
                $group = Read-Host "Enter the group name to check for managers"
                fncCheckGroupManagers -group $group
            }

            '15' {
				Clear-Host
				fncPrintBanner				
                $group = Read-Host "Enter the group name to check ACLs for"
                fncCheckGroupACLs -group $group
            }

            '16' {
				Clear-Host
				fncPrintBanner				
                $computer = Read-Host "Enter the computer name (hostname)"
                fncDumpComputerGroups -computer $computer
            }

            '17' {
				fncCheckComputerAccess
            }
            '18' {
				Clear-Host
				fncPrintBanner				
                $computer = Read-Host "Enter the computer name (hostname) to check ACLs for"
                fncCheckComputerACLs -computer $computer
            }
            '0' {
				fncMainMenu
            }

            '99' {
                Write-Host "`nComing soon" -ForegroundColor Magenta
            }            

            default {
                Write-Host "`n[!] Invalid option. Please try again." -ForegroundColor Red
            }
        }
    }
}


#===========#
# Main Logic #
#===========#

function fncMain {
    fncPrintBanner
    fncCheckGodMode

    # Load config
    $config = fncInitConfig -jsonFilePath $jsonFilePath

    # Check config file existence
    if (-not (Test-Path -Path $jsonFilePath)) {
        fncPrintMessage "Configuration file not found." "error"
        fncPrintMessage "Please run 'installer.ps1' first to complete setup." "warning"
        Exit 1
    }

    # Ensure config folder exists
    if (-not (Test-Path -Path (Split-Path -Path $jsonFilePath))) {
        New-Item -ItemType Directory -Path (Split-Path -Path $jsonFilePath) -Force | Out-Null
    }

    # Ensure setup complete
    if (-not ($global:config.IS_SETUP -eq $true)) {
        fncPrintMessage "Configuration detected but setup not marked complete." "warning"
        fncPrintMessage "Please re-run 'installer.ps1' to complete setup." "error"
        exit
    }

    fncUpdateDomainSettings

    # Then check PS and modules
    fncCheckPSVersion
    fncCheckModules
    fncLoadPSDrive 

    # Launch main menu
    fncMainMenu
}

# Run it
fncMain