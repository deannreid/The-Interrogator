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

    # Ask user to reuse last known domain
    if ($config.LAST_KWN_DOM) {
        $reuse = Read-Host "Do you want to use the last known domain ($($config.LAST_KWN_DOM))? (Y/N)"
        $DOMAIN = if ($reuse -match "^(Y|y)") {
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

    fncPrintMessage "Attempting nltest /dsgetdc:$DOMAIN" "debug"
    $nltestOutput = nltest /dsgetdc:$DOMAIN 2>&1
    $dcHost = ($nltestOutput | Where-Object { $_ -match 'DC:' }) -replace '.*DC:\s*',''
    $dcHost = $dcHost -replace '^\\\\', ''

    fncPrintMessage "Extracted DC Host: $dcHost" "debug"

    if (-not $dcHost) {
        fncPrintMessage "Failed to find a Domain Controller for $DOMAIN." "error"
        return
    }

    fncPrintMessage "Resolving DC hostname: $dcHost" "info"
    $nslookup = nslookup $dcHost 2>&1
    if ($nslookup -match 'Name:|Address:') {
        fncPrintMessage "DC hostname resolved successfully." "success"
    } else {
        fncPrintMessage "Failed to resolve DC hostname using nslookup." "error"
        return
    }

    # Prompt for username (reuse optional)
    if ($config.LAST_KWN_USR) {
        $reuseUser = Read-Host "Do you want to use the last known username ($($config.LAST_KWN_USR))? (Y/N)"
        $username = if ($reuseUser -match "^(Y|y)") {
            $config.LAST_KWN_USR
        } else {
            Read-Host "Enter your domain username"
        }
    } else {
        $username = Read-Host "Enter your domain username"
    }

    $securePassword = Read-Host "Enter your password" -AsSecureString
    $cred = New-Object System.Management.Automation.PSCredential ("$DOMAIN\$username", $securePassword)

    fncPrintMessage "Attempting PSDrive mount: domain=$DOMAIN, driveName=$($DOMAIN.Split('.')[0]), dcHost=$dcHost" "debug"
    fncPrintMessage "Mounting AD as PSDrive: $DOMAIN" "info"

    try {
        $driveName = ($DOMAIN.Split('.')[0])
        New-PSDrive -Name $driveName -PSProvider ActiveDirectory -Root "//RootDSE/" -Credential $cred -Server $dcHost -ErrorAction Stop | Out-Null
        fncPrintMessage "Connected to $DOMAIN successfully." "success"

        # Save values to config
        $config.LAST_KWN_DOM = $DOMAIN
        $config.LAST_KWN_USR = $username

        $config | ConvertTo-Json -Depth 10 | Out-File -FilePath $configPath -Encoding UTF8
        fncPrintMessage "Updated config with domain and username." "success"

        # Save globals for rest of session
        $global:dcHost = $dcHost
        $global:domainMap = @{}
        $global:domainMap[$DOMAIN] = $dcHost

        fncPrintMessage "Global DC host set: $dcHost" "debug"
        fncPrintMessage "domainMap: $($global:domainMap.Keys -join ', ')" "debug"
    } catch {
        $msg = $_.Exception.Message
        $inner = $_.Exception.InnerException

        if ($msg -match 'Authentication failed' -or $inner) {
            fncPrintMessage "Authentication failed: Username or Password is incorrect." "error"
        } else {
            fncPrintMessage "Failed to mount PSDrive for $DOMAIN. Error: $msg" "error"
        }
        Exit 1
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

function fncCheckWeakACLs {
    param (
        [Microsoft.ActiveDirectory.Management.ADUser]$userDetails
    )

    Write-Host "`n[+] Checking for weak ACLs on user object..." -ForegroundColor Cyan

    try {
        $dn = $userDetails.DistinguishedName
        $directoryEntry = [ADSI]"LDAP://$global:dcHost/$dn"
        $acl = $directoryEntry.psbase.ObjectSecurity

        $riskyRights = @(
            "GenericAll", "GenericWrite", "WriteOwner", "WriteDACL",
            "CreateChild", "DeleteChild", "WriteProperty", "Self"
        )

        $weakEntries = @()

        foreach ($ace in $acl.Access) {
            foreach ($right in $riskyRights) {
                if ($ace.ActiveDirectoryRights.ToString().Contains($right)) {
                    $weakEntries += $ace
                    break
                }
            }
        }

        # Remove duplicates
        $weakEntries = $weakEntries | Sort-Object IdentityReference, ActiveDirectoryRights -Unique

        # Default suppress setting if not configured
        if (-not ($global:config.PSObject.Properties.Name -contains "suppressSelfACE")) {
            $global:config | Add-Member -MemberType NoteProperty -Name suppressSelfACE -Value $false
        }

        if ($weakEntries.Count -gt 0) {
            Write-Host "`n[!] Weak permissions found on user object:" -ForegroundColor Red
            foreach ($entry in $weakEntries) {
                if ($global:config.suppressSelfACE -and $entry.IdentityReference -like "*SELF*") {
                    continue
                }

                if ($entry.ActiveDirectoryRights.ToString().Contains("GenericAll") -or
                    $entry.ActiveDirectoryRights.ToString().Contains("WriteDACL") -or
                    $entry.ActiveDirectoryRights.ToString().Contains("WriteOwner")) {
                    Write-Host "⚠️  HIGH RISK: $($entry.IdentityReference) - $($entry.ActiveDirectoryRights)" -ForegroundColor Red
                } else {
                    Write-Host "    Trustee : $($entry.IdentityReference)" -ForegroundColor Yellow
                    Write-Host "    Right   : $($entry.ActiveDirectoryRights)"
                    Write-Host "    Type    : $($entry.AccessControlType)"
                    Write-Host "    Inherited: $($entry.IsInherited)"
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

##############################
### Main Application Logic ###
##############################

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
        $privilegedPatterns = @("admin", "super admin", "sudo", "su", "root", "priv", "power", "cyberark")

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
        if ($userDetails.Secretary) {
            $deputyDetails = Get-ADUser -Server $global:dcHost -Filter "DistinguishedName -eq '$($userDetails.Secretary)'" -Properties Name, GivenName, Surname
            if ($deputyDetails) {
                Write-Host "$($deputyDetails.GivenName) $($deputyDetails.Surname) - $($deputyDetails.Name)"
            } else {
                Write-Host "Deputy manager not found"
            }
        } else {
            Write-Host "No deputy manager assigned"
        }

        Write-Host "===================================================================================="

        # Group Membership Breakdown
        Write-Host "-------------------------------------"
        Write-Host "Currently Applied Groups:`n"
        Write-Host "Key:"
        Write-Host "Group Name             - Yellow" -ForegroundColor Yellow
        Write-Host "Domain Component (DC)  - DarkBlue" -ForegroundColor DarkBlue
        Write-Host "Organisational Unit    - White"
        Write-Host "High Priv Group        - [!] + Red" -ForegroundColor Red
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

            $groupObjects += [PSCustomObject]@{
                Name         = $groupName
                DN           = $groupDN
                IsPrivileged = $isPrivGroup
            }
        }

        $sortedPriv   = $groupObjects | Where-Object { $_.IsPrivileged } | Sort-Object Name
        $sortedNormal = $groupObjects | Where-Object { -not $_.IsPrivileged } | Sort-Object Name

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

        Write-Host "-------------------------------------"

        # Advanced Info Mode
        if ($global:config.ADVANCED_MODE) {
            fncCheckWeakACLs -userDetails $userDetails
        } else {
            fncPrintMessage "Advanced Information Mode Disabled – Check Weak ACLs Disabled." "disabled"
        }

        Write-Host "-------------------------------------"
    } catch {
        fncPrintMessage "Error retrieving information for user: $user" "error"
    }
}


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
}

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

## Preset Runner 
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
        Write-Host "  [1] Search for User"
        Write-Host "  [2] Search for Group"
        Write-Host "  [3] Search for Computer"
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
