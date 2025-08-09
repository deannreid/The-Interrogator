<#
    Active Directory Toolbelt
    Developed by @ Dean Reid

    Class Name: References

    Class Information:
    Contains global variables, constants, and configuration values 
    used throughout the application. Centralised for easier 
    maintenance and updates.

    Program Version: 2.0
    Code Version: 1.0

    Updates:
    09/08/2025 - Initial PowerShell port of C# reference class
    09/08/2025 - Added logging and debug mode configuration
#>

$global:APP_NAME        = "The Interrogator"
$global:APP_VERSION     = "2.0 (build a001)"
$global:APP_AUTHOR      = "Dean Reid"
$global:APP_COPYRIGHT   = "© $(Get-Date -Format yyyy) Whoever finds it useful."

$global:COMPUTER_ID     = $env:COMPUTERNAME
$global:USER_ID         = $env:USERNAME
$global:USER_NM         = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name

$global:DEBUG_MODE        = $true  # Enable Debug Mode - all the lines
$global:TRAINING_WHEELS   = $true  # Training Wheels Mode
$global:DARK_MODE         = $true  # Enable Dark Mode - The Dark Side is with you

$global:ADT_ROOT_LOC        = "C:\Users\$($global:USER_ID)\AppData\Local\TheInterrogator"
$global:CONFIG_FILE_NAME    = Join-Path $global:ADT_ROOT_LOC "config.cfg"

$global:LOG_FILE_LOC        = Join-Path $global:ADT_ROOT_LOC "logs"
$global:DEB_LOG_FILE_LOC    = Join-Path $global:LOG_FILE_LOC "debug.log"
$global:ERR_LOG_FILE_LOC    = Join-Path $global:LOG_FILE_LOC "error.log"
$global:LOG_FILE_LOC_TEMP   = [System.IO.Path]::GetTempPath()

foreach ($dir in @($global:ADT_ROOT_LOC, $global:LOG_FILE_LOC)) {
    if (-not (Test-Path $dir)) { New-Item -Path $dir -ItemType Directory -Force | Out-Null }
}

$global:CONFIG = @{
    ADVANCED_MODE     = $false
    LOG_TO_EVENTLOG   = $false
    LOG_TO_DB         = $false
    THEME             = "DarkMetro"
    LAST_KWN_DOM      = ""
    LAST_KWN_USR      = ""
    DC_HOST           = ""
    DB_CONN_STRING    = ""
}

$global:SESSION = @{
    CURRENT_DC        = ""
    CURRENT_USER      = ""
    SESSION_START     = (Get-Date)
}

$global:LOG_FILE = Join-Path $global:LOG_FILE_LOC "interrogator_$(Get-Date -Format 'ddMMyyyy').log"

$global:ASSET_PATH         = Join-Path (Split-Path -Parent $PSScriptRoot) "assets"
$global:LOGO_PATH          = Join-Path $global:ASSET_PATH "logo.png"
$global:ICON_EXIT          = Join-Path $global:ASSET_PATH "icons\exit.png"

function Get-ConfigValue {
    param([string]$Key)
    if ($global:CONFIG.ContainsKey($Key)) { return $global:CONFIG[$Key] }
    else { return $null }
}

function Set-ConfigValue {
    param(
        [string]$Key,
        [Parameter(Mandatory = $true)] $Value
    )
    $global:CONFIG[$Key] = $Value
}

function Get-SessionValue {
    param([string]$Key)
    if ($global:SESSION.ContainsKey($Key)) { return $global:SESSION[$Key] }
    else { return $null }
}

function Set-SessionValue {
    param(
        [string]$Key,
        [Parameter(Mandatory = $true)] $Value
    )
    $global:SESSION[$Key] = $Value
}

$helpersPath = Join-Path (Split-Path $PSScriptRoot -Parent) "helpers"

$helperFiles = @(
    "RandomiserHelper.ps1"
)

foreach ($helper in $helperFiles) {
    $path = Join-Path $helpersPath $helper
    if (Test-Path $path) {
        . $path
    } else {
        Write-Host "Helper not found: $helper" -ForegroundColor Yellow
    }
}