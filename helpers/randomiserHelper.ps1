<#
    Active Directory Toolbelt
    Developed by @ Dean Reid

    Class Name: RandomiserHelper

    Class Information:
    Static helper functions for generating random numbers, 
    strings, and globally unique identifiers (GUIDs). 
    dunno why I need this just now but I'll figure it out
    
    Program Version: 2.0
    Code Version: 1.0

    Updates:
    09/08/2025 - Initial PowerShell randomiser helper module
#>

# ================================================================
# Function: fncGetRandomNumber
# Purpose : Generates a random integer within a given range
# Notes   : Defaults to 1–100 if no parameters are passed
# ================================================================
function fncGetRandomNumber {
    param(
        [int]$Min = 1,
        [int]$Max = 100
    )

    try {
        return Get-Random -Minimum $Min -Maximum ($Max + 1)
    }
    catch {
        fncHandleError -Message "Failed to generate random number: $($_.Exception.Message)" -Severity "ERROR" -Module "RandomiserHelper"
    }
}

# ================================================================
# Function: fncGetRandomString
# Purpose : Generates a random string of specified length
# Notes   : Defaults to uppercase/lowercase letters & numbers
# ================================================================
function fncGetRandomString {
    param(
        [int]$Length = 12,
        [string]$Charset = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
    )

    try {
        -join ((1..$Length) | ForEach-Object { $Charset[(Get-Random -Minimum 0 -Maximum $Charset.Length)] })
    }
    catch {
        fncHandleError -Message "Failed to generate random string: $($_.Exception.Message)" -Severity "ERROR" -Module "RandomiserHelper"
    }
}

# ================================================================
# Function: fncGetSecureRandomString
# Purpose : Generates a cryptographically secure random string
# Notes   : Uses RNGCryptoServiceProvider for higher entropy
# ================================================================
function fncGetSecureRandomString {
    param(
        [int]$Length = 16
    )

    try {
        Add-Type -AssemblyName System.Security
        $bytes = New-Object 'System.Byte[]' $Length
        [System.Security.Cryptography.RNGCryptoServiceProvider]::Create().GetBytes($bytes)
        return [System.Convert]::ToBase64String($bytes)
    }
    catch {
        fncHandleError -Message "Failed to generate secure random string: $($_.Exception.Message)" -Severity "ERROR" -Module "RandomiserHelper"
    }
}

# ================================================================
# Function: fncGetRandomGuid
# Purpose : Generates a random GUID
# Notes   : Useful for unique IDs
# ================================================================
function fncGetRandomGuid {
    try {
        return [guid]::NewGuid().ToString()
    }
    catch {
        fncHandleError -Message "Failed to generate GUID: $($_.Exception.Message)" -Severity "ERROR" -Module "RandomiserHelper"
    }
}
