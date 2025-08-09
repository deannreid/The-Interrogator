<#
    Active Directory Toolbelt
    Developed by @ Dean Reid

    Class Name: errorHandler

    Class Information:
    Handle all script errors

    Program Version: 2.0
    Code Version: 1.0

    Updates:
    09/08/2025 - Integrated with fncHandleError for consistent error handling
    09/08/2025 - Ensured mandatory file logging with optional Event Log and DB
#>

function fncHandleError {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Message,

        [Parameter()]
        [System.Management.Automation.ErrorRecord]$ErrorRecord,

        [Parameter()]
        [ValidateSet("Debug","Low","Medium","High","Critical")]
        [string]$Severity = "Low"
    )

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $fullMessage = "[${timestamp}] [$Severity] $Message"

    if ($ErrorRecord) {
        $fullMessage += " | Exception: $($ErrorRecord.Exception.Message)"
    }

    if ($Severity -eq "Debug") {
        if ($global:DEBUG_MODE) {
            fncWriteLog -Message $fullMessage -Type "Debug"
            fncWriteTheme $fullMessage "Debug"
        }
        return
    }

    fncWriteLog -Message $fullMessage -Type "Error"

    if ($global:LOG_TO_EVENTLOG) {
        try {
            if (-not (Get-EventLog -LogName Application -Source "TheInterrogator" -ErrorAction SilentlyContinue)) {
                New-EventLog -LogName Application -Source "TheInterrogator" -ErrorAction Stop
            }
            Write-EventLog -LogName Application -Source "TheInterrogator" -EntryType Error -EventId 1000 -Message $fullMessage
        }
        catch {
            fncWriteLog -Message "Failed to write to Event Log: $($_.Exception.Message)" -Type "Error"
        }
    }

    # Optional: DB Logging
    if ($global:LOG_TO_DB) {
        try {
            # DB logging logic placeholder
            # Invoke-Sqlcmd -Query "INSERT INTO LogTable (Timestamp, Severity, Message) VALUES ('$timestamp', '$Severity', '$fullMessage')" -ServerInstance "SQLSERVER" -Database "Logs"
            fncWriteLog -Message "[DB-Log] $fullMessage" -Type "Debug"
        }
        catch {
            fncWriteLog -Message "Failed to write to database: $($_.Exception.Message)" -Type "Error"
        }
    }

    fncWriteTheme $fullMessage "Error"

    if ($Severity -eq "Critical") {
        throw $fullMessage
    }
}
