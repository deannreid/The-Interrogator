<#
    Active Directory Toolbelt
    Developed by @ Dean Reid

    Class Name: LogHelper

    Class Information:
    Handles logging to file, Event Log, and Database.
    Always writes to a log file. Event Log and DB are optional.

    Program Version: 2.0
    Code Version: 1.0

    Updates:
    09/08/2025 - Integrated with fncHandleError for consistent error handling
    09/08/2025 - Ensured mandatory file logging with optional Event Log and DB
#>

function fncWriteLog {
    param(
        [Parameter(Mandatory = $true)][string]$Message,
        [Parameter(Mandatory = $false)][string]$Level = "INFO", # INFO, WARN, ERROR, DEBUG
        [Parameter(Mandatory = $false)][string]$Module = "General"
    )

    try {
        $timestamp = (Get-Date).ToString("dd-MM-yyyy HH:mm:ss")
        $user      = $global:USER_NM
        $computer  = $global:COMPUTER_ID

        $logLine = "[$timestamp] [$Level] [$Module] [$user@$computer] $Message"

        # Ensure log folder exists
        if (-not (Test-Path -Path $global:LOG_FILE_LOC)) {
            try {
                New-Item -ItemType Directory -Path $global:LOG_FILE_LOC -Force | Out-Null
            }
            catch {
                fncHandleError -Message "Failed to create log directory: $global:LOG_FILE_LOC" -ErrorRecord $_ -Severity "High"
                return
            }
        }

        # Write to main log file (always enabled)
        $logFilePath = Join-Path $global:LOG_FILE_LOC "activity.log"
        try {
            Add-Content -Path $logFilePath -Value $logLine
        }
        catch {
            fncHandleError -Message "Failed to write to log file: $logFilePath" -ErrorRecord $_ -Severity "High"
        }

        # Event Log logging (optional)
        if ($global:LOG_TO_EVENTLOG) {
            try {
                $source = "TheInterrogator-PowershellEdition"
                if (-not [System.Diagnostics.EventLog]::SourceExists($source)) {
                    New-EventLog -LogName Application -Source $source
                }
                Write-EventLog -LogName Application -Source $source -EventId 1000 -EntryType Information -Message $logLine
            }
            catch {
                fncHandleError -Message "Event Log write failed" -ErrorRecord $_ -Severity "Low"
            }
        }

        # Database logging (optional)
        if ($global:LOG_TO_DB -and $global:DB_CONN_STRING) {
            try {
                $connection = New-Object System.Data.SqlClient.SqlConnection $global:DB_CONN_STRING
                $connection.Open()
                $cmd = $connection.CreateCommand()
                $cmd.CommandText = "INSERT INTO ADT_Logs (Timestamp, Level, Module, UserName, ComputerName, Message) VALUES (@Timestamp, @Level, @Module, @User, @Computer, @Message)"
                $cmd.Parameters.AddWithValue("@Timestamp", $timestamp) | Out-Null
                $cmd.Parameters.AddWithValue("@Level", $Level) | Out-Null
                $cmd.Parameters.AddWithValue("@Module", $Module) | Out-Null
                $cmd.Parameters.AddWithValue("@User", $user) | Out-Null
                $cmd.Parameters.AddWithValue("@Computer", $computer) | Out-Null
                $cmd.Parameters.AddWithValue("@Message", $Message) | Out-Null
                $cmd.ExecuteNonQuery() | Out-Null
                $connection.Close()
            }
            catch {
                fncHandleError -Message "Database logging failed" -ErrorRecord $_ -Severity "Low"
            }
        }
    }
    catch {
        fncHandleError -Message "LogHelper encountered a fatal error" -ErrorRecord $_ -Severity "Critical"
    }
}
