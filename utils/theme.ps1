<#
    Active Directory Toolbelt
    Developed by @ Dean Reid

    Class Name: Theme

    Class Information:
    Handles application colour schemes, including support for 
    light mode and dark mode. Provides reusable colour constants 
    and functions for both GUI and console output.

    Program Version: 2.0
    Code Version: 1.0

    Updates:
    09/08/2025 - Initial PowerShell theme handling module
    09/08/2025 - Added dark mode toggle and colour constants
#>

function fncLoadTheme {
    if ($global:DARK_MODE) {
        $global:THEME = @{
            # Console Colours
            "Console" = @{
                "Primary"   = "White"
                "Secondary" = "Gray"
                "Accent"    = "Cyan"
                "Error"     = "Red"
                "Warning"   = "Yellow"
                "Success"   = "Green"
            }
            # GUI Colours
            "GUI" = @{
                "Background" = "#1e1e1e" # Dark grey
                "Foreground" = "#ffffff" # White
                "Accent"     = "#007acc" # Blue accent
                "Error"      = "#ff4d4d"
                "Warning"    = "#ffd633"
                "Success"    = "#4dff88"
            }
        }
    }
    else {
        $global:THEME = @{
            # Console Colours
            "Console" = @{
                "Primary"   = "Black"
                "Secondary" = "DarkGray"
                "Accent"    = "Blue"
                "Error"     = "DarkRed"
                "Warning"   = "DarkYellow"
                "Success"   = "DarkGreen"
            }
            # GUI Colours
            "GUI" = @{
                "Background" = "#ffffff" # White
                "Foreground" = "#000000" # Black
                "Accent"     = "#005a9e" # Darker blue
                "Error"      = "#a80000"
                "Warning"    = "#b58900"
                "Success"    = "#007a00"
            }
        }
    }
}

function fncWriteTheme {
    param (
        [Parameter(Mandatory = $true)][string]$Text,
        [Parameter(Mandatory = $true)][ValidateSet("Primary","Secondary","Accent","Error","Warning","Success")]$Colour
    )

    $fg = $global:THEME["Console"][$Colour]
    Write-Host $Text -ForegroundColor $fg
}

function fncApplyGuiTheme {
    param (
        [Parameter(Mandatory = $true)]$FormOrControl
    )

    $FormOrControl.BackColor = $global:THEME["GUI"]["Background"]
    $FormOrControl.ForeColor = $global:THEME["GUI"]["Foreground"]
}

fncLoadTheme
