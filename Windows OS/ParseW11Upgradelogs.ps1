<#
https://github.com/notfocust/PowershellScripts/edit/main/Windows%20OS/ParseW11Upgradelogs.ps1
Script version: 0.1
#>

# Define log locations based on Microsoft documentation priority
$LogLocations = @(
    "C:\$Windows.~BT\Sources\Panther\setupact.log",        # Down-Level phase
    "C:\$Windows.~BT\Sources\Rollback\setupact.log",      # Rollback phase
    "C:\$Windows.~BT\Sources\Panther\UnattendGC\setupact.log", # OOBE phase
    "C:\Windows\Panther\setupact.log",                     # Post-upgrade phase
    "C:\Windows\setupact.log",                             # Pre-initialization
    "C:\Windows\Logs\Mosetup\BlueBox.log"                  # WSUS / Windows Update
)

$OutputFile = "$PSScriptRoot\UpgradeReport.html"
$TargetLog = $null

# Search for the first available log file in the priority list
foreach ($Path in $LogLocations) {
    if (Test-Path $Path) {
        $TargetLog = $Path
        break
    }
}

# Define HTML CSS styling
$Header = @"
<style>
    body { font-family: 'Segoe UI', sans-serif; background: #f4f4f4; padding: 20px; }
    table { border-collapse: collapse; width: 100%; background: white; box-shadow: 0 2px 5px rgba(0,0,0,0.1); margin-top: 20px; }
    th, td { padding: 10px; text-align: left; border-bottom: 1px solid #ddd; font-size: 12px; }
    th { background-color: #0078D4; color: white; }
    tr:hover { background-color: #f9f9f9; }
    .Error { color: #d83b01; font-weight: bold; background: #fde7e9; }
    .Warning { color: #847545; font-weight: bold; background: #fff8e6; }
    .Meta { font-size: 14px; margin-bottom: 10px; color: #555; }
</style>
"@

$ReportData = if ($null -ne $TargetLog) {
    Write-Host "Found log at: $TargetLog" -ForegroundColor Cyan
    # Read the log file (last 1000 lines for a broader view)
    Get-Content $TargetLog -Tail 1000 | ForEach-Object {
        $Level = if ($_ -match "Error" -or $_ -match "Failed") { "Error" } 
                 elseif ($_ -match "Warning") { "Warning" } 
                 else { "Info" }
        
        [PSCustomObject]@{
            Timestamp = ($_ -split " ", 2)[0]
            Source    = (Split-Path $TargetLog -Leaf)
            Level     = "<span class='$Level'>$Level</span>"
            Message   = $_
        }
    }
} else {
    Write-Warning "No setupact.log found in standard locations. Querying Event Viewer..."
    # Fallback to Event Viewer (Application & System)
    Get-WinEvent -FilterHashtable @{LogName='Application','System'; StartTime=(Get-Date).AddDays(-3)} -ErrorAction SilentlyContinue | 
        Where-Object { $_.Message -like "*upgrade*" -or $_.Message -like "*setup*" -or $_.Id -eq 1001 } | 
        Select-Object -First 200 | ForEach-Object {
            $Level = $_.LevelDisplayName
            [PSCustomObject]@{
                Timestamp = $_.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")
                Source    = "EventLog: $($_.LogName)"
                Level     = "<span class='$Level'>$Level</span>"
                Message   = $_.Message
            }
        }
}

# Generate HTML output
if ($ReportData) {
    $SourceInfo = if ($TargetLog) { "File: $TargetLog" } else { "Source: Event Viewer" }
    $HtmlBody = "<h2>Windows Upgrade Diagnostic Report</h2><div class='Meta'>$SourceInfo</div>"
    
    $ReportData | ConvertTo-Html -Head $Header -Body $HtmlBody -Title "Upgrade Audit" | Out-File $OutputFile
    
    Write-Host "Report generated at: $OutputFile" -ForegroundColor Green
    Invoke-Item $OutputFile
} else {
    Write-Error "No diagnostic data could be retrieved from files or Event Viewer."
}