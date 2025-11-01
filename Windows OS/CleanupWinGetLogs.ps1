<#
.SYNOPSIS
Checks a folder's total size against a 1 GB threshold. If exceeded, 
it lists items, prompts for confirmation, and performs a cleanup.
#>

$FolderPath = "C:\Windows\Temp\WinGet\defaultState"
$Threshold = 1GB

function Format-Bytes {
    param([long]$Bytes)
    $Sizes = "B", "KB", "MB", "GB", "TB"
    $i = 0
    while ($Bytes -ge 1024 -and $i -lt $Sizes.Count) { $Bytes /= 1024; $i++ }
    return "{0:N2} {1}" -f $Bytes, $Sizes[$i]
}

# 1. Path Check Test
if (-not (Test-Path $FolderPath -PathType Container)) {
    Write-Output "ERROR: Path '$FolderPath' does not exist. Exiting 1."
    exit 1
}

# 2. Calculate Size
[long]$FolderSize = (Get-ChildItem -Path $FolderPath -Recurse -Force -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum).Sum

$FormattedSize = Format-Bytes $FolderSize
$FormattedThreshold = Format-Bytes $Threshold

# 3. Comparison and Action
if ($FolderSize -gt $Threshold) {
    Write-Host "SIZE EXCEEDED: $($FormattedSize) > $($FormattedThreshold). Cleanup is required." -ForegroundColor Yellow
    
    # Identify all items inside the folder 
    $ItemsToDelete = Get-ChildItem -Path "$FolderPath\*" -Recurse -Force -ErrorAction SilentlyContinue
    
    Write-Host "--------------------------------------------------------"
    Write-Host "Found $($ItemsToDelete.Count) items (files/folders) to be removed inside '$FolderPath'." -ForegroundColor Cyan
    
    # List the first 5 items to show what will be deleted
    if ($ItemsToDelete.Count -gt 0) {
        Write-Host "Preview of the first 5 items to be deleted:"
        $ItemsToDelete | Select-Object -First 5 | Select-Object FullName | Format-Table -AutoSize
    }
    
    # Confirmation Prompt
    $Confirm = Read-Host "`nDo you want to proceed with deleting ALL items listed above (and all others inside '$FolderPath')? (Y/N)"

    if ($Confirm -ceq 'Y') {
        Write-Host "Proceeding with cleanup..." -ForegroundColor Green
        
        # Perform Deletion
        try {
            # Pipe the collection of items to Remove-Item
            $ItemsToDelete | Remove-Item -Recurse -Force -ErrorAction Stop
            Write-Host "CLEANUP SUCCESS: All contents inside '$FolderPath' have been removed." -ForegroundColor Green
            exit 0 # Success after cleanup
        } catch {
            Write-Host "ERROR during deletion: $($_.Exception.Message)" -ForegroundColor Red
            exit 1 # Failure during deletion
        }
        
    } else {
        Write-Host "Cleanup canceled by user. Exiting 1 (Size still exceeded)." -ForegroundColor Red
        exit 1
    }

} else {
    Write-Host "SIZE OK: $($FormattedSize) is within limits ($($FormattedThreshold)). Exiting 0." -ForegroundColor Green
    exit 0
}