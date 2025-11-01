# Configuration
$repoOwner = "notfocust"
$repoName = "PowershellScripts"
$branch = "main"
$baseUrl = "https://raw.githubusercontent.com/$repoOwner/$repoName/$branch"
$apiUrl = "https://api.github.com/repos/$repoOwner/$repoName/contents"

$script:currentPath = ""

function Get-RepoContents {
    param (
        [string]$path = ""
    )

    try {
        # Prepare the API URL with the current path
        $requestUrl = if ($path) { "$apiUrl/$path" } else { $apiUrl }

        # Set up headers for GitHub API
        $headers = @{ 'Accept' = 'application/vnd.github.v3+json'; 'User-Agent' = 'ToolieWhoolie-Script' }

        # Get repository contents using GitHub API
        $response = Invoke-RestMethod -Uri $requestUrl -Method Get -Headers $headers -ErrorAction Stop

        if (-not $response) { return @() }

        # If response is a single item convert to array
        $collection = @()
        if ($response -is [System.Array]) { $collection = $response } else { $collection = @($response) }

        # Filter and map directories and .ps1 files only
        $items = $collection | Where-Object { $_.type -eq 'dir' -or ($_.type -eq 'file' -and $_.name -like '*.ps1') } |
            ForEach-Object {
                [pscustomobject]@{
                    Name       = $_.name
                    IsDirectory= $_.type -eq 'dir'
                    FullPath   = $_.path
                    Url        = if ($_.type -eq 'file') { $_.download_url } else { $null }
                }
            } | Sort-Object @{Expression = 'IsDirectory'; Descending = $true}, Name

        # If we're listing the repository root, hide this launcher script from the listing
        if ([string]::IsNullOrEmpty($path)) {
            $items = $items | Where-Object { $_.Name -ne 'ToolieWhoolie.ps1' }
        }

        return $items
    }
    catch {
        $err = $_.Exception
        $msg = $err.Message
        if ($err.Response) {
            try { $status = [int]$err.Response.StatusCode } catch { $status = 0 }
            switch ($status) {
                404 { $msg = 'Repository or path not found (404).' }
                403 { $msg = 'Access denied or rate limited (403).' }
                default { $msg = "$msg (HTTP $status)" }
            }
        }
        Write-Host "Error accessing GitHub repository: $msg" -ForegroundColor Red
        return @()
    }
}

function Show-Menu {
    Clear-Host
    Write-Host "================ PowerShell Script Browser ================" -ForegroundColor Cyan
    Write-Host "Repository: $repoOwner/$repoName" -ForegroundColor Yellow
    Write-Host "Branch: $branch" -ForegroundColor Yellow
    Write-Host "Current Path: /$script:currentPath" -ForegroundColor Yellow

    Write-Host "`nFetching repository contents..." -ForegroundColor Cyan
    $items = Get-RepoContents -path $script:currentPath

    Write-Host "`nContents:" -ForegroundColor Yellow

    if ($script:currentPath) { Write-Host "0: [..] Back to parent directory" -ForegroundColor Magenta }

    if (-not $items -or $items.Count -eq 0) {
        Write-Host "(empty)" -ForegroundColor DarkGray
    }

    for ($i = 0; $i -lt $items.Count; $i++) {
        $item = $items[$i]
        if ($item.IsDirectory) {
            # Count immediate .ps1 files in directory
            $sub = Get-RepoContents -path $item.FullPath
            $psCount = ($sub | Where-Object { -not $_.IsDirectory }).Count
            $scriptText = if ($psCount -eq 1) { 'script' } else { 'scripts' }
            Write-Host "$($i + 1): [DIR]  $($item.Name) ($psCount PowerShell $scriptText)" -ForegroundColor Blue
        } else {
            Write-Host "$($i + 1): [PS1]  $($item.Name)" -ForegroundColor Green
        }
    }

    Write-Host "`nQ: Quit" -ForegroundColor Red
    Write-Host "====================================================="
    return ,$items
}

function Execute-Script {
    param (
        [string]$scriptUrl,
        [string]$scriptName
    )

    try {
        $tempDir = Join-Path $env:TEMP 'GitHubScripts'
        if (-not (Test-Path $tempDir)) { New-Item -ItemType Directory -Path $tempDir -Force | Out-Null }

        $scriptPath = Join-Path $tempDir $scriptName
        Write-Host "Downloading script from GitHub..." -ForegroundColor Cyan

        # Download raw content
        $scriptContent = Invoke-RestMethod -Uri $scriptUrl -Method Get -Headers @{ 'Accept' = 'application/vnd.github.v3.raw'; 'User-Agent' = 'ToolieWhoolie-Script' }

        if (-not $scriptContent) { throw 'Downloaded script is empty.' }

        Write-Host "`nScript Content Preview:" -ForegroundColor Cyan
        $scriptContent -split "`n" | Select-Object -First 20 | ForEach-Object { Write-Host "  $_" -ForegroundColor Gray }
        if (($scriptContent -split "`n").Count -gt 20) { Write-Host "  ..." -ForegroundColor Gray }

        $confirm = Read-Host "`nDo you want to run this script? (Y/N)"
        if ($confirm -ine 'Y') { Write-Host 'Cancelled.' -ForegroundColor Yellow; return }

        $scriptContent | Out-File -FilePath $scriptPath -Force -Encoding UTF8

        Write-Host "`nExecuting script..." -ForegroundColor Yellow
        Start-Process powershell.exe -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$scriptPath`"" -Wait -Verb RunAs
        Write-Host "Script execution completed!" -ForegroundColor Green

        Remove-Item -Path $scriptPath -Force -ErrorAction SilentlyContinue
    }
    catch {
        Write-Host "Error executing script: $($_.Exception.Message)" -ForegroundColor Red
    }
}

function Enter-DirectoryAndChooseScript {
    param (
        [psobject]$dirItem
    )

    # List .ps1 files inside the directory and allow choosing one
    $all = Get-RepoContents -path $dirItem.FullPath
    $psFiles = $all | Where-Object { -not $_.IsDirectory }

    if (-not $psFiles -or $psFiles.Count -eq 0) {
        Write-Host "No PowerShell scripts found in $($dirItem.Name)." -ForegroundColor Yellow
        return
    }

    Write-Host "`nPowerShell scripts in $($dirItem.Name):" -ForegroundColor Cyan
    for ($i = 0; $i -lt $psFiles.Count; $i++) { Write-Host "$($i + 1): $($psFiles[$i].Name)" -ForegroundColor Green }
    Write-Host "0: Back to folder listing" -ForegroundColor Magenta

    do {
        $choice = Read-Host "Select script to run (0 to go back)"
        if ($choice -eq '0') { return }
        if ($choice -match '^[0-9]+$') {
            $idx = [int]$choice - 1
            if ($idx -ge 0 -and $idx -lt $psFiles.Count) {
                Execute-Script -scriptUrl $psFiles[$idx].Url -scriptName $psFiles[$idx].Name
                return
            }
        }
        Write-Host 'Invalid selection, try again.' -ForegroundColor Red
    } while ($true)
}

function Process-Selection {
    param (
        [string]$selection,
        $items
    )

    if ($selection -eq 'Q') { return $false }

    if ($selection -eq '0') {
        if (-not [string]::IsNullOrEmpty($script:currentPath)) {
            # Trim last path segment
            if ($script:currentPath -match '/') {
                $script:currentPath = $script:currentPath.Substring(0, $script:currentPath.LastIndexOf('/'))
            } else {
                $script:currentPath = ''
            }
        }
        return $true
    }

    if ($selection -match '^[0-9]+$') {
        $index = [int]$selection - 1
        if ($index -lt 0 -or $index -ge $items.Count) { Write-Host 'Invalid selection.' -ForegroundColor Red; return $true }

        $sel = $items[$index]
        if ($sel.IsDirectory) {
            # Enter directory and show scripts inside
            Enter-DirectoryAndChooseScript -dirItem $sel
            # After returning, remain in the same directory (do not auto-change current path)
        } else {
            Execute-Script -scriptUrl $sel.Url -scriptName $sel.Name
        }

        return $true
    }

    Write-Host "Invalid input. Please enter a number, 0 to go back, or 'Q' to quit." -ForegroundColor Red
    return $true
}

# Main loop
do {
    $items = Show-Menu
    if (-not $items -or $items.Count -eq 0) {
        Write-Host "No items found in repository or unable to access repository. Press any key to continue..." -ForegroundColor Yellow
        $null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
    }

    $selection = Read-Host "Please make a selection"
    $continue = Process-Selection $selection $items
} while ($continue)