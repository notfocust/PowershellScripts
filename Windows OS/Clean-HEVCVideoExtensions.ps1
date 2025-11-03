<#
.SYNOPSIS
Script to clean up HEVC Video Extension packages and ensure the correct version is installed.

.PARAMETER Force
Use this switch to automatically remove packages without confirmation.
#>

param (
    [switch]$Force
)

# Configuration
$KeepPackageFamilyName = "Microsoft.HEVCVideoExtension_8wekyb3d8bbwe"
$StoreLink = "ms-windows-store://pdp/?ProductId=9n4wgh0z6vhq"

# 1. Retrieve all relevant AppX packages
$AllHEVCPackages = Get-AppxPackage | Where-Object { $_.Name -match "Microsoft.HEVCVideoExtension" }

if (-not $AllHEVCPackages) {
    Write-Host "No 'Microsoft.HEVCVideoExtension' packages found." -ForegroundColor Cyan
} else {
    # 2. Filter packages that should be removed
    $PackagesToRemove = $AllHEVCPackages | Where-Object { $_.PackageFamilyName -ne $KeepPackageFamilyName }

    # 3. Remove unwanted packages
    if ($PackagesToRemove) {
        Write-Host "Multiple HEVC Video Extension packages found. Starting cleanup..." -ForegroundColor Cyan

        foreach ($Package in $PackagesToRemove) {
            Write-Host "---"
            Write-Host "Full package name: $($Package.PackageFullName)" -ForegroundColor Yellow

            $Confirmation = 'N'
            if (-not $Force) {
                $Confirmation = Read-Host "Do you want to remove this package? (Y/N)"
            }

            if ($Force -or $Confirmation -match '^[Yy]$') {
                try {
                    Write-Host "$(Get-Date -Format 'HH:mm:ss') - Starting removal..." -ForegroundColor DarkGray
                    Remove-AppxPackage -Package $Package.PackageFullName -ErrorAction Stop
                    Write-Host "Package successfully removed." -ForegroundColor Green
                } catch {
                    Write-Host "Error during removal: $($_.Exception.Message)" -ForegroundColor Red
                }
            } else {
                Write-Host "Removal skipped." -ForegroundColor Gray
            }
        }
    } else {
        Write-Host "Only the desired version '$KeepPackageFamilyName' is present. No action required." -ForegroundColor Green
    }

    # 4. Check if the desired package is present
    $KeepPackageFound = $AllHEVCPackages | Where-Object { $_.PackageFamilyName -eq $KeepPackageFamilyName } | Select-Object -First 1

    if (-not $KeepPackageFound) {
        Write-Host "---"
        Write-Host "Warning: The package '$KeepPackageFamilyName' was not found." -ForegroundColor Red
        $DownloadConfirmation = Read-Host "Do you want to download this package via the Microsoft Store? (Y/N)"

        if ($DownloadConfirmation -match '^[Yy]$') {
            try {
                Write-Host "Opening Microsoft Store: $StoreLink" -ForegroundColor Cyan
                Start-Process $StoreLink
            } catch {
                Write-Host "Failed to open Microsoft Store: $($_.Exception.Message)" -ForegroundColor Red
            }
        } else {
            Write-Host "Download skipped." -ForegroundColor Gray
        }
    }
}