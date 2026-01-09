<#
Script version: 0.1
Author: nofocust
Description: This script runs prechecks and fixes for Windows 11 updates.
We also remove the Windows 11 requirements, because we love Microsoft
Warning: Use at your own risk. Read every line carefully.
#>

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "No Admin permissions. Starting as admin..." -ForegroundColor Yellow
    Start-Process powershell -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath` format" -Verb RunAs
    exit
}

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $logDir = 'C:\Temp\W11UpgradeLogs'
    if (-not (Test-Path $logDir)) { New-Item -Path $logDir -ItemType Directory -Force | Out-Null }
    $logFile = Join-Path $logDir 'W11Upgrade.log'
    $timestamp = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    Add-Content -Path $logFile -Value "[$timestamp] [$Level] $Message"
}

function Test-DiskSpace {
    $confirm = Read-Host "Run disk space check? (Y/N)"
    if ($confirm -ne "Y" -and $confirm -ne "y") {
        Write-Host "Disk space check skipped." -ForegroundColor Gray
        return
    }
    Write-Log "Starting disk space check"
    $minGB = 25
    $c = Get-PSDrive -Name C -ErrorAction SilentlyContinue
    $freeGB = [math]::Round($c.Free / 1GB, 2)
    Write-Host "Free space on C:: $freeGB GB" -ForegroundColor Green
    Write-Log "Free space on C:: $freeGB GB"
    if ($freeGB -lt $minGB) {
        Write-Log "Insufficient disk space: $freeGB GB (required $minGB GB)" "ERROR"
        throw "At least $minGB GB of free space is required on C:. Currently: $freeGB GB"
    }
    Write-Log "Disk space check completed successfully"
}

function Reset-WindowsUpdate {
    $confirm = Read-Host "Run Windows Update reset? (Y/N)"
    if ($confirm -ne "Y" -and $confirm -ne "y") {
        Write-Host "Windows Update reset skipped." -ForegroundColor Gray
        return
    }
    Write-Log "Starting Windows Update reset"
    Write-Host "`n*** Executing Windows Update reset and network settings reset... ***" -ForegroundColor Cyan
    
    Write-Host "1. Stopping Windows Update services..."
    Write-Log "Stopping Windows Update services"
    Stop-Service -Name BITS -Force -ErrorAction SilentlyContinue
    Stop-Service -Name wuauserv -Force -ErrorAction SilentlyContinue
    Stop-Service -Name appidsvc -Force -ErrorAction SilentlyContinue
    Stop-Service -Name cryptsvc -Force -ErrorAction SilentlyContinue

    Write-Host "2. Deleting QMGR files..."
    Write-Log "Deleting QMGR files"
    Remove-Item "$env:ALLUSERSPROFILE\Application Data\Microsoft\Network\Downloader\qmgr*.dat" -ErrorAction SilentlyContinue

    Write-Host "3. Renaming folders: SoftwareDistribution and Catroot2..."
    Write-Log "Renaming SoftwareDistribution and Catroot2 folders"
    Rename-Item "$env:systemroot\SoftwareDistribution" "SoftwareDistribution.bak" -ErrorAction SilentlyContinue
    Rename-Item "$env:systemroot\System32\Catroot2" "catroot2.bak" -ErrorAction SilentlyContinue

    Write-Host "4. Deleting WindowsUpdate.log file..."
    Write-Log "Deleting WindowsUpdate.log"
    Remove-Item "$env:systemroot\WindowsUpdate.log" -ErrorAction SilentlyContinue

    Write-Host "5. Registering DLL files..."
    Write-Log "Registering DLL files"
    Set-Location $env:systemroot\System32

    $dlls = @(
        "atl.dll", "urlmon.dll", "mshtml.dll", "shdocvw.dll", "browseui.dll",
        "jscript.dll", "vbscript.dll", "scrrun.dll", "msxml.dll", "msxml3.dll", "msxml6.dll",
        "actxprxy.dll", "softpub.dll", "wintrust.dll", "dssenh.dll", "rsaenh.dll", "gpkcsp.dll",
        "sccbase.dll", "slbcsp.dll", "cryptdlg.dll", "oleaut32.dll", "ole32.dll", "shell32.dll",
        "initpki.dll", "wuapi.dll", "wuaueng.dll", "wuaueng1.dll", "wucltui.dll", "wups.dll",
        "wups2.dll", "wuweb.dll", "qmgr.dll", "qmgrprxy.dll", "wucltux.dll", "muweb.dll", "wuwebv.dll"
    )

    foreach ($dll in $dlls) {
        try {
            regsvr32.exe /s $dll
        }
        catch {
            Write-Log "Failed to register $dll" "WARNING"
            Write-Host "Failed to register $dll" -ForegroundColor Yellow
        }
    }

    Write-Host "6. Executing network reset commands..."
    Write-Log "Executing network reset commands"
    arp -d * | Out-Null
    nbtstat -R | Out-Null
    nbtstat -RR | Out-Null
    ipconfig /flushdns | Out-Null
    ipconfig /registerdns | Out-Null
    netsh winsock reset | Out-Null
    netsh int ip reset c:\resetlog.txt | Out-Null

    Write-Host "7. Restarting Windows Update services..."
    Write-Log "Restarting Windows Update services"
    Start-Service -Name BITS -ErrorAction SilentlyContinue
    Start-Service -Name wuauserv -ErrorAction SilentlyContinue
    Start-Service -Name appidsvc -ErrorAction SilentlyContinue
    Start-Service -Name cryptsvc -ErrorAction SilentlyContinue

    Write-Host "`n*** Windows Update reset and network settings reset completed. ***" -ForegroundColor Green
    Write-Log "Windows Update reset completed successfully"
}

function Set-WUTargetRelease {
    $confirm = Read-Host "Configure Windows Update Target Release? (Y/N)"
    if ($confirm -ne "Y" -and $confirm -ne "y") {
        Write-Host "Target Release configuration skipped." -ForegroundColor Gray
        return
    }
    Write-Log "Starting Set-WUTargetRelease"
    Write-Host "`n*** Configure Windows Update Target Release Version ***" -ForegroundColor Cyan
    Write-Host "1 (or press Enter) - Set default target release version to 24H2"
    Write-Host "2 - Set a custom target release version"

    $choice = Read-Host "Select an option (1-2)"
    $WinUpdatePath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"

    if ($choice -eq "" -or $choice -eq "1") {
        $targetRelease = "24H2"
    }
    elseif ($choice -eq "2") {
        $targetRelease = Read-Host "Enter the Windows 11 target release version (e.g 23H2, 24H2)"
    }
    else {
        Write-Log "Invalid selection in Set-WUTargetRelease" "WARNING"
        Write-Host "Invalid selection." -ForegroundColor Red
        return
    }

    Write-Host "Setting Windows Update target release to $targetRelease..." -ForegroundColor Cyan
    Write-Log "Setting target release to $targetRelease"
    if (!(Test-Path $WinUpdatePath)) {
        New-Item -Path $WinUpdatePath -Force | Out-Null
    }
    New-ItemProperty -Path $WinUpdatePath -Name "ProductVersion" -Value "Windows 11" -PropertyType String -Force | Out-Null
    New-ItemProperty -Path $WinUpdatePath -Name "TargetReleaseVersion" -Value 1 -PropertyType DWord -Force | Out-Null
    New-ItemProperty -Path $WinUpdatePath -Name "TargetReleaseVersionInfo" -Value $targetRelease -PropertyType String -Force | Out-Null
    Write-Log "Target release configured successfully"
}

function Remove-WUTargetRelease {
    $confirm = Read-Host "Remove Windows Update Target Release? (Y/N)"
    if ($confirm -ne "Y" -and $confirm -ne "y") {
        Write-Host "Remove Target Release skipped." -ForegroundColor Gray
        return
    }
    Write-Log "Starting Remove-WUTargetRelease"
    Write-Host "`n*** Removing Windows Update Target Release Version ***" -ForegroundColor Cyan
    $WinUpdatePath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"

    if (Test-Path $WinUpdatePath) {
        Write-Log "Removing target release version settings"
        Remove-ItemProperty -Path $WinUpdatePath -Name "ProductVersion" -ErrorAction SilentlyContinue
        Remove-ItemProperty -Path $WinUpdatePath -Name "TargetReleaseVersion" -ErrorAction SilentlyContinue
        Remove-ItemProperty -Path $WinUpdatePath -Name "TargetReleaseVersionInfo" -ErrorAction SilentlyContinue
        Write-Host "Target release version settings removed." -ForegroundColor Green
        Write-Log "Target release version settings removed successfully"
    }
    else {
        Write-Log "No target release version settings found" "WARNING"
        Write-Host "No target release version settings found." -ForegroundColor Yellow
    }
}

function Set-BypassRegistryTweaks {
    $confirm = Read-Host "Apply registry tweaks to bypass hardware restrictions? (Y/N)"
    if ($confirm -ne "Y" -and $confirm -ne "y") {
        Write-Host "Registry tweaks skipped." -ForegroundColor Gray
        return
    }
    Write-Log "Starting Set-BypassRegistryTweaks"
    Write-Host "`n*** Applying registry tweaks to bypass Windows 11 hardware restrictions ***" -ForegroundColor Cyan
    $moSetupPath = "HKLM:\SYSTEM\Setup\MoSetup"
    $appCompatFlagsPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags"
    $hwReqChkPath = "$appCompatFlagsPath\HwReqChk"

    @($moSetupPath, $hwReqChkPath) | ForEach-Object {
        if (-not (Test-Path $_)) {
            New-Item -Path $_ -Force | Out-Null
        }
    }

    Write-Log "Creating registry paths"
    New-ItemProperty -Path $moSetupPath -Name "AllowUpgradesWithUnsupportedTPMOrCPU" -Value 1 -PropertyType DWord -Force | Out-Null

    @(
        "$appCompatFlagsPath\CompatMarkers",
        "$appCompatFlagsPath\Shared",
        "$appCompatFlagsPath\TargetVersionUpgradeExperienceIndicators"
    ) | ForEach-Object {
        Remove-Item -Path $_ -Force -Recurse -ErrorAction SilentlyContinue
    }

    Write-Log "Setting hardware requirement check variables"
    New-ItemProperty -Path $hwReqChkPath -Name "HwReqChkVars" -PropertyType MultiString -Value @(
        "SQ_SecureBootCapable=TRUE",
        "SQ_SecureBootEnabled=TRUE",
        "SQ_TpmVersion=2",
        "SQ_RamMB=8192"
    ) -Force | Out-Null

    $systemPolicyKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
    if (-not (Test-Path $systemPolicyKey)) {
        New-Item -Path $systemPolicyKey -Force | Out-Null
    }
    New-ItemProperty -Path $systemPolicyKey -Name "HideUnsupportedHardwareNotifications" -PropertyType DWord -Value 1 -Force | Out-Null
    Write-Log "Disabled unsupported hardware notifications"

    $uhncKey = "HKCU:\Control Panel\UnsupportedHardwareNotificationCache"
    if (-not (Test-Path $uhncKey)) {
        New-Item -Path $uhncKey -Force | Out-Null
    }
    New-ItemProperty -Path $uhncKey -Name "SV2" -Value 0 -PropertyType DWord -Force | Out-Null

    try {
        Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Value 0 -Type DWord -Force
        Write-Host "Telemetry disabled." -ForegroundColor Green
        Write-Log "Telemetry disabled successfully"
    }
    catch {
        Write-Log "Failed to modify telemetry settings: $_" "ERROR"
        Write-Host ("Failed to modify telemetry settings: $($_)") -ForegroundColor Red
    }

    $telemetryTasks = @(
        "\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser",
        "\Microsoft\Windows\Application Experience\PcaPatchDbTask",
        "\Microsoft\Windows\Application Experience\StartupAppTask"
    )

    Write-Log "Disabling telemetry tasks"
    foreach ($task in $telemetryTasks) {
        schtasks /query /tn "$task" 2>$null
        if ($LASTEXITCODE -eq 0) {
            schtasks /change /disable /tn "$task" | Out-Null
            Write-Log "Disabled task: $task"
            Write-Host "Disabled task: $task" -ForegroundColor Green
        }
    }
    Write-Log "Set-BypassRegistryTweaks completed successfully"
}

function Wait-AfterInfo {
    param ($seconds = 3)
    Write-Log "Pausing for $seconds seconds"
    Write-Host "`n[Pause for $seconds seconds...]" -ForegroundColor DarkGray
    Start-Sleep -Seconds $seconds
}

function Test-DefaultBootEntry {
    $confirm = Read-Host "Check and fix default boot entry? (Y/N)"
    if ($confirm -ne "Y" -and $confirm -ne "y") {
        Write-Host "Boot entry check skipped." -ForegroundColor Gray
        return
    }
    Write-Log "Starting default boot entry check"
    Write-Host "`n*** Checking Boot Manager settings... ***" -ForegroundColor Cyan
    
    # 1. Get the current default boot entry via bcdedit
    $bcdDefault = bcdedit /enum {bootmgr} | Select-String "default"
    $defaultGUID = ($bcdDefault -split "\s+")[1]

    # 2. Get the description of the default entry
    $description = bcdedit /enum $defaultGUID | Select-String "description"
    $osName = ($description -split "\s+", 2)[1]

    Write-Host "Current default OS at startup: $osName" -ForegroundColor Yellow
    Write-Log "Current default OS: $osName"

    # 3. Check if 'Windows Rollback' is set as default
    if ($osName -like "*Rollback*") {
        Write-Host "[WARNING] Windows Rollback is set as default!" -ForegroundColor Red
        Write-Log "Windows Rollback detected as default boot option" "WARNING"
        
        $confirm2 = Read-Host "Set Windows 11/10 as default boot option? (Y/N)"
        if ($confirm2 -eq "Y" -or $confirm2 -eq "y") {
            try {
                bcdedit /default {current} | Out-Null
                Write-Host "[OK] Windows is now set as default OS." -ForegroundColor Green
                Write-Log "Boot Manager updated: Windows set as default (was Rollback)" "INFO"
            }
            catch {
                Write-Host "[ERROR] Could not modify boot configuration." -ForegroundColor Red
                Write-Log "Failed to modify boot configuration: $_" "ERROR"
            }
        }
    }
    else {
        Write-Host "[OK] Boot loader is correctly set to: $osName" -ForegroundColor Green
        Write-Log "Boot loader configuration verified successfully"
    }
}

function Repair-SystemFiles {
    $confirm = Read-Host "Run SFC and DISM system file repair? (Y/N)"
    if ($confirm -ne "Y" -and $confirm -ne "y") {
        Write-Host "System file repair skipped." -ForegroundColor Gray
        Write-Log "System file repair skipped by user"
        return
    }
    Write-Log "Starting Repair-SystemFiles"
    Write-Host "`n*** System File Repair: SFC & DISM ***" -ForegroundColor Cyan
    Write-Host "This action checks and repairs corrupted Windows system files."
    
    Write-Log "Starting system file repair: DISM and SFC" "INFO"
    
    # 1. DISM RestoreHealth (Restores source files via Windows Update)
    Write-Host "`n[1/2] Running DISM /RestoreHealth... (This may take a while)" -ForegroundColor Yellow
    Write-Log "Executing DISM /RestoreHealth"
    dism /online /cleanup-image /restorehealth
    
    # 2. SFC Scannow (Repairs the actual system files)
    Write-Host "`n[2/2] Running SFC /Scannow..." -ForegroundColor Yellow
    Write-Log "Executing SFC /Scannow"
    sfc /scannow
    
    Write-Host "`n*** System file repair completed. ***" -ForegroundColor Green
    Write-Log "System file repair completed successfully"
}

function Test-DriverBlockers {
    $confirm = Read-Host "Check for incompatible drivers? (Y/N)"
    if ($confirm -ne "Y" -and $confirm -ne "y") {
        Write-Host "Driver blocker check skipped." -ForegroundColor Gray
        return
    }
    Write-Log "Starting Test-DriverBlockers"
    Write-Host "`n*** Checking for incompatible drivers... ***" -ForegroundColor Cyan
    $badDrivers = @()

    # List of driver patterns that often cause issues with Windows 11 upgrades
    $driverPatterns = @(
        "*Intel*Smart Sound*",
        "*Realtek*Audio*",
        "*Conexant*",
        "*Killer*Networking*",
        "*DisplayLink*"
    )

    $installedDrivers = Get-PnpDevice -PresentOnly | Where-Object { $_.Status -eq "OK" }

    foreach ($pattern in $driverPatterns) {
        $match = $installedDrivers | Where-Object { $_.FriendlyName -like $pattern }
        if ($match) {
            foreach ($m in $match) {
                $badDrivers += [PSCustomObject]@{
                    Name     = $m.FriendlyName
                    Instance = $m.InstanceId
                }
            }
        }
    }

    if ($badDrivers.Count -gt 0) {
        Write-Log "Incompatible drivers detected: $($badDrivers.Count)" "WARNING"
        Write-Host "[!] The following drivers may block the upgrade:" -ForegroundColor Yellow
        $badDrivers | ForEach-Object { 
            Write-Host "  - $($_.Name)" 
            Write-Log "Detected driver: $($_.Name)"
        }

        $confirm2 = Read-Host "`nDo you want to update these drivers via Windows Update? (Y/N)"
        if ($confirm2 -eq "Y" -or $confirm2 -eq "y") {
            Write-Host "Searching for driver updates..." -ForegroundColor Cyan
            Write-Log "Searching for driver updates"
            try {
                $session = New-Object -ComObject Microsoft.Update.Session
                $searcher = $session.CreateUpdateSearcher()
                $result = $searcher.Search("IsInstalled=0 and Type='Driver'")
                
                if ($result.Updates.Count -gt 0) {
                    Write-Host "Updates found. Install via Windows Settings." -ForegroundColor Green
                    Write-Log "Driver updates found: $($result.Updates.Count)"
                } else {
                    Write-Host "No newer drivers found via automatic scan." -ForegroundColor Yellow
                    Write-Log "No driver updates available" "WARNING"
                }
            }
            catch {
                Write-Log "Failed to search for driver updates: $_" "ERROR"
                Write-Host "Failed to search for driver updates: $_" -ForegroundColor Red
            }
        }
    } else {
        Write-Host "[OK] No critical driver blockers detected." -ForegroundColor Green
        Write-Log "No incompatible drivers detected"
    }
    Write-Log "Test-DriverBlockers completed successfully"
}

function Test-DeepBlockers {
    $confirm = Read-Host "Run deep scan for system configuration and peripherals? (Y/N)"
    if ($confirm -ne "Y" -and $confirm -ne "y") {
        Write-Host "Deep scan skipped." -ForegroundColor Gray
        return
    }
    Write-Log "Starting deep scan for system configuration and peripherals"
    Write-Host "`n*** Deep Scan: System Configuration & Peripherals ***" -ForegroundColor Cyan

    # 1. Check Partition Style (MBR vs GPT)
    $disk = Get-Disk | Where-Object { $_.Number -eq 0 } # Usually the OS disk
    if ($disk.PartitionStyle -eq "MBR") {
        Write-Log "CRITICAL: System disk is MBR. Windows 11 requires GPT/UEFI!" "ERROR"
        Write-Host "[!] CRITICAL: System disk is MBR. Windows 11 requires GPT/UEFI!" -ForegroundColor Red
        Write-Host "    Use 'mbr2gpt /validate /allowFullOS' to test this." -ForegroundColor Yellow
    }

    # 2. Check EFI Partition space
    $efiPartition = Get-Partition | Where-Object { $_.GptType -eq "{c12a7328-f81f-11d2-ba4b-00a0c93ec93b}" } # EFI GUID
    if ($efiPartition) {
        $freeSpace = $efiPartition.SizeRemaining / 1MB
        if ($freeSpace -lt 15) {
            Write-Log "WARNING: Low space on EFI partition ($([math]::Round($freeSpace,2)) MB free)." "WARNING"
            Write-Host "[!] WARNING: Low space on EFI partition ($([math]::Round($freeSpace,2)) MB free)." -ForegroundColor Yellow
        }
    }

    # 3. Check for connected USB storage (except the OS disk)
    $usbDrives = Get-Disk | Where-Object { $_.BusType -eq "USB" -and $_.OperationalStatus -eq "Online" }
    if ($usbDrives) {
        Write-Log "Advice: Disconnect all USB drives/external disks during the upgrade" "INFO"
        Write-Host "[i] Advice: Disconnect all USB drives/external disks during the upgrade." -ForegroundColor Gray
    }

    # 4. Check Developer Mode
    $devMode = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock" -Name "AllowDevelopmentWithoutDevLicense" -ErrorAction SilentlyContinue
    if ($devMode.AllowDevelopmentWithoutDevLicense -eq 1) {
        Write-Log "Info: Developer Mode is enabled." "INFO"
        Write-Host "[i] Info: Developer Mode is enabled." -ForegroundColor Gray
    }

    
}

function Show-MainMenu {
    Write-Host "`n*** Windows 11 Upgrade Precheck Menu ***" -ForegroundColor Cyan
    Write-Host "1. Reset Windows Update"
    Write-Host "2. Apply registry tweaks to bypass hardware restrictions"
    Write-Host "3. Configure Windows Update Target Release"
    Write-Host "4. Run deep scan for blockers and drivers"
    Write-Host "5. Run SFC and DISM system file repair"
    Write-Host "0. Exit"
    $choice = Read-Host "`Choose an option"
    switch ($choice) {
        "1" { Reset-WindowsUpdate; Show-MainMenu }
        "2" { Set-BypassRegistryTweaks; Show-MainMenu }
        "3" { Set-WUTargetRelease; Show-MainMenu }
        "4" { Test-DeepBlockers; Test-DriverBlockers; Show-MainMenu }
        "5" { Repair-SystemFiles; Show-MainMenu }
        "0" { exit }
        default { Show-MainMenu }
    }
}

Show-MainMenu



