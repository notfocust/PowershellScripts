# --- FUNCTION: ENFORCE ADMINISTRATOR PRIVILEGES ---
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "ERROR: This script must be run with Administrator privileges." -ForegroundColor Red
    exit 1
}

# --- TLS 1.2 Security Protocol Enforcement ---
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# --- VARIABLE DEFINITIONS ---
$DownloadUrl = "https://download2.veeam.com/VBR/v12/VeeamBackup&Replication_12.3.2.4165_20251006_patch.zip"
$TargetDir = "C:\Temp\VeeamPatch"
$InstallerFileName = "VeeamBackup&Replication_12.3.2.4165_20251006_patch.exe"
$ZipFilePath = Join-Path $TargetDir "VeeamPatch.zip"
$InstallerPath = Join-Path $TargetDir $InstallerFileName
$InstallArgsString = "/silent /accepteula /acceptlicensingpolicy /acceptthirdpartylicenses /acceptrequiredsoftware /noreboot"

# --- USER CONFIRMATION ---
$Confirmation = Read-Host "Proceed with download and installation of patch 12.3.2.4165_20251006? (Y/N)"

if ($Confirmation -ieq "Y") {

    # --- DIRECTORY SETUP ---
    if (-not (Test-Path $TargetDir)) {
        Write-Host "Creating directory '$TargetDir'..."
        New-Item -Path $TargetDir -ItemType Directory | Out-Null
    }

    # --- DOWNLOAD & EXTRACTION ---
    if (-not (Test-Path $InstallerPath)) {
        Write-Host "Downloading patch from '$DownloadUrl'..."
        try {
            $DownloadClient = New-Object System.Net.WebClient
            $DownloadClient.DownloadFile($DownloadUrl, $ZipFilePath)
            Write-Host "Download complete."
        } catch {
            Write-Host "ERROR: Failed to download file. $($_.Exception.Message)" -ForegroundColor Red
            exit 1
        }

        Write-Host "Extracting installer to '$TargetDir'..."
        try {
            Expand-Archive -Path $ZipFilePath -DestinationPath $TargetDir -Force
            Write-Host "Extraction complete."
        } catch {
            Write-Host "ERROR: Failed to extract file. $($_.Exception.Message)" -ForegroundColor Red
            exit 1
        }
    } else {
        Write-Host "Installer file already exists. Skipping download and extraction."
    }

    # --- VERIFY INSTALLER EXISTS ---
    if (-not (Test-Path $InstallerPath)) {
        Write-Host "ERROR: Installer not found at expected path '$InstallerPath'" -ForegroundColor Red
        exit 1
    }

    # --- SILENT INSTALLATION ---
    Write-Host "Launching silent installation of the Veeam patch..."
    try {
        Start-Process -FilePath $InstallerPath -ArgumentList $InstallArgsString -WindowStyle Hidden
        Write-Host "======================================================================"
        Write-Host "INSTALLATION INITIATED." -ForegroundColor Green
        Write-Host "The silent patch process is now running. Script finished."
        Write-Host "======================================================================"
    } catch {
        Write-Host "ERROR: Failed to execute installer. $($_.Exception.Message)" -ForegroundColor Red
        exit 1
    }

} else {
    Write-Host "Installation cancelled by user."
}
