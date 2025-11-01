function Show-Menu {
    Clear-Host
    Write-Host "================ Network Tools ================"
    Write-Host "1: Flush DNS Cache"
    Write-Host "2: Release/Renew IP Address"
    Write-Host "3: Display IP Configuration"
    Write-Host "4: Ping Google DNS (8.8.8.8)"
    Write-Host "5: Reset Network Stack"
    Write-Host "Q: Quit"
    Write-Host "============================================="
}

function Execute-NetworkAction {
    param (
        [string]$action
    )
    
    Write-Host "`n"
    switch ($action) {
        '1' {
            Write-Host "Flushing DNS cache..." -ForegroundColor Yellow
            $result = Start-Process -FilePath "ipconfig.exe" -ArgumentList "/flushdns" -Wait -NoNewWindow -PassThru -Verb RunAs
            if ($result.ExitCode -eq 0) {
                Write-Host "DNS cache successfully flushed!" -ForegroundColor Green
            }
        }
        '2' {
            Write-Host "Releasing and renewing IP..." -ForegroundColor Yellow
            Start-Process -FilePath "ipconfig.exe" -ArgumentList "/release" -Wait -NoNewWindow -Verb RunAs
            Start-Process -FilePath "ipconfig.exe" -ArgumentList "/renew" -Wait -NoNewWindow -Verb RunAs
            Write-Host "IP address has been released and renewed!" -ForegroundColor Green
        }
        '3' {
            Write-Host "IP Configuration:" -ForegroundColor Yellow
            ipconfig /all
        }
        '4' {
            Write-Host "Pinging 8.8.8.8..." -ForegroundColor Yellow
            $pingResult = Test-Connection -ComputerName "8.8.8.8" -Count 4 -ErrorAction SilentlyContinue
            if ($pingResult) {
                $avgTime = [math]::Round(($pingResult | Measure-Object -Property ResponseTime -Average).Average)
                Write-Host "Ping successful! Average response time: ${avgTime}ms" -ForegroundColor Green
            } else {
                Write-Host "Unable to ping 8.8.8.8" -ForegroundColor Red
            }
        }
        '5' {
            Write-Host "Resetting network stack..." -ForegroundColor Yellow
            $commands = @(
                "ipconfig /release",
                "ipconfig /flushdns",
                "netsh winsock reset",
                "netsh int ip reset",
                "ipconfig /renew"
            )
            foreach ($cmd in $commands) {
                Write-Host "Executing: $cmd" -ForegroundColor Cyan
                Start-Process "cmd.exe" -ArgumentList "/c $cmd" -Wait -NoNewWindow -Verb RunAs
            }
            Write-Host "Network stack reset completed! Please restart your computer." -ForegroundColor Green
        }
        'Q' {
            return $false
        }
        default {
            Write-Host "Invalid option selected." -ForegroundColor Red
        }
    }
    Write-Host "`nPress any key to continue..."
    $null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
    return $true
}

# Main loop
do {
    Show-Menu
    $selection = Read-Host "Please make a selection"
    $continue = Execute-NetworkAction $selection
} while ($continue)