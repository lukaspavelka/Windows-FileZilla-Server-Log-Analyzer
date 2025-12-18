<#
.SYNOPSIS
    FileZilla Server Log Analyzer v28 - Final English Production Version.
.AUTHOR
    Lukas Pavelka (lukas.pavelka@gmail.com)
.DESCRIPTION
    Analyzes data transfer volume, security threats, and errors in FileZilla logs.
    Optimized for modern v1.11.1 and legacy versions.
#>

# --- ADMIN CHECK START (Add here) ---
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Warning "This script is not running as Administrator. It may fail to read log files due to permission restrictions."
    Write-Host "Please right-click PowerShell and select 'Run as Administrator'.`n" -ForegroundColor Yellow
}
# --- ADMIN CHECK END ---

# --- USER CONFIGURATION ---
$logFolder     = "C:\Program Files\FileZilla Server\Logs\"
$DaysLimit     = 30                 # Process files modified within the last X days
$Author        = "Lukas Pavelka"
$Contact       = "lukas.pavelka@gmail.com"

# --- IP WHITELIST CONFIGURATION ---
# These IPs will be ignored in attack and scan statistics
$IPWhitelist = @(
    "192.168.1.12", 
    "192.168.1.13",
    "127.0.0.1"
)

# --- INITIALIZATION ---
$failedLogins = @(); $successfulLogins = @(); $securityEvents = @()
$missingFiles = @(); $ipTraffic = @{}; $totalBytes = 0
$sessionFileTracker = @{}

$cutOffDate = (Get-Date).AddDays(-$DaysLimit)
$logFiles = Get-ChildItem -Path $logFolder -Filter "filezilla-server*.log*" | Where-Object { $_.LastWriteTime -gt $cutOffDate }

Write-Host "`n===========================================================" -ForegroundColor Gray
Write-Host "   FILEZILLA SERVER LOG ANALYZER - v28" -ForegroundColor Cyan
Write-Host "   Author: $Author ($Contact)" -ForegroundColor Gray
Write-Host "===========================================================" -ForegroundColor Gray
Write-Host "Time Filter: Last $DaysLimit days"
Write-Host "Logs Found:  $($logFiles.Count)"
Write-Host "-----------------------------------------------------------`n"

if ($null -eq $logFiles) { Write-Warning "No log files found matching the criteria."; return }

foreach ($file in $logFiles) {
    # Using UTF8 for compatibility
    $logLines = Get-Content -Path $file.FullName -Encoding UTF8
    
    foreach ($line in $logLines) {
        if ([string]::IsNullOrWhiteSpace($line)) { continue }

        # Extract Session ID and IP
        $sid = "0"; $ip = "Unknown"
        if ($line -match "Session (?:ID: )?(?<SID>\d+) (?<IP>[\d\.]+)") { 
            $sid = $Matches['SID']; $ip = $Matches['IP'] 
        }

        # Check Whitelist
        $isWhitelisted = $false
        foreach ($wIP in $IPWhitelist) { if ($ip -like "*$wIP*") { $isWhitelisted = $true; break } }

        # 1. TRACK FILENAMES (For Error 550 context)
        if ($line -match "(SIZE|STOR|RETR|MLST|MLSD) (?<File>.*)") {
            $sessionFileTracker[$sid] = $Matches['File'].Trim()
        }

        # 2. DATA TRANSFER CALCULATION (Direct capture from 213 code or transfer text)
        if ($line -match " 213 (?<Bytes>\d+)" -or $line -match "(?<Bytes>\d+) bytes transferred") {
            $bytes = [int64]$Matches['Bytes']
            $totalBytes += $bytes
            $ipTraffic[$ip] += $bytes
        }

        # 3. SECURITY (Filtered by Whitelist)
        if (-not $isWhitelisted) {
            if ($line -match " 530 Login incorrect") {
                $failedLogins += [PSCustomObject]@{ IP = $ip }
            }
            elseif ($line -match "!!|GnuTLS error|ECONNABORTED|501 What are you|GET / HTTP|SIP/|RTSP/") {
                $cleanMsg = $line.Split(']')[-1].Trim()
                $securityEvents += [PSCustomObject]@{ IP = $ip; Msg = $cleanMsg }
            }
        }

        # 4. ACTIVITY
        if ($line -match " 230 Login successful") {
            $successfulLogins += [PSCustomObject]@{ IP = $ip }
        }
        if ($line -match " 550 ") {
            $fileName = if ($sessionFileTracker.ContainsKey($sid)) { $sessionFileTracker[$sid] } else { "System Check/Root" }
            $missingFiles += [PSCustomObject]@{ File = $fileName }
        }
    }
    $sessionFileTracker.Clear()
}

# --- RENDER RESULTS ---

$totalMB = [math]::Round($totalBytes / 1MB, 2)
Write-Host "[#] DATA TRANSFER SUMMARY" -ForegroundColor White
Write-Host "Total Managed Volume: " -NoNewline
Write-Host "$totalMB MB" -ForegroundColor Green
if ($ipTraffic.Count -gt 0) {
    $ipTraffic.GetEnumerator() | Sort-Object Value -Descending | ForEach-Object {
        $mb = [math]::Round($_.Value / 1MB, 2)
        if ($mb -gt 0) { Write-Host " -> $($_.Key.PadRight(15)) | $mb MB" }
    }
}
Write-Host "------------------------------------"



Write-Host "[!] FAILED LOGINS (External Only)" -ForegroundColor Yellow
if ($failedLogins.Count -gt 0) {
    $failedLogins | Group-Object IP | Select-Object @{N="IP Address"; E={$_.Name}}, @{N="Attempts"; E={$_.Count}} | Sort-Object Attempts -Descending | Select-Object -First 15 | Format-Table -AutoSize
}

Write-Host "[?] BOT SCANS & CONNECTION ERRORS" -ForegroundColor Magenta
if ($securityEvents.Count -gt 0) {
    $securityEvents | Group-Object IP | Select-Object @{N="IP Address"; E={$_.Name}}, @{N="Total"; E={$_.Count}}, @{N="Last Action"; E={$_.Group[-1].Msg}} | Sort-Object Total -Descending | Select-Object -First 10 | Format-Table -AutoSize
}

Write-Host "[OK] SUCCESSFUL LOGINS (All IPs)" -ForegroundColor Green
if ($successfulLogins.Count -gt 0) {
    $successfulLogins | Group-Object IP | Select-Object @{N="IP Address"; E={$_.Name}}, @{N="Sessions"; E={$_.Count}} | Sort-Object Sessions -Descending | Format-Table -AutoSize
}

Write-Host "[i] TOP MISSING FILES (Error 550)" -ForegroundColor Gray
if ($missingFiles.Count -gt 0) {
    $missingFiles | Group-Object File | Select-Object @{N="Filename"; E={$_.Name}}, @{N="Count"; E={$_.Count}} | Sort-Object Count -Descending | Select-Object -First 10 | Format-Table -AutoSize
}

Write-Host "`n--- ANALYSIS COMPLETE ---"