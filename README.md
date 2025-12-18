# Windows-FileZilla-Server-Log-Analyzer
A high-performance PowerShell tool for FileZilla Server (v1.x &amp; legacy). It provides automated summaries of data transfer volumes (MB), identifies brute-force attacks and bot scans, tracks successful logins, and identifies common 550 file errors. Includes IP whitelisting and time-based log filtering. Ideal for automated server audits.

🚀 Key Features
Managed Volume Calculation: Accurately calculates data transfer (MB) per IP by tracking session states and 213/226 FTP status codes.
Security Auditing: Automatically identifies and groups brute-force login attempts and automated bot scans.
IP Whitelisting: Exclude internal servers or trusted backup IPs from security alerts while still tracking their data usage.
Time-Based Filtering: Configurable look-back period (e.g., last 30 days) to optimize performance on large log sets.
Multi-Version Support: Compatible with modern FileZilla Server 1.x and legacy log formats.
Error Tracking: Summarizes frequent 550 "File Not Found" errors to help debug failed client syncs.

🛠️ Configuration
Open the script in any text editor and modify the header variables:

PowerShell

$logFolder     = "C:\Path\To\Your\Logs\"  # Path to FileZilla logs
$DaysLimit     = 30                       # Only process recent logs
$IPWhitelist   = @("192.168.1.12", "...") # IPs to ignore in security alerts

📋 Usage
Download FileZillaLogAnalyzer.ps1.
Right-click the file and select Run with PowerShell.

Note: You may need to bypass the execution policy for the current session:

PowerShell

Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process
.\FileZillaLogAnalyzer.ps1

📊 Sample Output
Plaintext

===========================================================
   FILEZILLA SERVER LOG ANALYZER - v28
   Author: Lukas Pavelka (lukas.pavelka@gmail.com)
===========================================================
Time Filter: Last 30 days
Logs Found:  5
-----------------------------------------------------------

[#] DATA TRANSFER SUMMARY
Total Managed Volume: 10406.87 MB
 -> 192.168.1.12    | 10406.87 MB
------------------------------------
[!] FAILED LOGINS (External Only)
...

👤 Author
Lukas Pavelka
Email: lukas.pavelka@gmail.com
GitHub: @lukaspavelka

📄 License
This project is licensed under the MIT License - see the LICENSE file for details.
