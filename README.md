# 🛡️ Windows FileZilla Server Log Analyzer

![PowerShell](https://img.shields.io/badge/PowerShell-%235391FE.svg?style=for-the-badge&logo=powershell&logoColor=white)
![License: MIT](https://img.shields.io/badge/License-MIT-green.svg?style=for-the-badge)
![Status: Production](https://img.shields.io/badge/Status-Production-success.svg?style=for-the-badge)

A professional PowerShell-based security and traffic audit tool designed for **FileZilla Server (v1.x and Legacy)**. This script parses complex FTP logs to provide clear, actionable insights for system administrators.



## ✨ Key Features

* 📊 **Managed Volume Calculation:** Accurately calculates total data transfer (MB) per IP using session-state tracking.
* 🔒 **Security Audit:** Detects and groups brute-force login attempts and automated bot scans.
* ⚪ **IP Whitelisting:** Define trusted IPs (e.g., internal backup servers) to exclude them from security alerts.
* ⏳ **Time-Based Filtering:** Configurable variable to process only logs from the last X days (e.g., last 30 days).
* 📁 **Error 550 Context:** Identifies and lists the specific filenames causing "File Not Found" errors.
* 🌍 **English Output:** Clean, localized console output with no encoding/character issues.

## 🛠️ Configuration

At the top of the script, you can customize the following variables:

| Variable | Description |
| :--- | :--- |
| `$logFolder` | The path where your FileZilla Server logs are stored. |
| `$DaysLimit` | How many days of history to analyze (e.g., `30`). |
| `$IPWhitelist` | An array of IPs that should be ignored in security reports. |

## 🚀 How to Use

1.  Download the `FileZillaLogAnalyzer.ps1` script.
2.  Open the script and set your `$logFolder` path.
3.  Right-click the file and select **Run with PowerShell**.
4.  Run PowerShell as Administrator (Recommended). ///or/// Alternatively, ensure the user account executing the script has explicit Read permissions for the FileZilla log folder.
5.  If you have execution policy restrictions, run this command in your terminal first:
    ```powershell
    Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process
    ```

##  👨‍💻 Author
Lukas Pavelka 📧 Email: lukas.pavelka@gmail.com

📄 License
This project is licensed under the MIT License - free for personal and commercial use.


## 📊 Sample Output

```text
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
IP Address      Attempts
----------      --------
84.0.116.35            5
...

