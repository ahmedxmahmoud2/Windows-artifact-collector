# Windows Artifact Collector

A PowerShell-based forensic data collection tool designed to extract key Windows artifacts for incident response and digital forensics investigations.

## Features
- Collects registry hives, event logs, browser data, and other forensic artifacts.
- Generates a structured output directory for easier analysis.
- Creates SHA256 hashes for integrity verification.
- Lightweight and suitable for live-response scenarios.

## Usage
1. Run PowerShell as Administrator.
2. Execute the script:
   ```powershell
   powershell -ExecutionPolicy Bypass -File "Windows_Artifact_Collector.ps1"
The tool will create an output folder with collected artifacts and log files.

Output Example
mathematica
Copy code
C:\Forensic_Collection\
│
├── Registry\
├── EventLogs\
├── BrowserData\
├── Hashes.txt
└── Log.txt
Requirements
Windows PowerShell 5.1 or later

Administrative privileges

Disclaimer
This tool is intended for legitimate forensic and incident response purposes only. The author is not responsible for any misuse or unauthorized application.

<img width="1897" height="1062" alt="image" src="https://github.com/user-attachments/assets/791af572-f16f-493e-8f77-cbb8da784e7d" />

<img width="1429" height="732" alt="image" src="https://github.com/user-attachments/assets/8159bbfd-7c86-4d7b-8f66-48397e90d2f2" />

