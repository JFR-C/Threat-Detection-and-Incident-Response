### VirusTotal Scanner (PowerShell script)
-----------------------------------------

#### DESCRIPTION

- This script allows to submit files to the VirusTotal API (v3) for malware analysis. Each file is scanned by dozens of antivirus engines, machine‑learning classifiers, threat‑intelligence feeds, and behavioral sandboxes.  

- After the analysis completes, the script generates a concise forensic HTML report for each file, including:
  - File information (metadata and hashes)
  - Threat classification
  - Antivirus detection summary
  - Direct links to the corresponding VirusTotal analysis Web pages

- A VirusTotal API key is required. You may use either a free/public API key or a Premium one.  
  The free/public API tier allows 500 requests per day and a rate of 4 requests per minute.

#### USAGE

- The script supports scanning a single file or all files in a folder, generating one report per file.  
  Reports are saved in the same directory as the input file(s).

```
🔹 Scan a single file
----------------------
PS C:\Temp> .\Invoke-VirusTotal-Scanner.ps1 -FilePath "C:\path\Samples\test.exe" -ApiKey "YOUR_API_KEY"

🔹 Scan all files inside a folder
----------------------------------
PS C:\Temp> .\Invoke-VirusTotal-Scanner.ps1 -FolderPath "C:\path\Samples" -ApiKey "YOUR_API_KEY"
```

#### LICENSE

GNU General Public License v3.0
