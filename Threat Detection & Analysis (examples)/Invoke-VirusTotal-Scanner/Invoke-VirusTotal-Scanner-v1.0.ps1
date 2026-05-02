<# 
.SYNOPSIS
    Submit to VirusTotal a single file or all files located in a folder, wait for analysis, and generate HTML forensic reports.

.DESCRIPTION
    This script can operate in two modes:

      1. Single-file mode:
         - Takes a file path as input
         - Uploads the file to VirusTotal (API v3)
         - Polls until the analysis is completed
         - Retrieves detailed metadata and per‑engine results
         - Generates a HTML report (.html)

      2. Folder mode:
         - Takes a folder path as input
         - Sequentially processes every file inside the folder
         - Generates a separate HTML report for each file

.PARAMETER FilePath
    Path to a single file to be analyzed.

.PARAMETER FolderPath
    Path to a folder. All files inside it will be analyzed sequentially.

.PARAMETER ApiKey
    VirusTotal API key (free or commercial, depending on your usage). 
    If omitted, the script will try to read it from the environment variable VIRUSTOTAL_API_KEY.

.EXAMPLE
    .\Invoke-VirusTotal-Scanner.ps1 -FilePath C:\Samples\test.exe -ApiKey "YOUR_API_KEY"

.EXAMPLE
    .\Invoke-VirusTotal-Scanner.ps1 -FolderPath C:\Samples -ApiKey "YOUR_API_KEY"

.EXAMPLE
    $env:VIRUSTOTAL_API_KEY = "YOUR_API_KEY"
    .\Invoke-VirusTotal-Scanner.ps1 -FolderPath C:\Samples
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false, Position = 0)]
    [string]$FilePath,

  	[Parameter(Mandatory = $false)]
	  [string]$FolderPath,

    [Parameter(Mandatory = $false)]
    [string]$ApiKey
)

function Show-Usage {
    Write-Host "Usage:" -ForegroundColor Yellow
    Write-Host "  $(Split-Path -Leaf $PSCommandPath) -FilePath <path_to_file> -ApiKey <virustotal_api_key>" -ForegroundColor Yellow
    Write-Host "  $(Split-Path -Leaf $PSCommandPath) -FolderPath <path_to_folder> -ApiKey <virustotal_api_key>" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Modes:" -ForegroundColor Yellow
    Write-Host "  -FilePath : Analyze a single file"
    Write-Host "  -FolderPath : Analyze all files inside a folder (sequentially)"
    Write-Host ""
    Write-Host "Run with -? for full help." -ForegroundColor Yellow
}

if ($FolderPath) {

    if (-not (Test-Path -LiteralPath $FolderPath)) {
        Write-Error "Folder not found: $FolderPath"
        return
    }

    $files = Get-ChildItem -LiteralPath $FolderPath -File

    if ($files.Count -eq 0) {
        Write-Warning "No files found in folder: $FolderPath"
        return
    }

    Write-Host "Processing folder: $FolderPath" -ForegroundColor Cyan
    Write-Host "Found $($files.Count) files." -ForegroundColor Cyan

    foreach ($file in $files) {
        Write-Host ""
        Write-Host "=== Processing file: $($file.FullName) ===" -ForegroundColor Yellow

        # Call your existing script logic for each file
        & $PSCommandPath -FilePath $file.FullName -ApiKey $ApiKey
    }

    Write-Host ""
    Write-Host "All files processed." -ForegroundColor Green
    return
}

# If no argument is provided, show usage and exit
if (-not $FilePath) {
    Show-Usage
    return
}

# Resolve API key: parameter > environment variable
if (-not $ApiKey) {
    $ApiKey = $env:VIRUSTOTAL_API_KEY
}

if (-not $ApiKey) {
    Write-Error "No API key provided. Use -ApiKey or set the VIRUSTOTAL_API_KEY environment variable."
    return
}

# Validate file
if (-not (Test-Path -LiteralPath $FilePath)) {
    Write-Error "File not found: $FilePath"
    return
}

# --- Configuration -----------------------------------------------------------

$VTBaseUri      = "https://www.virustotal.com/api/v3"
$UploadEndpoint = "$VTBaseUri/files"
$AnalysisEndpoint = "$VTBaseUri/analyses"
$FilesEndpoint  = "$VTBaseUri/files"

# Output report paths
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$baseName  = [IO.Path]::GetFileNameWithoutExtension($FilePath)
$directory = Split-Path -Parent (Resolve-Path -LiteralPath $FilePath)

$txtReportPath  = Join-Path $directory "$($baseName)_VT_Report_$timestamp.txt"
$htmlReportPath = Join-Path $directory "$($baseName)_VT_Report_$timestamp.html"

# --- Helper: Build headers ---------------------------------------------------

function Get-VTHeaders {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ApiKey
    )

    return @{
        "x-apikey" = $ApiKey
    }
}

# --- Helper: Upload file to VirusTotal --------------------------------------

function Submit-VTFile {
    param(
        [Parameter(Mandatory = $true)]
        [string]$FilePath,

        [Parameter(Mandatory = $true)]
        [string]$ApiKey
    )

    Write-Verbose "Submitting file to VirusTotal: $FilePath"

    $headers = Get-VTHeaders -ApiKey $ApiKey

    # Create multipart/form-data body
    $fileBytes = [System.IO.File]::ReadAllBytes($FilePath)
    $fileName  = [System.IO.Path]::GetFileName($FilePath)

    $boundary = [System.Guid]::NewGuid().ToString()
    $LF = "`r`n"

    $bodyLines = (
        "--$boundary",
        "Content-Disposition: form-data; name=`"file`"; filename=`"$fileName`"",
        "Content-Type: application/octet-stream$LF"
    )

    $bodyStream = New-Object System.IO.MemoryStream
    $writer = New-Object System.IO.StreamWriter($bodyStream)

    foreach ($line in $bodyLines) {
        $writer.Write($line + $LF)
    }
    $writer.Flush()

    $bodyStream.Write($fileBytes, 0, $fileBytes.Length)
    $writer.Write($LF + "--$boundary--$LF")
    $writer.Flush()
    $bodyStream.Position = 0

    $contentType = "multipart/form-data; boundary=$boundary"

    try {
        $response = Invoke-RestMethod -Method Post -Uri $UploadEndpoint -Headers $headers -ContentType $contentType -Body $bodyStream
        return $response
    }
    catch {
        Write-Error "Error submitting file to VirusTotal: $_"
        return $null
    }
    finally {
        $writer.Dispose()
        $bodyStream.Dispose()
    }
}

# --- Helper: Poll analysis until completed ----------------------------------

function Wait-VTAnalysis {
    param(
        [Parameter(Mandatory = $true)]
        [string]$AnalysisId,

        [Parameter(Mandatory = $true)]
        [string]$ApiKey,

        [int]$PollIntervalSeconds = 30,

        [int]$MaxWaitSeconds = 300
    )

    $headers = Get-VTHeaders -ApiKey $ApiKey
    $elapsed = 0

    Write-Host "Waiting for VirusTotal analysis to complete..." -ForegroundColor Cyan

    while ($true) {
        try {
            $uri = "$AnalysisEndpoint/$AnalysisId"
            $analysis = Invoke-RestMethod -Method Get -Uri $uri -Headers $headers
        }
        catch {
            Write-Warning "Error querying analysis status: $_"
            Start-Sleep -Seconds $PollIntervalSeconds
            $elapsed += $PollIntervalSeconds
            if ($elapsed -ge $MaxWaitSeconds) {
                Write-Error "Timeout waiting for analysis."
                return $null
            }
            continue
        }

        $status = $analysis.data.attributes.status
        Write-Host "  Status: $status (elapsed: $elapsed s)" -ForegroundColor DarkCyan

        if ($status -eq "completed") {
            return $analysis
        }

        Start-Sleep -Seconds $PollIntervalSeconds
        $elapsed += $PollIntervalSeconds

        if ($elapsed -ge $MaxWaitSeconds) {
            Write-Error "Timeout waiting for analysis."
            return $null
        }
    }
}

# --- Helper: Get file report (for richer metadata) ---------------------------

function Get-VTFileReport {
    param(
        [Parameter(Mandatory = $true)]
        [string]$FileId,   # usually SHA256

        [Parameter(Mandatory = $true)]
        [string]$ApiKey
    )

    $headers = Get-VTHeaders -ApiKey $ApiKey
    $uri = "$FilesEndpoint/$FileId"

    try {
        $response = Invoke-RestMethod -Method Get -Uri $uri -Headers $headers
        return $response
    }
    catch {
        Write-Warning "Error retrieving file report: $_"
        return $null
    }
}

# --- Helper: Generate HTML report -------------------------------------------

function Write-HtmlReport {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        $Analysis,

        [Parameter(Mandatory = $true)]
        $FileReport,

        [Parameter(Mandatory = $true)]
        [string]$OriginalFilePath
    )

    Add-Type -AssemblyName System.Web

    $fileAttr = $FileReport.data.attributes
    $stats    = $fileAttr.last_analysis_stats
    $results  = $fileAttr.last_analysis_results

    function Convert-UnixHtml {
        param([long]$ts)
        if ($ts -gt 0) {
            return [System.Web.HttpUtility]::HtmlEncode([DateTimeOffset]::FromUnixTimeSeconds($ts).ToLocalTime())
        }
        return ""
    }

    $firstSub = Convert-UnixHtml $fileAttr.first_submission_date
    $lastSub  = Convert-UnixHtml $fileAttr.last_submission_date
    $lastAna  = Convert-UnixHtml $fileAttr.last_analysis_date

    $sha256 = $fileAttr.sha256
    $vtFileUrl = "https://www.virustotal.com/gui/file/$sha256"
	$vtDetailsUrl  = "https://www.virustotal.com/gui/file/$sha256/details"
    $vtBehaviorUrl  = "https://www.virustotal.com/gui/file/$sha256/behavior"
    $vtRelationsUrl = "https://www.virustotal.com/gui/file/$sha256/relations"

    # Risk score
    $riskScore = ($stats.malicious * 5) + ($stats.suspicious * 2)

    if ($riskScore -ge 20) {
        $riskColor = "#ff0000"
        $riskLabel = "High Risk"
    }
    elseif ($riskScore -ge 5) {
        $riskColor = "#ff9800"
        $riskLabel = "Suspicious"
    }
    else {
        $riskColor = "#4caf50"
        $riskLabel = "Likely Harmless"
    }

    # Color-coded detection summary
    $colorHarmless   = "#4caf50"
    $colorMalicious  = "#ff0000"
    $colorSuspicious = "#ff9800"
    $colorUndetected = "#607d8b"
    $colorTimeout    = "#9e9e9e"

    $html = @()

    $html += "<!DOCTYPE html>"
    $html += "<html lang='en'>"
    $html += "<head>"
    $html += "  <meta charset='UTF-8' />"
    $html += "  <title>VirusTotal File Analysis Report</title>"
    $html += "  <style>"
    $html += "    body { font-family: Arial, sans-serif; background-color: #f5f5f5; color: #333; margin: 0; padding: 0; }"
    $html += "    .container { max-width: 1200px; margin: 20px auto; background: #fff; padding: 20px 30px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }"
    $html += "    h1 { color: #333; }"
    $html += "    h2 { color: #444; border-bottom: 1px solid #ddd; padding-bottom: 4px; }"
    $html += "    .badge { display: inline-block; padding: 8px 14px; border-radius: 4px; color: #fff; font-weight: bold; margin-bottom: 15px; }"
    $html += "    .summary-table, .engines-table { border-collapse: collapse; width: 100%; margin-bottom: 20px; }"
    $html += "    .summary-table th, .summary-table td, .engines-table th, .engines-table td { border: 1px solid #ddd; padding: 8px; font-size: 13px; }"
    $html += "    .summary-table th, .engines-table th { background-color: #f0f0f0; text-align: left; }"
    $html += "  </style>"
    $html += "</head>"
    $html += "<body>"
    $html += "  <div class='container'>"
    $html += "    <h1>VirusTotal File Analysis Report</h1>"
    $html += "    <div class='badge' style='background-color: $riskColor;'>$riskLabel - Score: $riskScore</div>"

    # --- FILE INFORMATION ---
    $html += "    <h2>File Information</h2>"
    $html += "    <table class='summary-table'>"
    $html += "      <tr><th>Original path</th><td>$([System.Web.HttpUtility]::HtmlEncode($OriginalFilePath))</td></tr>"
    $html += "      <tr><th>File name</th><td>$([System.Web.HttpUtility]::HtmlEncode($fileAttr.meaningful_name))</td></tr>"
    $html += "      <tr><th>Size (bytes)</th><td>$($fileAttr.size)</td></tr>"
    $html += "      <tr><th>Type</th><td>$([System.Web.HttpUtility]::HtmlEncode($fileAttr.type_description))</td></tr>"
    $html += "      <tr><th>MD5</th><td>$($fileAttr.md5)</td></tr>"
    $html += "      <tr><th>SHA1</th><td>$($fileAttr.sha1)</td></tr>"
    $html += "      <tr><th>SHA256</th><td>$sha256</td></tr>"
    $html += "      <tr><th>vHash</th><td>$($fileAttr.vhash)</td></tr>"
    $html += "      <tr><th>First submission</th><td>$firstSub</td></tr>"
    $html += "      <tr><th>Last submission</th><td>$lastSub</td></tr>"
    $html += "      <tr><th>Last analysis</th><td>$lastAna</td></tr>"
    $html += "    </table>"

    # --- THREAT CLASSIFICATION ---
    if ($fileAttr.popular_threat_classification) {

        $threat = $fileAttr.popular_threat_classification
        $html += "    <h2>Threat Classification</h2>"
        $html += "    <table class='summary-table'>"
        # Suggested label (most important)
        if ($threat.suggested_threat_label) {
            $html += "      <tr><th>Suggested label</th><td>$([System.Web.HttpUtility]::HtmlEncode($threat.suggested_threat_label))</td></tr>"
        }
        # Threat categories (Trojan, Worm, etc.)
        if ($threat.popular_threat_category) {
            $cats = ($threat.popular_threat_category | ForEach-Object { $_.value }) -join ", "
            $html += "      <tr><th>Threat categories</th><td>$([System.Web.HttpUtility]::HtmlEncode($cats))</td></tr>"
        }
        # Threat families (Agent, Injector, etc.)
        if ($threat.popular_threat_family) {
            $families = ($threat.popular_threat_family | ForEach-Object { $_.value }) -join ", "
            $html += "      <tr><th>Threat families</th><td>$([System.Web.HttpUtility]::HtmlEncode($families))</td></tr>"
        }
        # Threat names (e.g., "Trojan.Generic", "W32.Agent")
        if ($threat.popular_threat_name) {
            $names = ($threat.popular_threat_name | ForEach-Object { $_.value }) -join ", "
            $html += "      <tr><th>Threat names</th><td>$([System.Web.HttpUtility]::HtmlEncode($names))</td></tr>"
        }

        $html += "    </table>"
    }


    # --- DETECTION SUMMARY ---
    $html += "    <h2>Antivirus Detection Summary</h2>"
    $html += "    <table class='summary-table'>"
    $html += "      <tr><th>Harmless</th><th>Malicious</th><th>Suspicious</th><th>Undetected</th><th>Timeout</th></tr>"
    $html += "      <tr>"
    $html += "        <td style='color: $colorHarmless; font-weight: bold;'>$($stats.harmless)</td>"
    $html += "        <td style='color: $colorMalicious; font-weight: bold;'>$($stats.malicious)</td>"
    $html += "        <td style='color: $colorSuspicious; font-weight: bold;'>$($stats.suspicious)</td>"
    $html += "        <td style='color: $colorUndetected; font-weight: bold;'>$($stats.undetected)</td>"
    $html += "        <td style='color: $colorTimeout; font-weight: bold;'>$($stats.timeout)</td>"
    $html += "      </tr>"
    $html += "    </table>"


    # --- VT LINKS ---
    $html += "    <h2>VirusTotal Links</h2>"
    $html += "    <table class='summary-table'>"
    $html += "      <tr><th>File page</th><td><a href='$vtFileUrl'>$vtFileUrl</a></td></tr>"
	$html += "      <tr><th>Details page</th><td><a href='$vtDetailsUrl'>$vtDetailsUrl</a></td></tr>"
    $html += "      <tr><th>Behavior page</th><td><a href='$vtBehaviorUrl'>$vtBehaviorUrl</a></td></tr>"
    $html += "      <tr><th>Relations page</th><td><a href='$vtRelationsUrl'>$vtRelationsUrl</a></td></tr>"
    $html += "    </table>"

    # --- FILE VERSION INFORMATION ---
    if ($fileAttr.pe_info -and $fileAttr.pe_info.resource_details) {

        # Extract version info from resource_details
        $versionInfo = $null

        foreach ($res in $fileAttr.pe_info.resource_details) {
            if ($res.file_version_info) {
                $versionInfo = $res.file_version_info
                break
            }
        }

        if ($versionInfo) {
            $html += "    <h2>File Version Information</h2>"
            $html += "    <table class='summary-table'>"

            foreach ($key in $versionInfo.Keys) {
                $value = $versionInfo[$key]
                if ($value) {
                    $html += "      <tr><th>$([System.Web.HttpUtility]::HtmlEncode($key))</th><td>$([System.Web.HttpUtility]::HtmlEncode($value))</td></tr>"
                }
            }

            $html += "    </table>"
        }
    }

    # --- PE INFO ---
    if ($fileAttr.pe_info) {
        $html += "    <h2>PE Information</h2>"
        $html += "    <table class='summary-table'>"
        $html += "      <tr><th>Entry point</th><td>$($fileAttr.pe_info.entry_point)</td></tr>"
        $html += "      <tr><th>Machine type</th><td>$($fileAttr.pe_info.machine_type)</td></tr>"
        $html += "      <tr><th>imphash</th><td>$($fileAttr.pe_info.imphash)</td></tr>"
        $html += "    </table>"

        if ($fileAttr.pe_info.sections) {
            $html += "    <h3>Sections</h3>"
            $html += "    <table class='engines-table'>"
            $html += "      <tr><th>Name</th><th>Size</th><th>Entropy</th></tr>"
            foreach ($s in $fileAttr.pe_info.sections) {
                $html += "      <tr><td>$($s.name)</td><td>$($s.size)</td><td>$($s.entropy)</td></tr>"
            }
            $html += "    </table>"
        }
    }

    $html += "    </table>"

    $html += "    <div class='footer'>Report generated on $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</div>"
    $html += "  </div>"
    $html += "</body>"
    $html += "</html>"

    $html -join "`r`n" | Out-File -FilePath $Path -Encoding UTF8
    Write-Host "HTML report written to: $Path" -ForegroundColor Green
}


# --- Main logic --------------------------------------------------------------

Write-Host "Submitting file to VirusTotal..." -ForegroundColor Cyan
$submitResponse = Submit-VTFile -FilePath $FilePath -ApiKey $ApiKey

if (-not $submitResponse) {
    Write-Error "File submission failed. Aborting."
    return
}

$analysisId = $submitResponse.data.id
Write-Host "Analysis ID: $analysisId" -ForegroundColor Cyan

$analysis = Wait-VTAnalysis -AnalysisId $analysisId -ApiKey $ApiKey

if (-not $analysis) {
    Write-Error "Could not retrieve completed analysis. Aborting."
    return
}

# The analysis object usually contains a reference to the file (sha256)
$fileId = $analysis.meta.file_info.sha256
if (-not $fileId) {
    # Fallback: try from submission response
    $fileId = $submitResponse.meta.file_info.sha256
}

if (-not $fileId) {
    Write-Warning "Could not determine file ID (SHA256). File report will be limited."
    $fileReport = $null
}
else {
    Write-Host "Retrieving detailed file report..." -ForegroundColor Cyan
    $fileReport = Get-VTFileReport -FileId $fileId -ApiKey $ApiKey
}

if (-not $fileReport) {
    Write-Warning "No detailed file report available. Using analysis data only for reports."
    # Build a minimal pseudo fileReport structure from analysis if needed
    $fileReport = @{
        data = @{
            attributes = @{
                meaningful_name      = [IO.Path]::GetFileName($FilePath)
                size                 = (Get-Item -LiteralPath $FilePath).Length
                type_description     = "Unknown"
                md5                  = ""
                sha1                 = ""
                sha256               = $fileId
                first_submission_date = ""
                last_submission_date  = ""
                last_analysis_date    = ""
            }
        }
    }
}

Write-Host "Generating the report..." -ForegroundColor Cyan
Write-HtmlReport -Path $htmlReportPath -Analysis $analysis -FileReport $fileReport -OriginalFilePath $FilePath

Write-Host "Done." -ForegroundColor Green
