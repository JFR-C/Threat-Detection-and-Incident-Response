param(
    [Parameter(Mandatory=$true)][string]$TargetHost,
    [Parameter(Mandatory=$true)][string]$OutputRoot,   # Local path on collector, e.g. D:\IR\Collections
    [Parameter(Mandatory=$false)][string]$CredUser,    # DOMAIN\User or .\LocalUser
    [Parameter(Mandatory=$false)][securestring]$CredPassword
)

if (-not (Test-Path $OutputRoot)) {
    New-Item -ItemType Directory -Path $OutputRoot | Out-Null
}

$sessionOptions = @{}
if ($CredUser -and $CredPassword) {
    $cred = New-Object System.Management.Automation.PSCredential($CredUser, $CredPassword)
    $sessionOptions.Credential = $cred
}

$session = New-PSSession -ComputerName $TargetHost @sessionOptions

$remoteScript = {
    param($RemoteStaging)

    $logRoot = "$env:SystemRoot\System32\winevt\Logs"
    $regHives = @(
        "$env:SystemRoot\System32\config\SAM",
        "$env:SystemRoot\System32\config\SECURITY",
        "$env:SystemRoot\System32\config\SYSTEM",
        "$env:SystemRoot\System32\config\SOFTWARE"
    )

    if (-not (Test-Path $RemoteStaging)) {
        New-Item -ItemType Directory -Path $RemoteStaging | Out-Null
    }

    $destLogs = Join-Path $RemoteStaging "winevt_logs"
    $destReg  = Join-Path $RemoteStaging "registry_hives"

    New-Item -ItemType Directory -Path $destLogs,$destReg -ErrorAction SilentlyContinue | Out-Null

    # Copy EVTX logs
    Copy-Item -Path (Join-Path $logRoot "*.evtx") -Destination $destLogs -ErrorAction SilentlyContinue

    # Copy key registry hives (for timeline/context)
    foreach ($h in $regHives) {
        if (Test-Path $h) {
            Copy-Item -Path $h -Destination $destReg -ErrorAction SilentlyContinue
        }
    }

    # Optional: export key event logs via wevtutil (for consistency)
    $exportDir = Join-Path $RemoteStaging "wevtutil_exports"
    New-Item -ItemType Directory -Path $exportDir -ErrorAction SilentlyContinue | Out-Null

    $coreLogs = @("System","Application","Security","Setup")
    foreach ($logName in $coreLogs) {
        $outFile = Join-Path $exportDir "$($logName).evtx"
        wevtutil epl $logName $outFile /ow:true
    }

    # Compress everything into a single archive on the remote host
    $archivePath = Join-Path $RemoteStaging "windows_logs_$(Get-Date -Format 'yyyyMMdd_HHmmss').zip"
    Compress-Archive -Path (Join-Path $RemoteStaging "*") -DestinationPath $archivePath -Force

    # Compute hash for integrity
    $hash = Get-FileHash -Path $archivePath -Algorithm SHA256
    $hash | Out-File -FilePath ($archivePath + ".sha256.txt")

    return $archivePath
}

$remoteStaging = "C:\IR_Staging"
$archivePath = Invoke-Command -Session $session -ScriptBlock $remoteScript -ArgumentList $remoteStaging

# Pull archive + hash back to collector
$remoteUNC = "\\$TargetHost\" + ($archivePath -replace ":", "$")
$remoteHashUNC = $remoteUNC + ".sha256.txt"

$localDir = Join-Path $OutputRoot $TargetHost
if (-not (Test-Path $localDir)) {
    New-Item -ItemType Directory -Path $localDir | Out-Null
}

Copy-Item -Path $remoteUNC -Destination $localDir
Copy-Item -Path $remoteHashUNC -Destination $localDir

Write-Host "Collected archive: $(Join-Path $localDir (Split-Path $archivePath -Leaf))"
Write-Host "Hash file:        $(Join-Path $localDir ((Split-Path $archivePath -Leaf) + '.sha256.txt'))"

Remove-PSSession $session
