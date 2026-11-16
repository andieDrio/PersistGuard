#Requires -Version 5.1
[CmdletBinding(DefaultParameterSetName = 'Upgrade')]
param(
    [Parameter(Mandatory, ParameterSetName = 'Upgrade')]
    [string]$CandidatePath,

    [Parameter(Mandatory, ParameterSetName = 'Upgrade')]
    [ValidatePattern('\A[0-9A-Fa-f]{40}\z')]
    [string]$SigningCertificateThumbprint,

    [Parameter(Mandatory, ParameterSetName = 'Rollback')]
    [string]$RollbackFrom
)

$ErrorActionPreference = 'Stop'
if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
    throw 'Windows service updates require Windows.'
}

$serviceName = 'PersistGuardAgent'
$config = Get-CimInstance Win32_Service -Filter "Name = '$serviceName'"
if ($config.PathName -notmatch '^\s*(?:"([^"]+)"|([^\s"]+))(?=\s|$)') {
    throw 'Could not read the installed PersistGuardAgent executable path.'
}
$installed = if ($Matches[1]) { $Matches[1] } else { $Matches[2] }
if ($installed -notmatch '^[A-Za-z]:[\\/]' -or [IO.Path]::GetExtension($installed) -ine '.exe') {
    throw 'The service must use an absolute local executable path. Quote the path if it contains spaces.'
}
$installed = [IO.Path]::GetFullPath($installed)
$directory = [IO.Path]::GetDirectoryName($installed)
$service = Get-Service -Name $serviceName
$timeout = [TimeSpan]::FromSeconds(30)

function Stop-AgentService {
    $service.Refresh()
    if ($service.Status -eq 'Stopped') { return }
    if ($service.Status -ne 'StopPending') { Stop-Service -InputObject $service -NoWait }
    $service.WaitForStatus('Stopped', $timeout)
}

function Start-AgentService {
    $service.Refresh()
    if ($service.Status -eq 'Running') { return }
    if ($service.Status -eq 'StopPending') { $service.WaitForStatus('Stopped', $timeout) }
    if ($service.Status -ne 'StartPending') { $service.Start() }
    $service.WaitForStatus('Running', $timeout)
    $service.Refresh()
    if ($service.Status -ne 'Running') { throw 'The service exited during startup.' }
}

$lockPath = Join-Path $directory '.persistguard-agent-update.lock'
try {
    $lock = [IO.FileStream]::new($lockPath, [IO.FileMode]::CreateNew, [IO.FileAccess]::ReadWrite,
        [IO.FileShare]::None, 4096, [IO.FileOptions]::DeleteOnClose)
} catch [IO.IOException] {
    throw "Could not acquire the PersistGuardAgent update lock in '$directory'. Check for another update in progress. $($_.Exception.Message)"
}

$id = [guid]::NewGuid().ToString('N')
$staged = Join-Path $directory ".persistguard-agent-stage-$id.exe"
$backup = Join-Path $directory "persistguard-agent-backup-$id.exe"
try {
    $existing = Get-Item -LiteralPath $installed
    if ($existing.PSIsContainer -or ($existing.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw 'The registered service executable must be a regular file.'
    }

    $isUpgrade = $PSCmdlet.ParameterSetName -eq 'Upgrade'
    $inputPath = if ($isUpgrade) { $CandidatePath } else { $RollbackFrom }
    $source = Get-Item -LiteralPath $inputPath
    if ($source.PSIsContainer -or $source -isnot [IO.FileInfo]) { throw 'Provide a Windows executable file.' }
    if (-not $isUpgrade -and ([IO.Path]::GetFullPath($source.DirectoryName) -ine $directory -or
            $source.Name -notmatch '\Apersistguard-agent-backup-[0-9a-f]{32}\.exe\z' -or
            ($source.Attributes -band [IO.FileAttributes]::ReparsePoint))) {
        throw 'For rollback, use a backup executable created by this script in the service installation directory.'
    }

    [IO.File]::Copy($source.FullName, $staged)
    if ($isUpgrade) {
        $signature = Get-AuthenticodeSignature -LiteralPath $staged
        if ($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Thumbprint -ine $SigningCertificateThumbprint -or
                -not $signature.TimeStamperCertificate) {
            throw 'The upgrade executable must have a valid, timestamped Authenticode signature from the expected signer.'
        }
    }

    $service.Refresh()
    if ($service.Status -notin @('Running', 'Stopped')) { throw 'Wait for the service to be Running or Stopped before updating.' }
    $wasRunning = $service.Status -eq 'Running'
    try {
        if ($wasRunning) { Stop-AgentService }
        [IO.File]::Replace($staged, $installed, $backup)
        if ($wasRunning) { Start-AgentService }
    } catch {
        $updateError = $_.Exception.Message
        try {
            if ([IO.File]::Exists($backup)) {
                Stop-AgentService
                if ([IO.File]::Exists($installed)) {
                    [IO.File]::Replace($backup, $installed, [NullString]::Value)
                } else {
                    [IO.File]::Move($backup, $installed)
                }
            }
            if (-not [IO.File]::Exists($installed)) { throw 'The service executable is missing.' }
            if ($wasRunning) { Start-AgentService }
        } catch {
            throw "Service update failed ($updateError). Automatic recovery failed ($($_.Exception.Message)). Check '$installed' and the backup, if present, at '$backup'."
        }
        throw "Service update failed ($updateError). The previous executable and service state were restored."
    }

    [PSCustomObject]@{ Service = $serviceName; ExecutablePath = $installed; BackupPath = $backup; Status = $service.Status }
} finally {
    try { [IO.File]::Delete($staged) } finally { $lock.Dispose() }
}
