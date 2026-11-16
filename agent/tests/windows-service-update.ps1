#Requires -Version 5.1
$ErrorActionPreference = 'Stop'

function Assert-Equal($Actual, $Expected, $Message) {
    if ($Actual -cne $Expected) { throw "$Message (expected '$Expected', got '$Actual')." }
}

function Assert-Rejected([scriptblock]$Operation, [string]$MessagePattern) {
    try { & $Operation | Out-Null } catch {
        if ($_.Exception.Message -like $MessagePattern) { return }
        throw
    }
    throw "Expected failure matching '$MessagePattern'."
}

$root = Join-Path $env:TEMP ('PersistGuard update fixture ' + [guid]::NewGuid().ToString('N'))
[IO.Directory]::CreateDirectory($root) | Out-Null
$installed = Join-Path $root 'persistguard-agent.exe'
$candidate = Join-Path $root 'candidate.exe'
$key = Join-Path $root 'device-key.dpapi'
$certificate = Join-Path $root 'client.pem'
$thumbprint = 'A' * 40
$updater = Join-Path $PSScriptRoot '../update-windows-service.ps1'
$commandLine = '"{0}" --windows-service --watch-inventory-jobs --device-key "{1}" --client-cert "{2}"' -f $installed, $key, $certificate

# Use real Windows file operations with a disposable service-controller fixture.
$fixture = [PSCustomObject]@{
    Status = 'Running'; Starts = 0; Stops = 0; FailNextStart = $false
    ExitAfterNextStart = $false; ExitOnRefresh = $false
}
$fixture | Add-Member ScriptMethod Refresh {
    if ($this.ExitOnRefresh) {
        $this.ExitOnRefresh = $false
        $this.Status = 'Stopped'
    }
}
$fixture | Add-Member ScriptMethod Start {
    $this.Starts++
    if ($this.FailNextStart) {
        $this.FailNextStart = $false
        throw 'Simulated service startup failure.'
    }
    $this.Status = 'Running'
    $this.ExitOnRefresh = $this.ExitAfterNextStart
    $this.ExitAfterNextStart = $false
}
$fixture | Add-Member ScriptMethod WaitForStatus {
    param($Status, $Timeout)
    if ($this.Status -ne $Status) { throw "Fixture failed to reach $Status within $Timeout." }
}
function Get-CimInstance($ClassName, $Filter) {
    Assert-Equal $ClassName 'Win32_Service' 'Unexpected CIM class'
    Assert-Equal $Filter "Name = 'PersistGuardAgent'" 'Unexpected CIM service filter'
    [PSCustomObject]@{ PathName = $commandLine }
}
function Get-Service($Name) {
    Assert-Equal $Name 'PersistGuardAgent' 'Unexpected service name'
    $fixture
}
function Stop-Service($InputObject, [switch]$NoWait) {
    Assert-Equal $NoWait.IsPresent $true 'The service stop must use a bounded wait'
    $InputObject.Stops++
    $InputObject.Status = 'Stopped'
}
$signature = $null
function Get-AuthenticodeSignature($LiteralPath) {
    if ($null -eq $signature) {
        return Microsoft.PowerShell.Security\Get-AuthenticodeSignature -LiteralPath $LiteralPath
    }
    Assert-Equal ([IO.Path]::GetDirectoryName($LiteralPath)) $root 'Verify the staged file in the service directory'
    Assert-Equal ([IO.File]::ReadAllText($LiteralPath)) 'candidate' 'Verify the exact bytes to be installed'
    $signature
}

try {
    [IO.File]::WriteAllText($installed, 'previous')
    [IO.File]::WriteAllText($candidate, 'candidate')
    [IO.File]::WriteAllText($key, 'key fixture')
    [IO.File]::WriteAllText($certificate, 'certificate fixture')
    $upgrade = { & $updater -CandidatePath $candidate -SigningCertificateThumbprint $thumbprint }

    Assert-Rejected $upgrade '*must have a valid, timestamped Authenticode signature*'
    $signature = [PSCustomObject]@{ Status = 'Valid'; SignerCertificate = @{ Thumbprint = 'B' * 40 }; TimeStamperCertificate = $true }
    Assert-Rejected $upgrade '*expected signer*'
    $signature.SignerCertificate.Thumbprint = $thumbprint
    $signature.TimeStamperCertificate = $null
    Assert-Rejected $upgrade '*timestamped Authenticode signature*'
    $signature.TimeStamperCertificate = $true
    Assert-Equal $fixture.Stops 0 'Reject unauthenticated candidates before stopping the service'
    Assert-Equal ([IO.File]::ReadAllText($installed)) 'previous' 'Preserve the binary after rejection'

    $lockPath = Join-Path $root '.persistguard-agent-update.lock'
    $competingLock = [IO.FileStream]::new($lockPath, [IO.FileMode]::CreateNew, [IO.FileAccess]::ReadWrite,
        [IO.FileShare]::None, 4096, [IO.FileOptions]::DeleteOnClose)
    try { Assert-Rejected $upgrade '*could not acquire*update lock*' } finally { $competingLock.Dispose() }

    $upgraded = & $upgrade
    Assert-Equal $upgraded.ExecutablePath $installed 'Keep the registered executable path'
    Assert-Equal $upgraded.Status 'Running' 'Restart a running service after upgrade'
    Assert-Equal ([IO.File]::ReadAllText($installed)) 'candidate' 'Install the candidate'
    Assert-Equal ([IO.File]::ReadAllText($upgraded.BackupPath)) 'previous' 'Retain the previous binary'

    Assert-Rejected { & $updater -RollbackFrom $candidate } '*backup executable created by this script*'
    $rolledBack = & $updater -RollbackFrom $upgraded.BackupPath
    Assert-Equal $rolledBack.Status 'Running' 'Restart a running service after manual rollback'
    Assert-Equal ([IO.File]::ReadAllText($installed)) 'previous' 'Restore the previous binary'
    Assert-Equal ([IO.File]::ReadAllText($rolledBack.BackupPath)) 'candidate' 'Retain the binary replaced by rollback'

    $fixture.FailNextStart = $true
    Assert-Rejected $upgrade '*Simulated service startup failure*previous executable and service state were restored*'
    Assert-Equal $fixture.Status 'Running' 'Restart the previous binary after failure'
    Assert-Equal ([IO.File]::ReadAllText($installed)) 'previous' 'Restore the binary after a failed restart'

    $fixture.ExitAfterNextStart = $true
    Assert-Rejected $upgrade '*service exited during startup*previous executable and service state were restored*'
    Assert-Equal $fixture.Status 'Running' 'Restart the previous binary after immediate exit'
    Assert-Equal ([IO.File]::ReadAllText($installed)) 'previous' 'Restore the binary after immediate exit'

    $fixture.Status = 'Stopped'
    $starts = $fixture.Starts
    $stops = $fixture.Stops
    $offline = & $upgrade
    Assert-Equal $offline.Status 'Stopped' 'Preserve the stopped service state'
    Assert-Equal $fixture.Starts $starts 'Do not start a stopped service'
    Assert-Equal $fixture.Stops $stops 'Do not stop a stopped service'
    Assert-Equal ([IO.File]::ReadAllText($installed)) 'candidate' 'Update a stopped service binary'
    Assert-Equal ([IO.File]::ReadAllText($key)) 'key fixture' 'Keep the DPAPI key file intact'
    Assert-Equal ([IO.File]::ReadAllText($certificate)) 'certificate fixture' 'Keep the client certificate intact'
    if (Get-ChildItem -LiteralPath $root -Force | Where-Object { $_.Name -like '.persistguard-agent-*' }) {
        throw 'An update leaked a staging file or lock.'
    }
    'Verified signature rejection, exclusive update, upgrade, manual rollback, restart recovery, and stopped-service update.'
} finally {
    Get-ChildItem -LiteralPath $root -File -Force | ForEach-Object { [IO.File]::Delete($_.FullName) }
    [IO.Directory]::Delete($root)
}
