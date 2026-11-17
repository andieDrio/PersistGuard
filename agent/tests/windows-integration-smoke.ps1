#Requires -Version 5.1
<#
.SYNOPSIS
  Read-only Windows agent integration smoke test (no enrollment or network writes).
.DESCRIPTION
  Runs Go unit tests, checks local agent configuration, and exercises the three
  Windows persistence collectors through the combined inventory command.
  Never prints inventory entries or credentials. Fails on malformed output.
#>
[CmdletBinding()]
param(
    [string]$AgentDirectory = (Split-Path -Parent $PSScriptRoot),
    [switch]$SkipGoTests
)

$ErrorActionPreference = 'Stop'
if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
    throw 'Windows agent smoke test must run on Windows.'
}
if (-not (Test-Path -LiteralPath (Join-Path $AgentDirectory 'go.mod'))) {
    throw 'AgentDirectory must contain agent/go.mod.'
}

Push-Location $AgentDirectory
try {
    if (-not $SkipGoTests) {
        Write-Host 'Checking Go agent tests...'
        & go test ./...
        if ($LASTEXITCODE -ne 0) { throw "Go tests failed with exit code $LASTEXITCODE." }
    }

    Write-Host 'Checking agent configuration validation...'
    $previousServer = [Environment]::GetEnvironmentVariable('PERSISTGUARD_AGENT_SERVER_URL', 'Process')
    try {
        [Environment]::SetEnvironmentVariable('PERSISTGUARD_AGENT_SERVER_URL', 'https://persistguard.example.test', 'Process')
        $configOutput = & go run . --check-config 2>&1
        if ($LASTEXITCODE -ne 0 -or (($configOutput -join ' ') -notmatch 'configuration is valid')) {
            throw 'Agent HTTPS configuration validation failed.'
        }
    } finally {
        [Environment]::SetEnvironmentVariable('PERSISTGUARD_AGENT_SERVER_URL', $previousServer, 'Process')
    }

    Write-Host 'Running read-only Windows persistence inventory...'
    $raw = & go run . --windows-inventory 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "Windows inventory command failed with exit code $LASTEXITCODE."
    }
    try {
        $report = ($raw -join "`n") | ConvertFrom-Json -ErrorAction Stop
    } catch {
        throw 'Windows inventory did not return valid JSON.'
    }
    if ($report.schema_version -ne 1 -or $report.os_family -ne 'windows') {
        throw 'Unexpected Windows inventory schema or OS family.'
    }
    if ($report.status -notin @('collected', 'partial', 'error')) {
        throw 'Unexpected aggregate inventory status.'
    }
    foreach ($source in @('registry', 'scheduled_tasks', 'services')) {
        $collector = $report.collectors.$source
        if ($null -eq $collector -or $collector.status -notin @('collected', 'partial', 'error')) {
            throw "Missing or invalid collector status: $source."
        }
        if ($collector.status -eq 'error' -and [string]::IsNullOrWhiteSpace($collector.error)) {
            throw "Collector $source reported an error without diagnostics."
        }
        if ($collector.status -ne 'error' -and $null -eq $collector.report) {
            throw "Collector $source omitted its report."
        }
        Write-Host ("{0}: {1}" -f $source, $collector.status)
        if ($source -eq 'services' -and $collector.status -eq 'partial') {
            $coverage = $collector.report.coverage
            $issues = @($coverage.issues | Where-Object { $null -ne $_ })
            $entryCount = @($collector.report.entries | Where-Object { $null -ne $_ }).Count
            Write-Host ("  services enumerated: {0}; coverage issues: {1}" -f $entryCount, $issues.Count)
            if ($issues.Count -eq 0) {
                throw 'Services reported partial coverage without issue diagnostics.'
            }
            foreach ($issue in $issues) {
                if ([string]::IsNullOrWhiteSpace($issue.operation) -or [string]::IsNullOrWhiteSpace($issue.code)) {
                    throw 'Services coverage issue is missing operation or code.'
                }
            }
            $groups = $issues | Group-Object -Property operation, code | Sort-Object -Property Name
            foreach ($group in $groups) {
                Write-Host ("  issue: {0}; count: {1}" -f $group.Name, $group.Count)
            }
            Write-Host '  NOTE: partial coverage is retained; no permissions are changed.'
        }
    }
    Write-Host ("Aggregate inventory status: {0}" -f $report.status)
    if ($report.status -eq 'error') {
        throw 'All collectors failed; inspect coverage locally without sharing sensitive inventory.'
    }
    Write-Host 'PASS: Windows agent local smoke test completed.'
} finally {
    Pop-Location
}
