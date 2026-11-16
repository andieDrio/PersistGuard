#Requires -Version 5.1
[CmdletBinding(DefaultParameterSetName = 'Signed')]
param(
    [Parameter(Mandatory)]
    [ValidatePattern('\Av(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z]+([.-][0-9A-Za-z]+)*)?\z')]
    [string]$Version,

    [Parameter(Mandatory)]
    [string]$OutputDirectory,

    [Parameter(Mandatory, ParameterSetName = 'Unsigned')]
    [switch]$Unsigned,

    [Parameter(Mandatory, ParameterSetName = 'Signed')]
    [ValidatePattern('\A[0-9A-Fa-f]{40}\z')]
    [string]$SigningCertificateThumbprint,

    [Parameter(Mandatory, ParameterSetName = 'Signed')]
    [ValidateScript({ $_.IsAbsoluteUri -and $_.Scheme -in @('http', 'https') -and $_.Host -and -not $_.UserInfo })]
    [uri]$TimestampUrl
)

$ErrorActionPreference = 'Stop'
if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
    throw 'Build the Windows release from a Windows PowerShell session.'
}

$name = "persistguard-agent-$Version-windows-amd64"
if ($PSCmdlet.ParameterSetName -eq 'Unsigned') {
    if (-not $Unsigned) { throw 'Pass -Unsigned to build an unsigned test package.' }
    $name += '-unsigned'
} else {
    $certificate = Get-Item -LiteralPath "Cert:\CurrentUser\My\$SigningCertificateThumbprint"
    if (-not $certificate.HasPrivateKey) { throw 'The signing certificate needs an accessible private key.' }
    $signTool = (Get-Command signtool.exe -CommandType Application).Source
}

$output = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputDirectory)
$release = Join-Path $output $name
if (Test-Path -LiteralPath $release) { throw "Release directory already exists: $release" }

$staging = Join-Path $output ('.persistguard-build-' + [guid]::NewGuid().ToString('N'))
$executable = Join-Path $staging 'persistguard-agent.exe'
$zipName = "$name.zip"
$archive = Join-Path $staging $zipName
$checksums = Join-Path $staging 'SHA256SUMS.txt'
$buildEnvironment = @{ GOOS = 'windows'; GOARCH = 'amd64'; GOAMD64 = 'v1'; CGO_ENABLED = '0' }
$previousEnvironment = @{}
[IO.Directory]::CreateDirectory($staging) | Out-Null
try {
    foreach ($variable in $buildEnvironment.Keys) {
        $previousEnvironment[$variable] = [Environment]::GetEnvironmentVariable($variable)
        [Environment]::SetEnvironmentVariable($variable, $buildEnvironment[$variable])
    }
    & go -C $PSScriptRoot build -mod=readonly -trimpath -ldflags "-X main.agentVersion=$Version" -o $executable . | Out-Host
    if ($LASTEXITCODE -ne 0) { throw "Windows agent build failed (exit $LASTEXITCODE)." }

    if ($PSCmdlet.ParameterSetName -eq 'Signed') {
        & $signTool sign /s My /sha1 $SigningCertificateThumbprint /fd SHA256 /tr $TimestampUrl.AbsoluteUri /td SHA256 $executable | Out-Host
        if ($LASTEXITCODE -ne 0) { throw "Authenticode signing failed (exit $LASTEXITCODE)." }
        & $signTool verify /pa /tw $executable | Out-Host
        if ($LASTEXITCODE -ne 0) { throw "Authenticode signature or timestamp verification failed (exit $LASTEXITCODE)." }
    }

    Add-Type -AssemblyName System.IO.Compression, System.IO.Compression.FileSystem
    $zip = [IO.Compression.ZipFile]::Open($archive, [IO.Compression.ZipArchiveMode]::Create)
    try {
        [IO.Compression.ZipFileExtensions]::CreateEntryFromFile($zip, $executable, 'persistguard-agent.exe') | Out-Null
    } finally {
        $zip.Dispose()
    }
    $hash = (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant()
    "$hash  $zipName" | Set-Content -LiteralPath $checksums -Encoding Ascii
    [IO.File]::Delete($executable)
    [IO.Directory]::Move($staging, $release)
    Get-Item -LiteralPath $release
} finally {
    foreach ($variable in $previousEnvironment.Keys) {
        [Environment]::SetEnvironmentVariable($variable, $previousEnvironment[$variable])
    }
    if ([IO.Directory]::Exists($staging)) {
        [IO.File]::Delete($executable)
        [IO.File]::Delete($archive)
        [IO.File]::Delete($checksums)
        [IO.Directory]::Delete($staging)
    }
}
