# Windows production signing and rollout

## Release inputs

- [ ] Record the exact source commit or release tag, version, successful GitHub Actions run, and rollout window. Use a clean checkout of that source for signing.
- [ ] Select an enrolled Windows x64 canary and record its endpoint ID, current service state, and baseline full scan result. Assign an operator to verify the canary and perform rollback if needed.
- [ ] Identify the production code-signing certificate, its expected thumbprint, and the signing provider's RFC 3161 timestamp URL. Confirm that the signing identity can use the private key from `Cert:\CurrentUser\My` on the signing workstation. Use the certificate trust chain approved for production endpoints.
- [ ] Prepare a rollback record for each endpoint with its prior executable SHA-256 and the backup path returned by the updater.

The MAT staging exercise verified a signed upgrade and rollback with a temporary staging signer. A full inventory completed before the upgrade, after the upgrade, and after rollback. The rollback restored the original SHA-256. Production signing and production endpoint trust still require verification with the intended certificate. [MAT compatibility PR](https://github.com/andieDrio/PersistGuard/pull/4) · [Post-merge CI](https://github.com/andieDrio/PersistGuard/actions/runs/43821855984)

## Sign and stage the package

- [ ] In Visual Studio Developer PowerShell on the Windows signing workstation, use Go as specified in `agent/go.mod` and confirm `signtool.exe` is available. From the release checkout, set `$version`, `$releaseOutput`, `$signerThumbprint`, and `$timestampUrl` to the recorded release values, then run the build.

```powershell
go -C agent test ./...
if ($LASTEXITCODE -ne 0) { throw 'Windows agent tests failed.' }

$release = ./agent/build-windows-release.ps1 -Version $version `
    -OutputDirectory $releaseOutput -SigningCertificateThumbprint $signerThumbprint `
    -TimestampUrl $timestampUrl
$release.FullName
```

- [ ] Confirm the output includes `persistguard-agent-$version-windows-amd64.zip` and `SHA256SUMS.txt`. The build signs the executable using SHA-256, applies an RFC 3161 timestamp, and packages it after SignTool verification succeeds. [Microsoft SignTool documentation](https://learn.microsoft.com/windows/win32/seccrypto/signtool)
- [ ] Stage `agent/update-windows-service.ps1` separately from the same source revision. Record its SHA-256 and the ZIP SHA-256 in the release record. Distribute the package, checksum manifest, and updater through the approved deployment channel. Supply the expected signer thumbprint and release hashes from the release record.

```powershell
Get-Content -LiteralPath (Join-Path $release.FullName 'SHA256SUMS.txt')
Get-FileHash -LiteralPath .\agent\update-windows-service.ps1 -Algorithm SHA256
```

## Verify on the endpoint

- [ ] On an enrolled staging endpoint representative of production trust policy, set `$packageDir` to the directory containing the ZIP and manifest, `$extractDir` to a new extraction directory, and `$updater` to the staged PowerShell script. Set `$version`, `$expectedSigner`, `$expectedZipHash`, and `$expectedUpdaterHash` from the release record.
- [ ] Run the package and updater checks in Administrator PowerShell. Use these same checks on the canary before applying the upgrade. [Microsoft Get-AuthenticodeSignature documentation](https://learn.microsoft.com/powershell/module/microsoft.powershell.security/get-authenticodesignature)

```powershell
$ErrorActionPreference = 'Stop'
$zipName = "persistguard-agent-$version-windows-amd64.zip"
$zip = Join-Path $packageDir $zipName
$manifest = Join-Path $packageDir 'SHA256SUMS.txt'
$zipHash = (Get-FileHash -LiteralPath $zip -Algorithm SHA256).Hash.ToLowerInvariant()
if ($zipHash -ine $expectedZipHash -or (Get-Content -LiteralPath $manifest -Raw).Trim() -cne "$zipHash  $zipName") {
    throw 'ZIP checksum verification failed.'
}
if ((Get-FileHash -LiteralPath $updater -Algorithm SHA256).Hash -ine $expectedUpdaterHash) {
    throw 'Updater checksum verification failed.'
}

Expand-Archive -LiteralPath $zip -DestinationPath $extractDir
$candidate = Join-Path $extractDir 'persistguard-agent.exe'
$signature = Get-AuthenticodeSignature -LiteralPath $candidate
if ($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Thumbprint -ine $expectedSigner -or
        -not $signature.TimeStamperCertificate) {
    throw 'Expected a valid, timestamped Authenticode signature from the production signer.'
}
$installedCandidateVersion = & $candidate --version
if ($LASTEXITCODE -ne 0 -or $installedCandidateVersion -cne $version) {
    throw 'The executable version does not match the release.'
}
$candidateHash = (Get-FileHash -LiteralPath $candidate -Algorithm SHA256).Hash
```

- [ ] Run the upgrade, heartbeat and scan checks, and rollback below on that staging endpoint using the production-signed package. Record the signature verdict, signer thumbprint, resulting version, and rollback hash before promoting the same package to the production canary.

## Roll out the control plane and canary

- [ ] If the target environment predates targeted scans, apply the PostgreSQL migrations for the release. Confirm `0016_targeted_scans` is applied before the new backend and gateway serve targeted jobs. Verify gateway mTLS and full inventory uploads from an existing agent before enabling the dashboard's targeted scopes. Deploy the dashboard for the same release. [PostgreSQL migrations](../README.md#apply-the-postgresql-migration)
- [ ] Before each agent upgrade, verify the intended endpoint is approved and recently connected, let any active scan finish, and confirm that the service is `Running`. Run a full baseline scan under the service account. Keep the scan ID and collector coverage for comparison. Set `$currentAgentPath` to the executable from the service's registered `ImagePath`.
- [ ] Record the original SHA-256, then apply the verified candidate. Verify the backed-up and installed bytes and save the backup path and original SHA-256 for rollback.

```powershell
$originalSHA256 = (Get-FileHash -LiteralPath $currentAgentPath -Algorithm SHA256).Hash
$originalSHA256
$update = & $updater -CandidatePath $candidate -SigningCertificateThumbprint $expectedSigner
$backupPath = $update.BackupPath
$updatedAt = [DateTimeOffset]::Now
if ($update.Status -ne 'Running' -or
        (Get-FileHash -LiteralPath $backupPath -Algorithm SHA256).Hash -ine $originalSHA256 -or
        (Get-FileHash -LiteralPath $update.ExecutablePath -Algorithm SHA256).Hash -ine $candidateHash) {
    throw 'Service state, backup hash, or installed binary verification failed.'
}
$update | Format-List
$updatedAt
```

- [ ] Check that endpoint last seen advances past the recorded upgrade time and the dashboard reports `Connected`. A pre-upgrade heartbeat can keep the endpoint listed as connected for up to two minutes. [Agent heartbeat behavior](../README.md#run-and-upload-an-assigned-inventory-job)
- [ ] Queue a new full scan and confirm a matching upload receipt and assessment. Compare Registry, Scheduled Tasks, and Services coverage with the baseline. Check any new `Partial` or `Failed` result before continuing. If targeted scopes are in the rollout, queue each intended scope and verify that its result and assessment contain the selected collector.
- [ ] Continue in groups when the canary passes. Keep the rollback record through validation of each group. Pause the next group if the service fails, the fresh heartbeat is missing, or scan coverage regresses unexpectedly.

## Roll back the agent

- [ ] If the updater reports successful automatic recovery, use `Get-Service` and `Get-FileHash -LiteralPath $currentAgentPath -Algorithm SHA256` to confirm `Running` and the original SHA-256. Then check the heartbeat and full scan as described below.
- [ ] If verification fails after a successful upgrade, restore the affected endpoint using its saved `$backupPath` and `$originalSHA256`.

```powershell
$rollback = & $updater -RollbackFrom $backupPath
$restoredSHA256 = (Get-FileHash -LiteralPath $rollback.ExecutablePath -Algorithm SHA256).Hash
$rolledBackAt = [DateTimeOffset]::Now
if ($rollback.Status -ne 'Running' -or $restoredSHA256 -ine $originalSHA256) {
    throw 'Restored service or binary verification failed.'
}
$rollback | Format-List
$restoredSHA256
$rolledBackAt
```

- [ ] Verify an authenticated heartbeat after the rollback time, then queue a full scan and match its receipt and coverage against the baseline. Record the restored hash and scan ID. An older agent may leave a targeted job queued. Inspect the endpoint's Scan history and cancel an incompatible unfinished job before queueing the full scan.
- [ ] Keep the schema migration applied during agent rollback. Downgrading `0016_targeted_scans` requires archiving and removing targeted scan rows first. [Migration](../backend/migrations/versions/0016_targeted_scans.py)
