# PersistGuard

Centralized, cross-platform persistence detection and threat hunting platform (early scaffold).

## Architecture
- Web dashboard: Next.js + TypeScript scan history and assessments
- Backend: FastAPI scaffold and initial PostgreSQL migration
- Endpoint agents: Go startup scaffold, Windows mTLS client, and read-only Registry, Scheduled Tasks, and Services collectors
- Detection: initial explainable heuristic scoring implemented in `backend/persistguard/detection.py`

## Run the agent locally

From the repository root in PowerShell, with Go 1.25 or newer installed:

```powershell
cd agent
go test ./...
$env:PERSISTGUARD_AGENT_SERVER_URL = 'https://persistguard.example.test'
go run . --check-config
go run .
```

Press `Ctrl+C` to stop the agent. The scaffold validates the HTTPS server URL
locally and waits for shutdown. Enrollment and server communication are planned.

### Generate a device CSR on Windows

Run these commands from `agent` under the Windows account that will run the
agent. The first run creates an ECDSA P-256 key protected by user-scoped Windows
DPAPI. Later runs reuse the key and write another PEM certificate signing
request to stdout. Keep the protected key under the agent account's profile.

```powershell
$agentState = Join-Path $env:LOCALAPPDATA 'PersistGuard'
New-Item -ItemType Directory -Path $agentState -Force | Out-Null
$deviceKey = Join-Path $agentState 'device-key.dpapi'
$csr = go run . --generate-csr --device-key $deviceKey
if ($LASTEXITCODE -ne 0) { throw 'CSR generation failed' }
$csr | Set-Content -Encoding ascii (Join-Path $agentState 'device.csr')
```

The CSR contains the public key and a signature. The enrollment server will
assign the endpoint identity when it issues the client certificate.

### Collect Windows startup inventory

From `agent`, run the collector as the Windows user whose startup configuration
you want to inspect. The command works locally without gateway configuration.

```powershell
$inventory = go run . --startup-inventory | ConvertFrom-Json
$inventory.coverage | Format-Table hive, key_path, registry_view, status, error
```

The JSON report lists `Run` and `RunOnce` entries for the process's current
user and the local machine, including both machine Registry views on 64-bit
Windows. It preserves `REG_SZ` and `REG_EXPAND_SZ` commands as text and reports
coverage for each location, including absent keys and partial reads. The report
stays local and can contain sensitive command-line data.

### Collect Windows Scheduled Tasks inventory

From `agent`, run the local collector under the Windows account whose Task
Scheduler access you want to inspect. It uses Windows PowerShell and the Task
Scheduler API to read visible task definitions, including hidden tasks the
account can access.

```powershell
$scheduled = go run . --scheduled-tasks-inventory | ConvertFrom-Json
$scheduled.coverage
$scheduled.entries | Select-Object path, state, enabled, hidden
```

The JSON report includes triggers, executable paths and arguments, and COM
handler IDs. Coverage reports partial reads and unavailable folders. Task
commands and arguments are returned as text in the local report.

### Collect Windows Services inventory

From `agent`, run the local collector under the Windows account whose service
access you want to inspect.

```powershell
$services = go run . --services-inventory | ConvertFrom-Json
$services.coverage
$services.entries | Select-Object name, state, start_type
```

The report includes the configured command line, service account, and startup
type for visible Win32 services. If a service is visible but its configuration
is inaccessible, the report retains its name and state and records the access
issue. Windows can omit services when the account cannot query their status.

To investigate a partial result, run the collector under the same Windows
account as the agent and group the reported issues by operation and code.

```powershell
$services.coverage.issues | Group-Object -Property operation, code | Select-Object Count, Name
```

A `query_config` issue with code `access_denied` means Windows denied access
to service configuration. The retained service entry can still provide its
name and state. Command-based assessment requires a readable command line.

### Collect all Windows inventories in one run

From `agent`, run the read-only collectors together. The command needs no
gateway configuration.

```powershell
$inventory = go run . --windows-inventory | ConvertFrom-Json
$inventory.status
$inventory.collectors.registry.status
$inventory.collectors.scheduled_tasks.status
$inventory.collectors.services.status
```

Each collector includes its original `report` when available. A collector that
cannot return a report includes an `error` and the other collectors continue.
Check the JSON `status` for `collected`, `partial`, or `error`. To use an
existing normalizer, save the corresponding nested report as JSON.

### Normalize Windows inventory into artifacts

Save any one local collector report as JSON. From `backend`, after installing
the backend dependencies, run the normalizer with the corresponding source
`registry`, `scheduled_tasks`, or `services`.

```powershell
python -m persistguard.normalize_inventory --source services 'C:\path\to\services.json'
```

The output has versioned `artifacts` and `coverage` arrays. Each artifact retains
its source mechanism and metadata. Registry views and value names are preserved
in metadata, and Scheduled Tasks retain all actions and triggers. Executable
and argument fields supplied separately by Task Scheduler stay separate; Registry
and service command lines remain raw text. This step runs locally and prepares
the data for detection without scoring it.

### Assess a normalized inventory

Save the normalized JSON to a file and run the assessment from `backend`.

```powershell
python -m persistguard.assess_inventory --endpoint-id local-test 'C:\path\to\normalized.json'
```

The result contains a score, verdict, and reasons for each artifact, plus the
original coverage report. It recognizes a directly observed PowerShell encoded
command option. Signature, baseline, write access, and hash signals require
independent evidence. An assessment with no signals has the `unknown` verdict.

Optional `--evidence` accepts a local JSON file with `report_sha256` from the
assessment output and an `artifacts` object keyed by zero-based artifact index.
Each entry accepts verified `signature_status`, `is_new`,
`user_writable_executable`, or `known_malicious_hash` fields. Use only evidence
you independently verified for that exact inventory.

## Run the backend locally

From the repository root:

```bash
cd backend
python -m pip install -r requirements.txt
python -m uvicorn persistguard.api:app
```

Open `http://127.0.0.1:8000/healthz` to check that the process is running.
Interactive API documentation is at `http://127.0.0.1:8000/docs`.

## Run the scan history dashboard

With Node.js 20.9 or newer, run these commands from `dashboard`.

```powershell
npm.cmd ci
npm.cmd run dev
```

Open `http://127.0.0.1:3000`. The dashboard opens with labeled sample data.
To view live scan history, start the backend with PostgreSQL and authentication
configured, select **Connect API**, and enter a linked account's access token.
The token stays in browser memory until disconnect or reload. Set the dashboard
server's `PERSISTGUARD_API_URL` before starting it if the backend uses a different
address than `http://127.0.0.1:8000`.

In a live session, admins and analysts can select **Queue scan**, find an
approved Windows endpoint by hostname, and queue its inventory job. Select a
queued scan to cancel it. Viewer accounts can browse scans and assessments.

Admins can also open **Endpoint onboarding** to create an invitation and copy
its token before closing the dialog. Use the token and organization ID in the
device registration flow below. Once the device appears under **Pending**,
approve it and download its client certificate PEM. Install the PEM on the
device alongside the existing DPAPI-protected key. Click **Refresh** after the
device registers if its request has not appeared yet.

## Verify API identity

Configure the trusted token issuer, a dedicated PersistGuard API audience, and
the issuer's RSA public key in PEM format. Set these before starting the server.

```powershell
$env:PERSISTGUARD_AUTH_ISSUER = 'https://identity.example.test/'
$env:PERSISTGUARD_AUTH_AUDIENCE = 'https://persistguard.example.test/api'
$env:PERSISTGUARD_AUTH_PUBLIC_KEY_FILE = 'C:\path\to\issuer-public.pem'
```

Apply the PostgreSQL migrations and set `PERSISTGUARD_DATABASE_URL` before
starting the API. To provision access, set `identity_issuer` and `identity_subject`
on the intended `users` row using the issuer and subject supplied by your
identity provider. The pair identifies one local user across organizations.
Both values must match exactly, and the user's organization must be active.

With an RS256 access token issued for that audience in `$env:PERSISTGUARD_ACCESS_TOKEN`,
call `GET /api/me` to return `subject`, `user_id`, and `organization_id`.
An invalid or missing token gets `401`. A valid token without an active local
account gets `403`.

```powershell
Invoke-RestMethod 'http://127.0.0.1:8000/api/me' -Headers @{Authorization = "Bearer $env:PERSISTGUARD_ACCESS_TOKEN"}
```

To test role-based access, call `GET /api/users` with a linked admin's token.
It lists users in that admin's organization. The database role determines access
on each request. Analyst and viewer accounts get `403`. Use `limit` (default 50,
maximum 100) and `offset` (default 0) to page through the results.

```powershell
Invoke-RestMethod 'http://127.0.0.1:8000/api/users?limit=10' -Headers @{Authorization = "Bearer $env:PERSISTGUARD_ACCESS_TOKEN"}
```

PostgreSQL records `users.list` audit events for linked accounts that receive a
`200` or `403`. Each event stores the actor ID, organization ID, status, and
timestamp. If the event cannot be saved, the API returns `503`. For an
append-only audit trail, use a non-owner API database role with `INSERT` on
`audit_events` and reserve read access for the audit role.

```sql
SELECT occurred_at, organization_id, actor_id, action, status_code
FROM audit_events
WHERE action = 'users.list'
ORDER BY occurred_at DESC
LIMIT 10;
```

## Apply the PostgreSQL migration

Create an empty PostgreSQL database and use a database role with permission to
create tables in its target schema. From `backend` after installing the backend
dependencies, set the connection URL and apply the migration in PowerShell.

```powershell
$env:PERSISTGUARD_DATABASE_URL = 'postgresql+psycopg://USER:PASSWORD@localhost:5432/persistguard'
python -m alembic upgrade head
python -m alembic current
```

To preview the migration SQL without connecting, run `python -m alembic upgrade head --sql`.

## Queue a Windows inventory scan

After applying the migrations, use an admin or analyst access token and the
ID of an approved Windows endpoint in that account's organization.

```powershell
$headers = @{Authorization = "Bearer $env:PERSISTGUARD_ACCESS_TOKEN"}
$job = Invoke-RestMethod -Method Post "http://127.0.0.1:8000/api/endpoints/$($device.endpoint_id)/scan-jobs" -Headers $headers
Invoke-RestMethod "http://127.0.0.1:8000/api/scan-jobs/$($job.id)" -Headers $headers
```

An empty request queues `persistence_full_scan`. To queue one collector, select
**Scan scope** in the dashboard or send JSON with `scan_type` set to
`persistence_registry_scan`, `persistence_scheduled_tasks_scan`, or
`persistence_services_scan`.

The API returns `201` for a new job, `200` for an unfinished job with the same
scope, and `409` if an unfinished job has a different scope. An older agent can
still poll for full scans. A targeted job stays queued until an agent that
supports targeted scans polls or an operator cancels it. Apply migration
`0016_targeted_scans` and upgrade the gateway before scheduling targeted scans.

### List or cancel queued scans

Linked users can list scans in their organization. The list supports `status`,
`limit`, and `offset` filters and shows newest jobs first. Admins and analysts
can cancel a queued job. Cancellation retries return the same canceled job.
Already dispatched jobs return `409` and continue through the agent flow.

```powershell
Invoke-RestMethod 'http://127.0.0.1:8000/api/scan-jobs?status=queued&limit=20' -Headers $headers
Invoke-RestMethod -Method Post "http://127.0.0.1:8000/api/scan-jobs/$($job.id)/cancel" -Headers $headers
```

## Issue an enrollment token

Apply the database migrations and use a linked admin's access token.
`POST /api/enrollment-tokens` returns the new token, its organization ID, and
its lifetime in seconds. The API uses the admin's own organization. Analyst and
viewer accounts get `403`. The response is the only time the new token is shown.

```powershell
$invitation = Invoke-RestMethod -Method Post 'http://127.0.0.1:8000/api/enrollment-tokens' -Headers @{Authorization = "Bearer $env:PERSISTGUARD_ACCESS_TOKEN"}
```

The new token expires after 15 minutes. PostgreSQL stores only its SHA-256 digest
and commits issuance together with an `enrollment_tokens.issue` audit event.

## Register a device

On Windows, the Go agent can generate or reuse its DPAPI-protected key and
submit the signed CSR in one command. Use the trusted TLS 1.3 address of the
enrollment API and the organization ID from the invitation. From `agent`:

```powershell
$agentState = Join-Path $env:LOCALAPPDATA 'PersistGuard'
New-Item -ItemType Directory -Path $agentState -Force | Out-Null
$deviceKey = Join-Path $agentState 'device-key.dpapi'
$organizationId = '00000000-0000-0000-0000-000000000000' # Replace with the invitation's organization ID.
$invitationSecret = Read-Host 'Enrollment token' -AsSecureString
try {
    $device = [Net.NetworkCredential]::new('', $invitationSecret).Password |
        go run . --enroll --enrollment-url 'https://enrollment.example.test' --organization-id $organizationId --device-key $deviceKey |
        ConvertFrom-Json
    if ($LASTEXITCODE -ne 0) { throw 'Device registration failed' }
    $device
} finally {
    $invitationSecret.Dispose()
}
```

For a private server CA, add `--server-ca` with its PEM bundle. The command
prints the pending endpoint ID. Approve that device and save its certificate
before connecting to the mTLS gateway.

### Register with PowerShell on loopback

For a local test, run the API on loopback and use the `$invitation` and
`$agentState` variables from the token and CSR examples. For remote enrollment,
use the API's trusted HTTPS address.

```powershell
$enrollment = @{
    organization_id = $invitation.organization_id
    hostname = $env:COMPUTERNAME
    os_family = 'windows'
    csr = Get-Content -Raw (Join-Path $agentState 'device.csr')
} | ConvertTo-Json
$device = Invoke-RestMethod -Method Post 'http://127.0.0.1:8000/api/agent/enroll' `
    -ContentType 'application/json' -Body $enrollment `
    -Headers @{Authorization = "Bearer $($invitation.token)"}
```

A successful request returns `201`, an `endpoint_id`, and `pending` status.
The API validates the signed ECDSA P-256 CSR, stores its public key, and consumes
the token in the same database transaction. An invalid or reused token returns
`401`, an invalid CSR returns `422`, and a key already registered in that
organization returns `409`. Failed registrations leave an unused token available.
Endpoint group scoping is planned.

## Approve a device certificate

Set `PERSISTGUARD_AGENT_CA_CERT_FILE` and `PERSISTGUARD_AGENT_CA_KEY_FILE` to
the PEM certificate and unencrypted signing key of a dedicated agent issuing
CA before starting the API. Restrict access to the key file to the API service
account. The integration test creates its own disposable CA.

Use a linked admin's access token and the pending endpoint's ID. Given the
registration response in `$device`, run this from PowerShell.

```powershell
$issued = Invoke-RestMethod -Method Put `
    "http://127.0.0.1:8000/api/endpoints/$($device.endpoint_id)/client-certificate" `
    -Headers @{Authorization = "Bearer $env:PERSISTGUARD_ACCESS_TOKEN"}
```

On first approval the API returns `201`, stores the issued certificate and
audit event, and sets the endpoint status to `approved`. An authorized retry
returns the same valid certificate with `200`. The certificate is valid for up
to 24 hours and uses the verified device public key. Agent certificate delivery
is manual at this stage.

### Revoke an endpoint

In **Endpoint onboarding → Approved**, choose **Revoke** for the endpoint and
confirm. An Admin can also call `POST /api/endpoints/{endpoint_id}/revoke`.
The endpoint moves to **Revoked**, the gateway rejects its device certificates,
and unfinished scans are canceled. Existing scan assessments remain available.
The action is audited and successful retries return the same revoked status.

## Run the mTLS gateway

Run the gateway separately from the admin and enrollment API. It serves
`GET /api/agent/identity` and `POST /api/agent/heartbeat` on `127.0.0.1:8443` by default. The TLS handshake
requires a client certificate from the configured agent CA. For every request,
the gateway checks that the exact certificate is registered in PostgreSQL,
unexpired and unrevoked, and belongs to an approved endpoint in an active organization.

After applying the backend migrations, grant a dedicated gateway database role
read access to the columns it uses and permission to update `last_seen`. For a
database using the `public` schema:

```sql
GRANT USAGE ON SCHEMA public TO persistguard_gateway;
GRANT SELECT (certificate_serial, endpoint_id, certificate_pem, expires_at, revoked_at)
    ON public.agent_credentials TO persistguard_gateway;
GRANT SELECT (id, organization_id, status, last_seen), UPDATE (last_seen)
    ON public.endpoints TO persistguard_gateway;
GRANT SELECT (id, status) ON public.organizations TO persistguard_gateway;
GRANT SELECT (id, endpoint_id, organization_id, scan_type, status, result, finished_at),
    UPDATE (status, result, finished_at)
    ON public.scan_jobs TO persistguard_gateway;
```

From `gateway` in PowerShell, set the PostgreSQL connection URL, agent CA PEM,
and the gateway's HTTPS server certificate and key. Use a server certificate
that matches the hostname agents will connect to.

```powershell
$env:PERSISTGUARD_GATEWAY_DATABASE_URL = 'postgresql://USER:PASSWORD@DBHOST:5432/persistguard?sslmode=verify-full'
$env:PERSISTGUARD_GATEWAY_AGENT_CA_FILE = 'C:\path\to\agent-ca.pem'
$env:PERSISTGUARD_GATEWAY_TLS_CERT_FILE = 'C:\path\to\gateway-cert.pem'
$env:PERSISTGUARD_GATEWAY_TLS_KEY_FILE = 'C:\path\to\gateway-key.pem'
go run .
```

Set `PERSISTGUARD_GATEWAY_LISTEN` to select a different address. A registered
device receives its `endpoint_id` and `organization_id`. Missing or untrusted
certificates fail the TLS handshake. Revoked or unregistered certificates
that pass TLS verification receive `403`.

To run the gateway integration test, set `PERSISTGUARD_GATEWAY_TEST_DATABASE_URL`
to a writable PostgreSQL URL for a migrated disposable database and run
`go test -v ./...` from `gateway`. Optionally set
`PERSISTGUARD_GATEWAY_TEST_READER_URL` to test the restricted gateway role too.

### Check the Windows agent's gateway identity

Save the issued certificate from `$issued` to the agent's state directory.
Run these commands from `agent` as the Windows account that generated the CSR.
Set the URL to the gateway's HTTPS address. For a private CA, pass a PEM trust
bundle for the gateway's server certificate. Omit `--server-ca` to use the
Windows trust store.

```powershell
$clientCert = Join-Path $agentState 'device-cert.pem'
$issued.certificate_pem | Set-Content -Encoding ascii $clientCert
$env:PERSISTGUARD_AGENT_SERVER_URL = 'https://gateway.example.test:8443'
go run . --check-identity --device-key $deviceKey --client-cert $clientCert --server-ca 'C:\path\to\gateway-server-ca.pem'
```

The command prints the assigned endpoint and organization IDs as JSON and
exits. A missing or mismatched device key causes the check to fail locally.

### Send a heartbeat

With the same gateway and device configuration, run:

```powershell
go run . --heartbeat --device-key $deviceKey --client-cert $clientCert --server-ca 'C:\path\to\gateway-server-ca.pem'
```

The gateway uses the verified client certificate to select the endpoint and
PostgreSQL supplies the UTC `last_seen` timestamp. The command prints the
endpoint ID, organization ID, and stored timestamp as JSON, then exits.

### Poll for an assigned inventory job

After queuing a scan, run this from `agent` with the assigned device's
certificate and the same gateway configuration as the heartbeat command.

```powershell
go run . --poll-job --device-key $deviceKey --client-cert $clientCert --server-ca $serverCA
```

The mTLS gateway selects the job using the authenticated endpoint. The command
prints the dispatched job or `null` if there is no job to dispatch. A retry
returns the same dispatched job. Polling reports the job and exits. Running the
inventory for that job and submitting the results are separate steps.

### Run and upload an assigned inventory job

Apply the latest migration and gateway database grants. Once a job is queued,
run this from `agent` using the enrolled device's credentials.

```powershell
go run . --run-inventory-job --device-key $deviceKey --client-cert $clientCert --server-ca $serverCA
```

The command polls once, runs the fixed read-only Windows collectors, and sends
the combined report over mTLS. It prints a receipt or `null` if there is no job.
The gateway accepts an identical retry and retains the first completion time.
If some collectors are incomplete it stores `partial`. If every collector fails
it stores `failed`. Complete collection stores `completed`.

To automatically process queued jobs while the Windows agent is running, use:

```powershell
go run . --watch-inventory-jobs --poll-interval 30s --device-key $deviceKey --client-cert $clientCert --server-ca $serverCA
```

Watch mode polls immediately, handles one assigned inventory job at a time,
and waits 30 seconds by default before the next poll. It retries after a gateway
or network error and prints JSON receipts for uploaded jobs. Press `Ctrl+C` to
stop the foreground agent.

Watch mode sends an authenticated heartbeat immediately and every 30 seconds
independently of scan polling. The dashboard refreshes endpoint health every
15 seconds. An approved endpoint is Connected if its heartbeat is at most two
minutes old. New Installed counts enrollments from the past 24 hours.

Watch mode also renews the device certificate when it enters the final quarter
of its lifetime, up to six hours before expiry. Configure the gateway and
signing API with the rotation secret and give the agent account write access
to the `--client-cert` file and its directory. The agent saves a pending PEM
next to the active file before confirming it, then activates it at the same
path. If interrupted, the next run resumes from the pending PEM. Keep that file
until the agent finishes renewal.

Use a linked user access token to read the report in the same organization.

```powershell
Invoke-RestMethod "http://127.0.0.1:8000/api/scan-jobs/$($job.id)/result" -Headers $headers
```

### Run watch mode as a Windows service

Build `persistguard-agent.exe` from `agent` with `go build -o persistguard-agent.exe .`.
Place the executable in a directory writable only by administrators. In an
elevated PowerShell session, set `$agentExe`, `$deviceKey`, `$clientCert`, and
`$serverCA` to the absolute paths for this installation. Set `$gatewayURL` to
the HTTPS URL of the mTLS gateway. Use a certificate and device key already
provisioned under the Windows account that will run the service. That same
account must have **Log on as a service**, access to the key and CA, and write
access to the certificate and its directory for renewal. User-scoped Registry
inventory reflects the service account's profile when its hive is available.

```powershell
$serviceLog = Join-Path (Split-Path -Parent $clientCert) 'agent-service.log'
$binary = '"{0}" --windows-service --watch-inventory-jobs --gateway-url "{1}" --device-key "{2}" --client-cert "{3}" --server-ca "{4}" --service-log "{5}"' -f $agentExe, $gatewayURL, $deviceKey, $clientCert, $serverCA, $serviceLog
New-Service -Name 'PersistGuardAgent' -DisplayName 'PersistGuard Agent' `
    -BinaryPathName $binary -Credential (Get-Credential) -StartupType Automatic
Start-Service -Name 'PersistGuardAgent'
Get-Service -Name 'PersistGuardAgent'
```

Omit `--server-ca` when the gateway CA is already trusted by the service
account. The optional `--service-log` appends job receipts and polling or
renewal errors to the given file. Restrict access to that directory. Queue an
inventory job from the dashboard and check for a receipt in the log to verify
gateway access. To stop the worker, run `Stop-Service -Name 'PersistGuardAgent'`
from elevated PowerShell.

To verify Services coverage under the deployment account, identify the running
service and its configured account on the endpoint.

```powershell
Get-CimInstance Win32_Service -Filter "Name = 'PersistGuardAgent'" | Select-Object Name, State, StartName
```

Use the service name from that installation. Queue a new inventory scan and
match its ID to the service log receipt. In **Scan history → Coverage**, check
the Windows Services collector status and issue codes for that scan. An
interactive collector run measures the access of the account running it.

### Operations workspace

Apply `alembic upgrade head` from `backend` for the Cases, IOCs, and detection rules tables. Connect
the dashboard with a linked account to see its tenant’s counts. Admins and analysts
can create cases, change their status, and add IP, domain, SHA-256, or URL indicators.
In **Rules and Detection**, admins can save a draft, run it against sample inventory,
and publish it after at least one sample matches. For a quick check, select Windows
Services and Command, enter `fixture-agent.exe` as the match text, and run the two
preloaded samples. The condition uses case-insensitive literal text. Editing an
active rule creates a draft while its published version continues scoring. Use
**History** to see published definitions. The active version contributes points to
matching artifacts when this tenant opens an assessment, including older scans.

See [XDRCapabilities.md](XDRCapabilities.md) for the capability baseline. Scored
Windows persistence findings include ATT&CK context for their inventory mechanism.
Open **Rules and Detection → ATT&CK Coverage** for the catalog, coverage filters,
and fixture evidence. Keep the baseline Markdown file at the repository root when
running the API. Coverage reflects product-level evidence in the repository.

Saved IP, domain, and HTTP(S) URL IOCs are checked against arguments captured by
the Windows collectors. A match adds 60 points once per artifact and lists the
matched indicators in its findings. Domain and IP checks use complete hosts,
including hosts in URLs. URL paths, queries, and fragments are case-sensitive.
Use a saved domain like `ioc.example.test` and a sample command with
`--host ioc.example.test`; `--host ioc.example.test.invalid` is a non-match.
SHA-256 IOCs match the digests collected by the Windows agent for local
executables referenced by Registry startup entries, Scheduled Task Exec actions,
and Windows Services. The agent reads regular `.exe`, `.com`, and `.sys` files
only when the executable path resolves directly to a local disk. It skips
inaccessible files, relative paths, and paths with reparse points. Collection is
limited to 64 MiB per file, 256 MiB and 512 candidate paths per collector, and a
10-second hashing window per collector. Hashes are optional, so older scans
remain readable. Install the updated agent and run a new scan to collect them.

### Assess a stored scan result

A linked user in the same organization can generate an assessment of the
stored inventory on demand.

```powershell
$assessment = Invoke-RestMethod "http://127.0.0.1:8000/api/scan-jobs/$($job.id)/assessment" -Headers $headers
$assessment.collectors.services.assessments
```

The response includes scan status, assessment status, and each collector's
scores, reasons, and coverage. A failed or invalid collector report is reported
alongside the results that could be assessed. The endpoint uses observed
signals from the uploaded report. It does not accept client-supplied signature,
hash, or other independent evidence.

The assessment selects the most recent earlier saved `completed` or `partial`
scan of a compatible scope for the same endpoint and organization. Full scans
compare with full scans. Targeted scans can compare with a full scan or one
of the same collector. Coverage for targeted scans shows the requested
collector. Each artifact reports a
`baseline_status` of `new`, `existing`, or `unknown`. Only comparable Registry
locations and fully collected Scheduled Tasks or Services reports contribute a
new-entry signal. HKCU stays `unknown` because the current reports do not
record the Windows user SID. The first scan has no baseline.

### Renew a device certificate

Run the gateway and signing API on the same host. Set the same randomly
generated `PERSISTGUARD_ROTATION_SECRET` (64 lowercase hex characters) in
both processes. The gateway calls the signing API on loopback port `8000`.
Set `PERSISTGUARD_ROTATION_PORT` on the gateway if the signing API uses another
port. Keep this route private at any public API reverse proxy. The signing key
stays with the API.

Before the old certificate expires, request a replacement, save it to a
separate file, and verify it through the gateway. In the example, `$serverCA`
is the PEM trust bundle for the gateway's HTTPS certificate.

```powershell
$replacement = Join-Path $agentState ('device-cert-' + [guid]::NewGuid().ToString('N') + '.pem')
$pem = go run . --renew-certificate --device-key $deviceKey --client-cert $clientCert --server-ca $serverCA
if ($LASTEXITCODE -ne 0) { throw 'Certificate renewal failed' }
$pem | Set-Content -Encoding ascii $replacement
go run . --check-identity --device-key $deviceKey --client-cert $replacement --server-ca $serverCA
if ($LASTEXITCODE -ne 0) { throw 'Replacement certificate check failed' }
go run . --confirm-certificate --device-key $deviceKey --client-cert $replacement --server-ca $serverCA
if ($LASTEXITCODE -ne 0) { throw 'Certificate confirmation failed' }
$clientCert = $replacement
```

Both certificates can authenticate until the device confirms with the new
certificate or the old one expires. Retrying an interrupted renewal returns
the same pending replacement. Use the new certificate for subsequent agent
commands once confirmed. Renewal reuses the existing DPAPI-protected key.
Downgrading to revision `0006_agent_credentials` retires overlapping
predecessors and keeps the latest credential available.

## Run current tests
```bash
cd backend
python -m pip install -r requirements-dev.txt
python -m unittest discover -s tests -v
```

To include the database integration tests, including enrollment tokens, apply the
migrations to a disposable PostgreSQL database, then run these commands from
`backend` in PowerShell. The tests clean up their records.

```powershell
$env:PERSISTGUARD_TEST_DATABASE_URL = $env:PERSISTGUARD_DATABASE_URL
python -m unittest discover -s tests -v
python -m alembic check
```

### Run dashboard browser tests

```bash
cd dashboard
npm ci
npx playwright install chromium
npm run test:e2e
```

The suite starts a production dashboard on loopback port 3416 and a fixture
API on port 3415. It checks desktop and mobile footer boundaries, Admin
revocation and rule rollback through the dashboard proxy, and role-based
controls for Analyst and Viewer. The dashboard verification job runs the
same suite in GitHub Actions.

**Status:** PersistGuard supports Windows agent enrollment, manual inventory scans and uploads, and a local dashboard for scan history, assessment, and coverage. Do not use for production security decisions.
