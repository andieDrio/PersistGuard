# Windows Agent Integration Verification

This runbook separates **local collector smoke tests** from **end-to-end deployment tests**. A passing local test does not prove that enrollment, mTLS, heartbeat, or remote scan delivery works.

## Prerequisites

- Work on `main` only; do not reset, force-push, or create feature branches.
- Windows test endpoint with Go installed, PowerShell 5.1+, and access to its own persistence configuration.
- For end-to-end testing: a separately configured FastAPI backend, migrated PostgreSQL, a TLS-enabled gateway, an agent CA, a provisioned admin account, and a test-only enrollment invitation.
- Use an authorized, non-production test endpoint. Do not paste enrollment tokens, private keys, access tokens, certificate PEMs, or full inventory reports into tickets or chats.
- No dashboard layout, sidebar, top navigation, or footer modifications are part of this test.

## Stage 1: local Windows collector smoke test

From the repository root:

```powershell
git status -sb
git pull --ff-only origin main
& .\agent\tests\windows-integration-smoke.ps1
```

The script runs `go test ./...`, checks HTTPS agent configuration, and invokes `go run . --windows-inventory`. It validates JSON schema, aggregate status, and Registry, Scheduled Tasks, and Services collector results. Partial coverage is reported, not silently treated as complete. This stage performs no enrollment or network writes.

Expected terminal message: `PASS: Windows agent local smoke test completed.`

If a collector reports `partial`, inspect the corresponding coverage locally before declaring full visibility. Never change endpoint persistence settings to make a test pass.

## Stage 2: enrollment and approval (manual, test environment)

1. Start the configured backend and gateway with valid TLS trust and a migrated test database.
2. In **Endpoint onboarding**, generate a **single-use** invitation for the intended organization. Keep the token private.
3. On the Windows endpoint, run the agent's `--enroll` flow with the HTTPS enrollment URL, organization ID, DPAPI device-key path, and trusted server CA. Provide the invitation through standard input, not a command-line argument.
4. Confirm the endpoint appears as **Pending** in the correct tenant. Approve it as an authorized admin and install the issued client certificate PEM beside the existing DPAPI-protected device key.
5. Verify replay of the invitation is rejected. Do not share the token in test output.

See the repository README for the complete device enrollment command syntax and environment configuration.

## Stage 3: authenticated gateway operations

Using the enrolled agent and its configured `--gateway-url`, `--device-key`, `--client-cert`, and `--server-ca`:

1. Run `--check-identity` and confirm the returned endpoint/organization identifiers match the approved record.
2. Run `--heartbeat` and verify `last_seen` advances for that endpoint only.
3. Queue a persistence scan for the approved endpoint from the dashboard.
4. Run `--run-inventory-job` (or `--watch-inventory-jobs` for ongoing polling), then verify the scan reaches a terminal status and its collector coverage is visible.
5. Check that registry, scheduled-task, and service findings are attributable to the correct endpoint. A clean endpoint may legitimately produce no suspicious findings.
6. Repeat with a second tenant or endpoint to verify no cross-tenant scan job or findings leakage.
7. In a disposable test environment, revoke a test device credential and verify identity, heartbeat, poll, and result submission are rejected.

**Never revoke a production device credential for this test.** Keep endpoint collectors read-only; no arbitrary remote shell or remediation.

## Evidence and acceptance

Record only sanitized metadata: test date, test endpoint alias, agent version, organization alias, scan-job ID, collector status, heartbeat result, expected vs actual behavior, and any redacted error. Do not publish raw commands, persistence entries, certificates, or credentials.

Acceptance criteria:
- Local smoke test passes; any partial coverage is documented.
- Enrollment is single-use and pending approval is enforced.
- Approved mTLS identity and heartbeat succeed; unapproved/revoked credentials fail.
- A queued scan is picked up and its result/coverage is stored against the correct endpoint.
- Tenant isolation and retry/idempotency are verified.
- Dashboard layout remains unchanged.

Automated gateway integration tests may skip database-dependent cases when `PERSISTGUARD_GATEWAY_TEST_DATABASE_URL` is absent. A skipped test is **not** a pass for end-to-end integration.
