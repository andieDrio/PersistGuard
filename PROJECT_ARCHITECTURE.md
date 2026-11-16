# **PersistGuard — Centralized Security Dashboard**

Technical Architecture v1.0 | Multi-Endpoint Malware Persistence Detection Platform

> **Project scope:** PersistGuard is a new, standalone project developed from scratch. This architecture does not depend on or migrate code, folders, configuration, or history from any previous local project. The canonical repository is `andieDrio/PersistGuard`, using the existing `main` branch only.

## Loop Instruction for Project Updates

This file owns system design, data flows, authorization, and implementation order.
Use the complementary baselines when planning and verifying changes.

- Capability requirements and validation criteria. [XDRCapabilities.md](XDRCapabilities.md)
- GUI interaction, accessibility, layout, and verification standards. [Standard_UIUX.md](Standard_UIUX.md)

1. Start with this architecture. Identify the affected component, data flow,
   tenant boundary, allowed roles, and implementation milestone.
2. Consult the capability baseline for the relevant use case. Confirm the telemetry,
   detection rule, and evidence needed to validate it. Read the GUI baseline before
   each GUI update and identify the applicable standards.
3. Implement through the existing architecture. If the update needs an architectural
   change, document the decision here before implementing it.
4. Test through the normal entry point. Verify positive and negative cases, and
   check role and tenant boundaries for tenant-scoped features.
5. Update this architecture when an implementation decision changes. Update the
   baseline when capability requirements change and the GUI guide when GUI standards
   change. Record verified detection
   evidence in the coverage matrix and use the remaining gaps to choose the next priority.
   Return to step 1 for the next update.

Para sa centralized version ng PersistGuard, irerekomenda ko ang **agent-based, zero-trust architecture**. Mag-i-install ka ng lightweight agent sa bawat Windows, macOS, at Linux endpoint, habang ang isang central web dashboard ang magko-control ng scanning, searching, detection, investigation, at reporting.

Ang pinakaimportanteng design decision: **ang endpoint agent ang nagbabasa ng OS artifacts, hindi ang browser o central backend nang direkta.** Ito ang mas secure, mas reliable, at mas madaling i-scale.

## **1. Target System Architecture**

**Centralized Web Dashboard**

Next.js • TypeScript • RBAC • Scan Management • Threat Hunting

HTTPS + Session Authentication

Central Backend — FastAPI

Auth & RBAC

Endpoint Manager

Scan Orchestrator

Search API

Detection Engine

Report Service

PostgreSQL

Assets, scans, findings

Redis / Queue

Jobs and processing

Object Storage

Evidence and reports

Agent Gateway • TLS 1.3 + mTLS • Outbound Connections

Windows

Go Agent

Registry, Tasks, Services, WMI

macOS

Go Agent

Launch Services, Login Items

Linux

Go Agent

systemd, cron, autostart

Ang agents ay **outbound-only**: sila ang kumokonekta sa Agent Gateway sa port 443 para mag-check ng pending jobs at mag-upload ng findings. Hindi kailangang buksan ang inbound remote administration ports ng endpoints.

Para sa MVP, isang backend deployment at worker pool muna. Huwag agad gumamit ng Kubernetes o microservices kung hindi pa kailangan.

## **2. Endpoint Enrollment Architecture**

Ang enrollment ang proseso ng secure registration ng bagong computer sa PersistGuard.

1. **Admin creates enrollment invitation**

   Gumagawa ang server ng short-lived, single-use enrollment token na naka-scope sa organization at endpoint group.
2. **Install endpoint agent**

   Admin installs the signed Go agent using MSI/EXE sa Windows, PKG sa macOS, o DEB/RPM sa Linux.
3. **Agent generates its own private key**

   Gumagawa ang agent ng device-specific key pair. Hindi dapat lumabas sa endpoint ang private key.
4. **Agent submits enrollment request**

   Isinusumite nito ang token, public key, agent version, at minimal device metadata sa HTTPS enrollment endpoint.
5. **Server validates and approves identity**

   Vine-verify ang token, organization scope, approval policy, at device identity. Nag-i-issue ang server ng short-lived client certificate.
6. **Agent establishes mTLS session**

   Lahat ng susunod na agent communications ay authenticated at encrypted. May certificate rotation at revocation support.

### **Enrollment security controls**

- Store only a cryptographic hash of enrollment tokens in the database.
- Limit token lifetime, uses, and permitted endpoint groups.
- Require admin approval for high-security environments.
- Protect private keys with OS-native facilities such as Windows CNG/DPAPI, macOS Keychain, or appropriate Linux key storage.
- Support certificate renewal, endpoint revocation, and re-enrollment.
- Do not rely on hostname, MAC address, or IP address as proof of device identity.

Ang enrollment token ay para lamang sa bootstrap. **Hindi ito permanent authentication credential.**

## **3. Agent and Server Communication**

Irerekomenda ko ang **HTTPS polling muna**, kaysa full-time WebSocket connection, para simple at compatible sa corporate networks.

| Operation           | Direction      | Purpose                        |
| ------------------- | -------------- | ------------------------------ |
| Enrollment          | Agent → Server | Register identity              |
| Heartbeat           | Agent → Server | Health and status              |
| Poll jobs           | Agent → Server | Retrieve assigned scans        |
| Upload results      | Agent → Server | Submit findings                |
| Rule updates        | Agent → Server | Fetch signed detection bundles |
| Certificate renewal | Agent → Server | Rotate credentials             |

Sample flow:

```
Admin clicks "Scan 50 Endpoints"
             |
             v
Backend creates 50 scan jobs
             |
             v
Agents poll for assigned jobs
             |
             v
Each agent validates job scope
             |
             v
Collectors run locally (read-only)
             |
             v
Results are batched and uploaded
             |
             v
Detection workers analyze findings
             |
             v
Dashboard updates scan progress
```

Ang server ay hindi dapat makapagpadala ng arbitrary shell commands. Gumamit ng allowlisted job types, halimbawa `persistence_full_scan`, `persistence_targeted_scan`, at `inventory_refresh`.

Maglagay ng maximum job runtime, output size limits, retry with backoff, at idempotency keys para hindi madoble ang processing kapag may network interruption.

# **4. Database Design**

**PostgreSQL** ang primary database. Sa centralized platform, mahalagang paghiwalayin ang endpoints, scan jobs, collected artifacts, detections, at investigation records.

## **Entity Relationship Diagram**

### **Core Tables**

| Table                  | Important fields                                               |
| ---------------------- | -------------------------------------------------------------- |
| `organizations`        | id, name, status                                               |
| `users`                | id, organization_id, email, role_id                            |
| `endpoints`            | id, organization_id, hostname, os, agent_version, last_seen    |
| `agent_credentials`    | endpoint_id, certificate_serial, expires_at, revoked_at        |
| `enrollment_tokens`    | token_hash, organization_id, expires_at, used_at               |
| `scan_jobs`            | id, endpoint_id, scan_type, status, created_at                 |
| `scan_runs`            | id, job_id, started_at, finished_at, collection_status         |
| `artifacts`            | id, endpoint_id, scan_run_id, mechanism, path, command, sha256 |
| `findings`             | id, artifact_id, severity, score, confidence, status           |
| `detection_rules`      | id, rule_version, platform, enabled                            |
| `finding_rule_matches` | finding_id, rule_id, evidence                                  |
| `cases`                | id, organization_id, title, status                            |
| `case_findings`        | case_id, scan_job_id, source, artifact_index, evidence, attached_at |
| `coverage_validations` | organization_id, use_case_id, result, tested_on, reference, recorded_by |
| `audit_events`         | actor_id, action, target_id, timestamp                         |

**Important:** Lahat ng tenant-owned records ay dapat may organization scope, directly or through enforced parent relationships. Gumamit ng database constraints, scoped queries, at optional PostgreSQL Row-Level Security para maiwasan ang cross-organization data leakage.

The ATT&CK Coverage Matrix stores tenant deployment test records with their
outcome, test date, reference, recorder, and audit event. The catalog identifies
each use case by its group code and technique ID. Deployment records remain
separate from product fixture evidence and product coverage classifications.

Admin and analyst users attach scored findings from **Scan History** to an existing
case. The backend verifies the current server assessment and stores a snapshot
with the source scan ID, score, reasons, and ATT&CK context. Composite foreign
keys enforce that both records belong to the same tenant. **Cases → Evidence**
shows the saved snapshot even when a later assessment changes.

### **Example SQL Schema**

```

CREATE TABLE organizations (
    id UUID PRIMARY KEY,
    name TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE endpoints (
    id UUID PRIMARY KEY,
    organization_id UUID NOT NULL
        REFERENCES organizations(id),
    hostname TEXT NOT NULL,
    os_family TEXT NOT NULL,
    os_version TEXT,
    agent_version TEXT,
    status TEXT NOT NULL DEFAULT 'pending',
    last_seen TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (id, organization_id)
);

CREATE TABLE scan_jobs (
    id UUID PRIMARY KEY,
    organization_id UUID NOT NULL,
    endpoint_id UUID NOT NULL,
    scan_type TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'queued',
    requested_by UUID,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    FOREIGN KEY (endpoint_id, organization_id)
        REFERENCES endpoints(id, organization_id)
);

CREATE TABLE artifacts (
    id UUID PRIMARY KEY,
    organization_id UUID NOT NULL,
    endpoint_id UUID NOT NULL,
    scan_run_id UUID NOT NULL,
    mechanism TEXT NOT NULL,
    artifact_path TEXT NOT NULL,
    executable_path TEXT,
    sha256 CHAR(64),
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    collected_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE findings (
    id UUID PRIMARY KEY,
    organization_id UUID NOT NULL,
    artifact_id UUID NOT NULL REFERENCES artifacts(id),
    severity TEXT NOT NULL CHECK (
        severity IN ('critical','high','medium','low','info')
    ),
    risk_score SMALLINT NOT NULL
        CHECK (risk_score BETWEEN 0 AND 100),
    confidence TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'open',
    detected_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_endpoints_org
    ON endpoints(organization_id);

CREATE INDEX idx_jobs_endpoint_status
    ON scan_jobs(endpoint_id, status);

CREATE INDEX idx_artifacts_endpoint
    ON artifacts(endpoint_id, collected_at DESC);

CREATE INDEX idx_findings_org_severity
    ON findings(organization_id, severity);

```

Ito ay starter schema lamang. Bago production, idagdag ang missing foreign keys para sa `scan_runs`, tenant-consistency constraints sa artifacts/findings, unique job execution identifiers, at migration management gamit ang Alembic.

# **5. Security Architecture**

Dahil centralized ang platform at may endpoint access, kailangan mong protektahan hindi lang ang dashboard kundi pati ang agents laban sa unauthorized commands at server compromise.

**Security Boundaries**

User Identity

SSO/OIDC, MFA, RBAC

Agent Identity

mTLS certificates, revocation

Job Authorization

Allowlisted jobs, scope validation

Data Protection

Tenant isolation, encryption

Auditability

Immutable-style event history

Supply Chain

Signed agents and rule bundles

## **Role-Based Access Control**

PersistGuard has three application roles. Apply the permissions below within
the user's authorized organization. GUI presentation follows the GUI baseline.

| Permission             | Admin | Analyst | Viewer |
| ---------------------- | ----- | ------- | ------ |
| View endpoints         | ✓     | ✓       | ✓      |
| View findings          | ✓     | ✓       | ✓      |
| Start scans            | ✓     | ✓       | —      |
| Attach findings and update cases | ✓ | ✓ | — |
| Enroll endpoints       | ✓     | —       | —      |
| Revoke approved endpoints | ✓ | — | — |
| View detection rules and version history | ✓ | ✓ | ✓ |
| View deployment validation evidence | ✓ | ✓ | ✓ |
| Record deployment validation evidence | ✓ | ✓ | — |
| Create, test, publish, import, or export detection rules | ✓ | — | — |
| Manage users           | ✓     | —       | —      |

Magkaroon din ng endpoint group permissions para halimbawa, ang analyst ng Finance department ay hindi automatic na makakapag-scan ng HR computers.

Revocation applies to an approved endpoint in the administrator's organization.
The API locks the endpoint row and commits the revoked status, credential
revocations, cancellation of unfinished scans, and audit event in one transaction.
Completed scan evidence remains available. The gateway denies the endpoint's
certificates, and repeated requests return the existing revoked status.

### **Endpoint hardening**

Iminumungkahi ko ang mga sumusunod na controls:

- Run the agent as an OS-managed service with the minimum necessary privileges.
- Separate privileged artifact collection from network communication where practical.
- Verify signed scan jobs and rule updates before execution.
- Never deserialize untrusted data into executable code.
- Prevent symlink/path traversal attacks when collecting file metadata.
- Apply CPU, memory, execution-time, and upload-size limits.
- Encrypt sensitive stored evidence, and redact secrets from collected command lines or configuration values.
- Maintain an append-only audit trail with restricted deletion permissions and external backup.

Kung makompromiso ang central server, dapat limitado pa rin ang puwedeng ipagawa nito sa endpoints. Kaya mahalaga ang fixed scan operations at hindi generic command execution.

# **6. Detection Engine Architecture**

Ang detection pipeline ay dapat may apat na magkahiwalay na stages.

Collection

Enrichment

Detection

Risk Scoring

**Collection:** Kunin ang persistence entries gamit ang OS-specific collectors.

**Enrichment:** Kunin ang file hash, digital signature status, process association, file owner, creation/modification timestamps, at baseline history.

**Detection:** I-match sa custom rules, threat intelligence, at behavioral indicators.

**Risk Scoring:** I-compute ang severity at confidence, at ilagay ang explanation sa findings.

Halimbawa, ang isang unsigned executable sa `C:\ProgramData` ay hindi awtomatikong malicious. Pero kung bagong registry autostart entry ito, gumagamit ng obfuscated PowerShell, at may confirmed malicious hash match, magiging mas mataas ang risk.

## **Suggested Detection Rule Format**

```

id: PG-WIN-001
title: Suspicious Registry Autostart
platform: windows
category: persistence

conditions:
  mechanism: registry_run_key
  executable_path:
    location: user_writable
  signature_status:
    - unsigned
    - invalid

risk:
  base_score: 45
  confidence: medium

mitre:
  tactic: persistence
  technique: T1547.001

response:
  action: alert_only

```

Mas mainam na gumawa ng typed, validated rule schema kaysa direktang mag-execute ng YAML expressions o user-supplied scripts.

The current YAML import profile uses the fields supported by the Windows rule
editor. Use **Rules and Detection → Import YAML** to validate it and create an
unpublished draft. The existing sample test and publication flow applies to
imported drafts. The broader rule format above describes target capabilities.

```yaml
schema_version: 1
title: Fixture service command
platform: windows
conditions:
  source: services
  field: command
  contains: fixture-agent.exe
risk:
  base_score: 40
response:
  action: alert_only
```

The source accepts `registry`, `scheduled_tasks`, or `services`. The field accepts
`path` or `command`, and `contains` uses a case-insensitive literal comparison.
Each import accepts one YAML document of up to 16 KiB.
Admins can export the saved draft and individual published versions as YAML.
Exported files contain the definition. Importing an export starts a new draft
with its own rule identity and sample-test workflow.

# **7. Centralized Scan Scheduling**

Dapat suportahan ang tatlong scan modes:

| Mode              | Trigger                  | Purpose                          |
| ----------------- | ------------------------ | -------------------------------- |
| Full Scan         | Manual / scheduled       | Comprehensive enumeration        |
| Targeted Scan     | Manual search            | Specific paths, keys, mechanisms |
| Differential Scan | Scheduled / event-driven | Changes since last baseline      |

## **Suggested Scan Lifecycle**

```
QUEUED
   |
   v
DISPATCHED
   |
   v
ACKNOWLEDGED
   |
   v
RUNNING
   |
   v
UPLOADING
   |
   v
ANALYZING
   |
   +----> COMPLETED
   |
   +----> PARTIAL
   |
   +----> FAILED
```

Ang `PARTIAL` status ay mahalaga. Halimbawa, kung hindi mabasa ng Linux agent ang isang protected system directory, dapat ipakita iyon bilang coverage gap at hindi bilang clean scan.

Para sa malaking fleet, gumamit ng concurrency limits per organization at endpoint group. Huwag sabay-sabay magpatakbo ng resource-intensive full scans sa libo-libong machines.

# **8. Implementation Steps**

Ito ang recommended order ng development.

Sprint 1

Backend Foundation

Create FastAPI project and PostgreSQL migrations

Implement organizations, users, and endpoint models

Add authentication and RBAC

Build audit logging middleware

Sprint 2

Agent Enrollment

Create Go agent service skeleton

Implement single-use enrollment tokens

Add device key generation and mTLS

Implement heartbeat and credential rotation

Sprint 3

Windows Persistence Collection

Implement Registry Run/RunOnce collector

Implement Scheduled Tasks and Services collectors

Normalize artifacts into common schema

Build collection errors and coverage reporting

Sprint 4

Scan Orchestration

Implement job queue and polling

Add full and targeted scan APIs

Implement result upload and deduplication

Build scan status and retry handling

Sprint 5

Detection and Dashboard

Build YAML rule validator and engine

Implement explainable severity scoring

Create five severity cards and findings table

The Findings view uses the existing tenant-scoped scan assessment pipeline.
Cards and table results cover the displayed batch of scans. Newer and Older scans
move between batches while findings are paginated within the selected batch.
The scan ID on each finding opens that scan and its exact collector evidence
through tenant-scoped lookups, including scans outside the loaded history page.

Add search, filtering, and investigation view

Sprint 6

Cross-Platform and Hardening

Add macOS and Linux collectors

Implement differential scanning

Add signing, tests, and telemetry

Run security and performance validation

## **9. Recommended MVP Acceptance Criteria**

Windows scan requests select either full inventory or one collector (Registry,
Scheduled Tasks, or Services). The requested scope is stored in `scan_type`.
The gateway dispatches collector-specific jobs only to agents that advertise
targeted scan support on poll and accepts results for the stored scope. A
targeted job queued for an older agent can be canceled or run after upgrade.
Full scans use full scans as baselines. Targeted scans use the latest eligible
full scan or a scan of the same collector. Unrequested collectors are omitted
from the assessment.

Bago mo tawaging working MVP ang PersistGuard, dapat pumasa ito sa sumusunod:

- Isang administrator ang makakapag-enroll at makakapag-revoke ng endpoint.
- Makakapag-scan ng hindi bababa sa isang Windows machine nang walang arbitrary remote command execution.
- Maipapakita ang scan progress, failed collectors, at completed findings.
- May manual search sa collected artifacts at targeted live scan.
- Lahat ng suspicious findings ay may severity, explanation, at supporting evidence.
- Hindi makakakita ng ibang organization's data ang isang tenant.
- Secure ang communication gamit ang TLS at authenticated agent credentials.
- May automated tests para sa known benign at suspicious persistence examples.

### Windows endpoint acceptance evidence

| Check | Result on 2026-11-15 |
| --- | --- |
| Enrollment and identity | A Windows agent enrolled over TLS using a DPAPI-protected key. Admin approval, mTLS identity, and heartbeat succeeded against a local test stack. |
| Scan and assessment | The job progressed from queued to dispatched to partial. The assessment included 8 Registry, 198 Scheduled Task, and 310 Windows Service artifacts. Windows denied `SERVICE_QUERY_CONFIG` for one visible service under the test account. The collector retained its name and state and reported partial coverage. A local rerun reproduced the denial at `OpenService`. |
| Collector failure reporting | The PostgreSQL-backed gateway test stored a partial scan with a Scheduled Tasks collector error. |
| Authorization and isolation | The Viewer was denied enrollment-token issuance and scan creation. An Admin from a second tenant could not approve the test endpoint or read its scan or assessment. |
| Revocation | An Admin revoked the fixture through the dashboard. The open scan was canceled, the earlier assessment remained available, one audit event was recorded, and the gateway returned HTTP 403 for the revoked device. |

These results document inventory collection and access control on one Windows
host. The scan produced no scored detections. Technique-level detection
validation requires evidence from a matching artifact.

On 2026-11-16, the MAT Windows test VM ran `PersistGuardAgent` as
`NT AUTHORITY\LocalService` and uploaded scan `ebb2958a-2125-4b51-953e-cad8d3c85a38`
with status `completed`. All three collectors reported `collected`: 2 Registry
entries, 183 Scheduled Tasks, and 271 visible Windows Services. The Services
collector reported zero issues. Coverage reflects the services visible to
that account on MAT.

A manually triggered certificate renewal on MAT ran as `LocalService` while
`PersistGuardAgent` was running. The gateway accepted the replacement and
rejected the predecessor with HTTP 403. PostgreSQL recorded the renewal and
confirmation audit events, and the service completed follow-up scan
`124113a2-f224-4d51-b994-a6071b6b00bf`.

The normal service polling loop also renewed a same-key test certificate
already inside its renewal window, without advancing the guest clock or
calling the manual renewal command. The agent activated the replacement,
the gateway retired the test predecessor, and PostgreSQL recorded both
audit events. The service completed follow-up scan
`8049dd74-e65b-4b68-81d8-e40dde2892fb`, and the test script restored the original gateway. The
fixture started inside the window, so this check covered the renewal path
when due.

On 2026-11-16, a separate loopback Windows test exercised all three targeted
scopes with the rebuilt agent. Registry and Scheduled Tasks finished as
`completed`; Services finished as `partial`. Each upload and assessment
contained only the requested collector.

## **10. Recommended Starting Configuration**

Initial Deployment Profile

| Deployment  | Single private server / VM |
| ----------- | -------------------------- |
| Dashboard   | Next.js                    |
| API         | FastAPI                    |
| Database    | PostgreSQL                 |
| Queue       | Redis + workers            |
| Agent       | Go, Windows-first          |
| Transport   | HTTPS / mTLS               |
| Remediation | Disabled; detection-only   |

**Ang irerekomenda kong unang functional milestone:** Makapag-enroll ng tatlong Windows endpoints, makapag-trigger ng scan mula sa dashboard, at makapag-display ng actual Registry, Scheduled Task, at Service persistence findings na may severity classification.

Kapag stable na iyon, saka idagdag ang Linux/macOS collectors, real-time monitoring, at advanced threat intelligence.

Sa ganitong architecture, ang PersistGuard ay hindi lang simpleng malware scanner. Magiging foundation ito ng isang **centralized endpoint persistence monitoring at threat hunting platform** na puwedeng palawakin sa enterprise environments.
