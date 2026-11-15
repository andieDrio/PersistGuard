# **PersistGuard — Centralized Security Dashboard**

Technical Architecture v1.0 | Multi-Endpoint Malware Persistence Detection Platform

> **Project scope:** PersistGuard is a new, standalone project developed from scratch. This architecture does not depend on or migrate code, folders, configuration, or history from any previous local project. The canonical repository is `andieDrio/PersistGuard`, using the existing `main` branch only.

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
| `audit_events`         | actor_id, action, target_id, timestamp                         |

**Important:** Lahat ng tenant-owned records ay dapat may organization scope, directly or through enforced parent relationships. Gumamit ng database constraints, scoped queries, at optional PostgreSQL Row-Level Security para maiwasan ang cross-organization data leakage.

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

| Permission             | Admin | Analyst | Viewer |
| ---------------------- | ----- | ------- | ------ |
| View endpoints         | ✓     | ✓       | ✓      |
| View findings          | ✓     | ✓       | ✓      |
| Start scans            | ✓     | ✓       | —      |
| Investigate findings   | ✓     | ✓       | —      |
| Enroll endpoints       | ✓     | —       | —      |
| Modify detection rules | ✓     | —       | —      |
| Manage users           | ✓     | —       | —      |

Magkaroon din ng endpoint group permissions para halimbawa, ang analyst ng Finance department ay hindi automatic na makakapag-scan ng HR computers.

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

Add search, filtering, and investigation view

Sprint 6

Cross-Platform and Hardening

Add macOS and Linux collectors

Implement differential scanning

Add signing, tests, and telemetry

Run security and performance validation

## **9. Recommended MVP Acceptance Criteria**

Bago mo tawaging working MVP ang PersistGuard, dapat pumasa ito sa sumusunod:

- Isang administrator ang makakapag-enroll at makakapag-revoke ng endpoint.
- Makakapag-scan ng hindi bababa sa isang Windows machine nang walang arbitrary remote command execution.
- Maipapakita ang scan progress, failed collectors, at completed findings.
- May manual search sa collected artifacts at targeted live scan.
- Lahat ng suspicious findings ay may severity, explanation, at supporting evidence.
- Hindi makakakita ng ibang organization's data ang isang tenant.
- Secure ang communication gamit ang TLS at authenticated agent credentials.
- May automated tests para sa known benign at suspicious persistence examples.

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