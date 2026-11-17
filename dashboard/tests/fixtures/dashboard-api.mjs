import { createServer } from "node:http";

const endpoint = {
  id: "bca1da67-0a54-48e8-b857-f037a467cf41",
  hostname: "Regression fixture",
  os_family: "windows",
  created_at: "2026-01-01T00:00:00Z",
  has_device_key: true,
};
const revoked = new Set();
const validationRecords = new Map();
const validationCase = "D-T1053.005";
const validationCatalog = [
  { id: validationCase, group: "Persistence", use_case: "Scheduled task persistence", technique_id: "T1053.005",
    priority: "P1", coverage: "partial", evidence: { telemetry: "Scheduled task inventory",
      rule: "New-task baseline comparison", validation: "Fixture evidence" } },
  { id: "D-T1543.003", group: "Persistence", use_case: "Windows service persistence", technique_id: "T1543.003",
    priority: "P1", coverage: "partial", evidence: { telemetry: "Service inventory",
      rule: "New-service baseline comparison", validation: "Fixture evidence" } },
];
const rule = {
  id: "f82ee004-ea52-4b49-8e77-badfdbbeb6be", name: "Restore regression rule",
  source: "services", field: "command", pattern: "fixture-agent.exe", score: 50,
  revision: 3, enabled: true, tested: true, draft_version: 2, published_version: 2,
};
const versions = [2, 1].map(version => ({
  version, name: rule.name, source: rule.source, field: rule.field, pattern: rule.pattern,
  score: version === 2 ? 50 : 40, published_at: "2026-01-01T00:00:00Z",
}));
const restoredRules = new Map();
const queuedScans = new Map();
const scanSchedules = new Map();
const fixtureScheduleId = "0a27d2c2-e7ea-40d1-bbe1-a1b047bf36a4";
const fixtureSchedule = { id: fixtureScheduleId, endpoint_id: endpoint.id, hostname: endpoint.hostname,
  scan_type: "persistence_services_scan", frequency: "weekly", enabled: true, next_run_at: "2038-02-08T01:30:00Z",
  last_run_at: "2026-11-17T01:30:00Z", last_outcome: "skipped_busy" };
const sourceScan = {
  id: "9d0be757-f8b9-4cbe-856e-dff4ba0c4e95", endpoint_id: endpoint.id,
  status: "partial", scan_type: "persistence_full_scan", created_at: "2025-12-01T00:00:00Z",
};
const scheduledScan = { ...sourceScan, id: "5b746050-eb06-414b-8cd0-2ab6bfda1b63", scan_type: fixtureSchedule.scan_type,
  schedule_id: fixtureScheduleId, created_at: "2026-11-10T01:30:09Z" };
const runningScan = { ...scheduledScan, id: "a44dee07-13cf-4f76-ad6f-ff1ceca374f8", status: "running" };
const serviceFinding = {
  artifact_index: 0, reasons: ["Fixture service finding"], path: "HKLM\\SYSTEM\\CurrentControlSet\\Services\\SampleAgent",
  severity: "high", score: 70, fingerprint: "a".repeat(64), attack_technique: "T1543.003",
};
const taskFinding = {
  artifact_index: 0, reasons: ["Fixture task finding"], path: "\\Maintenance\\Inventory",
  severity: "medium", score: 50, fingerprint: "b".repeat(64),
};
const findings = [["services", serviceFinding], ["scheduled_tasks", taskFinding]].map(([source, finding]) => ({
  ...finding, source, scan_job_id: sourceScan.id, scan_created_at: sourceScan.created_at, hostname: endpoint.hostname,
}));

async function readJSON(request) {
  try {
    const chunks = [];
    for await (const chunk of request) chunks.push(chunk);
    return JSON.parse(Buffer.concat(chunks).toString("utf8"));
  } catch {
    return null;
  }
}

createServer(async (request, response) => {
  const { pathname, searchParams } = new URL(request.url, "http://127.0.0.1");
  const send = (status, data) => {
    response.writeHead(status, { "Content-Type": "application/json", "Cache-Control": "no-store" });
    response.end(JSON.stringify(data));
  };
  if (pathname === "/healthz") return send(200, { status: "ok" });

  const authorization = request.headers.authorization;
  const credentials = /^Bearer dashboard-(admin|analyst|viewer)-[a-f0-9-]+$/.exec(authorization ?? "");
  if (!credentials) return send(401, { detail: "A fixture token is required" });
  const role = credentials[1];
  const isAdmin = role === "admin";
  const currentRule = restoredRules.get(authorization) ?? rule;
  const status = revoked.has(authorization) ? "revoked" : "approved";

  if (request.method === "GET") {
    switch (pathname) {
      case "/api/attack-coverage": return send(200, validationCatalog);
      case "/api/attack-coverage/latest-validations": {
        const records = validationRecords.get(authorization) ?? [];
        const latest = [...records].sort((a, b) => b.tested_on.localeCompare(a.tested_on) ||
          b.recorded_at.localeCompare(a.recorded_at));
        return send(200, [...new Map(latest.map(row => [row.use_case_id, row])).values()]
          .map(({ use_case_id, result, tested_on, recorded_at }) => ({ use_case_id, result, tested_on, recorded_at })));
      }
      case `/api/attack-coverage/${validationCase}/validations`: {
        const records = (validationRecords.get(authorization) ?? []).slice().sort((a, b) =>
          b.tested_on.localeCompare(a.tested_on) || b.recorded_at.localeCompare(a.recorded_at));
        const offset = Number(searchParams.get("offset") ?? 0);
        return send(200, { records: records.slice(offset, offset + 25), next_offset: null, can_manage: role !== "viewer" });
      }
      case "/api/scan-jobs": return send(200, queuedScans.get(authorization) ?? []);
      case "/api/scan-schedules": return send(200, { has_more: false, schedules: scanSchedules.has(authorization) ?
        [scanSchedules.get(authorization)] : role === "viewer" ? [fixtureSchedule] : [] });
      case `/api/scan-schedules/${fixtureScheduleId}/runs`: {
        const schedule = scanSchedules.get(authorization) ?? (role === "viewer" ? fixtureSchedule : null);
        if (!schedule) return send(404, { detail: "Scan schedule not found" });
        return send(200, { schedule, has_more: false, runs: role === "viewer" ? [
          { id: "989e90ac-39f2-4c71-b63a-945506e74fe3", scheduled_for: "2026-11-17T01:30:00Z",
            attempted_at: "2026-11-17T01:30:04Z", outcome: "skipped_busy", job_id: null, job_status: null },
          { id: scheduledScan.id, scheduled_for: null, attempted_at: scheduledScan.created_at,
            outcome: "queued", job_id: scheduledScan.id, job_status: scheduledScan.status },
          { id: runningScan.id, scheduled_for: "2026-11-03T01:30:00Z", attempted_at: "2026-11-03T01:30:14Z",
            outcome: "queued", job_id: runningScan.id, job_status: runningScan.status },
        ] : [] });
      }
      case `/api/scan-jobs/${sourceScan.id}`: return send(200, sourceScan);
      case `/api/scan-jobs/${scheduledScan.id}`: return send(200, scheduledScan);
      case `/api/scan-jobs/${runningScan.id}`: return send(200, runningScan);
      case `/api/scan-jobs/${sourceScan.id}/assessment`:
      case `/api/scan-jobs/${scheduledScan.id}/assessment`: return send(200, {
        status: "partial", baseline_job_id: null, collectors: {
          services: { status: "collected", coverage: [], assessments: [serviceFinding] },
          scheduled_tasks: { status: "partial", coverage: [{ error: "fixture_coverage_gap" }], assessments: [taskFinding] },
        },
      });
      case "/api/findings": {
        const query = (searchParams.get("query") ?? "").toLowerCase();
        const severity = searchParams.get("severity");
        const matches = findings.filter(finding => finding.reasons[0].toLowerCase().includes(query));
        const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
        for (const finding of matches) counts[finding.severity]++;
        const rows = severity ? matches.filter(finding => finding.severity === severity) : matches;
        return send(200, { counts, findings: rows, total: rows.length, can_manage: role !== "viewer",
          scan_count: 1, scan_batch_size: 5, has_older_scans: false, page_size: 25 });
      }
      case "/api/scan-targets": return send(200, { can_manage: role !== "viewer", can_onboard: isAdmin,
        endpoints: [{ id: endpoint.id, hostname: endpoint.hostname }] });
      case "/api/workspace": return send(200, {
        tenant: { name: "Regression tenant", count: 1 },
        can_manage: role !== "viewer",
        endpoint_counts: { total: 0, new_installed: 0, connected: 0, disconnected: 0 },
        endpoints: [],
      });
      case "/api/endpoints":
        if (!isAdmin) return send(403, { detail: "Administrator access required" });
        return send(200, searchParams.get("status") === status ? [{ ...endpoint, status }] : []);
      case "/api/detection-rules": return send(200, { can_manage: isAdmin, rules: [currentRule] });
      case `/api/detection-rules/${rule.id}/versions`: return send(200, versions);
    }
  }

  if (request.method === "POST" && pathname === `/api/attack-coverage/${validationCase}/validations`) {
    if (role === "viewer") return send(403, { detail: "Active admin or analyst access required" });
    const body = await readJSON(request);
    if (!["passed", "failed", "inconclusive"].includes(body?.result) ||
        !/^\\d{4}-\\d{2}-\\d{2}$/.test(body?.tested_on ?? "") || !body?.reference?.trim())
      return send(422, { detail: "Invalid validation" });
    const records = validationRecords.get(authorization) ?? [];
    const existing = records.find(row => row.tested_on === body.tested_on && row.result === body.result &&
      row.reference === body.reference);
    if (existing) return send(200, existing);
    const record = { ...body, id: crypto.randomUUID(), use_case_id: validationCase,
      recorded_by: endpoint.id, recorded_role: role, recorded_at: new Date().toISOString() };
    validationRecords.set(authorization, [...records, record]);
    return send(201, record);
  }
  if (request.method === "POST" && pathname === "/api/scan-schedules") {
    if (role === "viewer") return send(403, { detail: "Recurring scans require an admin or analyst" });
    if (scanSchedules.has(authorization)) return send(409, { detail: "This endpoint already has a schedule for this scope. Edit the existing schedule." });
    const body = await readJSON(request);
    if (body?.endpoint_id !== endpoint.id) return send(404, { detail: "Endpoint not found" });
    const schedule = { ...body, id: fixtureScheduleId, hostname: endpoint.hostname, enabled: true,
      last_run_at: null, last_outcome: null };
    scanSchedules.set(authorization, schedule);
    return send(201, schedule);
  }
  if (request.method === "PATCH" && pathname === `/api/scan-schedules/${fixtureScheduleId}`) {
    if (role === "viewer") return send(403, { detail: "Recurring scans require an admin or analyst" });
    const schedule = scanSchedules.get(authorization);
    if (!schedule) return send(404, { detail: "Scan schedule not found" });
    const body = await readJSON(request);
    const updated = { ...schedule, ...body?.timing, enabled: body?.enabled ?? schedule.enabled };
    scanSchedules.set(authorization, updated);
    return send(200, updated);
  }
  if (request.method === "POST" && pathname === `/api/endpoints/${endpoint.id}/revoke`) {
    if (!isAdmin) return send(403, { detail: "Administrator access required" });
    revoked.add(authorization);
    return send(200, { endpoint_id: endpoint.id, status: "revoked" });
  }
  if (request.method === "POST" && pathname === `/api/endpoints/${endpoint.id}/scan-jobs`) {
    if (role === "viewer") return send(403, { detail: "Scan scheduling requires an admin or analyst" });
    const body = await readJSON(request);
    if (body?.scan_type !== "persistence_services_scan") return send(422, { detail: "Invalid fixture scan scope" });
    const job = { id: "cd3c2b28-a25c-409f-a694-fc26e79331ac", endpoint_id: endpoint.id,
      scan_type: body.scan_type, status: "queued", created_at: endpoint.created_at };
    queuedScans.set(authorization, [job]);
    return send(201, job);
  }
  if (request.method === "POST" && pathname === `/api/detection-rules/${rule.id}/rollback`) {
    if (!isAdmin) return send(403, { detail: "Administrator access required" });
    const body = await readJSON(request);
    if (!body) return send(422, { detail: "Invalid rollback request" });
    if (body?.revision !== currentRule.revision) return send(409, { detail: "Rule revision has changed" });
    if (!versions.some(version => version.version === body.version)) return send(404, { detail: "Version not found" });
    if (body.version === currentRule.published_version) return send(409, { detail: "Version is already active" });
    const updated = { ...currentRule, revision: currentRule.revision + 1, published_version: body.version };
    restoredRules.set(authorization, updated);
    return send(200, updated);
  }
  return send(404, { detail: "Unknown fixture route" });
}).listen(Number(process.env.DASHBOARD_FIXTURE_PORT), "127.0.0.1");
