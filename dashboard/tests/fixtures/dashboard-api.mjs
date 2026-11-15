import { createServer } from "node:http";

const endpoint = {
  id: "bca1da67-0a54-48e8-b857-f037a467cf41",
  hostname: "Regression fixture",
  os_family: "windows",
  created_at: "2026-01-01T00:00:00Z",
  has_device_key: true,
};
const revoked = new Set();
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
      case "/api/scan-jobs": return send(200, queuedScans.get(authorization) ?? []);
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
