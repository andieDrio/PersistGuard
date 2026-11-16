import type { NextConfig } from "next";

const api = (process.env.PERSISTGUARD_API_URL ?? "http://127.0.0.1:8000").replace(/\/$/, "");

const config: NextConfig = {
  poweredByHeader: false,
  devIndicators: false,
  agentRules: false,
  async rewrites() {
    return [
      { source: "/pg-api/findings", destination: `${api}/api/findings` },
      { source: "/pg-api/attack-coverage", destination: `${api}/api/attack-coverage` },
      { source: "/pg-api/attack-coverage/:id/validations", destination: `${api}/api/attack-coverage/:id/validations` },
      { source: "/pg-api/detection-rules", destination: `${api}/api/detection-rules` },
      { source: "/pg-api/detection-rules/import", destination: `${api}/api/detection-rules/import` },
      { source: "/pg-api/detection-rules/import/validate", destination: `${api}/api/detection-rules/import/validate` },
      { source: "/pg-api/detection-rules/:id", destination: `${api}/api/detection-rules/:id` },
      { source: "/pg-api/detection-rules/:id/test", destination: `${api}/api/detection-rules/:id/test` },
      { source: "/pg-api/detection-rules/:id/versions", destination: `${api}/api/detection-rules/:id/versions` },
      { source: "/pg-api/detection-rules/:id/export", destination: `${api}/api/detection-rules/:id/export` },
      { source: "/pg-api/detection-rules/:id/activation", destination: `${api}/api/detection-rules/:id/activation` },
      { source: "/pg-api/detection-rules/:id/rollback", destination: `${api}/api/detection-rules/:id/rollback` },
      { source: "/pg-api/workspace", destination: `${api}/api/workspace` },
      { source: "/pg-api/workspace/cases", destination: `${api}/api/workspace/cases` },
      { source: "/pg-api/workspace/cases/:id", destination: `${api}/api/workspace/cases/:id` },
      { source: "/pg-api/workspace/cases/:id/findings", destination: `${api}/api/workspace/cases/:id/findings` },
      { source: "/pg-api/workspace/iocs", destination: `${api}/api/workspace/iocs` },
      { source: "/pg-api/endpoints", destination: `${api}/api/endpoints` },
      { source: "/pg-api/enrollment-tokens", destination: `${api}/api/enrollment-tokens` },
      { source: "/pg-api/endpoints/:id/client-certificate", destination: `${api}/api/endpoints/:id/client-certificate` },
      { source: "/pg-api/endpoints/:id/revoke", destination: `${api}/api/endpoints/:id/revoke` },
      { source: "/pg-api/scan-targets", destination: `${api}/api/scan-targets` },
      { source: "/pg-api/scan-schedules", destination: `${api}/api/scan-schedules` },
      { source: "/pg-api/scan-schedules/:id", destination: `${api}/api/scan-schedules/:id` },
      { source: "/pg-api/endpoints/:id/scan-jobs", destination: `${api}/api/endpoints/:id/scan-jobs` },
      { source: "/pg-api/scan-jobs/:id/cancel", destination: `${api}/api/scan-jobs/:id/cancel` },
      { source: "/pg-api/scan-jobs", destination: `${api}/api/scan-jobs` },
      { source: "/pg-api/scan-jobs/:id", destination: `${api}/api/scan-jobs/:id` },
      { source: "/pg-api/scan-jobs/:id/assessment", destination: `${api}/api/scan-jobs/:id/assessment` },
    ];
  },
};

export default config;
