export type Job = {
  id: string;
  endpoint_id: string;
  status: string;
  created_at: string;
  scan_type: string;
  endpointLabel?: string;
};

export type Finding = {
  artifact_index: number;
  path: string;
  score: number;
  severity: string;
  reasons: string[];
  baseline_status?: string;
  attack_technique?: string;
  fingerprint?: string;
};

export type Collector = {
  status: string;
  error?: string;
  assessments: Finding[];
  coverage: { status?: string; error?: string; issues?: { code?: string }[] }[];
};

export type Assessment = {
  baseline_job_id: string | null;
  status: string;
  collectors: Record<string, Collector>;
};

export const sourceNames: Record<string, string> = {
  registry: "Registry",
  scheduled_tasks: "Scheduled Tasks",
  services: "Windows Services",
};

export const activeStatuses = ["queued", "dispatched", "acknowledged", "running", "uploading", "analyzing"];
export const terminalStatuses = ["completed", "partial", "failed"];

const preview = [
  ["7340a91c", "WIN-OPS-024", "partial", "10:42"],
  ["c82bc5ef", "WIN-FIN-018", "completed", "10:36"],
  ["ab23d891", "WIN-ENG-007", "running", "10:31"],
  ["7e34a112", "WIN-HR-011", "completed", "10:24"],
  ["d9c0f231", "WIN-OPS-012", "completed", "10:18"],
  ["6d421a8e", "WIN-ENG-021", "queued", "10:12"],
  ["a8d01163", "WIN-FIN-008", "partial", "10:02"],
  ["c2318059", "WIN-QA-004", "completed", "09:56"],
  ["e562880b", "WIN-OPS-004", "completed", "09:45"],
  ["fb3fa2d0", "WIN-HR-003", "failed", "09:32"],
  ["5304efb7", "WIN-QA-009", "dispatched", "09:16"],
  ["2219037b", "WIN-FIN-012", "completed", "09:08"],
];

export const previewJobs: Job[] = preview.map(([id, device, status, time], index) => ({
  id: `${id}-db01-44ca-8ea9-5e2dbb2b${String(index).padStart(4, "0")}`,
  endpoint_id: `${id}-aaa1-487f-869d-bf8ee7dbcd01`,
  endpointLabel: device,
  status,
  scan_type: "persistence_full_scan",
  created_at: `2026-11-15T${time}:00+08:00`,
}));

export function previewAssessment(job: Job): Assessment {
  if (job.status === "failed") {
    return { status: "error", baseline_job_id: null, collectors: Object.fromEntries(
      Object.keys(sourceNames).map(source => [source, { status: "error", error: "Collector unavailable", coverage: [], assessments: [] }]),
    ) };
  }
  const partial = job.status === "partial";
  return {
    status: partial ? "partial" : "collected",
    baseline_job_id: previewJobs[3].id,
    collectors: {
      registry: { status: "collected", coverage: [{ status: "collected" }], assessments: partial ? [{
        artifact_index: 0, path: "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", score: 10,
        severity: "info", reasons: ["New persistence entry"], baseline_status: "new",
      }] : [] },
      scheduled_tasks: { status: "collected", coverage: [{ status: "collected" }], assessments: partial ? [{
        artifact_index: 0, path: "\\Operations\\InventorySync", score: 25,
        severity: "low", reasons: ["Encoded startup command"], baseline_status: "existing",
      }] : [] },
      services: { status: partial ? "partial" : "collected", assessments: [], coverage: [
        partial ? { status: "partial", issues: [{ code: "access_denied" }] } : { status: "collected" },
      ] },
    },
  };
}
export const scanTypes = {
  persistence_full_scan: "Windows full inventory",
  persistence_registry_scan: "Startup Registry",
  persistence_scheduled_tasks_scan: "Scheduled Tasks",
  persistence_services_scan: "Windows Services",
} satisfies Record<string, string>;

export function scanTypeLabel(scanType: string) {
  return Object.hasOwn(scanTypes, scanType) ? scanTypes[scanType as keyof typeof scanTypes] : scanType;
}
