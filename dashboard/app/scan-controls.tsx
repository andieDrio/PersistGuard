"use client";

import { useEffect, useRef, useState, type FormEvent } from "react";
import { X } from "lucide-react";
import { readAPI } from "./api";
import { scanTypes, type Job } from "./scan-data";

export type ScanTarget = { id: string; hostname: string };
export type ScanTargets = { can_manage: boolean; can_onboard: boolean; endpoints: ScanTarget[] };
export type ScanAction = { kind: "queue" } | { kind: "cancel"; job: Job };

export function ScanTargetFields({ token, busy, target, scanType, setTarget, setScanType }: {
  token: string; busy: boolean; target: string; scanType: string;
  setTarget: (id: string) => void; setScanType: (value: string) => void;
}) {
  const [query, setQuery] = useState("");
  const [targets, setTargets] = useState<{ query: string; entries: ScanTarget[]; error: string } | null>(null);
  const results = targets?.query === query ? targets : null;

  useEffect(() => {
    const request = new AbortController();
    const timer = window.setTimeout(() => {
      readAPI<ScanTargets>(`scan-targets?query=${encodeURIComponent(query)}`, token, request.signal)
        .then(data => { if (!request.signal.aborted) setTargets({ query, entries: data.endpoints, error: "" }); })
        .catch((error: Error) => { if (!request.signal.aborted) setTargets({ query, entries: [], error: error.message }); });
    }, 180);
    return () => { window.clearTimeout(timer); request.abort(); };
  }, [query, token]);

  return <>
    <label htmlFor="target-query">Find an endpoint</label>
    <input id="target-query" maxLength={253} value={query} placeholder="Search by hostname" disabled={busy}
      onChange={event => { setTarget(""); setQuery(event.target.value); }} />
    <label htmlFor="scan-target">Endpoint</label>
    <select id="scan-target" required value={target} disabled={busy || !results?.entries.length} onChange={event => setTarget(event.target.value)}>
      <option value="">{!results ? "Loading endpoints…" : results.entries.length ? "Select an endpoint" : "No matching endpoints"}</option>
      {results?.entries.map(endpoint => <option value={endpoint.id} key={endpoint.id}>{endpoint.hostname} ({endpoint.id.slice(0, 8)})</option>)}
    </select>
    <label htmlFor="scan-scope">Scan scope</label>
    <select id="scan-scope" value={scanType} disabled={busy} onChange={event => setScanType(event.target.value)}>
      {Object.entries(scanTypes).map(([type, label]) => <option value={type} key={type}>{label}</option>)}
    </select>
    {scanType !== "persistence_full_scan" && <p className="muted">Targeted scans require an agent with targeted scan support.</p>}
    {results?.error && <p role="alert" className="api-error">{results.error}</p>}
  </>;
}

export function ScanControlDialog({ action, token, close, onSaved }: {
  action: ScanAction; token: string; close: () => void; onSaved: (job: Job, action: ScanAction) => void;
}) {
  const dialog = useRef<HTMLDialogElement>(null);
  const actionRequest = useRef<AbortController | null>(null);
  const [selected, setSelected] = useState("");
  const [scanType, setScanType] = useState("persistence_full_scan");
  const [busy, setBusy] = useState(false);
  const [issue, setIssue] = useState("");
  const queue = action.kind === "queue";

  useEffect(() => {
    if (dialog.current && !dialog.current.open) dialog.current.showModal();
    return () => actionRequest.current?.abort();
  }, []);

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (busy || (queue && !selected)) return;
    const request = new AbortController();
    actionRequest.current = request;
    setBusy(true);
    setIssue("");
    const path = action.kind === "queue" ? `endpoints/${encodeURIComponent(selected)}/scan-jobs` :
      `scan-jobs/${encodeURIComponent(action.job.id)}/cancel`;
    try {
      const job = await readAPI<Job>(path, token, request.signal, "POST", queue ? { scan_type: scanType } : undefined);
      if (!request.signal.aborted) onSaved(job, action);
    } catch (error) {
      if (!request.signal.aborted) setIssue(error instanceof Error ? error.message : "The scan could not be updated.");
    } finally {
      if (!request.signal.aborted) setBusy(false);
    }
  }

  return <dialog ref={dialog} onClose={close} aria-labelledby="scan-action-title"
    onCancel={event => { if (busy) event.preventDefault(); }}>
    <div className="dialog-title"><div><h2 id="scan-action-title">{queue ? "Queue Windows scan" : "Cancel queued scan?"}</h2>
      <p>{action.kind === "queue" ? "Select an approved Windows endpoint." : `Scan #${action.job.id.slice(0, 8)} will leave the queue.`}</p></div>
      <button className="button icon-button" type="button" aria-label="Close" disabled={busy} onClick={() => dialog.current?.close()}><X size={17} /></button></div>
    <form onSubmit={submit}>
      {queue && <ScanTargetFields token={token} busy={busy} target={selected} scanType={scanType}
        setTarget={setSelected} setScanType={setScanType} />}
      {issue && <p role="alert" className="api-error">{issue}</p>}
      <div className="action-footer">
        <button className="button" type="button" disabled={busy} onClick={() => dialog.current?.close()}>{queue ? "Close" : "Keep scan"}</button>
        <button type="submit" className={`button ${queue ? "primary" : "danger"}`} disabled={busy || (queue && !selected)}>
          {busy ? (queue ? "Queuing…" : "Canceling…") : queue ? "Queue scan" : "Cancel scan"}
        </button>
      </div>
    </form>
  </dialog>;
}
