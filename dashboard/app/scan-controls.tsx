"use client";

import { useEffect, useRef, useState, type FormEvent } from "react";
import { X } from "lucide-react";
import { readAPI } from "./api";
import type { Job } from "./scan-data";

export type ScanTarget = { id: string; hostname: string };
export type ScanTargets = { can_manage: boolean; can_onboard: boolean; endpoints: ScanTarget[] };
export type ScanAction = { kind: "queue" } | { kind: "cancel"; job: Job };

export function ScanControlDialog({ action, token, close, onSaved }: {
  action: ScanAction; token: string; close: () => void; onSaved: (job: Job, action: ScanAction) => void;
}) {
  const dialog = useRef<HTMLDialogElement>(null);
  const actionRequest = useRef<AbortController | null>(null);
  const [query, setQuery] = useState("");
  const [selected, setSelected] = useState("");
  const [targets, setTargets] = useState<{ query: string; entries: ScanTarget[]; error: string } | null>(null);
  const [busy, setBusy] = useState(false);
  const [issue, setIssue] = useState("");
  const queue = action.kind === "queue";
  const results = targets?.query === query ? targets : null;

  useEffect(() => {
    if (dialog.current && !dialog.current.open) dialog.current.showModal();
    return () => actionRequest.current?.abort();
  }, []);

  useEffect(() => {
    if (!queue) return;
    const request = new AbortController();
    const timer = window.setTimeout(() => {
      readAPI<ScanTargets>(`scan-targets?query=${encodeURIComponent(query)}`, token, request.signal)
        .then(data => { if (!request.signal.aborted) setTargets({ query, entries: data.endpoints, error: "" }); })
        .catch((error: Error) => { if (!request.signal.aborted) setTargets({ query, entries: [], error: error.message }); });
    }, 180);
    return () => { window.clearTimeout(timer); request.abort(); };
  }, [query, queue, token]);

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (busy || (queue && (!selected || !results?.entries.some(endpoint => endpoint.id === selected)))) return;
    const request = new AbortController();
    actionRequest.current = request;
    setBusy(true);
    setIssue("");
    const path = action.kind === "queue" ? `endpoints/${encodeURIComponent(selected)}/scan-jobs` :
      `scan-jobs/${encodeURIComponent(action.job.id)}/cancel`;
    try {
      const job = await readAPI<Job>(path, token, request.signal, "POST");
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
      {queue && <>
        <label htmlFor="target-query">Find an endpoint</label>
        <input id="target-query" maxLength={253} value={query} placeholder="Search by hostname" disabled={busy}
          onChange={event => { setSelected(""); setQuery(event.target.value); }} />
        <label htmlFor="scan-target">Endpoint</label>
        <select id="scan-target" required value={selected} disabled={busy || !results?.entries.length} onChange={event => setSelected(event.target.value)}>
          <option value="">{!results ? "Loading endpoints…" : results.entries.length ? "Select an endpoint" : "No matching endpoints"}</option>
          {results?.entries.map(endpoint => <option value={endpoint.id} key={endpoint.id}>{endpoint.hostname} ({endpoint.id.slice(0, 8)})</option>)}
        </select>
        {results?.error && <p role="alert" className="api-error">{results.error}</p>}
      </>}
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
