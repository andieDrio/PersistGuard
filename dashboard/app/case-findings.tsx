"use client";

import { useEffect, useRef, useState, type FormEvent } from "react";
import { X } from "lucide-react";
import { readAPI } from "./api";
import { sourceNames, type Finding } from "./scan-data";

const pageSize = 50;
type CaseTarget = { id: string; title: string; status: string };
type CaseTargets = { cases: CaseTarget[]; case_counts: Record<string, number> };
type Link = { id: string; scan_job_id: string; source: string; attached_at: string; evidence: Finding & { endpoint_id: string } };

export function AttachFindingDialog({ token, jobId, finding, close, saved }: {
  token: string; jobId: string; finding: Finding & { source: string }; close: () => void; saved: (title: string) => void;
}) {
  const dialog = useRef<HTMLDialogElement>(null);
  const submission = useRef<AbortController | null>(null);
  const [query, setQuery] = useState("");
  const [offset, setOffset] = useState(0);
  const [selection, setSelection] = useState("");
  const [loaded, setLoaded] = useState<{ query: string; offset: number; data: CaseTargets }>();
  const [loadError, setLoadError] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const data = loaded?.query === query && loaded.offset === offset ? loaded.data : undefined;
  const total = Object.values(data?.case_counts ?? {}).reduce((sum, count) => sum + count, 0);

  useEffect(() => {
    if (dialog.current && !dialog.current.open) dialog.current.showModal();
    return () => submission.current?.abort();
  }, []);

  useEffect(() => {
    const request = new AbortController();
    const timer = window.setTimeout(() => {
      readAPI<CaseTargets>(`workspace?section=cases&offset=${offset}&case_query=${encodeURIComponent(query)}`, token, request.signal)
        .then(result => { if (!request.signal.aborted) setLoaded({ query, offset, data: result }); })
        .catch(cause => { if (!request.signal.aborted) setLoadError(cause.message); });
    }, 150);
    return () => { window.clearTimeout(timer); request.abort(); };
  }, [offset, query, token]);

  async function attach(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const target = data?.cases.find(item => item.id === selection);
    if (!target || !finding.fingerprint || busy) return;
    const request = new AbortController();
    submission.current = request;
    setBusy(true); setError("");
    try {
      await readAPI<Link>(`workspace/cases/${encodeURIComponent(target.id)}/findings`, token, request.signal, "POST", {
        scan_job_id: jobId, source: finding.source, artifact_index: finding.artifact_index, fingerprint: finding.fingerprint,
      });
      if (!request.signal.aborted) saved(target.title);
    } catch (cause) {
      if (!request.signal.aborted) setError(cause instanceof Error ? cause.message : "Could not attach the finding.");
    } finally {
      if (!request.signal.aborted) setBusy(false);
    }
  }

  function changePage(next: number) {
    setSelection(""); setLoadError(""); setOffset(next);
  }

  return <dialog ref={dialog} aria-labelledby="attach-finding-title" onClose={close} onCancel={event => { if (busy) event.preventDefault(); }}>
    <div className="dialog-title"><div><h2 id="attach-finding-title">Attach finding to case</h2><p>{finding.path}</p></div>
      <button className="button icon-button" type="button" aria-label="Close" disabled={busy} onClick={() => dialog.current?.close()}><X size={17} /></button></div>
    <form onSubmit={attach}>
      <label htmlFor="case-query">Find a case</label>
      <input id="case-query" value={query} maxLength={200} disabled={busy} onChange={event => { setQuery(event.target.value); changePage(0); }} />
      <label htmlFor="attach-case">Case</label>
      <select id="attach-case" required value={selection} disabled={busy || !data?.cases.length} onChange={event => setSelection(event.target.value)}>
        <option value="">{loadError ? "Cases unavailable" : !data ? "Loading cases…" : data.cases.length ? "Select a case" : "No matching cases"}</option>
        {data?.cases.map(item => <option key={item.id} value={item.id}>{item.title} · {item.status.replaceAll("_", " ")} · #{item.id.slice(0, 8)}</option>)}
      </select>
      {(offset > 0 || offset + pageSize < total) && <div className="action-footer">
        <button className="button" type="button" disabled={busy || !offset} onClick={() => changePage(offset - pageSize)}>Previous cases</button>
        <button className="button" type="button" disabled={busy || offset + pageSize >= total} onClick={() => changePage(offset + pageSize)}>Next cases</button>
      </div>}
      {(loadError || error) && <p className="api-error" role="alert">{loadError || error}</p>}
      <button className="button primary" type="submit" disabled={busy || !selection}>{busy ? "Attaching…" : "Attach finding"}</button>
    </form>
  </dialog>;
}

export function CaseEvidenceDialog({ token, record, close }: { token: string; record: { id: string; title: string }; close: () => void }) {
  const dialog = useRef<HTMLDialogElement>(null);
  const [page, setPage] = useState(0);
  const [loaded, setLoaded] = useState<{ page: number; links: Link[] }>();
  const [error, setError] = useState("");
  const links = loaded?.page === page ? loaded.links : undefined;
  useEffect(() => { if (dialog.current && !dialog.current.open) dialog.current.showModal(); }, []);
  useEffect(() => {
    const request = new AbortController();
    readAPI<Link[]>(`workspace/cases/${encodeURIComponent(record.id)}/findings?offset=${page * pageSize}`, token, request.signal)
      .then(data => { if (!request.signal.aborted) setLoaded({ page, links: data }); })
      .catch(cause => { if (!request.signal.aborted) setError(cause.message); });
    return () => request.abort();
  }, [page, record.id, token]);

  return <dialog className="case-evidence-dialog" ref={dialog} aria-labelledby="case-evidence-title" onClose={close}>
    <div className="dialog-title"><div><h2 id="case-evidence-title">Case evidence</h2><p>{record.title}</p></div>
      <button className="button icon-button" type="button" aria-label="Close" onClick={() => dialog.current?.close()}><X size={17} /></button></div>
    {error && <p className="api-error" role="alert">{error}</p>}
    {!links && !error && <p role="status">Loading case evidence…</p>}
    {links?.length === 0 && <p>No findings attached on this page.</p>}
    <div className="case-evidence-list">{links?.map(link => <article className="finding" key={link.id}>
      <div className="finding-line"><span className={`severity ${link.evidence.severity}`}>{link.evidence.severity}</span>
        <span className="points mono">{link.evidence.score} pts</span></div>
      <strong>{link.evidence.reasons.join(" · ")}</strong><p title={link.evidence.path}>{link.evidence.path}</p>
      <small>{sourceNames[link.source] ?? link.source} · Scan <span className="mono" title={link.scan_job_id}>#{link.scan_job_id.slice(0, 8)}</span></small>
      {link.evidence.attack_technique && <small className="attack-context">ATT&amp;CK context · {link.evidence.attack_technique}</small>}
      <small className="attack-context">Attached {new Date(link.attached_at).toLocaleString()}</small>
    </article>)}</div>
    {(page > 0 || links?.length === pageSize) && <div className="action-footer">
      <button className="button" type="button" disabled={!page} onClick={() => { setError(""); setPage(page - 1); }}>Previous evidence</button>
      <button className="button" type="button" disabled={links?.length !== pageSize} onClick={() => { setError(""); setPage(page + 1); }}>Next evidence</button>
    </div>}
  </dialog>;
}
