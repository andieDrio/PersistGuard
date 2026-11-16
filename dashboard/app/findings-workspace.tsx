"use client";

import { useEffect, useState } from "react";
import { Search, ShieldAlert } from "lucide-react";
import { readAPI } from "./api";
import { AttachFindingDialog } from "./case-findings";
import { sourceNames, sourceScanHref, type Finding } from "./scan-data";

const severities = ["critical", "high", "medium", "low", "info"] as const;
type Severity = typeof severities[number];
type Row = Finding & { scan_job_id: string; scan_created_at: string; hostname: string; source: string };
type ResponseData = { counts: Record<Severity, number>; findings: Row[]; total: number; can_manage: boolean;
  scan_count: number; scan_batch_size: number; has_older_scans: boolean; page_size: number };
const title = (value: string) => value.charAt(0).toUpperCase() + value.slice(1);
const date = new Intl.DateTimeFormat("en-SG", { dateStyle: "medium", timeZone: "Asia/Singapore" });

export function FindingsWorkspace({ token }: { token: string }) {
  const [query, setQuery] = useState("");
  const [severity, setSeverity] = useState<Severity | "">("");
  const [scanOffset, setScanOffset] = useState(0);
  const [offset, setOffset] = useState(0);
  const [result, setResult] = useState<{ key: string; data?: ResponseData; error?: string }>();
  const [attachment, setAttachment] = useState<Row | null>(null);
  const [notice, setNotice] = useState("");
  const params = new URLSearchParams({ query, scan_offset: String(scanOffset), offset: String(offset) });
  if (severity) params.set("severity", severity);
  const key = params.toString();
  const active = result?.key === key ? result : undefined;
  const data = active?.data;
  const cards = result?.data;

  useEffect(() => {
    if (!token) return;
    const request = new AbortController();
    const timer = window.setTimeout(() => {
      readAPI<ResponseData>(`findings?${key}`, token, request.signal).then(data => {
        if (!request.signal.aborted) setResult({ key, data });
      }).catch((cause: Error) => { if (!request.signal.aborted) setResult({ key, error: cause.message }); });
    }, 150);
    return () => { window.clearTimeout(timer); request.abort(); };
  }, [key, token]);

  if (!token) return <p className="panel section-note">Connect the API to view findings for your tenant.</p>;

  return <>
    <div className="stats findings-stats" aria-label="Findings by severity">{severities.map(level =>
      <button className="stat panel stat-link severity-card" key={level} type="button" aria-pressed={severity === level}
        onClick={() => { setSeverity(severity === level ? "" : level); setOffset(0); }}>
        <span className="stat-line"><span>{title(level)}</span><span className={`severity ${level}`}><ShieldAlert size={14} /></span></span>
        <strong>{cards?.counts[level] ?? "—"}</strong>
      </button>)}
    </div>
    <section className="panel jobs" aria-label="Findings across scans">
      <div className="table-heading"><div><h2>Findings across scans</h2><p>{data?.scan_count ?
        `Scans ${scanOffset + 1}–${scanOffset + data.scan_count} by newest scan first` : "Browse result scans in batches"}</p></div>
        {data && <div className="heading-actions"><button className="button" type="button" disabled={!scanOffset} onClick={() => {
          setScanOffset(scanOffset - data.scan_batch_size); setOffset(0);
        }}>Newer scans</button><button className="button" type="button" disabled={!data.has_older_scans} onClick={() => {
          setScanOffset(scanOffset + data.scan_batch_size); setOffset(0);
        }}>Older scans</button></div>}
      </div>
      <div className="filters coverage-filters">
        <label className="search"><Search size={17} /><input aria-label="Search across scan findings" placeholder="Search reasons, endpoints, paths, or ATT&CK IDs"
          value={query} maxLength={250} onChange={event => { setQuery(event.target.value); setOffset(0); }} /></label>
        <label className="filter"><select aria-label="Severity across scan findings" value={severity}
          onChange={event => { setSeverity(event.target.value as Severity | ""); setOffset(0); }}>
          <option value="">All severities</option>{severities.map(level => <option key={level} value={level}>{title(level)}</option>)}
        </select></label>
      </div>
      {notice && <p className="action-notice rules-message" role="status">{notice}</p>}
      {!active && <p className="section-note" role="status">Loading findings…</p>}
      {active?.error && <p className="api-error rules-message" role="alert">{active.error}</p>}
      {data && <>
        <div className="table-scroll"><table className="coverage-table"><thead><tr><th>Finding</th><th>Severity</th><th>Endpoint</th><th>Scan</th><th>ATT&amp;CK</th><th aria-label="Investigation actions" /></tr></thead>
          <tbody>{data.findings.map(row => <tr key={`${row.scan_job_id}-${row.source}-${row.artifact_index}`}>
            <td className="table-finding"><strong>{row.reasons.join(" · ")}</strong><small>{sourceNames[row.source] ?? row.source} · {row.path}</small></td>
            <td><span className={`severity ${row.severity}`}>{title(row.severity)}</span> <span className="mono">{row.score}</span></td>
            <td>{row.hostname}</td><td><a className="source-scan-link mono"
              href={sourceScanHref({ jobId: row.scan_job_id, source: row.source, artifactIndex: row.artifact_index })}
              aria-label={`Open source scan #${row.scan_job_id.slice(0, 8)} for ${row.reasons.join(" · ")}`} title={row.scan_job_id}>
              #{row.scan_job_id.slice(0, 8)}</a><small>{date.format(new Date(row.scan_created_at))}</small></td>
            <td className="mono">{row.attack_technique ?? "—"}</td><td>{data.can_manage && row.fingerprint &&
              <button className="button" type="button" onClick={() => { setNotice(""); setAttachment(row); }}>Attach to case</button>}</td>
          </tr>)}</tbody></table></div>
        {!data.findings.length && <p className="section-note" role="status">{data.scan_count ? "No findings match these filters in this scan batch." : "No scan results in this batch."}</p>}
        {(data.total > data.page_size || offset > 0) && <footer className="pagination"><span>{data.findings.length ? offset + 1 : 0}–{offset + data.findings.length} of {data.total}</span><div>
          <button className="button" type="button" disabled={!offset} onClick={() => setOffset(offset - data.page_size)}>Previous findings</button>
          <button className="button" type="button" disabled={offset + data.page_size >= data.total} onClick={() => setOffset(offset + data.page_size)}>Next findings</button></div></footer>}
      </>}
    </section>
    {attachment && <AttachFindingDialog token={token} jobId={attachment.scan_job_id} finding={attachment} close={() => setAttachment(null)}
      saved={name => { setAttachment(null); setNotice(`Finding attached to ${name}.`); }} />}
  </>;
}
