"use client";

import { useEffect, useRef, useState } from "react";
import { ArrowLeft, ArrowRight, ChevronDown, Search, X } from "lucide-react";
import { readAPI } from "./api";
import { CoverageValidations } from "./coverage-validations";

type Evidence = { telemetry: string; rule: string; validation: string };
type Coverage = {
  id: string; group: string; use_case: string; technique_id: string; priority: string;
  coverage: "partial" | "planned"; evidence: Evidence | null;
};
type LatestValidation = { use_case_id: string; result: "passed" | "failed" | "inconclusive"; tested_on: string; recorded_at: string };
const latestLabels = { passed: "Passed", failed: "Failed", inconclusive: "Inconclusive" };
const latestTones = { passed: "green", failed: "red", inconclusive: "amber" };
const pageSize = 15;

function ValidationDialog({ row, token, close }: { row: Coverage; token: string; close: () => void }) {
  const dialog = useRef<HTMLDialogElement>(null);
  useEffect(() => { if (dialog.current && !dialog.current.open) dialog.current.showModal(); }, []);
  return <dialog ref={dialog} className="case-evidence-dialog" aria-labelledby="validation-title" onClose={close}>
    <div className="dialog-title"><div><h2 id="validation-title">Validation evidence</h2>
      <p>{row.group} · {row.use_case} · <a className="technique-link" href={`https://attack.mitre.org/techniques/${row.technique_id.replace(".", "/")}/`}
        target="_blank" rel="noreferrer">{row.technique_id}</a></p></div>
      <button className="button icon-button" type="button" aria-label="Close validation evidence" onClick={() => dialog.current?.close()}><X size={17} /></button></div>
    {row.evidence && <dl className="coverage-evidence">
      <div><dt>Telemetry</dt><dd>{row.evidence.telemetry}</dd></div>
      <div><dt>Detection rule</dt><dd>{row.evidence.rule}</dd></div>
      <div><dt>Product fixture evidence</dt><dd>{row.evidence.validation}</dd></div>
    </dl>}
    <CoverageValidations token={token} useCaseId={row.id} />
  </dialog>;
}

export function AttackCoverage({ token }: { token: string }) {
  const [rows, setRows] = useState<Coverage[] | null>(null);
  const [latest, setLatest] = useState<Record<string, LatestValidation>>({});
  const [latestIssue, setLatestIssue] = useState("");
  const [latestLoading, setLatestLoading] = useState(false);
  const [latestRevision, setLatestRevision] = useState(0);
  const [issue, setIssue] = useState("");
  const [query, setQuery] = useState("");
  const [group, setGroup] = useState("");
  const [status, setStatus] = useState("");
  const [page, setPage] = useState(0);
  const [expanded, setExpanded] = useState<string | null>(null);

  useEffect(() => {
    if (!token) { setRows(null); setLatest({}); return; }
    const request = new AbortController();
    readAPI<Coverage[]>("attack-coverage", token, request.signal)
      .then(data => { if (!request.signal.aborted) { setRows(data); setIssue(""); } })
      .catch(error => { if (!request.signal.aborted) setIssue(error.message); });
    return () => request.abort();
  }, [token]);

  useEffect(() => {
    if (!token) return;
    const request = new AbortController();
    setLatestLoading(true);
    setLatestIssue("");
    readAPI<LatestValidation[]>("attack-coverage/latest-validations", token, request.signal)
      .then(data => {
        if (!request.signal.aborted) {
          setLatest(Object.fromEntries(data.map(item => [item.use_case_id, item])));
          setLatestLoading(false);
        }
      })
      .catch(error => {
        if (!request.signal.aborted) { setLatestIssue(error.message); setLatestLoading(false); }
      });
    return () => request.abort();
  }, [token, latestRevision]);

  const groups = [...new Set(rows?.map(row => row.group))];
  const partial = rows?.filter(row => row.coverage === "partial").length ?? 0;
  const search = query.trim().toLowerCase();
  const filtered = rows?.filter(row => (!group || row.group === group) && (!status || row.coverage === status) &&
    [row.use_case, row.technique_id, row.priority, row.group].some(value => value.toLowerCase().includes(search))) ?? [];
  const visible = filtered.slice(page * pageSize, (page + 1) * pageSize);
  const selected = rows?.find(row => row.id === expanded);

  return <section className="panel rules-panel" aria-labelledby="attack-coverage-title">
    <div className="table-heading"><div><h2 id="attack-coverage-title">ATT&amp;CK Coverage Matrix</h2>
      <p>Product coverage against the XDR capability baseline. Fixture tests document specific detection behavior. Deployment validation requires endpoint evidence.</p></div></div>
    {!token && <p className="section-note">Connect the API to view the coverage matrix.</p>}
    {token && !rows && !issue && <p className="section-note" role="status">Loading coverage…</p>}
    {issue && <p className="api-error rules-message" role="alert">{issue}</p>}
    {latestIssue && <p className="api-error rules-message" role="alert">Latest validation unavailable: {latestIssue} <button className="button" type="button" onClick={() => setLatestRevision(value => value + 1)}>Retry</button></p>}
    {rows && <>
      <div className="coverage-totals"><span><strong>{rows.length}</strong> baseline use cases</span>
        <span><strong>{partial}</strong> with partial coverage</span><span><strong>{rows.length - partial}</strong> planned</span></div>
      <div className="filters coverage-filters">
        <label className="search"><Search size={17} /><input aria-label="Search ATT&CK use cases" placeholder="Search use case, technique ID, or priority"
          value={query} onChange={event => { setQuery(event.target.value); setPage(0); }} /></label>
        <label className="filter"><select aria-label="ATT&CK group" value={group} onChange={event => { setGroup(event.target.value); setPage(0); }}>
          <option value="">All groups</option>{groups.map(name => <option key={name}>{name}</option>)}
        </select><ChevronDown size={14} /></label>
        <label className="filter"><select aria-label="Coverage status" value={status} onChange={event => { setStatus(event.target.value); setPage(0); }}>
          <option value="">All coverage</option><option value="partial">Partial</option><option value="planned">Planned</option>
        </select><ChevronDown size={14} /></label>
      </div>
      <div className="table-scroll"><table className="coverage-table"><thead><tr>
        <th>Detection use case</th><th>Latest validation</th><th>Validation</th><th>Technique</th><th>Priority</th><th>Telemetry</th><th>Detection rule</th><th>Coverage</th>
      </tr></thead><tbody>{visible.map(row => <tr key={row.id}><td><strong>{row.use_case}</strong><small>{row.group}</small></td>
          <td>{latestLoading ? "Loading…" : latestIssue ? "Unavailable" : latest[row.id] ? <div className="coverage-latest"><span className={`badge ${latestTones[latest[row.id].result]}`}><span />{latestLabels[latest[row.id].result]}</span><time dateTime={latest[row.id].tested_on}>{latest[row.id].tested_on}</time></div> : <span className="coverage-not-tested">Not tested</span>}</td>
          <td><button type="button" className="button" aria-haspopup="dialog" aria-label={`Validation for ${row.use_case}`}
            onClick={() => setExpanded(row.id)}>Validation</button></td>
          <td className="mono">{row.technique_id}</td><td>{row.priority}</td><td>{row.evidence ? "Inventory" : "Planned"}</td>
          <td>{row.evidence ? "Baseline comparison" : "Planned"}</td>
          <td><span className={`badge ${row.coverage === "partial" ? "amber" : "neutral"}`}><span />{row.coverage === "partial" ? "Partial" : "Planned"}</span></td>
        </tr>)}</tbody></table></div>
      {!filtered.length && <p className="section-note" role="status">No use cases match these filters.</p>}
      {filtered.length > 0 && <footer className="pagination"><span>{page * pageSize + 1}–{page * pageSize + visible.length} of {filtered.length}</span><div>
        <button className="button icon-button" type="button" aria-label="Previous coverage page" disabled={!page} onClick={() => setPage(page - 1)}><ArrowLeft size={15} /></button>
        <button className="button icon-button" type="button" aria-label="Next coverage page" disabled={(page + 1) * pageSize >= filtered.length} onClick={() => setPage(page + 1)}><ArrowRight size={15} /></button>
      </div></footer>}
    </>}
    {selected && <ValidationDialog key={selected.id} row={selected} token={token} close={() => { setExpanded(null); setLatestRevision(value => value + 1); }} />}
  </section>;
}
