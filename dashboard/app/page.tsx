"use client";

import { useEffect, useRef, useState, type FormEvent } from "react";
import {
  Activity, ArrowDown, ArrowLeft, ArrowRight, Check, ChevronDown, ChevronRight,
  CircleAlert, ClipboardList, Layers3, ListFilter, Monitor, Plug, RefreshCw, Search,
  Plus, ShieldCheck, TriangleAlert, UserRoundPlus, X,
} from "lucide-react";
import { readAPI } from "./api";
import { AttachFindingDialog } from "./case-findings";
import { EndpointOnboarding } from "./endpoint-onboarding";
import { ScanControlDialog, type ScanAction, type ScanTarget, type ScanTargets } from "./scan-controls";
import { activeStatuses, parseScanFinding, previewAssessment, previewJobs, scanTypeLabel, sourceNames, terminalStatuses,
  type Assessment, type Finding, type Job, type ScanFindingTarget } from "./scan-data";
import { sections, WorkspaceSection } from "./workspace";

const pageSize = 7;
const batchSize = 100;
const dateFormat = new Intl.DateTimeFormat("en-SG", { day: "numeric", month: "short", timeZone: "Asia/Singapore" });
const timeFormat = new Intl.DateTimeFormat("en-GB", { hour: "2-digit", minute: "2-digit", timeZone: "Asia/Singapore" });
const shortId = (id: string) => id.slice(0, 8);
const label = (value: string) => value.replaceAll("_", " ").replace(/^./, first => first.toUpperCase());
const findingSeverities = ["critical", "high", "medium", "low", "info"];
type View = typeof sections[number]["id"] | "scan-history" | "endpoint-onboarding";
type Route = { view: View } | { view: "source-scan"; query: string; keepFindings: boolean };
type ScanFinding = Finding & { source: string };

function Badge({ status }: { status: string }) {
  const tone = ["completed", "collected"].includes(status) ? "green" : status === "partial" ? "amber" :
    ["failed", "error"].includes(status) ? "red" : activeStatuses.includes(status) && status !== "queued" ? "blue" : "neutral";
  return <span className={`badge ${tone}`}><span />{label(status)}</span>;
}

function ScanDetail({ job, assessment, pending, error, cancel, attach, target }: {
  job: Job | undefined; assessment: Assessment | null; pending: boolean; error: string; cancel?: () => void;
  attach?: (finding: ScanFinding) => void; target?: ScanFindingTarget;
}) {
  const [tab, setTab] = useState<"findings" | "coverage">("findings");
  const [findingQuery, setFindingQuery] = useState("");
  const [severity, setSeverity] = useState("");
  const [showAll, setShowAll] = useState(false);
  const linkedOnly = Boolean(target && !showAll);
  const collectors = Object.entries(assessment?.collectors ?? {});
  const findings = collectors.flatMap(([source, collector]) => collector.assessments
    .filter(item => item.score > 0).map(item => ({ ...item, source }))).sort((a, b) => b.score - a.score);
  const terms = findingQuery.trim().toLowerCase().split(/\s+/).filter(Boolean);
  const visibleFindings = findings.filter(finding => {
    if (target && linkedOnly) return finding.source === target.source && finding.artifact_index === target.artifactIndex;
    if (severity && finding.severity !== severity) return false;
    if (!terms.length) return true;
    const searchable = [finding.path, sourceNames[finding.source] ?? label(finding.source),
      finding.attack_technique, ...finding.reasons].join(" ").toLowerCase();
    return terms.every(term => searchable.includes(term));
  });
  return <aside className="detail panel" id="scan-detail" aria-label="Scan details">
    <div className="detail-top"><div className="detail-icon"><ClipboardList size={19} /></div><div><h2>Scan details</h2>
      <p>{job ? `Scan #${shortId(job.id)}` : "Select a scan"}</p></div></div>
    {job && <>
      <dl className="detail-meta">
        <div><dt>Status</dt><dd><Badge status={job.status} /></dd></div>
        <div><dt>Endpoint</dt><dd className="mono endpoint-detail" title={job.endpoint_id}>{job.endpointLabel ?? shortId(job.endpoint_id)}</dd></div>
        <div><dt>Type</dt><dd>{scanTypeLabel(job.scan_type)}</dd></div>
        <div><dt>Baseline</dt><dd className={assessment?.baseline_job_id ? "mono" : ""}>{assessment?.baseline_job_id ? `#${shortId(assessment.baseline_job_id)}` : "—"}</dd></div>
      </dl>
      {cancel && <div className="detail-actions"><button className="button cancel-button" type="button" onClick={cancel}>Cancel scan</button></div>}
      <div className="detail-tabs" role="group" aria-label="Scan detail view">
        <button type="button" className={tab === "findings" ? "current" : ""} aria-pressed={tab === "findings"} onClick={() => setTab("findings")}>Findings <span>{findings.length}</span></button>
        <button type="button" className={tab === "coverage" ? "current" : ""} aria-pressed={tab === "coverage"} onClick={() => setTab("coverage")}>Coverage</button>
      </div>
      {pending ? <p className="detail-note" role="status">Loading assessment…</p> : error ? <p className="detail-note" role="alert">{error}</p> : !assessment ?
        <p className="detail-note">{job.status === "canceled" ? "This scan was canceled before dispatch." : "Results will appear after the agent uploads the inventory."}</p> : tab === "findings" ? <>
          {target && <div className="finding-filters"><div className="finding-filter-actions">
            <button className="button" type="button" onClick={() => setShowAll(!showAll)}>
              {linkedOnly ? "Show all findings" : "Show linked finding"}</button>
          </div></div>}
          {!linkedOnly && findings.length > 0 && <div className="finding-filters" role="group" aria-label="Filter scan findings">
            <label className="search"><Search size={16} /><input aria-label="Search findings" placeholder="Search reasons, paths, or ATT&CK IDs"
              value={findingQuery} onChange={event => setFindingQuery(event.target.value)} /></label>
            <div className="finding-filter-actions">
              <label className="filter"><ListFilter size={15} /><select aria-label="Filter findings by severity" value={severity}
                onChange={event => setSeverity(event.target.value)}>
                <option value="">All severities</option>{findingSeverities.map(value => <option key={value} value={value}>{label(value)}</option>)}
              </select><ChevronDown size={13} /></label>
              {(findingQuery || severity) && <button className="button" type="button" onClick={() => { setFindingQuery(""); setSeverity(""); }}>Clear filters</button>}
            </div>
            <p className="finding-result-count" role="status">{visibleFindings.length} of {findings.length} findings shown</p>
          </div>}
          <div className="detail-content">
          {visibleFindings.length === 0 && <p className="detail-note" role="status">{linkedOnly ?
            "The linked finding is unavailable in the current assessment." : findings.length === 0 ?
            "No scored signals in the available inventory." : "No findings match these filters."}</p>}
          {visibleFindings.map(finding => <div className="finding" key={`${finding.source}-${finding.artifact_index}`}>
            <div className="finding-line"><span className={`severity ${finding.severity}`}>{label(finding.severity)}</span><span className="points mono">{finding.score} pts</span></div>
            <strong>{finding.reasons.join(" · ")}</strong><p title={finding.path}>{finding.path}</p>
            <small>{sourceNames[finding.source] ?? label(finding.source)}{finding.baseline_status === "new" ? " · New since baseline" : ""}</small>
            {finding.attack_technique && <small className="attack-context">ATT&amp;CK context · {finding.attack_technique}</small>}
            {attach && finding.fingerprint && <button className="button attach-finding-button" type="button" onClick={() => attach(finding)}>Attach to case</button>}
          </div>)}
        </div></> : <div className="detail-content">
          {collectors.map(([key, collector]) => <div className="coverage-item" key={key}>
            <div><strong>{sourceNames[key] ?? label(key)}</strong><Badge status={collector.status} /></div>
            {collector.error && <p>{collector.error}</p>}
            {collector.coverage.flatMap(item => [item.error, ...(item.issues ?? []).map(issue => issue.code)])
              .filter((value): value is string => Boolean(value)).map((value, index) => <p key={index}>{label(value)}</p>)}
          </div>)}
        </div>}
    </>}
  </aside>;
}

function SourceScan({ target, token, endpoints, notice, attach }: {
  target: ScanFindingTarget | null; token: string; endpoints: ScanTarget[]; notice: string;
  attach?: (jobId: string, finding: ScanFinding) => void;
}) {
  const heading = useRef<HTMLHeadingElement>(null);
  const [loaded, setLoaded] = useState<{ job: Job; assessment: Assessment | null; error: string }>();
  const [issue, setIssue] = useState("");
  const jobId = target?.jobId;

  useEffect(() => {
    heading.current?.closest(".app-scroll")?.scrollTo({ top: 0 });
    heading.current?.focus({ preventScroll: true });
  }, []);

  useEffect(() => {
    if (!token || !jobId) return;
    const request = new AbortController();
    const path = `scan-jobs/${encodeURIComponent(jobId)}`;
    void Promise.allSettled([
      readAPI<Job>(path, token, request.signal),
      readAPI<Assessment>(`${path}/assessment`, token, request.signal),
    ]).then(([job, assessment]) => {
      if (request.signal.aborted) return;
      if (job.status === "rejected") { setIssue(job.reason.message); return; }
      setLoaded({ job: job.value, assessment: assessment.status === "fulfilled" ? assessment.value : null,
        error: assessment.status === "rejected" ? assessment.reason.message : "" });
    });
    return () => request.abort();
  }, [jobId, token]);

  const job = loaded && { ...loaded.job, endpointLabel: endpoints.find(endpoint => endpoint.id === loaded.job.endpoint_id)?.hostname };
  return <main className="source-scan">
    <div className="heading"><h1 ref={heading} tabIndex={-1}>Source scan</h1>
      <a className="button" href="#findings"><ArrowLeft size={15} />Back to Findings</a></div>
    {notice && <p className="action-notice" role="status"><Check size={16} />{notice}</p>}
    {!target ? <p className="api-error" role="alert">This source scan link is invalid.</p> :
      !token ? <p className="panel section-note">Connect the API to open this source scan.</p> :
      issue ? <p className="api-error" role="alert">{issue}</p> :
      !loaded || !job ? <p className="panel section-note" role="status">Loading source scan…</p> :
      <ScanDetail job={job} target={target} assessment={loaded.assessment} pending={false} error={loaded.error}
        attach={attach ? finding => attach(job.id, finding) : undefined} />}
  </main>;
}

export default function Page() {
  const [token, setToken] = useState("");
  const [liveJobs, setLiveJobs] = useState<Job[]>([]);
  const [hasOlder, setHasOlder] = useState(false);
  const [selectedId, setSelectedId] = useState(previewJobs[0].id);
  const [search, setSearch] = useState("");
  const [status, setStatus] = useState("all");
  const [page, setPage] = useState(0);
  const [loading, setLoading] = useState(false);
  const [issue, setIssue] = useState("");
  const [notice, setNotice] = useState("");
  const [canManage, setCanManage] = useState(false);
  const [canOnboard, setCanOnboard] = useState(false);
  const [route, setRoute] = useState<Route>({ view: "dashboard" });
  const [endpoints, setEndpoints] = useState<ScanTarget[]>([]);
  const [scanAction, setScanAction] = useState<ScanAction | null>(null);
  const [attachTarget, setAttachTarget] = useState<{ jobId: string; finding: ScanFinding } | null>(null);
  const [dialogIssue, setDialogIssue] = useState("");
  const [detail, setDetail] = useState<{ id: string; data: Assessment | null; error: string } | null>(null);
  const sidebar = useRef<HTMLElement>(null);
  const topbar = useRef<HTMLElement>(null);
  const dialog = useRef<HTMLDialogElement>(null);
  const listRequest = useRef<AbortController | null>(null);
  const live = token.length > 0;
  const sourceScanOpen = route.view === "source-scan";
  const view = sourceScanOpen ? "scan-history" : route.view;
  const currentView = view === "endpoint-onboarding" && (!live || !canOnboard) ? "endpoints" : view;
  const findingsOpen = currentView === "findings";
  const viewLabel = sections.find(section => section.id === currentView)?.label ??
    (currentView === "scan-history" ? "Scan history" : "Endpoint onboarding");
  const hostnames = new Map(endpoints.map(endpoint => [endpoint.id, endpoint.hostname]));
  const jobs = live ? liveJobs.map(job => ({ ...job, endpointLabel: hostnames.get(job.endpoint_id) })) : previewJobs;
  const query = search.trim().toLowerCase();
  const filtered = jobs.filter(job => (status === "all" || (status === "active" ? activeStatuses.includes(job.status) : status === job.status)) &&
    (!query || [job.id, job.endpoint_id, job.endpointLabel ?? "", scanTypeLabel(job.scan_type), label(job.status)].some(value => value.toLowerCase().includes(query))));
  const lastPage = Math.max(0, Math.ceil(filtered.length / pageSize) - 1);
  const currentPage = Math.min(page, lastPage);
  const items = filtered.slice(currentPage * pageSize, (currentPage + 1) * pageSize);
  const selected = items.find(job => job.id === selectedId) ?? items[0];
  const selectedJobId = selected?.id;
  const hasResult = terminalStatuses.includes(selected?.status ?? "");

  useEffect(() => {
    const sidebarElement = sidebar.current;
    const topbarElement = topbar.current;
    if (!sidebarElement || !topbarElement) return;

    const updateOffset = () => {
      topbarElement.style.setProperty("--mobile-sidebar-height", `${sidebarElement.getBoundingClientRect().height}px`);
    };

    updateOffset();
    const observer = new ResizeObserver(updateOffset);
    observer.observe(sidebarElement, { box: "border-box" });
    return () => observer.disconnect();
  }, []);

  useEffect(() => {
    if (!token || currentView !== "scan-history" || sourceScanOpen || !selectedJobId || !hasResult) return;
    const request = new AbortController();
    readAPI<Assessment>(`scan-jobs/${encodeURIComponent(selectedJobId)}/assessment`, token, request.signal)
      .then(data => { if (!request.signal.aborted) setDetail({ id: selectedJobId, data, error: "" }); })
      .catch(error => { if (!request.signal.aborted) setDetail({ id: selectedJobId, data: null, error: error.message }); });
    return () => request.abort();
  }, [token, currentView, sourceScanOpen, selectedJobId, hasResult, liveJobs]);

  useEffect(() => () => listRequest.current?.abort(), []);

  useEffect(() => {
    function syncView() {
      const [id, query] = window.location.hash.slice(1).split("?", 2);
      if (id === "scan-history" && query !== undefined) {
        setNotice("");
        setRoute(previous => ({ view: "source-scan", query,
          keepFindings: previous.view === "findings" || (previous.view === "source-scan" && previous.keepFindings) }));
        return;
      }
      const target = sections.find(section => section.id === id);
      if (target) setRoute({ view: target.id });
      else if (id === "scan-history" || id === "scan-detail") setRoute({ view: "scan-history" });
      else setRoute({ view: id === "endpoint-onboarding" ? id : "dashboard" });
    }
    syncView();
    window.addEventListener("hashchange", syncView);
    return () => window.removeEventListener("hashchange", syncView);
  }, []);

  async function loadJobs(accessToken: string, mode: "connect" | "refresh" | "older") {
    listRequest.current?.abort();
    const request = new AbortController();
    listRequest.current = request;
    setLoading(true);
    setIssue("");
    setDialogIssue("");
    try {
      const offset = mode === "older" ? liveJobs.length : 0;
      const [entries, targets] = await Promise.all([
        readAPI<Job[]>(`scan-jobs?limit=${batchSize}&offset=${offset}`, accessToken, request.signal),
        mode === "older" ? null : readAPI<ScanTargets>("scan-targets", accessToken, request.signal),
      ]);
      if (request.signal.aborted) return;
      if (targets) { setCanManage(targets.can_manage); setCanOnboard(targets.can_onboard); setEndpoints(targets.endpoints); }
      setHasOlder(entries.length === batchSize);
      if (mode === "older") {
        setLiveJobs(previous => [...previous, ...entries.filter(entry => !previous.some(job => job.id === entry.id))]);
      } else {
        setLiveJobs(entries);
        setDetail(null);
        setPage(0);
      }
      if (mode === "connect") {
        setToken(accessToken);
        setSelectedId(entries[0]?.id ?? "");
        setSearch("");
        setStatus("all");
        dialog.current?.close();
      }
    } catch (error) {
      if (!request.signal.aborted) {
        const message = error instanceof Error ? error.message : "Could not connect to the API.";
        (mode === "connect" ? setDialogIssue : setIssue)(message);
      }
    } finally {
      if (!request.signal.aborted) setLoading(false);
    }
  }

  function connect(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const value = String(new FormData(event.currentTarget).get("token") ?? "").trim();
    if (value) void loadJobs(value, "connect");
  }

  function disconnect() {
    listRequest.current?.abort();
    setLoading(false); setToken(""); setLiveJobs([]); setDetail(null); setIssue(""); setSearch(""); setStatus("all");
    setSelectedId(previewJobs[0].id); setPage(0);
    setCanManage(false); setCanOnboard(false); setEndpoints([]); setScanAction(null); setAttachTarget(null); setNotice("");
  }

  function saveScan(job: Job, action: ScanAction) {
    listRequest.current?.abort();
    setLoading(false);
    const next = [job, ...liveJobs.filter(entry => entry.id !== job.id)].sort((a, b) =>
      Date.parse(b.created_at) - Date.parse(a.created_at) || b.id.localeCompare(a.id));
    setLiveJobs(next);
    setSelectedId(job.id);
    setStatus("all"); setSearch("");
    setPage(Math.floor(next.findIndex(entry => entry.id === job.id) / pageSize));
    setScanAction(null); setIssue("");
    setNotice(action.kind === "cancel" ? `Scan #${shortId(job.id)} canceled.` : `Scan #${shortId(job.id)} · ${label(job.status)}`);
  }

  function attachFinding(jobId: string, finding: ScanFinding) {
    setNotice("");
    setAttachTarget({ jobId, finding });
  }

  const stats = [
    { name: "Total scans", count: jobs.length, icon: Layers3, tone: "ink", caption: live ? "Loaded scan jobs" : "Scans in preview" },
    { name: "Completed", count: jobs.filter(job => job.status === "completed").length, icon: Check, tone: "green", caption: "Full collection" },
    { name: "In progress", count: jobs.filter(job => activeStatuses.includes(job.status)).length, icon: Activity, tone: "blue", caption: "Queued or running" },
    { name: "Coverage gaps", count: jobs.filter(job => job.status === "partial").length, icon: TriangleAlert, tone: "amber", caption: "Partial collection" },
  ];
  const assessment = !live && selected && hasResult ? previewAssessment(selected) : live && hasResult && detail?.id === selectedJobId ? detail?.data ?? null : null;

  return <div className="shell">
    <aside className="sidebar" ref={sidebar}>
      <a className="brand" href="#dashboard"><span className="brand-mark"><ShieldCheck size={23} strokeWidth={2} /></span><span>PersistGuard</span></a>
      <div className="side-body"><p className="nav-label">OPERATIONS</p>
        <nav aria-label="Workspace">
          {sections.map(({ id, label, icon: Icon }) => <a key={id} href={`#${id}`} className={currentView === id ? "nav-current" : ""}
            aria-current={currentView === id ? "page" : undefined}><Icon size={18} />{label}</a>)}
          <a className={currentView === "scan-history" ? "nav-current" : ""} href="#scan-history" aria-current={currentView === "scan-history" ? "page" : undefined}>
            <Layers3 size={18} />Scan history</a>
          {live && canOnboard && <a className={currentView === "endpoint-onboarding" ? "nav-current" : ""} href="#endpoint-onboarding"
            aria-current={currentView === "endpoint-onboarding" ? "page" : undefined}><UserRoundPlus size={18} />Endpoint onboarding</a>}
        </nav>
      </div>
      <div className="side-footer"><span className={`side-dot ${live ? "is-live" : ""}`} /><div><strong>{live ? "Live workspace" : "Preview workspace"}</strong><small>{live ? "PersistGuard API" : "Sample scan data"}</small></div></div>
    </aside>
    <div className="workspace">
      <header className="topbar" ref={topbar}>
        <div className="breadcrumb"><span>Operations</span><ChevronRight size={15} /><strong>{viewLabel}</strong></div>
        <button className="button connect" type="button" onClick={() => { setDialogIssue(""); dialog.current?.showModal(); }}>
          <Plug size={16} />{live ? "API connected" : "Connect API"}
        </button>
      </header>
      {(findingsOpen || (sourceScanOpen && route.keepFindings)) && <div hidden={!findingsOpen}>
        <WorkspaceSection key={`findings-${live}`} section="findings" token={token} />
      </div>}
      {findingsOpen ? null : sourceScanOpen ?
        <SourceScan key={`${route.query}-${live}`} target={parseScanFinding(route.query)} token={token} endpoints={endpoints} notice={notice}
          attach={canManage ? attachFinding : undefined} /> :
        currentView === "endpoint-onboarding" ? <EndpointOnboarding token={token} /> : currentView !== "scan-history" ?
        <WorkspaceSection key={`${currentView}-${live}`} section={currentView} token={token} /> : <main id="overview">
        <div className="heading"><div><h1>Scan history</h1><p>Review endpoint scans, findings, and collection coverage.</p></div>
          <div className="heading-actions">
            <button className="button refresh" type="button" disabled={!live || loading} onClick={() => { setNotice(""); void loadJobs(token, "refresh"); }}><RefreshCw size={15} className={loading && live ? "spin" : ""} /> Refresh</button>
            {live && canManage && <button className="button primary" type="button" onClick={() => { setNotice(""); setScanAction({ kind: "queue" }); }}><Plus size={16} /> Queue scan</button>}
          </div>
        </div>
        <div className="stats" aria-label="Scan summary">{stats.map(({ name, count, icon: Icon, tone, caption }) =>
          <div className="stat panel" key={name}><div className="stat-line"><span>{name}</span><span className={`stat-icon ${tone}`}><Icon size={17} /></span></div><strong>{count}</strong><small>{caption}</small></div>
        )}</div>
        {issue && <p className="api-error" role="alert"><CircleAlert size={16} />{issue}</p>}
        {notice && <p className="action-notice" role="status"><Check size={16} />{notice}</p>}
        <div className="content-grid" id="scan-history">
          <section className="jobs panel" aria-label="Inventory jobs">
            <div className="table-heading"><div><h2>Inventory jobs</h2><p>{live ? "Scans in your organization" : "Sample scans for this preview"}</p></div><span className="jobs-count">{jobs.length} scans</span></div>
            <div className="filters"><label className="search"><Search size={17} /><input aria-label="Search scans or endpoints" placeholder="Search scans or endpoints" value={search} onChange={event => { setSearch(event.target.value); setPage(0); }} /></label>
              <label className="filter"><ListFilter size={16} /><select aria-label="Filter by status" value={status} onChange={event => { setStatus(event.target.value); setPage(0); }}>
                <option value="all">All statuses</option><option value="active">In progress</option>
                {['completed','partial','failed','canceled','queued'].map(name => <option key={name} value={name}>{label(name)}</option>)}
              </select><ChevronDown size={14} /></label></div>
            <div className="table-scroll"><table><thead><tr><th>Scan</th><th>Endpoint</th><th>Status</th><th>Created <ArrowDown size={12} /></th><th aria-label="Open details" /></tr></thead>
              <tbody>{items.map(job => <tr key={job.id} className={selected?.id === job.id ? "selected" : ""}>
                <td><button className="scan-button" type="button" aria-pressed={selected?.id === job.id} onClick={() => setSelectedId(job.id)}><strong>{scanTypeLabel(job.scan_type)}</strong><small className="mono">#{shortId(job.id)}</small></button></td>
                <td><span className="endpoint" title={job.endpoint_id}><Monitor size={15} /><span className="mono">{job.endpointLabel ?? shortId(job.endpoint_id)}</span></span></td>
                <td><Badge status={job.status} /></td>
                <td><div className="scan-date">{dateFormat.format(new Date(job.created_at))}<small>{timeFormat.format(new Date(job.created_at))}</small></div></td>
                <td className="chevron"><ChevronRight size={15} /></td>
              </tr>)}</tbody></table>
              {!items.length && <div className="empty"><ClipboardList size={24} /><strong>{jobs.length ? "No matching scans" : "No scans yet"}</strong><p>{jobs.length ? "Try a different search or status filter." : "Queued scans will appear here."}</p></div>}
            </div>
            <footer className="pagination"><span>{items.length ? `${currentPage * pageSize + 1}–${currentPage * pageSize + items.length} of ${filtered.length}` : "0 scans"}</span><div>
              {live && hasOlder && <button type="button" className="button" disabled={loading} onClick={() => void loadJobs(token, "older")}>Load older</button>}
              <button className="button icon-button" type="button" aria-label="Previous page" disabled={currentPage === 0} onClick={() => setPage(currentPage - 1)}><ArrowLeft size={15} /></button>
              <button className="button icon-button" type="button" aria-label="Next page" disabled={currentPage === lastPage} onClick={() => setPage(currentPage + 1)}><ArrowRight size={15} /></button>
            </div></footer>
          </section>
          <ScanDetail key={selectedJobId} job={selected} assessment={assessment}
            pending={Boolean(live && selectedJobId && hasResult && detail?.id !== selectedJobId)} error={detail?.id === selectedJobId ? detail?.error ?? "" : ""}
            attach={live && canManage && selected ? finding => attachFinding(selected.id, finding) : undefined}
            cancel={live && canManage && selected?.status === "queued" ? () => { setNotice(""); setScanAction({ kind: "cancel", job: selected }); } : undefined} />
        </div>
      </main>}
    </div>
    <dialog ref={dialog} onClose={() => {
      if (!live) { listRequest.current?.abort(); setLoading(false); }
      dialog.current?.querySelector("form")?.reset();
    }}>
      <div className="dialog-title"><div><h2>{live ? "API connected" : "Connect to PersistGuard"}</h2><p>{live ? "This browser session is using live scan data." : "Enter a linked account’s API access token."}</p></div>
        <button className="button icon-button" type="button" aria-label="Close" onClick={() => dialog.current?.close()}><X size={17} /></button></div>
      {live ? <button type="button" className="button" onClick={() => { disconnect(); dialog.current?.close(); }}>Disconnect</button> : <form onSubmit={connect}>
        <label htmlFor="api-token">Access token</label><input id="api-token" type="password" name="token" required autoComplete="off" />
        {dialogIssue && <p role="alert" className="api-error">{dialogIssue}</p>}
        <button type="submit" className="button primary" disabled={loading}>{loading ? "Connecting…" : "Connect API"}</button>
      </form>}
    </dialog>
    {scanAction && <ScanControlDialog action={scanAction} token={token} close={() => setScanAction(null)} onSaved={saveScan} />}
    {attachTarget && <AttachFindingDialog token={token} jobId={attachTarget.jobId} finding={attachTarget.finding} close={() => setAttachTarget(null)}
      saved={title => { setAttachTarget(null); setNotice(`Finding attached to ${title}.`); }} />}
  </div>;
}
