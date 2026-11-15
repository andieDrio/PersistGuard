"use client";

import { useEffect, useState, type FormEvent } from "react";
import { Activity, ArrowLeft, ArrowRight, Building2, ClipboardList, Fingerprint, LayoutDashboard, ShieldAlert,
  Monitor, Network, Plus, ShieldCheck, Unplug, type LucideIcon } from "lucide-react";
import { readAPI } from "./api";
import { AttackCoverage } from "./attack-coverage";
import { CaseEvidenceDialog } from "./case-findings";
import { FindingsWorkspace } from "./findings-workspace";
import { DetectionRules } from "./detection-rules";

export const sections = [
  { id: "dashboard", label: "Dashboard", icon: LayoutDashboard },
  { id: "cases", label: "Cases", icon: ClipboardList },
  { id: "findings", label: "Findings", icon: ShieldAlert },
  { id: "endpoints", label: "Endpoints", icon: Monitor },
  { id: "tenant", label: "Tenant", icon: Building2 },
  { id: "network", label: "Network", icon: Network },
  { id: "rules-and-detection", label: "Rules and Detection", icon: ShieldCheck },
  { id: "iocs", label: "IOCs", icon: Fingerprint },
] as const;

type Section = typeof sections[number]["id"];
type CaseStatus = "new" | "in_progress" | "resolved";
type Case = { id: string; title: string; status: CaseStatus };
type Endpoint = { id: string; hostname: string; last_seen: string | null; created_at: string; os_family: string; status: string; connected: boolean };
type Indicator = { id: string; kind: string; value: string };
type Snapshot = {
  tenant: { name: string; count: number }; can_manage: boolean;
  endpoint_counts?: { total: number; new_installed: number; connected: number; disconnected: number };
  case_counts?: Record<CaseStatus, number>; indicator_count?: number;
  cases?: Case[]; endpoints?: Endpoint[]; indicators?: Indicator[];
};
const caseStatuses = { new: "New", in_progress: "In Progress", resolved: "Resolved" } as const;
const statuses = Object.keys(caseStatuses) as CaseStatus[];
const indicatorKinds = { ip: "IP address", domain: "Domain", sha256: "SHA-256", url: "URL" };
const pageSize = 50;
const timestamp = new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" });

function StatCards({ cards }: { cards: { label: string; value?: number; icon: LucideIcon; tone: string; caption?: string; href?: string }[] }) {
  return <div className="stats">{cards.map(({ label, value, icon: Icon, tone, caption, href }) => {
    const content = <><div className="stat-line"><span>{label}</span><span className={`stat-icon ${tone}`}><Icon size={17} /></span></div>
      <strong>{value?.toLocaleString() ?? "—"}</strong>{caption && <small>{caption}</small>}</>;
    return href ? <a className="stat panel stat-link" key={label} href={href}>{content}</a> : <div className="stat panel" key={label}>{content}</div>;
  })}</div>;
}

export function WorkspaceSection({ section, token }: { section: Section; token: string }) {
  const [loaded, setLoaded] = useState<{ offset: number; snapshot: Snapshot }>();
  const [issue, setIssue] = useState("");
  const [mutationIssue, setMutationIssue] = useState("");
  const [feedback, setFeedback] = useState("");
  const [saving, setSaving] = useState(false);
  const [offset, setOffset] = useState(0);
  const [revision, setRevision] = useState(0);
  const [detectionView, setDetectionView] = useState<"rules" | "coverage">("rules");
  const [evidenceCase, setEvidenceCase] = useState<{ id: string; title: string } | null>(null);
  const snapshot = loaded?.offset === offset ? loaded.snapshot : undefined;
  const heading = sections.find(entry => entry.id === section)!.label;
  const hasData = section !== "network" && section !== "rules-and-detection" && section !== "findings";

  useEffect(() => {
    if (!token || !hasData) return;
    const controller = new AbortController();
    let pending = false;
    async function refresh() {
      if (pending) return;
      pending = true;
      try {
        const data = await readAPI<Snapshot>(`workspace?section=${section}&offset=${offset}`, token, controller.signal);
        if (!controller.signal.aborted) { setLoaded({ offset, snapshot: data }); setIssue(""); }
      } catch (error) {
        if (!controller.signal.aborted) setIssue(error instanceof Error ? error.message : "Workspace unavailable.");
      } finally {
        pending = false;
      }
    }
    void refresh();
    const interval = section === "endpoints" || section === "dashboard" ? window.setInterval(refresh, 15000) : undefined;
    return () => { controller.abort(); window.clearInterval(interval); };
  }, [section, token, offset, hasData, revision]);

  async function save(path: string, method: string, body: Record<string, string>, message: string) {
    setMutationIssue(""); setFeedback(""); setSaving(true);
    try {
      await readAPI(path, token, AbortSignal.timeout(10000), method, body);
      if (method === "POST") setOffset(0);
      setFeedback(message);
      setRevision(current => current + 1);
      return true;
    } catch (error) {
      setMutationIssue(error instanceof Error ? error.message : "Could not save changes.");
      return false;
    } finally {
      setSaving(false);
    }
  }

  async function create(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = event.currentTarget;
    const fields = new FormData(form);
    const body: Record<string, string> = section === "cases" ? { title: String(fields.get("title")) } :
      { kind: String(fields.get("kind")), value: String(fields.get("value")) };
    if (await save(`workspace/${section}`, "POST", body, section === "cases" ? "Case created." : "IOC added.")) form.reset();
  }

  const endpoints = snapshot?.endpoint_counts;
  const counts = snapshot?.case_counts;
  const caseTotal = counts && statuses.reduce((total, status) => total + counts[status], 0);
  const listTotal = (section === "cases" ? caseTotal : section === "endpoints" ? endpoints?.total : snapshot?.indicator_count) ?? 0;

  return <main id={section}>
    {section === "findings" ? <><div className="heading"><h1>Findings</h1></div><FindingsWorkspace token={token} /></> : <>
    <div className="heading"><div><h1>{heading}</h1></div></div>
    {section === "dashboard" && <StatCards cards={[
      { label: "Total Number of Endpoints", value: endpoints?.total, icon: Monitor, tone: "ink", href: "#endpoints" },
      { label: "Total Cases", value: caseTotal, icon: ClipboardList, tone: "blue", href: "#cases" },
      { label: "Total Number of Tenants", value: snapshot?.tenant.count, icon: Building2, tone: "green", href: "#tenant" },
      { label: "Number of IOCs", value: snapshot?.indicator_count, icon: Fingerprint, tone: "amber", href: "#iocs" },
    ]} />}
    {section === "cases" && <StatCards cards={statuses.map((status, index) => ({ label: caseStatuses[status], value: counts?.[status],
      icon: ClipboardList, tone: ["ink", "blue", "green"][index] }))} />}
    {section === "endpoints" && <StatCards cards={[
      { label: "Total Number of Endpoints", value: endpoints?.total, icon: Monitor, tone: "ink" },
      { label: "New Installed", value: endpoints?.new_installed, icon: Plus, tone: "blue", caption: "Enrolled in the last 24 hours" },
      { label: "Connected", value: endpoints?.connected, icon: Activity, tone: "green", caption: "Heartbeat within 2 minutes" },
      { label: "Disconnected", value: endpoints?.disconnected, icon: Unplug, tone: "amber", caption: "Approved endpoints without a recent heartbeat" },
    ]} />}
    {section === "tenant" && <StatCards cards={[{ label: "Number of Tenants", value: snapshot?.tenant.count, icon: Building2,
      tone: "green", caption: snapshot?.tenant.name }]} />}
    {section === "network" && <section className="panel section-note"><h2>Planned for a future release</h2></section>}
    {section === "iocs" && <p className="panel section-note ioc-note">Scan assessments match network indicators in command arguments and SHA-256 indicators against collected executable hashes.</p>}
    {section === "rules-and-detection" && <div className="heading-actions detection-navigation" role="group" aria-label="Rules and Detection views">
      <button className={`button ${detectionView === "rules" ? "primary" : ""}`} type="button" aria-pressed={detectionView === "rules"} onClick={() => setDetectionView("rules")}>Rules</button>
      <button className={`button ${detectionView === "coverage" ? "primary" : ""}`} type="button" aria-pressed={detectionView === "coverage"} onClick={() => setDetectionView("coverage")}>ATT&amp;CK Coverage</button>
    </div>}
    {section === "rules-and-detection" && <div hidden={detectionView !== "rules"}><section className="panel section-note"><h2>Windows inventory detection</h2>
      <p>Assessments cover startup Registry entries, Scheduled Tasks, and Windows Services.</p>
      <ul><li>Encoded PowerShell commands</li><li>New startup entries compared with the endpoint’s previous scan</li></ul>
      <a className="button" href="#scan-history">Open scan history <ArrowRight size={15} /></a>
    </section><DetectionRules token={token} /></div>}
    {section === "rules-and-detection" && detectionView === "coverage" && <AttackCoverage token={token} />}
    {!token && hasData && <p className="panel section-note">Connect the API to see your tenant’s live data.</p>}
    {token && !snapshot && !issue && hasData && <p className="panel section-note" role="status">Loading workspace…</p>}
    {issue && <p className="api-error" role="alert">{issue}</p>}
    {mutationIssue && <p className="api-error" role="alert">{mutationIssue}</p>}
    {feedback && <p className="action-notice" role="status">{feedback}</p>}
    {snapshot?.can_manage && (section === "cases" || section === "iocs") && <form className="panel workspace-form" onSubmit={create}>
      {section === "cases" ? <label>Case title<input name="title" required maxLength={200} /></label> : <>
        <label>Type<select name="kind">{Object.entries(indicatorKinds).map(([kind, label]) => <option key={kind} value={kind}>{label}</option>)}</select></label>
        <label>Indicator<input name="value" required maxLength={2048} /></label>
      </>}
      <button className="button primary" disabled={saving}><Plus size={16} />{section === "cases" ? "Create case" : "Add IOC"}</button>
    </form>}
    {snapshot?.cases && <section className="case-grid">{statuses.map(status => {
      const entries = snapshot.cases!.filter(record => record.status === status);
      return <section className="panel case-lane" key={status}><h2>{caseStatuses[status]}</h2>
        {entries.length === 0 && <p>No cases in this view.</p>}
        {entries.map(record => <article className="case-item" key={record.id}><strong>{record.title}</strong>
          <button className="button" type="button" aria-label={`View evidence for ${record.title}`} onClick={() => setEvidenceCase(record)}>Evidence</button>
          {snapshot.can_manage && <select aria-label={`Status for ${record.title}`} value={record.status} disabled={saving} onChange={event => {
            void save(`workspace/cases/${record.id}`, "PATCH", { status: event.target.value }, "Case status updated.");
          }}>{statuses.map(option => <option key={option} value={option}>{caseStatuses[option]}</option>)}</select>}
        </article>)}
      </section>;
    })}</section>}
    {evidenceCase && <CaseEvidenceDialog token={token} record={evidenceCase} close={() => setEvidenceCase(null)} />}
    {snapshot?.endpoints && <section className="panel table-scroll" aria-label="Enrolled endpoints"><table><thead><tr><th>Endpoint</th><th>Platform</th><th>Status</th><th>Last heartbeat</th></tr></thead>
      <tbody>{snapshot.endpoints.map(endpoint => <tr key={endpoint.id}><td><strong>{endpoint.hostname}</strong></td><td>{endpoint.os_family}</td>
        <td><span className={`badge ${endpoint.connected ? "green" : endpoint.status === "approved" ? "amber" : "neutral"}`}><span />
          {endpoint.connected ? "Connected" : endpoint.status === "approved" ? "Disconnected" : endpoint.status}</span></td>
        <td>{endpoint.last_seen ? timestamp.format(new Date(endpoint.last_seen)) : "Never"}</td></tr>)}</tbody>
    </table>{snapshot.endpoints.length === 0 && <p className="section-note">No endpoints in this view.</p>}</section>}
    {snapshot?.indicators && <section className="panel table-scroll" aria-label="Indicators of compromise"><table><thead><tr><th>Type</th><th>Indicator</th></tr></thead>
      <tbody>{snapshot.indicators.map(item => <tr key={item.id}><td>{indicatorKinds[item.kind as keyof typeof indicatorKinds]}</td>
        <td className="mono indicator-value">{item.value}</td></tr>)}</tbody></table>
      {snapshot.indicators.length === 0 && <p className="section-note">No IOCs in this view.</p>}
    </section>}
    {snapshot && listTotal > pageSize && ["cases", "endpoints", "iocs"].includes(section) && <footer className="pagination workspace-pagination">
      <span>{offset + 1}–{Math.min(offset + pageSize, listTotal)} of {listTotal}</span><div>
        <button type="button" className="button icon-button" aria-label="Previous page" disabled={!offset} onClick={() => setOffset(offset - pageSize)}><ArrowLeft size={15} /></button>
        <button type="button" className="button icon-button" aria-label="Next page" disabled={offset + pageSize >= listTotal} onClick={() => setOffset(offset + pageSize)}><ArrowRight size={15} /></button></div>
    </footer>}
  </>}</main>;
}
