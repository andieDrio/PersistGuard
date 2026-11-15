"use client";

import { useEffect, useRef, useState, type FormEvent } from "react";
import { Download, FlaskConical, Plus, RefreshCw, Upload, X } from "lucide-react";
import { readAPI } from "./api";

const sources = { registry: "Startup Registry", scheduled_tasks: "Scheduled Tasks", services: "Windows Services" };
const fields = { command: "Command", path: "Artifact path" };
type Definition = { name: string; source: keyof typeof sources; field: keyof typeof fields; pattern: string; score: number };
type Rule = Definition & { id: string; revision: number; enabled: boolean; tested: boolean; draft_version: number; published_version: number | null };
type PublishedRule = Definition & { version: number; published_at: string | null };
type RuleList = { can_manage: boolean; rules: Rule[] };
type Sample = { path: string; command: string };
type TestResult = { rule: Rule; matched_indices: number[] };
type YAMLExport = { filename: string; yaml: string };

const publishedDate = new Intl.DateTimeFormat("en-SG", {
  day: "numeric", month: "short", year: "numeric", hour: "2-digit", minute: "2-digit",
  timeZone: "Asia/Singapore", timeZoneName: "short",
});

const blank: Definition = { name: "", source: "services", field: "command", pattern: "", score: 40 };
const sampleRows: Sample[] = [
  { path: "FixtureAgent", command: "C:\\Fixtures\\fixture-agent.exe" },
  { path: "FixtureUpdater", command: "C:\\Fixtures\\fixture-updater.exe" },
];

const yamlTemplate = `schema_version: 1
title: Fixture service command
platform: windows
conditions:
  source: services
  field: command
  contains: fixture-agent.exe
risk:
  base_score: 40
response:
  action: alert_only
`;

function RuleYAMLImport({ token, close, saved }: { token: string; close: () => void; saved: (rule: Rule) => void }) {
  const dialog = useRef<HTMLDialogElement>(null);
  const inFlight = useRef<AbortController | null>(null);
  const [text, setText] = useState(yamlTemplate);
  const [example, setExample] = useState<Definition>();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const tooLarge = new TextEncoder().encode(text).length > 16 * 1024;

  useEffect(() => {
    if (dialog.current && !dialog.current.open) dialog.current.showModal();
    return () => inFlight.current?.abort();
  }, []);

  function replaceText(value: string) {
    setText(value); setExample(undefined); setError("");
  }

  async function loadFile(file: File) {
    setExample(undefined); setError("");
    if (file.size > 16 * 1024) { setError("Rule YAML exceeds the 16 KiB limit."); return; }
    setBusy(true);
    try { replaceText(await file.text()); }
    catch { setError("The YAML file could not be read."); }
    finally { setBusy(false); }
  }

  async function submit(importDraft: boolean) {
    if (busy || tooLarge || !text.trim() || (importDraft && !example)) return;
    const request = new AbortController();
    inFlight.current = request;
    setBusy(true); setError("");
    if (!importDraft) setExample(undefined);
    try {
      if (importDraft) {
        const rule = await readAPI<Rule>("detection-rules/import", token, request.signal, "POST", { yaml: text });
        if (!request.signal.aborted) saved(rule);
      } else {
        const definition = await readAPI<Definition>("detection-rules/import/validate", token, request.signal, "POST", { yaml: text });
        if (!request.signal.aborted) setExample(definition);
      }
    } catch (cause) {
      if (!request.signal.aborted) setError(cause instanceof Error ? cause.message : "Rule YAML could not be processed.");
    } finally {
      if (!request.signal.aborted) setBusy(false);
    }
  }

  return <dialog className="rule-yaml-dialog" ref={dialog} aria-labelledby="rule-yaml-title" onClose={close} onCancel={event => {
    if (busy) event.preventDefault();
  }}>
    <div className="dialog-title"><div><h2 id="rule-yaml-title">Import rule YAML</h2><p>Validate a Windows rule, then import it as a draft.</p></div>
      <button className="button icon-button" type="button" aria-label="Close" disabled={busy} onClick={() => dialog.current?.close()}><X size={17} /></button></div>
    <form onSubmit={event => { event.preventDefault(); void submit(false); }}>
      <label htmlFor="rule-yaml-file">YAML file</label>
      <input id="rule-yaml-file" type="file" accept=".yaml,.yml,text/yaml,application/yaml" disabled={busy}
        onChange={event => { if (event.target.files?.[0]) void loadFile(event.target.files[0]); }} />
      <label htmlFor="rule-yaml-text">YAML document</label>
      <textarea id="rule-yaml-text" className="mono" rows={12} spellCheck={false} value={text} disabled={busy}
        onChange={event => replaceText(event.target.value)} />
      {(error || tooLarge) && <p className="api-error" role="alert">{error || "Rule YAML exceeds the 16 KiB limit."}</p>}
      {example && <p className="action-notice" role="status"><strong>{example.name}</strong> · {sources[example.source]} · {fields[example.field]} contains {example.pattern} · {example.score} pts</p>}
      <div className="action-footer">
        <button className="button" type="submit" disabled={busy || tooLarge || !text.trim()}>Validate YAML</button>
        <button className="button primary" type="button" disabled={busy || !example || tooLarge} onClick={() => void submit(true)}>Import draft</button>
      </div>
    </form>
  </dialog>;
}

function RuleState({ rule }: { rule: Rule }) {
  return <span className={`badge ${rule.enabled ? "green" : rule.tested ? "blue" : "neutral"}`}><span />
    {rule.enabled ? `Active v${rule.published_version}` : rule.published_version !== null ? "Disabled" : rule.tested ? "Tested draft" : "Draft"}</span>;
}

function RuleHistory({ rule, token, exportVersion, rollbackVersion, exporting }: {
  rule: Rule; token: string; exportVersion?: (version: number) => void; rollbackVersion?: (version: number) => void; exporting: boolean;
}) {
  const [versions, setVersions] = useState<PublishedRule[]>([]);
  const [cursor, setCursor] = useState<number | null>(null);
  const [hasMore, setHasMore] = useState(false);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(true);
  useEffect(() => {
    const controller = new AbortController();
    const query = cursor === null ? "" : `?before=${cursor}`;
    readAPI<PublishedRule[]>(`detection-rules/${rule.id}/versions${query}`, token, controller.signal)
      .then(items => {
        if (controller.signal.aborted) return;
        setVersions(previous => cursor === null ? items : [...previous, ...items]);
        setHasMore(items.length === 25);
      }).catch(cause => { if (!controller.signal.aborted) setError(cause.message); })
      .finally(() => { if (!controller.signal.aborted) setLoading(false); });
    return () => controller.abort();
  }, [rule.id, token, cursor]);
  return <section className="rule-history section-note" aria-label="Rule version history">
    <h2>Published versions · {rule.name}</h2>
    {loading && <p role="status">Loading versions…</p>}
    {error && <p role="alert">{error}</p>}
    {!versions.length && !loading && !error && <p>No versions published yet.</p>}
    {!!versions.length && <div className="table-scroll"><table><thead><tr><th>Version</th><th>Definition</th><th>Points</th><th>Published</th>
      {exportVersion && <th>Export</th>}{rollbackVersion && <th>Restore</th>}</tr></thead>
      <tbody>{versions.map(version => <tr key={version.version}>
        <td>v{version.version}{version.version === rule.published_version && rule.enabled ? " · Active" : ""}</td>
        <td className="rule-condition"><strong>{version.name}</strong><br />{sources[version.source]} · {fields[version.field]} contains <code>{version.pattern}</code></td>
        <td>{version.score}</td><td>{version.published_at ? publishedDate.format(new Date(version.published_at)) : "Date unavailable"}</td>
        {exportVersion && <td><button className="button" type="button" disabled={exporting}
          onClick={() => exportVersion(version.version)}><Download size={15} />Export v{version.version}</button></td>}{rollbackVersion && <td><button className="button" type="button" disabled={exporting || (rule.enabled && rule.published_version === version.version)} onClick={() => rollbackVersion(version.version)}>Restore v{version.version}</button></td>}
      </tr>)}</tbody></table></div>}
    {hasMore && <button className="button" type="button" disabled={loading} onClick={() => {
      setError(""); setLoading(true); setCursor(versions[versions.length - 1].version);
    }}>Load older versions</button>}
  </section>;
}

export function DetectionRules({ token }: { token: string }) {
  const [data, setData] = useState<RuleList>();
  const [selected, setSelected] = useState<Rule | null>(null);
  const [historyId, setHistoryId] = useState<string | null>(null);
  const [editing, setEditing] = useState(false);
  const [importing, setImporting] = useState(false);
  const [draft, setDraft] = useState<Definition>(blank);
  const [samples, setSamples] = useState(sampleRows);
  const [matches, setMatches] = useState<number[] | null>(null);
  const [loadError, setLoadError] = useState("");
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [busy, setBusy] = useState(false);
  const [loading, setLoading] = useState(Boolean(token));
  const [refresh, setRefresh] = useState(0);
  const [exporting, setExporting] = useState(false);
  const [exportFeedback, setExportFeedback] = useState<{ status: "success" | "error"; message: string }>();
  const exportRequest = useRef<AbortController | null>(null);

  useEffect(() => () => exportRequest.current?.abort(), []);

  useEffect(() => {
    if (!token) return;
    const controller = new AbortController();
    readAPI<RuleList>("detection-rules", token, controller.signal).then(result => {
      if (!controller.signal.aborted) { setData(result); setLoadError(""); }
    }).catch(cause => {
      if (!controller.signal.aborted) setLoadError(cause instanceof Error ? cause.message : "Could not load rules.");
    }).finally(() => {
      if (!controller.signal.aborted) setLoading(false);
    });
    return () => controller.abort();
  }, [token, refresh]);

  function open(rule: Rule | null) {
    setSelected(rule);
    setDraft(rule ? { name: rule.name, source: rule.source, field: rule.field, pattern: rule.pattern, score: rule.score } : blank);
    setEditing(true); setSamples(sampleRows); setMatches(null); setError(""); setNotice("");
  }

  function updateRule(rule: Rule) {
    setSelected(rule);
    setDraft({ name: rule.name, source: rule.source, field: rule.field, pattern: rule.pattern, score: rule.score });
    setData(current => current && { ...current, rules: [...current.rules.filter(entry => entry.id !== rule.id), rule]
      .sort((a, b) => a.name.localeCompare(b.name) || a.id.localeCompare(b.id)) });
  }

  async function perform(action: () => Promise<void>) {
    setBusy(true); setError(""); setNotice("");
    try { await action(); }
    catch (cause) { setError(cause instanceof Error ? cause.message : "Could not save the rule."); }
    finally { setBusy(false); }
  }

  async function downloadYAML(rule: Rule, version?: number) {
    const controller = new AbortController();
    exportRequest.current = controller;
    setExporting(true); setExportFeedback(undefined);
    try {
      const query = version === undefined ? `revision=${rule.revision}` : `version=${version}`;
      const data = await readAPI<YAMLExport>(`detection-rules/${encodeURIComponent(rule.id)}/export?${query}`, token, controller.signal);
      if (controller.signal.aborted) return;
      const url = URL.createObjectURL(new Blob([data.yaml], { type: "application/yaml;charset=utf-8" }));
      const link = document.createElement("a");
      link.href = url; link.download = data.filename;
      document.body.append(link);
      link.click();
      link.remove();
      window.setTimeout(() => URL.revokeObjectURL(url), 1000);
      const label = version === undefined ? `Draft v${rule.draft_version}` : `Published v${version}`;
      setExportFeedback({ status: "success", message: `${label} YAML sent to your browser for download.` });
    } catch (cause) {
      if (!controller.signal.aborted) setExportFeedback({ status: "error", message: cause instanceof Error ? cause.message : "Could not export YAML." });
    } finally {
      if (!controller.signal.aborted) setExporting(false);
    }
  }

  async function save(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    await perform(async () => {
      const rule = await readAPI<Rule>(selected ? `detection-rules/${selected.id}` : "detection-rules", token,
        AbortSignal.timeout(10000), selected ? "PUT" : "POST", selected ? { ...draft, revision: selected.revision } : draft);
      updateRule(rule); setMatches(null);
      setNotice(`Draft v${rule.draft_version} saved. Test a matching sample before publishing.`);
    });
  }

  async function test(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!selected) return;
    await perform(async () => {
      const result = await readAPI<TestResult>(`detection-rules/${selected.id}/test`, token, AbortSignal.timeout(10000),
        "POST", { revision: selected.revision, samples });
      updateRule(result.rule); setMatches(result.matched_indices);
    });
  }

  async function changeActivation(enabled: boolean) {
    if (!selected) return;
    await perform(async () => {
      const rule = await readAPI<Rule>(`detection-rules/${selected.id}/activation`, token, AbortSignal.timeout(10000),
        "PUT", { revision: selected.revision, enabled });
      updateRule(rule);
      setNotice(rule.enabled ? `Version ${rule.published_version} is active for scan assessments.` : "Rule disabled.");
    });
  }

  async function rollbackVersion(rule: Rule, version: number) {
    if (!window.confirm(`Restore published v${version} for "${rule.name}"? This immediately changes live scoring. The draft and history will be preserved.`)) return;
    await perform(async () => {
      const updated = await readAPI<Rule>(`detection-rules/${rule.id}/rollback`, token, AbortSignal.timeout(10000),
        "POST", { revision: rule.revision, version });
      updateRule(updated);
      setRefresh(value => value + 1);
      setNotice(`Published v${version} restored and active. Existing history preserved.`);
    });
  }

  if (!token) return <p className="panel section-note rules-panel">Connect the API to view your tenant’s custom rules.</p>;
  const dirty = Boolean(selected && (Object.keys(draft) as (keyof Definition)[]).some(field => draft[field] !== selected[field]));
  const locked = busy || loading;
  const historyRule = data?.rules.find(rule => rule.id === historyId);
  const hasDraft = selected && selected.draft_version !== selected.published_version;
  const feedback = <>
    {error && <p className="api-error rules-message" role="alert">{error}</p>}
    {notice && <p className="action-notice rules-message" role="status">{notice}</p>}
  </>;

  return <section className="panel rules-panel" aria-labelledby="custom-rules-title">
    <div className="table-heading"><h2 id="custom-rules-title">Custom rules</h2><div className="heading-actions">
      <button className="button" type="button" disabled={locked} onClick={() => { setLoading(true); setRefresh(value => value + 1); }}><RefreshCw size={15} />Refresh rules</button>
      {data?.can_manage && <button className="button" type="button" disabled={locked} onClick={() => setImporting(true)}><Upload size={15} />Import YAML</button>}
      {data?.can_manage && <button className="button primary" type="button" disabled={locked} onClick={() => open(null)}><Plus size={16} />New rule</button>}
    </div></div>
    {loadError && <p className="api-error rules-message" role="alert">{loadError}</p>}
    {exporting && <p className="rules-message" role="status">Preparing YAML…</p>}
    {exportFeedback && <p className={`rules-message ${exportFeedback.status === "error" ? "api-error" : "action-notice"}`}
      role={exportFeedback.status === "error" ? "alert" : "status"}>{exportFeedback.message}</p>}
    {!data && !loadError && <p className="section-note" role="status">Loading rules…</p>}
    {data?.rules.length === 0 && <p className="section-note">No custom rules yet.</p>}
    {!!data?.rules.length && <div className="table-scroll"><table><thead><tr><th>Rule</th><th>Source</th><th>Match condition</th><th>Points</th><th>Status</th>
      <th aria-label="Rule actions" /></tr></thead><tbody>{data.rules.map(rule => <tr key={rule.id} className={selected?.id === rule.id ? "selected" : ""}>
      <td><strong>{rule.name}</strong></td><td>{sources[rule.source]}</td><td className="rule-condition">{fields[rule.field]} contains <code>{rule.pattern}</code></td>
      <td>{rule.score}</td><td><RuleState rule={rule} />{rule.published_version !== null && rule.published_version !== rule.draft_version && <div>Draft v{rule.draft_version}</div>}</td>
      <td><div className="rule-controls"><button type="button" className="button" aria-expanded={historyId === rule.id} aria-label={`Version history for ${rule.name}`}
        onClick={() => setHistoryId(historyId === rule.id ? null : rule.id)}>History</button>
        {data.can_manage && <button type="button" className="button" disabled={locked || exporting} aria-label={`Export saved draft of ${rule.name}`}
          onClick={() => void downloadYAML(rule)}><Download size={15} />Export draft</button>}
        {data.can_manage && <button type="button" className="button" disabled={locked} aria-label={`Edit ${rule.name}`} onClick={() => open(rule)}>Edit</button>}</div></td>
    </tr>)}</tbody></table></div>}
    {!editing && feedback}
    {historyRule && <RuleHistory key={`${historyRule.id}-${historyRule.published_version}-${refresh}`} rule={historyRule} token={token}
      exporting={locked || exporting} exportVersion={data?.can_manage ? version => void downloadYAML(historyRule, version) : undefined} rollbackVersion={data?.can_manage ? version => void rollbackVersion(historyRule, version) : undefined} />}
    {importing && <RuleYAMLImport token={token} close={() => setImporting(false)} saved={rule => {
      setImporting(false); open(rule); updateRule(rule); setNotice("YAML imported as a draft. Test a matching sample before publishing.");
    }} />}
    {editing && data?.can_manage && <div className="rule-editor">
      <div className="table-heading"><h2>{selected ? "Edit rule" : "New rule"}</h2>
        <button className="button" type="button" disabled={busy} onClick={() => { setEditing(false); setSelected(null); }}>Close editor</button></div>
      <form onSubmit={save}><fieldset className="rule-form rule-definition" disabled={locked} aria-label="Rule definition">
        <label>Rule name<input required maxLength={100} value={draft.name} onChange={event => setDraft({ ...draft, name: event.target.value })} /></label>
        <label>Source<select value={draft.source} onChange={event => setDraft({ ...draft, source: event.target.value as Definition["source"] })}>
          {Object.entries(sources).map(([key, name]) => <option key={key} value={key}>{name}</option>)}
        </select></label>
        <label>Match field<select value={draft.field} onChange={event => setDraft({ ...draft, field: event.target.value as Definition["field"] })}>
          {Object.entries(fields).map(([key, name]) => <option key={key} value={key}>{name}</option>)}
        </select></label>
        <label>Contains text<input required maxLength={256} placeholder="fixture-agent.exe" value={draft.pattern} onChange={event => setDraft({ ...draft, pattern: event.target.value })} /></label>
        <label>Points<input type="number" required min={1} max={100} value={Number.isNaN(draft.score) ? "" : draft.score} onChange={event => setDraft({ ...draft, score: event.target.valueAsNumber })} /></label>
        <div className="rule-controls"><button className="button primary" disabled={!!selected && !dirty}>Save draft</button></div>
        {selected?.enabled && (dirty || hasDraft) && <p className="rule-form-note">Version {selected.published_version} stays active until you publish a tested draft.</p>}
      </fieldset></form>
      {selected && !dirty && <form className="rule-test" onSubmit={test}>
        <h2>Test on sample inventory</h2>
        <p>Matching is case-insensitive. Edit the samples to check both a match and a non-match.</p>
        {samples.map((sample, index) => <fieldset className="rule-form" key={index} disabled={locked}>
          <legend>Sample {index + 1}{matches && <span className={`badge ${matches.includes(index) ? "green" : "neutral"}`}>
            {matches.includes(index) ? "Match" : "No match"}</span>}</legend>
          <label>Artifact path<input maxLength={2048} value={sample.path} onChange={event => {
            setMatches(null); setSamples(samples.map((item, key) => key === index ? { ...item, path: event.target.value } : item));
          }} /></label>
          <label>Command<input maxLength={4096} value={sample.command} onChange={event => {
            setMatches(null); setSamples(samples.map((item, key) => key === index ? { ...item, command: event.target.value } : item));
          }} /></label>
        </fieldset>)}
        <div className="rule-controls"><button className="button" disabled={locked}><FlaskConical size={15} />Run test</button>
          {(hasDraft || !selected.enabled) && <button className="button primary" type="button" disabled={locked || !selected.tested} onClick={() => void changeActivation(true)}>
            {hasDraft ? `Publish v${selected.draft_version}` : "Enable rule"}</button>}
          {selected.enabled && <button className="button" type="button" disabled={locked} onClick={() => void changeActivation(false)}>Disable rule</button>}</div>
        {matches && <p role="status">{matches.length} of {samples.length} samples matched.{matches.length > 0 ? ` Each match adds ${selected.score} points.` : ""}</p>}
      </form>}
      {feedback}
    </div>}
  </section>;
}
