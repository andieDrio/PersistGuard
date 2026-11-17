"use client";

import { useEffect, useRef, useState, type FormEvent } from "react";
import { ArrowLeft, Plus, RefreshCw, X } from "lucide-react";
import { APIError, pollWhileVisible, readAPI } from "./api";
import { ScanTargetFields } from "./scan-controls";
import { isUUID, scanScheduleHistoryHref, scanTypeLabel, scheduledScanHref } from "./scan-data";

type Frequency = "daily" | "weekly";
type Schedule = {
  id: string; endpoint_id: string; hostname: string; scan_type: string; frequency: Frequency; enabled: boolean;
  next_run_at: string; last_run_at: string | null; last_outcome: keyof typeof outcomes | null;
};
type SchedulePage = { schedules: Schedule[]; has_more: boolean };
type ScheduleRun = {
  id: string; scheduled_for: string | null; attempted_at: string; outcome: keyof typeof outcomes;
  job_id: string | null; job_status: string | null;
};
type RunPage = { schedule: Schedule; runs: ScheduleRun[]; has_more: boolean };
const frequencies = { daily: "Daily", weekly: "Weekly" };
const outcomes = { queued: "Queued", skipped_busy: "Skipped · unfinished scan", paused_endpoint: "Paused · endpoint ineligible",
  paused_owner: "Paused · scheduler access changed" };
const timeFormat = new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" });
const checkTimeFormat = new Intl.DateTimeFormat("en-GB", { timeStyle: "medium", timeZone: "Asia/Singapore" });
const pageSize = 25;

function localDateTime(value: string) {
  const date = new Date(value);
  return new Date(date.getTime() - date.getTimezoneOffset() * 60_000).toISOString().slice(0, 16);
}

function ScheduleDialog({ record, token, close, saved }: {
  record?: Schedule; token: string; close: () => void; saved: () => void;
}) {
  const dialog = useRef<HTMLDialogElement>(null);
  const submission = useRef<AbortController | null>(null);
  const [endpoint, setEndpoint] = useState("");
  const [scope, setScope] = useState("persistence_full_scan");
  const [frequency, setFrequency] = useState<Frequency>(record?.frequency ?? "daily");
  const [runAt, setRunAt] = useState(record && Date.parse(record.next_run_at) > Date.now() ? localDateTime(record.next_run_at) : "");
  const [busy, setBusy] = useState(false);
  const [issue, setIssue] = useState("");

  useEffect(() => {
    if (dialog.current && !dialog.current.open) dialog.current.showModal();
    return () => submission.current?.abort();
  }, []);

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (busy || (!record && !endpoint)) return;
    const firstRun = new Date(runAt);
    if (!Number.isFinite(firstRun.getTime()) || firstRun.getTime() <= Date.now()) {
      setIssue("Choose a run time in the future.");
      return;
    }
    if (localDateTime(firstRun.toISOString()) !== runAt) {
      setIssue("Choose a valid time in your local time zone.");
      return;
    }
    const request = new AbortController();
    submission.current = request;
    const timing = { frequency, next_run_at: firstRun.toISOString() };
    setBusy(true); setIssue("");
    try {
      if (record) await readAPI<Schedule>(`scan-schedules/${record.id}`, token, request.signal, "PATCH", { timing });
      else await readAPI<Schedule>("scan-schedules", token, request.signal, "POST", { ...timing, endpoint_id: endpoint, scan_type: scope });
      if (!request.signal.aborted) saved();
    } catch (error) {
      if (!request.signal.aborted) setIssue(error instanceof Error ? error.message : "The schedule could not be saved.");
    } finally {
      if (!request.signal.aborted) setBusy(false);
    }
  }

  return <dialog ref={dialog} aria-labelledby="schedule-title" onClose={close}
    onCancel={event => { if (busy) event.preventDefault(); }}>
    <div className="dialog-title"><div><h2 id="schedule-title">{record ? "Edit scan schedule" : "Create scan schedule"}</h2>
      {record && <p>{record.hostname} · {scanTypeLabel(record.scan_type)}</p>}</div>
      <button type="button" className="button icon-button" aria-label="Close" disabled={busy} onClick={() => dialog.current?.close()}><X size={17} /></button></div>
    <form onSubmit={submit}>
      {!record && <ScanTargetFields token={token} busy={busy} target={endpoint} scanType={scope} setTarget={setEndpoint} setScanType={setScope} />}
      <label htmlFor="schedule-frequency">Repeat</label>
      <select id="schedule-frequency" value={frequency} disabled={busy} onChange={event => setFrequency(event.target.value as Frequency)}>
        {Object.entries(frequencies).map(([value, label]) => <option value={value} key={value}>{label}</option>)}
      </select>
      <label htmlFor="schedule-run-at">{record ? "Next run (local time)" : "First run (local time)"}</label>
      <input id="schedule-run-at" required type="datetime-local" value={runAt} disabled={busy}
        aria-describedby="schedule-interval" onChange={event => setRunAt(event.target.value)} />
      <p id="schedule-interval" className="muted">Repeats every {frequency === "daily" ? "24 hours" : "7 days"}.</p>
      {issue && <p className="api-error" role="alert">{issue}</p>}
      <div className="action-footer">
        <button type="button" className="button" disabled={busy} onClick={() => dialog.current?.close()}>Cancel</button>
        <button type="submit" className="button primary" disabled={busy || (!record && !endpoint)}>{busy ? "Saving…" : "Save schedule"}</button>
      </div>
    </form>
  </dialog>;
}

export function ScanSchedules({ token, canManage }: { token: string; canManage: boolean }) {
  const [offset, setOffset] = useState(0);
  const [revision, setRevision] = useState(0);
  const [result, setResult] = useState<{ offset: number; data?: SchedulePage; error?: string }>();
  const [editor, setEditor] = useState<Schedule | "new" | null>(null);
  const [saving, setSaving] = useState("");
  const [issue, setIssue] = useState("");
  const [notice, setNotice] = useState("");
  const active = result?.offset === offset ? result : undefined;

  useEffect(() => {
    if (!token) return;
    const request = new AbortController();
    readAPI<SchedulePage>(`scan-schedules?limit=${pageSize}&offset=${offset}`, token, request.signal)
      .then(data => { if (!request.signal.aborted) setResult({ offset, data }); })
      .catch((error: Error) => { if (!request.signal.aborted) setResult({ offset, error: error.message }); });
    return () => request.abort();
  }, [offset, revision, token]);

  function reload() { setRevision(value => value + 1); }

  async function toggle(schedule: Schedule) {
    if (saving) return;
    setSaving(schedule.id); setIssue(""); setNotice("");
    try {
      const updated = await readAPI<Schedule>(`scan-schedules/${schedule.id}`, token, AbortSignal.timeout(10000), "PATCH", { enabled: !schedule.enabled });
      setNotice(updated.enabled ? "Scan schedule resumed." : "Scan schedule paused.");
      reload();
    } catch (error) {
      setIssue(error instanceof Error ? error.message : "The schedule could not be updated.");
    } finally { setSaving(""); }
  }

  return <main id="scan-schedules">
    <div className="heading"><div><h1>Scan schedules</h1><p>Recurring Windows inventory scans. Times use your browser’s time zone.</p></div>
      <div className="heading-actions">
        <a href="#scan-history" className="button"><ArrowLeft size={15} />Scan history</a>
        {token && <button className="button refresh" type="button" onClick={reload}><RefreshCw size={15} />Refresh schedules</button>}
        {token && canManage && <button className="button primary" type="button" onClick={() => { setIssue(""); setNotice(""); setEditor("new"); }}>
          <Plus size={16} />Create schedule</button>}
      </div></div>
    {!token ? <p className="panel section-note">Connect the API to view scan schedules.</p> : <section className="panel jobs" aria-label="Recurring Windows scans">
      {(issue || active?.error) && <p className="api-error rules-message" role="alert">{issue || active?.error}</p>}
      {notice && <p className="action-notice rules-message" role="status">{notice}</p>}
      {!active && <p className="section-note" role="status">Loading scan schedules…</p>}
      {active?.data && <>
        {active.data.schedules.length ? <div className="table-scroll"><table className="scan-schedules-table">
          <thead><tr><th>Endpoint</th><th>Scan scope</th><th>Repeat</th><th>Next run</th><th>Last attempt</th>
            <th>Actions</th></tr></thead>
          <tbody>{active.data.schedules.map(schedule => <tr key={schedule.id}>
            <td>{schedule.hostname}<small className="mono">{schedule.endpoint_id.slice(0, 8)}</small></td>
            <td>{scanTypeLabel(schedule.scan_type)}</td><td>{frequencies[schedule.frequency]}</td>
            <td>{schedule.enabled ? timeFormat.format(new Date(schedule.next_run_at)) : "Paused"}</td>
            <td>{schedule.last_outcome ? outcomes[schedule.last_outcome] : "—"}
              {schedule.last_run_at && <small>{timeFormat.format(new Date(schedule.last_run_at))}</small>}</td>
            <td><div className="heading-actions">
              <a className="button" href={scanScheduleHistoryHref(schedule.id)}>Run history</a>
              {canManage && <>
                <button type="button" className="button" disabled={!!saving} onClick={() => { setIssue(""); setNotice(""); setEditor(schedule); }}>Edit</button>
                <button type="button" className="button" disabled={!!saving} onClick={() => void toggle(schedule)}>
                  {saving === schedule.id ? "Saving…" : schedule.enabled ? "Pause" : "Resume"}</button>
              </>}
            </div></td>
          </tr>)}</tbody>
        </table></div> : <p className="section-note" role="status">No scan schedules on this page.</p>}
        {(offset > 0 || active.data.has_more) && <footer className="pagination"><span>Page {offset / pageSize + 1}</span><div>
          <button className="button" type="button" disabled={!offset} onClick={() => setOffset(offset - pageSize)}>Previous page</button>
          <button className="button" type="button" disabled={!active.data.has_more} onClick={() => setOffset(offset + pageSize)}>Next page</button>
        </div></footer>}
      </>}
    </section>}
    {editor && <ScheduleDialog token={token} record={editor === "new" ? undefined : editor} close={() => setEditor(null)} saved={() => {
      setNotice(editor === "new" ? "Scan schedule created." : "Scan schedule updated.");
      setEditor(null); setOffset(editor === "new" ? 0 : offset); reload();
    }} />}
  </main>;
}

export function ScanScheduleHistory({ token, scheduleId }: { token: string; scheduleId: string | null }) {
  const heading = useRef<HTMLHeadingElement>(null);
  const [offset, setOffset] = useState(0);
  const [revision, setRevision] = useState(0);
  const [loaded, setLoaded] = useState<{ offset: number; data?: RunPage; error?: string; checkedAt?: Date }>();
  const active = loaded?.offset === offset ? loaded : undefined;
  const data = active?.data;
  const valid = isUUID(scheduleId);

  useEffect(() => {
    heading.current?.closest(".app-scroll")?.scrollTo({ top: 0 });
    heading.current?.focus({ preventScroll: true });
  }, []);

  useEffect(() => {
    if (!token || !valid) return;
    const path = `scan-schedules/${scheduleId}/runs?limit=${pageSize}&offset=${offset}`;
    return pollWhileVisible(async request => {
      try {
        const signal = AbortSignal.any([request, AbortSignal.timeout(10000)]);
        const data = await readAPI<RunPage>(path, token, signal);
        if (request.aborted) return false;
        setLoaded({ offset, data, checkedAt: new Date() });
      } catch (cause) {
        if (request.aborted) return false;
        const error = cause instanceof Error ? cause.message : "Could not refresh run history.";
        // A transient failure can retain the current page. A denied or missing resource cannot.
        if (cause instanceof APIError && [401, 403, 404].includes(cause.status)) {
          setLoaded({ offset, error });
          return false;
        }
        setLoaded(previous => previous?.offset === offset ? { ...previous, error } : { offset, error });
      }
      return true;
    });
  }, [scheduleId, valid, offset, revision, token]);

  return <main>
    <div className="heading"><div><h1 ref={heading} tabIndex={-1}>Run history</h1>
      {data && <p>{data.schedule.hostname} · {scanTypeLabel(data.schedule.scan_type)}</p>}</div>
      <div className="heading-actions">
        <a className="button" href="#scan-schedules"><ArrowLeft size={15} />Scan schedules</a>
        {valid && token && <button type="button" className="button refresh" onClick={() => setRevision(value => value + 1)}>
          <RefreshCw size={15} />Refresh history</button>}
      </div></div>
    {!valid ? <p className="api-error" role="alert">This scan schedule link is invalid.</p> :
      !token ? <p className="panel section-note">Connect the API to view run history.</p> :
      active?.error && !data ? <p className="api-error" role="alert">{active.error}</p> :
      !data ? <p className="panel section-note" role="status">Loading run history…</p> :
      <section className="panel jobs" aria-label="Schedule runs">
        {active?.checkedAt && <div className="table-heading">
          <p>Last status check <time dateTime={active.checkedAt.toISOString()}>{checkTimeFormat.format(active.checkedAt)} SGT</time></p>
        </div>}
        {active?.error && <p className="api-error rules-message" role="alert">Run history may be out of date. {active.error}</p>}
        {data.runs.length ? <div className="table-scroll"><table className="scan-schedules-table">
          <thead><tr><th>Scheduled for</th><th>Attempted at</th><th>Outcome</th><th>Scan job</th></tr></thead>
          <tbody>{data.runs.map(run => <tr key={run.id}>
            <td>{run.scheduled_for ? timeFormat.format(new Date(run.scheduled_for)) : "—"}</td>
            <td>{timeFormat.format(new Date(run.attempted_at))}</td>
            <td>{outcomes[run.outcome]}</td>
            <td>{run.job_id ? <><a className="source-scan-link mono" href={scheduledScanHref(run.job_id, data.schedule.id)}>
              Scan #{run.job_id.slice(0, 8)}</a>
              {run.job_status && <small aria-live="polite">{run.job_status[0].toUpperCase() + run.job_status.slice(1)}</small>}</> : "—"}</td>
          </tr>)}</tbody>
        </table></div> : <p className="section-note" role="status">{offset ? "No runs on this page." : "This schedule has no runs yet."}</p>}
        {(offset > 0 || data.has_more) && <footer className="pagination"><span>Page {offset / pageSize + 1}</span><div>
          <button className="button" type="button" disabled={!offset} onClick={() => setOffset(offset - pageSize)}>Previous page</button>
          <button className="button" type="button" disabled={!data.has_more} onClick={() => setOffset(offset + pageSize)}>Next page</button>
        </div></footer>}
      </section>}
  </main>;
}
