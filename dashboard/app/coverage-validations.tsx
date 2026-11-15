"use client";

import { useEffect, useRef, useState, type FormEvent } from "react";
import { Plus } from "lucide-react";
import { readAPI } from "./api";

type TestResult = "passed" | "failed" | "inconclusive";
type ValidationRecord = { id: string; result: TestResult; tested_on: string; reference: string;
  recorded_by: string; recorded_role: "admin" | "analyst"; recorded_at: string };
type ValidationPage = { records: ValidationRecord[]; can_manage: boolean; next_offset: number | null };
const outcomes = { passed: "Passed", failed: "Failed", inconclusive: "Inconclusive" };
const tones = { passed: "green", failed: "red", inconclusive: "amber" };
const recordedDate = new Intl.DateTimeFormat("en-SG", { day: "numeric", month: "short", year: "numeric",
  hour: "2-digit", minute: "2-digit", timeZone: "Asia/Singapore", timeZoneName: "short" });

export function CoverageValidations({ useCaseId, token }: { useCaseId: string; token: string }) {
  const [offset, setOffset] = useState(0);
  const [revision, setRevision] = useState(0);
  const [loaded, setLoaded] = useState<{ key: string; data?: ValidationPage; error?: string }>();
  const [recording, setRecording] = useState(false);
  const [saving, setSaving] = useState(false);
  const [issue, setIssue] = useState("");
  const [notice, setNotice] = useState("");
  const submission = useRef<AbortController | null>(null);
  const recordButton = useRef<HTMLButtonElement>(null);
  const key = `${offset}-${revision}`;
  const active = loaded?.key === key ? loaded : undefined;
  const data = active?.data;
  const path = `attack-coverage/${encodeURIComponent(useCaseId)}/validations`;

  useEffect(() => () => submission.current?.abort(), []);
  useEffect(() => {
    const request = new AbortController();
    readAPI<ValidationPage>(`${path}?offset=${offset}`, token, request.signal)
      .then(data => { if (!request.signal.aborted) setLoaded({ key, data }); })
      .catch((error: Error) => { if (!request.signal.aborted) setLoaded({ key, error: error.message }); });
    return () => request.abort();
  }, [key, offset, path, token]);

  async function recordTest(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (saving || !data?.can_manage) return;
    const fields = new FormData(event.currentTarget);
    const controller = new AbortController();
    submission.current = controller;
    setSaving(true); setIssue(""); setNotice("");
    try {
      await readAPI<ValidationRecord>(path, token, controller.signal, "POST", {
        result: String(fields.get("result")), tested_on: String(fields.get("tested_on")), reference: String(fields.get("reference")),
      });
      if (controller.signal.aborted) return;
      setRecording(false); setNotice("Deployment test saved. Records are ordered by test date.");
      setOffset(0); setRevision(value => value + 1);
    } catch (error) {
      if (!controller.signal.aborted) setIssue(error instanceof Error ? error.message : "Could not record the deployment test.");
    } finally {
      if (!controller.signal.aborted) setSaving(false);
    }
  }

  return <section className="deployment-validations" aria-label="Deployment validation records">
    <div className="finding-line"><h3>Deployment tests</h3>{data?.can_manage && !recording &&
      <button ref={recordButton} className="button primary" type="button" onClick={() => { setRecording(true); setNotice(""); }}><Plus size={15} />Record test</button>}</div>
    {notice && <p className="action-notice" role="status">{notice}</p>}
    {!active && <p role="status">Loading deployment tests…</p>}
    {active?.error && <div><p role="alert">{active.error}</p><button className="button" type="button"
      onClick={() => setRevision(value => value + 1)}>Retry</button></div>}
    {recording && data?.can_manage && <form className="rule-form validation-form" onSubmit={recordTest}>
      <label>Test result<select name="result" defaultValue="" required disabled={saving} autoFocus>
        <option value="" disabled>Select a result</option>{Object.entries(outcomes).map(([value, label]) => <option key={value} value={value}>{label}</option>)}
      </select></label>
      <label>Test date<input type="date" name="tested_on" required disabled={saving} /></label>
      <label className="validation-reference">Evidence reference<input name="reference" placeholder="Ticket, report, or test run ID" required maxLength={500} disabled={saving} /></label>
      {issue && <p className="api-error validation-reference" role="alert">{issue}</p>}
      <div className="rule-controls validation-reference"><button className="button primary" disabled={saving}>{saving ? "Saving…" : "Save test"}</button>
        <button className="button" type="button" disabled={saving} onClick={() => {
          setRecording(false); setIssue(""); window.requestAnimationFrame(() => recordButton.current?.focus());
        }}>Cancel</button></div>
    </form>}
    {data?.records.length === 0 && <p>{offset ? "No tests on this page." : "No deployment tests recorded for this use case."}</p>}
    {!!data?.records.length && <ul className="validation-records">{data.records.map(record => <li key={record.id}>
      <div className="finding-line"><span className={`badge ${tones[record.result]}`}><span />{outcomes[record.result]}</span><time dateTime={record.tested_on}>{record.tested_on}</time></div>
      <p className="validation-record-reference">{record.reference}</p>
      <small title={record.recorded_by}>Recorded by {record.recorded_role} #{record.recorded_by.slice(0, 8)} · <time dateTime={record.recorded_at}>{recordedDate.format(new Date(record.recorded_at))}</time></small>
    </li>)}</ul>}
    {data && (offset > 0 || data.next_offset !== null) && <div className="rule-controls">
      <button className="button" type="button" disabled={!offset || recording} onClick={() => setOffset(Math.max(0, offset - 25))}>Previous tests</button>
      <button className="button" type="button" disabled={data.next_offset === null || recording} onClick={() => {
        if (data.next_offset !== null) setOffset(data.next_offset);
      }}>Older tests</button>
    </div>}
  </section>;
}
