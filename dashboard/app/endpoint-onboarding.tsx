"use client";

import { useEffect, useRef, useState, type FormEvent } from "react";
import { ArrowLeft, ArrowRight, Check, Copy, Download, KeyRound, Monitor, Plus, RefreshCw, X } from "lucide-react";
import { readAPI } from "./api";

const statusLabels = { pending: "Pending", approved: "Approved", revoked: "Revoked" } as const;
type EndpointStatus = keyof typeof statusLabels;
type Endpoint = {
  id: string; hostname: string; os_family: string; status: EndpointStatus; created_at: string; has_device_key: boolean;
};
type Invitation = { token: string; organization_id: string; expires_in_seconds: number };
type Certificate = { endpoint_id: string; certificate_pem: string; certificate_serial: string; expires_at: string };
type Action = { kind: "invite" } | { kind: "certificate" | "revoke"; endpoint: Endpoint };
const pageSize = 10;
const dateFormat = new Intl.DateTimeFormat("en-SG", {
  day: "numeric", month: "short", hour: "2-digit", minute: "2-digit", timeZone: "Asia/Singapore",
});

function EnrollmentDialog({ action, token, close, onApproved, onRevoked }: {
  action: Action; token: string; close: () => void; onApproved: () => void; onRevoked: (endpoint: Endpoint) => void;
}) {
  const dialog = useRef<HTMLDialogElement>(null);
  const request = useRef<AbortController | null>(null);
  const [busy, setBusy] = useState(false);
  const [issue, setIssue] = useState("");
  const [copied, setCopied] = useState(false);
  const [invitation, setInvitation] = useState<Invitation | null>(null);
  const [certificate, setCertificate] = useState<Certificate | null>(null);
  const approving = action.kind === "certificate" && action.endpoint.status === "pending";

  useEffect(() => {
    if (dialog.current && !dialog.current.open) dialog.current.showModal();
    return () => request.current?.abort();
  }, []);

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (busy) return;
    const controller = new AbortController();
    request.current = controller;
    setBusy(true);
    setIssue("");
    try {
      if (action.kind === "invite") {
        const issued = await readAPI<Invitation>("enrollment-tokens", token, controller.signal, "POST");
        if (!controller.signal.aborted) setInvitation(issued);
      } else if (action.kind === "revoke") {
        await readAPI(`endpoints/${encodeURIComponent(action.endpoint.id)}/revoke`, token, controller.signal, "POST");
        if (!controller.signal.aborted) {
          onRevoked(action.endpoint);
          dialog.current?.close();
        }
      } else {
        const issued = await readAPI<Certificate>(`endpoints/${encodeURIComponent(action.endpoint.id)}/client-certificate`,
          token, controller.signal, "PUT");
        if (!controller.signal.aborted) { setCertificate(issued); onApproved(); }
      }
    } catch (error) {
      if (!controller.signal.aborted) setIssue(error instanceof Error ? error.message : "The request could not be completed.");
    } finally {
      if (!controller.signal.aborted) setBusy(false);
    }
  }

  async function copyToken() {
    if (!invitation) return;
    try { await navigator.clipboard.writeText(invitation.token); setCopied(true); setIssue(""); }
    catch { setIssue("Clipboard access is unavailable. You can select and copy the token directly."); }
  }

  function downloadCertificate() {
    if (!certificate) return;
    const url = URL.createObjectURL(new Blob([certificate.certificate_pem], { type: "application/x-pem-file" }));
    const link = document.createElement("a");
    link.href = url;
    link.download = `device-${certificate.endpoint_id.slice(0, 8)}.pem`;
    link.click();
    window.setTimeout(() => URL.revokeObjectURL(url), 1000);
  }

  const title = action.kind === "invite" ? (invitation ? "Enrollment invitation" : "Create invitation") :
    action.kind === "revoke" ? "Revoke endpoint?" :
    (certificate ? "Device certificate" : approving ? "Approve device?" : "Get device certificate");
  return <dialog ref={dialog} className="enrollment-dialog" onClose={close} aria-labelledby="enrollment-action-title"
    onCancel={event => { if (busy) event.preventDefault(); }}>
    <div className="dialog-title"><div><h2 id="enrollment-action-title">{title}</h2>
      <p>{action.kind === "invite" ? "The invitation token is displayed once." : action.endpoint.hostname}</p></div>
      <button className="button icon-button" type="button" aria-label="Close" disabled={busy} onClick={() => dialog.current?.close()}><X size={17} /></button></div>
    {invitation ? <div className="enrollment-output">
      <p>Single use · Expires in {Math.round(invitation.expires_in_seconds / 60)} minutes</p>
      <label htmlFor="invitation-token">Enrollment token</label>
      <input id="invitation-token" readOnly value={invitation.token} className="mono" />
      <label htmlFor="invitation-org">Organization ID</label>
      <input id="invitation-org" readOnly value={invitation.organization_id} className="mono" />
      {issue && <p className="api-error" role="alert">{issue}</p>}
      <div className="action-footer"><button type="button" className="button" onClick={copyToken}>
        {copied ? <Check size={15} /> : <Copy size={15} />}{copied ? "Copied" : "Copy token"}</button>
        <button type="button" className="button primary" onClick={() => dialog.current?.close()}>Done</button></div>
    </div> : certificate ? <div className="enrollment-output">
      <p>Expires {dateFormat.format(new Date(certificate.expires_at))} SGT</p>
      <label htmlFor="issued-certificate">Certificate PEM</label>
      <textarea id="issued-certificate" readOnly rows={7} value={certificate.certificate_pem} className="mono" />
      <div className="action-footer"><button type="button" className="button" onClick={downloadCertificate}><Download size={15} /> Download PEM</button>
        <button type="button" className="button primary" onClick={() => dialog.current?.close()}>Done</button></div>
    </div> : <form onSubmit={submit}>
      <p className="enrollment-explanation">{action.kind === "invite" ? "The device will use this single-use token to submit its certificate request." :
        action.kind === "revoke" ? "This revokes the device’s certificates and cancels unfinished scans. Completed scan evidence stays available." :
        approving ? "Issue a client certificate for this device’s registered key." : "Retrieve the current client certificate for this device."}</p>
      {issue && <p className="api-error" role="alert">{issue}</p>}
      <div className="action-footer"><button type="button" className="button" disabled={busy} onClick={() => dialog.current?.close()}>Back</button>
        <button type="submit" className={`button ${action.kind === "revoke" ? "danger" : "primary"}`} disabled={busy}>
          {busy ? "Working…" : action.kind === "revoke" ? "Revoke endpoint" : action.kind === "invite" ? "Generate token" : approving ? "Approve device" : "Get certificate"}</button></div>
    </form>}
  </dialog>;
}

export function EndpointOnboarding({ token }: { token: string }) {
  const [status, setStatus] = useState<EndpointStatus>("pending");
  const [page, setPage] = useState(0);
  const [revision, setRevision] = useState(0);
  const [list, setList] = useState<{ key: string; entries: Endpoint[]; error: string } | null>(null);
  const [action, setAction] = useState<Action | null>(null);
  const [notice, setNotice] = useState("");
  const key = `${status}:${page}:${revision}`;
  const result = list?.key === key ? list : null;
  const devices = result?.entries.slice(0, pageSize) ?? [];

  useEffect(() => {
    const request = new AbortController();
    readAPI<Endpoint[]>(`endpoints?status=${status}&limit=${pageSize + 1}&offset=${page * pageSize}`, token, request.signal)
      .then(entries => { if (!request.signal.aborted) setList({ key, entries, error: "" }); })
      .catch((error: Error) => { if (!request.signal.aborted) setList({ key, entries: [], error: error.message }); });
    return () => request.abort();
  }, [key, page, status, token]);

  return <main id="endpoint-onboarding">
    <div className="heading"><div><h1>Endpoint onboarding</h1><p>Invite devices and manage their enrollment.</p></div>
      <div className="heading-actions"><button type="button" className="button" disabled={!result} onClick={() => setRevision(value => value + 1)}>
        <RefreshCw size={15} /> Refresh</button><button type="button" className="button primary" onClick={() => setAction({ kind: "invite" })}>
        <Plus size={16} /> Create invitation</button></div></div>
    <section className="panel jobs" aria-label="Enrollment endpoints">
      <div className="table-heading"><div><h2>Devices</h2><p>Enrollment requests in your organization</p></div></div>
      <div className="onboarding-tabs" role="group" aria-label="Enrollment status">
        {(Object.keys(statusLabels) as EndpointStatus[]).map(value => <button type="button" className={`button ${status === value ? "selected-tab" : ""}`}
          key={value} aria-pressed={status === value} onClick={() => { setStatus(value); setPage(0); }}>{statusLabels[value]}</button>)}
      </div>
      {notice && <p className="action-notice onboarding-error" role="status">{notice}</p>}
      {result?.error && <p className="api-error onboarding-error" role="alert">{result.error}</p>}
      <div className="table-scroll"><table className="device-table"><thead><tr><th>Endpoint</th><th>Platform</th><th>Registered (SGT)</th><th>Actions</th></tr></thead>
        <tbody>{devices.map(device => <tr key={device.id}>
          <td><div className="device-name"><Monitor size={17} /><span><strong>{device.hostname}</strong><small className="mono" title={device.id}>#{device.id.slice(0, 8)}</small></span></div></td>
          <td>{device.os_family === "windows" ? "Windows" : device.os_family === "macos" ? "macOS" : device.os_family === "linux" ? "Linux" : device.os_family}</td>
          <td>{dateFormat.format(new Date(device.created_at))}</td>
          <td><div className="rule-controls">
            {device.status === "revoked" ? <span className="muted">Revoked</span> : device.has_device_key ?
              <button type="button" className="button" onClick={() => setAction({ kind: "certificate", endpoint: device })}>
                <KeyRound size={14} />{device.status === "pending" ? "Approve" : "Get certificate"}</button> :
              <span className="muted">Awaiting device key</span>}
            {device.status === "approved" && <button type="button" className="button" aria-label={`Revoke ${device.hostname}`}
              onClick={() => { setNotice(""); setAction({ kind: "revoke", endpoint: device }); }}>Revoke</button>}
          </div></td>
        </tr>)}</tbody></table>
        {!result ? <div className="empty" role="status">Loading devices…</div> : !devices.length && !result.error &&
          <div className="empty"><Monitor size={24} /><strong>No {status} devices</strong>
            {status !== "revoked" && <p>{status === "pending" ? "New enrollment requests will appear here." : "Approved devices will appear here."}</p>}</div>}
      </div>
      <footer className="pagination"><span>{devices.length ? `${page * pageSize + 1}–${page * pageSize + devices.length}` : "0 devices"}</span><div>
        <button type="button" aria-label="Previous device page" className="button icon-button" disabled={!result || page === 0} onClick={() => setPage(page - 1)}><ArrowLeft size={15} /></button>
        <button type="button" aria-label="Next device page" className="button icon-button" disabled={!result || result.entries.length <= pageSize} onClick={() => setPage(page + 1)}><ArrowRight size={15} /></button>
      </div></footer>
    </section>
    {action && <EnrollmentDialog action={action} token={token} close={() => setAction(null)} onApproved={() => setRevision(value => value + 1)}
      onRevoked={endpoint => {
        setNotice(`${endpoint.hostname} was revoked.`);
        setStatus("revoked");
        setPage(0);
        setRevision(value => value + 1);
      }} />}
  </main>;
}
