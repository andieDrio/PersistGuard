export class APIError extends Error {
  constructor(readonly status: number, message: string) {
    super(message);
  }
}

export function pollWhileVisible(check: (signal: AbortSignal) => Promise<boolean>) {
  const request = new AbortController();
  let timer: number;

  function schedule() {
    timer = window.setTimeout(() => {
      if (document.hidden) schedule();
      else void poll();
    }, 5000);
  }

  async function poll() {
    if (await check(request.signal) && !request.signal.aborted) schedule();
  }

  void poll();
  return () => { request.abort(); window.clearTimeout(timer); };
}

export async function readAPI<T>(path: string, token: string, signal: AbortSignal, method = "GET", body?: Record<string, unknown>): Promise<T> {
  const response = await fetch(`/pg-api/${path}`, {
    method, headers: { Authorization: `Bearer ${token}`, ...(body && { "Content-Type": "application/json" }) },
    body: body && JSON.stringify(body), cache: "no-store", redirect: "error", signal,
  });
  if (!response.ok) {
    const apiError = (message: string) => new APIError(response.status, message);
    if (response.status === 401 || response.status === 403) throw apiError("Access denied. Check your API access token and role.");
    if ((path.startsWith("workspace/") || path.startsWith("detection-rules") || path.startsWith("attack-coverage/") ||
         path.startsWith("scan-schedules") ||
         (path.startsWith("endpoints/") && (path.endsWith("/revoke") || path.endsWith("/scan-jobs")))) && [404, 409, 422].includes(response.status)) {
      const info = await response.json().catch(() => null);
      throw apiError(typeof info?.detail === "string" ? info.detail : "Check the form and try again.");
    }
    if (response.status === 404) throw apiError("This endpoint, scan, or assessment is unavailable.");
    if (response.status === 409) {
      if (path.endsWith("/cancel")) throw apiError("This scan is no longer queued. Refresh to see its current status.");
      if (path.endsWith("/client-certificate")) throw apiError("This device has no current certificate or pending approval.");
      throw apiError("This endpoint is no longer eligible for a scan.");
    }
    throw apiError("The PersistGuard API did not return a result. Check that the backend is running.");
  }
  return response.json() as Promise<T>;
}
