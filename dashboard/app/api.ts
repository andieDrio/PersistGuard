export async function readAPI<T>(path: string, token: string, signal: AbortSignal, method = "GET", body?: Record<string, unknown>): Promise<T> {
  const response = await fetch(`/pg-api/${path}`, {
    method, headers: { Authorization: `Bearer ${token}`, ...(body && { "Content-Type": "application/json" }) },
    body: body && JSON.stringify(body), cache: "no-store", redirect: "error", signal,
  });
  if (!response.ok) {
    if (response.status === 401 || response.status === 403) throw new Error("Access denied. Check your API access token and role.");
    if ((path.startsWith("workspace/") || path.startsWith("detection-rules") || path.startsWith("attack-coverage/") ||
         (path.startsWith("endpoints/") && (path.endsWith("/revoke") || path.endsWith("/scan-jobs")))) && [404, 409, 422].includes(response.status)) {
      const info = await response.json().catch(() => null);
      throw new Error(typeof info?.detail === "string" ? info.detail : "Check the form and try again.");
    }
    if (response.status === 404) throw new Error("This endpoint, scan, or assessment is unavailable.");
    if (response.status === 409) {
      if (path.endsWith("/cancel")) throw new Error("This scan is no longer queued. Refresh to see its current status.");
      if (path.endsWith("/client-certificate")) throw new Error("This device has no current certificate or pending approval.");
      throw new Error("This endpoint is no longer eligible for a scan.");
    }
    throw new Error("The PersistGuard API did not return a result. Check that the backend is running.");
  }
  return response.json() as Promise<T>;
}
