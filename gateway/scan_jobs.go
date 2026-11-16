package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
)

type dispatchedScanJob struct {
	ID       string `json:"id"`
	ScanType string `json:"scan_type"`
	Status   string `json:"status"`
}

func pollScanJob(db *sql.DB, targeted bool) func(http.ResponseWriter, context.Context, deviceCredential) {
	return func(w http.ResponseWriter, ctx context.Context, device deviceCredential) {
		// Recheck the credential in the dispatch statement. Repeated polls return the same dispatched job.
		const dispatch = `WITH authorized AS (
			SELECT endpoint.id, endpoint.organization_id` + activeDeviceCredential + `
			AND credential.certificate_pem = $2
			AND endpoint.id = $3 AND endpoint.organization_id = $4
		), dispatched AS (
			UPDATE scan_jobs AS job SET status = 'dispatched'
			FROM authorized
			WHERE job.endpoint_id = authorized.id AND job.organization_id = authorized.organization_id
			  AND (job.scan_type = 'persistence_full_scan' OR $5) AND job.status IN ('queued', 'dispatched')
			RETURNING job.id::text, job.scan_type, job.status
		)
		SELECT EXISTS (SELECT 1 FROM authorized), dispatched.id, dispatched.scan_type, dispatched.status
		FROM (SELECT 1) AS result LEFT JOIN dispatched ON TRUE`
		var authorized bool
		var id, scanType, status sql.NullString
		if err := db.QueryRowContext(ctx, dispatch, device.serial, device.certificatePEM,
			device.identity.EndpointID, device.identity.OrganizationID, targeted).Scan(&authorized, &id, &scanType, &status); err != nil {
			http.Error(w, "scan queue unavailable", http.StatusServiceUnavailable)
			return
		}
		if !authorized {
			http.Error(w, "device credential unavailable", http.StatusForbidden)
			return
		}
		if !id.Valid {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(dispatchedScanJob{id.String, scanType.String, status.String})
	}
}
