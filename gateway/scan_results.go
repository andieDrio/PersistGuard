package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"regexp"
	"time"
)

var scanJobID = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

func scanResultStatus(payload []byte) (status, scanType string) {
	var report struct {
		Version    int    `json:"schema_version"`
		OSFamily   string `json:"os_family"`
		Status     string `json:"status"`
		Collectors map[string]struct {
			Status string          `json:"status"`
			Report json.RawMessage `json:"report"`
			Error  string          `json:"error"`
		} `json:"collectors"`
	}
	if err := json.Unmarshal(payload, &report); err != nil || report.Version != 1 || report.OSFamily != "windows" {
		return "", ""
	}
	sources := map[string]string{
		"registry": "persistence_registry_scan", "scheduled_tasks": "persistence_scheduled_tasks_scan",
		"services": "persistence_services_scan",
	}
	count := len(report.Collectors)
	if count != 1 && count != len(sources) {
		return "", ""
	}
	scanType = "persistence_full_scan"
	readable, complete := 0, 0
	for source, collector := range report.Collectors {
		targetType, known := sources[source]
		if !known {
			return "", ""
		}
		if count == 1 {
			scanType = targetType
		}
		switch collector.Status {
		case "collected":
			readable++
			complete++
		case "partial":
			readable++
		case "error":
			if len(collector.Report) == 0 && collector.Error != "" {
				continue
			}
		default:
			return "", ""
		}
		var nested struct {
			OSFamily string          `json:"os_family"`
			Entries  json.RawMessage `json:"entries"`
			Coverage json.RawMessage `json:"coverage"`
		}
		if err := json.Unmarshal(collector.Report, &nested); err != nil || nested.OSFamily != "windows" ||
			len(nested.Entries) == 0 || nested.Entries[0] != '[' || len(nested.Coverage) == 0 ||
			(nested.Coverage[0] != '[' && nested.Coverage[0] != '{') {
			return "", ""
		}
	}
	switch {
	case complete == count && report.Status == "collected":
		return "completed", scanType
	case readable == 0 && report.Status == "error":
		return "failed", scanType
	case readable > 0 && complete < count && report.Status == "partial":
		return "partial", scanType
	default:
		return "", ""
	}
}

func storeScanResult(db *sql.DB, w http.ResponseWriter, r *http.Request, device deviceCredential) {
	jobID := r.PathValue("job_id")
	if !scanJobID.MatchString(jobID) {
		http.Error(w, "scan job not found", http.StatusNotFound)
		return
	}
	const maxInventorySize = 32 * 1024 * 1024
	payload, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxInventorySize))
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			http.Error(w, "inventory is too large", http.StatusRequestEntityTooLarge)
		} else {
			http.Error(w, "could not read inventory", http.StatusBadRequest)
		}
		return
	}
	status, scanType := scanResultStatus(payload)
	if status == "" {
		http.Error(w, "invalid Windows inventory report", http.StatusUnprocessableEntity)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	const save = `WITH authorized AS (
		SELECT endpoint.id, endpoint.organization_id` + activeDeviceCredential + `
		AND credential.certificate_pem = $2 AND endpoint.id = $3 AND endpoint.organization_id = $4
	), target AS (
		SELECT job.id, job.scan_type FROM scan_jobs AS job JOIN authorized
		ON job.endpoint_id = authorized.id AND job.organization_id = authorized.organization_id
		WHERE job.id = $5
	), saved AS (
		UPDATE scan_jobs AS job SET result = $6::jsonb, status = $7,
			finished_at = COALESCE(job.finished_at, statement_timestamp())
		FROM target WHERE job.id = target.id AND target.scan_type = $8
		AND (job.status = 'dispatched' OR (job.status = $7 AND job.result = $6::jsonb))
		RETURNING job.finished_at
	)
	SELECT EXISTS (SELECT 1 FROM authorized), EXISTS (SELECT 1 FROM target),
		EXISTS (SELECT 1 FROM target WHERE scan_type = $8), (SELECT finished_at FROM saved)`
	var authorized, found, matchingScope bool
	var finished sql.NullTime
	if err := db.QueryRowContext(ctx, save, device.serial, device.certificatePEM,
		device.identity.EndpointID, device.identity.OrganizationID, jobID, string(payload), status, scanType).
		Scan(&authorized, &found, &matchingScope, &finished); err != nil {
		http.Error(w, "scan result storage unavailable", http.StatusServiceUnavailable)
		return
	}
	switch {
	case !authorized:
		http.Error(w, "device credential unavailable", http.StatusForbidden)
	case !found:
		http.Error(w, "scan job not found", http.StatusNotFound)
	case !matchingScope:
		http.Error(w, "inventory report does not match scan scope", http.StatusUnprocessableEntity)
	case !finished.Valid:
		http.Error(w, "job is not dispatched or already has a different result", http.StatusConflict)
	default:
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(struct {
			ID         string    `json:"id"`
			Status     string    `json:"status"`
			FinishedAt time.Time `json:"finished_at"`
		}{jobID, status, finished.Time.UTC()})
	}
}
