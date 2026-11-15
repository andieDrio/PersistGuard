package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"time"
)

var uuidText = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

type inventoryJob struct {
	ID       string `json:"id"`
	ScanType string `json:"scan_type"`
	Status   string `json:"status"`
}

func readInventoryJob(body []byte) (inventoryJob, error) {
	var job inventoryJob
	if err := json.Unmarshal(body, &job); err != nil || !uuidText.MatchString(job.ID) ||
		job.ScanType != "persistence_full_scan" || job.Status != "dispatched" {
		return inventoryJob{}, errors.New("gateway returned an invalid inventory job")
	}
	return job, nil
}

func executeInventoryJob(ctx context.Context, send func(string, string, []byte) (int, []byte, error),
	collect func(context.Context, io.Writer) error, output io.Writer) error {
	status, body, err := send(http.MethodPost, "scan-jobs/poll", nil)
	if err != nil {
		return err
	}
	if status == http.StatusNoContent {
		return json.NewEncoder(output).Encode(nil)
	}
	if status != http.StatusOK {
		return fmt.Errorf("job poll returned HTTP %d", status)
	}
	job, err := readInventoryJob(body)
	if err != nil {
		return err
	}
	var report bytes.Buffer
	if err := collect(ctx, &report); err != nil {
		return err
	}
	path := "scan-jobs/" + job.ID + "/result"
	for range 2 {
		if err := ctx.Err(); err != nil {
			return err
		}
		status, body, err = send(http.MethodPut, path, report.Bytes())
		if err == nil && status < 500 {
			break
		}
	}
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return fmt.Errorf("inventory upload returned HTTP %d", status)
	}
	var receipt struct {
		ID         string    `json:"id"`
		Status     string    `json:"status"`
		FinishedAt time.Time `json:"finished_at"`
	}
	if err := json.Unmarshal(body, &receipt); err != nil || receipt.ID != job.ID || receipt.FinishedAt.IsZero() ||
		(receipt.Status != "completed" && receipt.Status != "partial" && receipt.Status != "failed") {
		return errors.New("gateway returned an invalid inventory receipt")
	}
	return json.NewEncoder(output).Encode(receipt)
}

func watchInventory(ctx context.Context, interval time.Duration, runOne func(context.Context, io.Writer) error,
	output, diagnostics io.Writer) error {
	for ctx.Err() == nil {
		var receipt bytes.Buffer
		if err := runOne(ctx, &receipt); err != nil {
			if ctx.Err() == nil {
				fmt.Fprintf(diagnostics, "Inventory poll failed: %v. Retrying in %s.\n", err, interval)
			}
		} else if receipt.Len() > 0 && !bytes.Equal(bytes.TrimSpace(receipt.Bytes()), []byte("null")) {
			if _, err := receipt.WriteTo(output); err != nil {
				return err
			}
		}

		timer := time.NewTimer(interval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil
		case <-timer.C:
		}
	}
	return nil
}

func watchHeartbeat(ctx context.Context, interval time.Duration, send func(context.Context) error, diagnostics io.Writer) {
	for ctx.Err() == nil {
		if err := send(ctx); err != nil && ctx.Err() == nil {
			fmt.Fprintf(diagnostics, "Heartbeat failed: %v. Retrying in %s.\n", err, interval)
		}
		timer := time.NewTimer(interval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}
