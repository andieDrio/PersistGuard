package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestWatchHeartbeatRetriesAndStopsWithoutInventoryJobs(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	var diagnostics bytes.Buffer
	calls := 0
	watchHeartbeat(ctx, 5*time.Millisecond, func(context.Context) error {
		calls++
		if calls == 1 {
			return errors.New("offline")
		}
		if calls == 3 {
			cancel()
		}
		return nil
	}, &diagnostics)
	if calls != 3 || !strings.Contains(diagnostics.String(), "Heartbeat failed: offline") {
		t.Fatalf("heartbeat calls = %d, diagnostics = %q", calls, diagnostics.String())
	}
}

func TestInventoryJobRetriesTheSameReport(t *testing.T) {
	const id = "12345678-1234-1234-1234-123456789abc"
	const report = `{"schema_version":1,"status":"partial"}`
	var output bytes.Buffer
	uploads, collections := 0, 0
	send := func(method, path string, body []byte) (int, []byte, error) {
		if method == http.MethodPost && path == "scan-jobs/poll" {
			return 200, []byte(`{"id":"` + id + `","scan_type":"persistence_full_scan","status":"dispatched"}`), nil
		}
		if method != http.MethodPut || path != "scan-jobs/"+id+"/result" || string(body) != report {
			t.Fatalf("unexpected upload %s %s: %s", method, path, body)
		}
		uploads++
		if uploads == 1 {
			return http.StatusServiceUnavailable, nil, nil
		}
		return 200, []byte(`{"id":"` + id + `","status":"partial","finished_at":"2026-11-15T00:00:00Z"}`), nil
	}
	collect := func(_ context.Context, output io.Writer) error {
		collections++
		_, err := io.WriteString(output, report)
		return err
	}
	if err := executeInventoryJob(context.Background(), send, collect, &output); err != nil {
		t.Fatal(err)
	}
	if uploads != 2 || collections != 1 || !strings.Contains(output.String(), `"status":"partial"`) {
		t.Fatalf("uploads=%d collections=%d output=%q", uploads, collections, output.String())
	}
}

func TestInventoryWatchRecoversAndSuppressesEmptyPolls(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	interval := 10 * time.Millisecond
	var output, diagnostics bytes.Buffer
	var polls []time.Time
	const receipt = "{\"id\":\"fixture-job\",\"status\":\"partial\"}\n"
	runOne := func(_ context.Context, writer io.Writer) error {
		polls = append(polls, time.Now())
		switch len(polls) {
		case 1:
			return errors.New("fixture gateway offline")
		case 2:
			_, err := io.WriteString(writer, "null\n")
			return err
		default:
			cancel()
			_, err := io.WriteString(writer, receipt)
			return err
		}
	}
	if err := watchInventory(ctx, interval, runOne, &output, &diagnostics); err != nil {
		t.Fatal(err)
	}
	if len(polls) != 3 || output.String() != receipt || !strings.Contains(diagnostics.String(), "fixture gateway offline") {
		t.Fatalf("polls=%d output=%q diagnostics=%q", len(polls), output.String(), diagnostics.String())
	}
	if polls[1].Sub(polls[0]) < interval || polls[2].Sub(polls[1]) < interval {
		t.Fatal("watch mode did not wait between polls")
	}
}
