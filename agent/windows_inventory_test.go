package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"testing"
)

func TestCombinedInventoryRetainsReportsWhenACollectorFails(t *testing.T) {
	registryReport := `{"os_family":"windows","entries":[{"command":"fixture"}],"coverage":[{"status":"collected"},{"status":"absent"}]}`
	servicesReport := `{"os_family":"windows","entries":[],"coverage":{"status":"partial","issues":[{"code":"access_denied"}]}}`
	var output bytes.Buffer
	err := collectWindowsInventory(context.Background(), []inventoryCollector{
		{"registry", func(_ context.Context, output io.Writer) error {
			_, err := io.WriteString(output, registryReport)
			return err
		}},
		{"scheduled_tasks", func(context.Context, io.Writer) error { return errors.New("scheduler unavailable") }},
		{"services", func(_ context.Context, output io.Writer) error {
			_, err := io.WriteString(output, servicesReport)
			return err
		}},
	}, &output)
	if err != nil {
		t.Fatal(err)
	}
	var result combinedInventory
	if err := json.Unmarshal(output.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.SchemaVersion != 1 || result.OSFamily != "windows" || result.Status != "partial" || len(result.Collectors) != 3 {
		t.Fatalf("unexpected aggregate: %+v", result)
	}
	registry, tasks, services := result.Collectors["registry"], result.Collectors["scheduled_tasks"], result.Collectors["services"]
	if registry.Status != "collected" || string(registry.Report) != registryReport ||
		tasks.Status != "error" || len(tasks.Report) != 0 || tasks.Error != "scheduler unavailable" ||
		services.Status != "partial" || string(services.Report) != servicesReport {
		t.Fatalf("collector results were not preserved: %+v", result.Collectors)
	}
}

func TestCombinedInventoryCoverageSummaries(t *testing.T) {
	for _, test := range []struct {
		statuses []string
		want     string
	}{
		{[]string{"absent", "collected"}, "collected"},
		{[]string{"error", "absent"}, "partial"},
		{[]string{"error", "error"}, "error"},
	} {
		status, err := inventoryStatus(test.statuses)
		if err != nil || status != test.want {
			t.Errorf("unexpected status for %v: %q, %v", test.statuses, status, err)
		}
	}
	if _, err := collectorStatus([]byte(`{"os_family":"windows","coverage":{}}`)); err == nil {
		t.Fatal("missing collector status was accepted")
	}
}
