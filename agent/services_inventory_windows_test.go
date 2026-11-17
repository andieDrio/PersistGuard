package main

import (
	"context"
	"reflect"
	"testing"

	"golang.org/x/sys/windows"
)

func TestServiceInventoryKeepsEntriesWithUnavailableConfig(t *testing.T) {
	const command = `"%EXAMPLE%\café service.exe" --label="fixture"`
	report := serviceInventory{Entries: []serviceEntry{
		{Name: "Readable", State: serviceState(windows.SERVICE_RUNNING)},
		{Name: "Restricted", State: serviceState(windows.SERVICE_PAUSED)},
		{Name: "Removed", State: serviceState(windows.SERVICE_STOPPED)},
	}}
	report.Coverage.Status = "collected"
	err := collectServiceConfigs(context.Background(), &report, func(entry *serviceEntry) error {
		switch entry.Name {
		case "Restricted":
			return windows.ERROR_ACCESS_DENIED
		case "Removed":
			return windows.ERROR_SERVICE_DOES_NOT_EXIST
		}
		entry.Command = command
		entry.StartType = serviceStartType(windows.SERVICE_AUTO_START, true)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Entries) != 3 || report.Entries[0].Command != command || report.Entries[0].StartType != "automatic_delayed" ||
		report.Entries[1].State != "paused" || report.Entries[1].StartType != "" {
		t.Fatalf("unexpected entries: %+v", report.Entries)
	}
	want := []serviceIssue{{"Restricted", "query_config", "access_denied"}, {"Removed", "query_config", "not_found"}}
	if report.Coverage.Status != "partial" || !reflect.DeepEqual(report.Coverage.Issues, want) {
		t.Fatalf("unexpected coverage: %+v", report.Coverage)
	}
}

func TestServiceStartTypes(t *testing.T) {
	for _, test := range []struct {
		value   uint32
		delayed bool
		want    string
	}{
		{windows.SERVICE_BOOT_START, false, "boot"},
		{windows.SERVICE_SYSTEM_START, false, "system"},
		{windows.SERVICE_AUTO_START, false, "automatic"},
		{windows.SERVICE_AUTO_START, true, "automatic_delayed"},
		{windows.SERVICE_DEMAND_START, false, "manual"},
		{windows.SERVICE_DISABLED, true, "disabled"},
		{99, false, "unknown"},
	} {
		if got := serviceStartType(test.value, test.delayed); got != test.want {
			t.Errorf("start type for %d, delayed=%t: got %q, want %q", test.value, test.delayed, got, test.want)
		}
	}
}

func TestServiceInventoryRestrictedServicePreservesPartialCoverage(t *testing.T) {
    report := serviceInventory{Entries: []serviceEntry{
        {Name: "Readable", State: "running"},
        {Name: "McmSvc", State: "stopped"},
    }}
    report.Coverage.Status = "collected"
    err := collectServiceConfigs(context.Background(), &report, func(entry *serviceEntry) error {
        if entry.Name == "McmSvc" {
            return windows.ERROR_ACCESS_DENIED
        }
        entry.Command = `C:\\Windows\\System32\\svchost.exe`
        entry.StartType = "automatic"
        return nil
    })
    if err != nil {
        t.Fatal(err)
    }
    if report.Coverage.Status != "partial" {
        t.Fatalf("restricted service must retain partial coverage, got %q", report.Coverage.Status)
    }
    if len(report.Coverage.Issues) != 1 || report.Coverage.Issues[0] != (serviceIssue{
        Name: "McmSvc", Operation: "query_config", Code: "access_denied",
    }) {
        t.Fatalf("unexpected coverage diagnostics: %+v", report.Coverage.Issues)
    }
    if len(report.Entries) != 2 || report.Entries[1].Name != "McmSvc" ||
        report.Entries[1].State != "stopped" || report.Entries[1].StartType != "" ||
        report.Entries[0].StartType != "automatic" {
        t.Fatalf("collector must preserve both readable and restricted entries: %+v", report.Entries)
    }
}

func TestServiceInventoryAllConfigsReadable(t *testing.T) {
    report := serviceInventory{Entries: []serviceEntry{{Name: "Readable"}}}
    report.Coverage.Status = "collected"
    err := collectServiceConfigs(context.Background(), &report, func(entry *serviceEntry) error {
        entry.StartType = "manual"
        return nil
    })
    if err != nil {
        t.Fatal(err)
    }
    if report.Coverage.Status != "collected" || len(report.Coverage.Issues) != 0 {
        t.Fatalf("fully readable services should remain collected: %+v", report.Coverage)
    }
}
