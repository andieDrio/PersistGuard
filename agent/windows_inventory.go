package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"runtime"
)

type inventoryCollector struct {
	source string
	run    func(context.Context, io.Writer) error
}

type collectorResult struct {
	Status string          `json:"status"`
	Report json.RawMessage `json:"report,omitempty"`
	Error  string          `json:"error,omitempty"`
}

type combinedInventory struct {
	SchemaVersion int                        `json:"schema_version"`
	OSFamily      string                     `json:"os_family"`
	Status        string                     `json:"status"`
	Collectors    map[string]collectorResult `json:"collectors"`
}

func inventoryStatus(statuses []string) (string, error) {
	readable, incomplete := false, false
	for _, status := range statuses {
		switch status {
		case "collected", "absent":
			readable = true
		case "partial":
			readable, incomplete = true, true
		case "error":
			incomplete = true
		default:
			return "", errors.New("collector reported an invalid coverage status")
		}
	}
	if !readable {
		return "error", nil
	}
	if incomplete {
		return "partial", nil
	}
	return "collected", nil
}

func collectorStatus(payload []byte) (string, error) {
	var report struct {
		OSFamily string          `json:"os_family"`
		Coverage json.RawMessage `json:"coverage"`
	}
	if err := json.Unmarshal(payload, &report); err != nil || report.OSFamily != "windows" || len(report.Coverage) == 0 {
		return "", errors.New("collector returned an invalid Windows report")
	}
	type coverage struct {
		Status string `json:"status"`
	}
	var results []coverage
	if report.Coverage[0] == '[' {
		if err := json.Unmarshal(report.Coverage, &results); err != nil || len(results) == 0 {
			return "", errors.New("collector returned invalid coverage")
		}
	} else {
		var result coverage
		if err := json.Unmarshal(report.Coverage, &result); err != nil {
			return "", errors.New("collector returned invalid coverage")
		}
		results = []coverage{result}
	}
	statuses := make([]string, 0, len(results))
	for _, result := range results {
		statuses = append(statuses, result.Status)
	}
	return inventoryStatus(statuses)
}

func collectWindowsInventory(ctx context.Context, collectors []inventoryCollector, output io.Writer) error {
	report := combinedInventory{SchemaVersion: 1, OSFamily: "windows", Collectors: make(map[string]collectorResult, len(collectors))}
	statuses := make([]string, 0, len(collectors))
	for _, collector := range collectors {
		if err := ctx.Err(); err != nil {
			return err
		}
		var payload bytes.Buffer
		result := collectorResult{Status: "error"}
		if err := collector.run(ctx, &payload); err != nil {
			result.Error = err.Error()
		} else if status, err := collectorStatus(payload.Bytes()); err != nil {
			result.Error = err.Error()
		} else {
			result.Status, result.Report = status, payload.Bytes()
		}
		report.Collectors[collector.source] = result
		statuses = append(statuses, result.Status)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	report.Status, _ = inventoryStatus(statuses)
	return json.NewEncoder(output).Encode(report)
}

func writeWindowsInventory(ctx context.Context, output io.Writer) error {
	if runtime.GOOS != "windows" {
		return errors.New("combined Windows inventory requires Windows")
	}
	return collectWindowsInventory(ctx, []inventoryCollector{
		{"registry", writeStartupInventory}, {"scheduled_tasks", writeScheduledTasksInventory}, {"services", writeServicesInventory},
	}, output)
}
