package main

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"
)

func TestScheduledTaskInventoryParsesDefinitionsAndPreservesCoverage(t *testing.T) {
	const definition = `<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <Triggers>
    <LogonTrigger><Enabled>false</Enabled></LogonTrigger>
    <TimeTrigger><StartBoundary>2026-11-15T08:30:00+08:00</StartBoundary></TimeTrigger>
  </Triggers>
  <Settings><Hidden>true</Hidden></Settings>
  <Actions>
    <Exec><Command>%EXAMPLE%\test fixture.exe</Command><Arguments>--name "café &amp; tea"</Arguments><WorkingDirectory>C:\Example</WorkingDirectory></Exec>
    <ComHandler><ClassId>{11111111-1111-1111-1111-111111111111}</ClassId></ComHandler>
  </Actions>
</Task>`
	payload, err := json.Marshal(map[string]any{
		"tasks": []scheduledTaskDefinition{
			{Path: `\Test\Zulu`, Enabled: false, State: 1, XML: definition},
			{Path: `\Alpha`, Enabled: true, State: 3, XML: `<Task/>`},
			{Path: `\Malformed`, XML: `<Task><Actions>`},
		},
		"folders_visited": 3,
		"issues":          []scheduledTaskIssue{{`\Restricted`, "enumerate_tasks", "access_denied"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	inventory, err := decodeScheduledTaskInventory(payload)
	if err != nil {
		t.Fatal(err)
	}
	if inventory.OSFamily != "windows" || len(inventory.Entries) != 2 || inventory.Coverage.FoldersVisited != 3 ||
		inventory.Coverage.Status != "partial" || len(inventory.Coverage.Issues) != 2 ||
		inventory.Coverage.Issues[0].Code != "access_denied" || inventory.Coverage.Issues[1].Code != "invalid_definition" {
		t.Fatalf("unexpected report: %+v", inventory)
	}
	empty, task := inventory.Entries[0], inventory.Entries[1]
	if empty.Path != `\Alpha` || empty.State != "ready" || empty.Actions == nil || empty.Triggers == nil {
		t.Fatalf("unexpected first entry: %+v", empty)
	}
	if task.Path != `\Test\Zulu` || task.State != "disabled" || task.Enabled || !task.Hidden ||
		task.Mechanism != "scheduled_task" || len(task.Actions) != 2 || len(task.Triggers) != 2 {
		t.Fatalf("unexpected task: %+v", task)
	}
	if task.Actions[0] != (scheduledTaskAction{
		Type: "Exec", Command: `%EXAMPLE%\test fixture.exe`, Arguments: `--name "café & tea"`, WorkingDirectory: `C:\Example`,
	}) || task.Actions[1] != (scheduledTaskAction{Type: "ComHandler", ClassID: "{11111111-1111-1111-1111-111111111111}"}) {
		t.Fatalf("unexpected actions: %+v", task.Actions)
	}
	if task.Triggers[0] != (scheduledTaskTrigger{Type: "LogonTrigger", Enabled: false}) || task.Triggers[1] != (scheduledTaskTrigger{
		Type: "TimeTrigger", Enabled: true, StartBoundary: "2026-11-15T08:30:00+08:00",
	}) {
		t.Fatalf("unexpected triggers: %+v", task.Triggers)
	}
}

func TestScheduledTaskInventoryReportsUnavailableScheduler(t *testing.T) {
	payload := []byte(`{"tasks":[],"folders_visited":0,"issues":[{"path":"\\","operation":"connect","code":"read_failed"}]}`)
	inventory, err := decodeScheduledTaskInventory(payload)
	if err != nil || inventory.Coverage.Status != "error" || inventory.Entries == nil || len(inventory.Entries) != 0 {
		t.Fatalf("unexpected scheduler unavailable report: %+v, %v", inventory, err)
	}
	if _, err := decodeScheduledTaskInventory([]byte(`{}`)); err == nil {
		t.Fatal("missing provider results were accepted")
	}
}

func TestScheduledTaskInventoryRejectsCombinedModes(t *testing.T) {
	var output, diagnostics bytes.Buffer
	if code := run(context.Background(), []string{"--scheduled-tasks-inventory", "--startup-inventory"}, nil, &output, &diagnostics); code != 2 || output.Len() != 0 {
		t.Fatal("combined inventory modes were not rejected")
	}
}
