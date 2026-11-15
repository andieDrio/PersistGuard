package main

import (
	"context"
	_ "embed"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/windows"
)

//go:embed scheduled_tasks.ps1
var scheduledTasksScript string

type scheduledTaskDefinition struct {
	Path    string `json:"path"`
	Enabled bool   `json:"enabled"`
	State   int    `json:"state"`
	XML     string `json:"xml"`
}

type scheduledTaskIssue struct {
	Path      string `json:"path"`
	Operation string `json:"operation"`
	Code      string `json:"code"`
}

type scheduledTaskAction struct {
	Type             string `json:"type"`
	Command          string `json:"command,omitempty"`
	ExecutableSHA256 string `json:"executable_sha256,omitempty"`
	Arguments        string `json:"arguments,omitempty"`
	WorkingDirectory string `json:"working_directory,omitempty"`
	ClassID          string `json:"class_id,omitempty"`
}

type scheduledTaskTrigger struct {
	Type          string `json:"type"`
	Enabled       bool   `json:"enabled"`
	StartBoundary string `json:"start_boundary,omitempty"`
}

type scheduledTaskEntry struct {
	Mechanism string                 `json:"mechanism"`
	Path      string                 `json:"path"`
	State     string                 `json:"state"`
	Enabled   bool                   `json:"enabled"`
	Hidden    bool                   `json:"hidden"`
	Actions   []scheduledTaskAction  `json:"actions"`
	Triggers  []scheduledTaskTrigger `json:"triggers"`
}

type scheduledTaskCoverage struct {
	Status         string               `json:"status"`
	FoldersVisited int                  `json:"folders_visited"`
	Issues         []scheduledTaskIssue `json:"issues,omitempty"`
}

type scheduledTaskInventory struct {
	OSFamily string                `json:"os_family"`
	Entries  []scheduledTaskEntry  `json:"entries"`
	Coverage scheduledTaskCoverage `json:"coverage"`
}

func parseScheduledTask(task scheduledTaskDefinition) (scheduledTaskEntry, error) {
	var definition struct {
		XMLName xml.Name `xml:"Task"`
		Hidden  bool     `xml:"Settings>Hidden"`
		Actions struct {
			Items []struct {
				XMLName          xml.Name
				Command          string `xml:"Command"`
				Arguments        string `xml:"Arguments"`
				WorkingDirectory string `xml:"WorkingDirectory"`
				ClassID          string `xml:"ClassId"`
			} `xml:",any"`
		} `xml:"Actions"`
		Triggers struct {
			Items []struct {
				XMLName       xml.Name
				Enabled       *bool  `xml:"Enabled"`
				StartBoundary string `xml:"StartBoundary"`
			} `xml:",any"`
		} `xml:"Triggers"`
	}
	if !strings.HasPrefix(task.Path, `\`) || strings.HasSuffix(task.Path, `\`) {
		return scheduledTaskEntry{}, errors.New("invalid scheduled task path")
	}
	decoder := xml.NewDecoder(strings.NewReader(task.XML))
	decoder.CharsetReader = func(charset string, input io.Reader) (io.Reader, error) {
		// COM supplies a string that PowerShell has already serialized as UTF-8.
		if strings.EqualFold(charset, "utf-16") {
			return input, nil
		}
		return nil, fmt.Errorf("unexpected XML encoding %q", charset)
	}
	if err := decoder.Decode(&definition); err != nil {
		return scheduledTaskEntry{}, err
	}
	states := [...]string{"unknown", "disabled", "queued", "ready", "running"}
	state := states[0]
	if task.State >= 0 && task.State < len(states) {
		state = states[task.State]
	}
	entry := scheduledTaskEntry{
		Mechanism: "scheduled_task", Path: task.Path, State: state, Enabled: task.Enabled, Hidden: definition.Hidden,
		Actions:  make([]scheduledTaskAction, 0, len(definition.Actions.Items)),
		Triggers: make([]scheduledTaskTrigger, 0, len(definition.Triggers.Items)),
	}
	for _, action := range definition.Actions.Items {
		entry.Actions = append(entry.Actions, scheduledTaskAction{
			Type: action.XMLName.Local, Command: action.Command, Arguments: action.Arguments,
			WorkingDirectory: action.WorkingDirectory, ClassID: action.ClassID,
		})
	}
	for _, trigger := range definition.Triggers.Items {
		entry.Triggers = append(entry.Triggers, scheduledTaskTrigger{
			Type: trigger.XMLName.Local, Enabled: trigger.Enabled == nil || *trigger.Enabled, StartBoundary: trigger.StartBoundary,
		})
	}
	return entry, nil
}

func decodeScheduledTaskInventory(payload []byte) (scheduledTaskInventory, error) {
	var raw struct {
		Tasks          []scheduledTaskDefinition `json:"tasks"`
		Issues         []scheduledTaskIssue      `json:"issues"`
		FoldersVisited int                       `json:"folders_visited"`
	}
	if err := json.Unmarshal(payload, &raw); err != nil || raw.Tasks == nil || raw.Issues == nil {
		return scheduledTaskInventory{}, errors.New("Task Scheduler returned an invalid inventory")
	}
	inventory := scheduledTaskInventory{
		OSFamily: "windows", Entries: make([]scheduledTaskEntry, 0, len(raw.Tasks)),
		Coverage: scheduledTaskCoverage{Status: "collected", FoldersVisited: raw.FoldersVisited, Issues: raw.Issues},
	}
	for _, task := range raw.Tasks {
		entry, err := parseScheduledTask(task)
		if err != nil {
			inventory.Coverage.Issues = append(inventory.Coverage.Issues, scheduledTaskIssue{task.Path, "parse_task", "invalid_definition"})
			continue
		}
		inventory.Entries = append(inventory.Entries, entry)
	}
	if len(inventory.Coverage.Issues) > 0 {
		inventory.Coverage.Status = "partial"
		if raw.FoldersVisited == 0 {
			inventory.Coverage.Status = "error"
		}
	}
	sort.Slice(inventory.Entries, func(i, j int) bool { return inventory.Entries[i].Path < inventory.Entries[j].Path })
	return inventory, nil
}

func writeScheduledTasksInventory(ctx context.Context, output io.Writer) error {
	systemDirectory, err := windows.GetSystemDirectory()
	if err != nil {
		return fmt.Errorf("locate Windows PowerShell: %w", err)
	}
	collectCtx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	powershell := filepath.Join(systemDirectory, "WindowsPowerShell", "v1.0", "powershell.exe")
	command := exec.CommandContext(collectCtx, powershell, "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", scheduledTasksScript)
	command.SysProcAttr = &syscall.SysProcAttr{CreationFlags: windows.CREATE_NO_WINDOW}
	stdout, err := command.StdoutPipe()
	if err != nil {
		return err
	}
	if err := command.Start(); err != nil {
		return fmt.Errorf("start Task Scheduler inventory: %w", err)
	}
	const maxPayload = 32 * 1024 * 1024
	payload, readErr := io.ReadAll(io.LimitReader(stdout, maxPayload+1))
	if len(payload) > maxPayload || readErr != nil {
		cancel()
		command.Wait()
		return errors.New("could not read Task Scheduler inventory within the output limit")
	}
	if err := command.Wait(); err != nil {
		if collectCtx.Err() != nil {
			return fmt.Errorf("Task Scheduler inventory interrupted: %w", collectCtx.Err())
		}
		return fmt.Errorf("Task Scheduler inventory failed: %w", err)
	}
	inventory, err := decodeScheduledTaskInventory(payload)
	if err != nil {
		return err
	}
	hasher := newExecutableHasher()
	for index := range inventory.Entries {
		for actionIndex := range inventory.Entries[index].Actions {
			action := &inventory.Entries[index].Actions[actionIndex]
			if action.Type == "Exec" {
				action.ExecutableSHA256 = hasher.hashExecutable(ctx, action.Command)
			}
		}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return json.NewEncoder(output).Encode(inventory)
}
