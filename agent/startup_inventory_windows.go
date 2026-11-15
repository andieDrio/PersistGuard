package main

import (
	"context"
	"debug/pe"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"runtime"
	"sort"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

type startupLocation struct {
	Hive      string `json:"hive"`
	KeyPath   string `json:"key_path"`
	View      string `json:"registry_view"`
	Mechanism string `json:"mechanism"`
	key       registry.Key
	access    uint32
}

type startupEntry struct {
	startupLocation
	ValueName        string `json:"value_name"`
	ValueType        string `json:"value_type"`
	Command          string `json:"command"`
	ExecutableSHA256 string `json:"executable_sha256,omitempty"`
}

type startupIssue struct {
	ValueName string `json:"value_name"`
	Code      string `json:"code"`
}

type startupCoverage struct {
	startupLocation
	Status string         `json:"status"`
	Error  string         `json:"error,omitempty"`
	Issues []startupIssue `json:"issues,omitempty"`
}

type startupInventory struct {
	OSFamily string            `json:"os_family"`
	Entries  []startupEntry    `json:"entries"`
	Coverage []startupCoverage `json:"coverage"`
}

func startupLocations(has64BitView bool) []startupLocation {
	const base = `Software\Microsoft\Windows\CurrentVersion\`
	var locations []startupLocation
	for _, item := range []struct{ name, mechanism string }{
		{"Run", "registry_run_key"},
		{"RunOnce", "registry_run_once_key"},
	} {
		path := base + item.name
		if has64BitView {
			locations = append(locations,
				startupLocation{"HKLM", path, "64-bit", item.mechanism, registry.LOCAL_MACHINE, registry.WOW64_64KEY},
				startupLocation{"HKLM", path, "32-bit", item.mechanism, registry.LOCAL_MACHINE, registry.WOW64_32KEY},
			)
		} else {
			locations = append(locations, startupLocation{"HKLM", path, "32-bit", item.mechanism, registry.LOCAL_MACHINE, 0})
		}
		locations = append(locations, startupLocation{"HKCU", path, "shared", item.mechanism, registry.CURRENT_USER, 0})
	}
	return locations
}

func has64BitRegistryView() (bool, error) {
	if runtime.GOARCH != "386" {
		return true, nil
	}
	var processMachine, nativeMachine uint16
	if err := windows.IsWow64Process2(windows.CurrentProcess(), &processMachine, &nativeMachine); err != nil {
		return false, fmt.Errorf("detect Windows Registry views: %w", err)
	}
	return nativeMachine == pe.IMAGE_FILE_MACHINE_AMD64 || nativeMachine == pe.IMAGE_FILE_MACHINE_ARM64, nil
}

func registryError(err error) string {
	switch {
	case errors.Is(err, registry.ErrNotExist), errors.Is(err, windows.ERROR_PATH_NOT_FOUND):
		return "not_found"
	case errors.Is(err, windows.ERROR_ACCESS_DENIED):
		return "access_denied"
	case errors.Is(err, registry.ErrShortBuffer):
		return "value_too_large"
	default:
		return "read_failed"
	}
}

func readStartupLocation(location startupLocation, entries []startupEntry) ([]startupEntry, startupCoverage) {
	coverage := startupCoverage{startupLocation: location, Status: "collected"}
	key, err := registry.OpenKey(location.key, location.KeyPath, registry.QUERY_VALUE|location.access)
	if err != nil {
		code := registryError(err)
		if code == "not_found" {
			coverage.Status = "absent"
		} else {
			coverage.Status, coverage.Error = "error", code
		}
		return entries, coverage
	}
	defer key.Close()
	names, err := key.ReadValueNames(-1)
	if err != nil {
		coverage.Status, coverage.Error = "partial", registryError(err)
		if len(names) == 0 {
			coverage.Status = "error"
		}
	}
	sort.Strings(names)
	// Bound individual values while retaining the outcome for every enumerated name.
	buffer := make([]byte, 64*1024)
	for _, name := range names {
		size, valueType, err := key.GetValue(name, buffer)
		var code, nameOfType string
		switch {
		case err != nil:
			code = registryError(err)
		case valueType != registry.SZ && valueType != registry.EXPAND_SZ:
			code = "unsupported_type"
		case size%2 != 0:
			code = "invalid_string"
		case valueType == registry.SZ:
			nameOfType = "REG_SZ"
		default:
			nameOfType = "REG_EXPAND_SZ"
		}
		if code != "" {
			coverage.Status = "partial"
			coverage.Issues = append(coverage.Issues, startupIssue{name, code})
			continue
		}
		data := make([]uint16, size/2)
		for index := range data {
			data[index] = binary.LittleEndian.Uint16(buffer[2*index:])
		}
		entries = append(entries, startupEntry{startupLocation: location, ValueName: name, ValueType: nameOfType, Command: windows.UTF16ToString(data)})
	}
	return entries, coverage
}

func writeStartupInventory(ctx context.Context, output io.Writer) error {
	has64BitView, err := has64BitRegistryView()
	if err != nil {
		return err
	}
	locations := startupLocations(has64BitView)
	report := startupInventory{
		OSFamily: "windows",
		Entries:  []startupEntry{},
		Coverage: make([]startupCoverage, 0, len(locations)),
	}
	for _, location := range locations {
		if err := ctx.Err(); err != nil {
			return err
		}
		var coverage startupCoverage
		report.Entries, coverage = readStartupLocation(location, report.Entries)
		report.Coverage = append(report.Coverage, coverage)
	}
	hasher := newExecutableHasher()
	for index := range report.Entries {
		entry := &report.Entries[index]
		entry.ExecutableSHA256 = hasher.hashCommand(ctx, entry.Command)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return json.NewEncoder(output).Encode(report)
}
