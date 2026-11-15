package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

func TestReadStartupRegistryFixture(t *testing.T) {
	// The fixture is a regular software key outside any Windows startup location.
	path := `Software\PersistGuardCollectorTest-` + rand.Text()
	fixture, existed, err := registry.CreateKey(registry.CURRENT_USER, path, registry.SET_VALUE)
	if err != nil {
		t.Fatal(err)
	}
	if existed {
		fixture.Close()
		t.Fatal("registry fixture already exists")
	}
	t.Cleanup(func() {
		fixture.Close()
		if err := registry.DeleteKey(registry.CURRENT_USER, path); err != nil {
			t.Error(err)
		}
	})
	const rawCommand = `"%PG_TEST_ROOT%\sample test.exe" --label="café"`
	if err := fixture.SetExpandStringValue("Expandable", rawCommand); err != nil {
		t.Fatal(err)
	}
	if err := fixture.SetStringValue("", "default entry"); err != nil {
		t.Fatal(err)
	}
	if err := fixture.SetDWordValue("Number", 4); err != nil {
		t.Fatal(err)
	}
	if err := fixture.SetStringValue("Oversized", strings.Repeat("x", 33*1024)); err != nil {
		t.Fatal(err)
	}

	location := startupLocation{"HKCU", path, "shared", "registry_run_key", registry.CURRENT_USER, 0}
	entries, coverage := readStartupLocation(location, nil)
	want := []startupEntry{
		{startupLocation: location, ValueType: "REG_SZ", Command: "default entry"},
		{startupLocation: location, ValueName: "Expandable", ValueType: "REG_EXPAND_SZ", Command: rawCommand},
	}
	if !reflect.DeepEqual(entries, want) {
		t.Fatalf("unexpected fixture entries: %+v", entries)
	}
	wantIssues := []startupIssue{{"Number", "unsupported_type"}, {"Oversized", "value_too_large"}}
	if coverage.Status != "partial" || !reflect.DeepEqual(coverage.Issues, wantIssues) {
		t.Fatalf("unexpected fixture coverage: %+v", coverage)
	}
	location.KeyPath += `\missing`
	entries, coverage = readStartupLocation(location, nil)
	if len(entries) != 0 || coverage.Status != "absent" || coverage.Error != "" {
		t.Fatalf("unexpected coverage for missing key: %+v", coverage)
	}
}

func TestStartupRegistryLocationsAndErrors(t *testing.T) {
	for _, tc := range []struct {
		is64Bit bool
		views   []string
	}{
		{true, []string{"64-bit", "32-bit", "shared", "64-bit", "32-bit", "shared"}},
		{false, []string{"32-bit", "shared", "32-bit", "shared"}},
	} {
		locations := startupLocations(tc.is64Bit)
		var views []string
		for _, location := range locations {
			views = append(views, location.View)
			if (location.Hive == "HKCU") != (location.View == "shared") {
				t.Fatalf("wrong hive for view: %+v", location)
			}
		}
		if !reflect.DeepEqual(views, tc.views) {
			t.Fatalf("registry views = %v; want %v", views, tc.views)
		}
	}
	if registryError(windows.ERROR_ACCESS_DENIED) != "access_denied" ||
		registryError(windows.ERROR_PATH_NOT_FOUND) != "not_found" ||
		registryError(windows.ERROR_INVALID_HANDLE) != "read_failed" {
		t.Fatal("unexpected Registry error classification")
	}
}

func TestStartupInventoryCommandDoesNotRequireGatewayConfig(t *testing.T) {
	t.Setenv(serverURLEnv, "")
	var output, diagnostics bytes.Buffer
	if code := run(context.Background(), []string{"--startup-inventory"}, nil, &output, &diagnostics); code != 0 {
		t.Fatalf("startup inventory exited %d: %s", code, diagnostics.String())
	}
	var inventory startupInventory
	if err := json.Unmarshal(output.Bytes(), &inventory); err != nil {
		t.Fatal(err)
	}
	is64Bit, err := has64BitRegistryView()
	if err != nil {
		t.Fatal(err)
	}
	if inventory.OSFamily != "windows" || inventory.Entries == nil || len(inventory.Coverage) != len(startupLocations(is64Bit)) {
		t.Fatal("inventory is missing platform, entries array, or expected coverage")
	}
	for _, result := range inventory.Coverage {
		if result.Hive == "" || result.KeyPath == "" || result.View == "" || result.Status == "" {
			t.Fatal("inventory coverage omitted source information")
		}
	}
	output.Reset()
	if code := run(context.Background(), []string{"--startup-inventory", "--generate-csr", "--device-key", "unused"}, nil, &output, &diagnostics); code != 2 || output.Len() != 0 {
		t.Fatal("combined modes were not rejected")
	}
}
