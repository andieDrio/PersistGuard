package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"sort"
	"unsafe"

	"golang.org/x/sys/windows"
)

type serviceEntry struct {
	Mechanism        string `json:"mechanism"`
	Name             string `json:"name"`
	DisplayName      string `json:"display_name"`
	State            string `json:"state"`
	StartType        string `json:"start_type,omitempty"`
	Command          string `json:"command,omitempty"`
	ExecutableSHA256 string `json:"executable_sha256,omitempty"`
	Account          string `json:"account,omitempty"`
}

type serviceIssue struct {
	Name      string `json:"name,omitempty"`
	Operation string `json:"operation"`
	Code      string `json:"code"`
}

type serviceInventory struct {
	OSFamily string         `json:"os_family"`
	Entries  []serviceEntry `json:"entries"`
	Coverage struct {
		Status string         `json:"status"`
		Issues []serviceIssue `json:"issues,omitempty"`
	} `json:"coverage"`
}

func serviceState(value uint32) string {
	states := [...]string{"unknown", "stopped", "start_pending", "stop_pending", "running", "continue_pending", "pause_pending", "paused"}
	if value < uint32(len(states)) {
		return states[value]
	}
	return "unknown"
}

func serviceStartType(value uint32, delayed bool) string {
	switch value {
	case windows.SERVICE_BOOT_START:
		return "boot"
	case windows.SERVICE_SYSTEM_START:
		return "system"
	case windows.SERVICE_AUTO_START:
		if delayed {
			return "automatic_delayed"
		}
		return "automatic"
	case windows.SERVICE_DEMAND_START:
		return "manual"
	case windows.SERVICE_DISABLED:
		return "disabled"
	default:
		return "unknown"
	}
}

func serviceError(err error) string {
	switch {
	case errors.Is(err, windows.ERROR_ACCESS_DENIED):
		return "access_denied"
	case errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST), errors.Is(err, windows.ERROR_SERVICE_MARKED_FOR_DELETE):
		return "not_found"
	default:
		return "read_failed"
	}
}

func enumerateWindowsServices(ctx context.Context, manager windows.Handle) ([]serviceEntry, error) {
	entries := make([]serviceEntry, 0)
	buff := make([]byte, 256*1024)
	var resume uint32
	for {
		if err := ctx.Err(); err != nil {
			return entries, err
		}
		var needed, returned uint32
		err := windows.EnumServicesStatusEx(manager, windows.SC_ENUM_PROCESS_INFO, windows.SERVICE_WIN32,
			windows.SERVICE_STATE_ALL, &buff[0], uint32(len(buff)), &needed, &returned, &resume, nil)
		if err != nil && (!errors.Is(err, windows.ERROR_MORE_DATA) || returned == 0) {
			return entries, err
		}
		for _, item := range unsafe.Slice((*windows.ENUM_SERVICE_STATUS_PROCESS)(unsafe.Pointer(&buff[0])), int(returned)) {
			entries = append(entries, serviceEntry{
				Mechanism: "windows_service", Name: windows.UTF16PtrToString(item.ServiceName),
				DisplayName: windows.UTF16PtrToString(item.DisplayName), State: serviceState(item.ServiceStatusProcess.CurrentState),
			})
		}
		if err == nil {
			return entries, nil
		}
	}
}

func queryServiceConfig(manager windows.Handle, entry *serviceEntry) error {
	name, err := windows.UTF16PtrFromString(entry.Name)
	if err != nil {
		return err
	}
	service, err := windows.OpenService(manager, name, windows.SERVICE_QUERY_CONFIG)
	if err != nil {
		return err
	}
	defer windows.CloseServiceHandle(service)
	// QueryServiceConfig permits a buffer of at most 8 KiB.
	buffer := make([]byte, 8*1024)
	config := (*windows.QUERY_SERVICE_CONFIG)(unsafe.Pointer(&buffer[0]))
	var needed uint32
	if err := windows.QueryServiceConfig(service, config, uint32(len(buffer)), &needed); err != nil {
		return err
	}
	entry.Command = windows.UTF16PtrToString(config.BinaryPathName)
	entry.Account = windows.UTF16PtrToString(config.ServiceStartName)
	entry.StartType = serviceStartType(config.StartType, false)
	if config.StartType == windows.SERVICE_AUTO_START {
		var info windows.SERVICE_DELAYED_AUTO_START_INFO
		if err := windows.QueryServiceConfig2(service, windows.SERVICE_CONFIG_DELAYED_AUTO_START_INFO,
			(*byte)(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info)), &needed); err != nil {
			return err
		}
		entry.StartType = serviceStartType(config.StartType, info.IsDelayedAutoStartUp != 0)
	}
	return nil
}

func collectServiceConfigs(ctx context.Context, report *serviceInventory, query func(*serviceEntry) error) error {
	for index := range report.Entries {
		if err := ctx.Err(); err != nil {
			return err
		}
		entry := &report.Entries[index]
		if err := query(entry); err != nil {
			report.Coverage.Status = "partial"
			report.Coverage.Issues = append(report.Coverage.Issues, serviceIssue{entry.Name, "query_config", serviceError(err)})
		}
	}
	return nil
}

func writeServicesInventory(ctx context.Context, output io.Writer) error {
	report := serviceInventory{OSFamily: "windows", Entries: []serviceEntry{}}
	report.Coverage.Status = "collected"
	manager, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT|windows.SC_MANAGER_ENUMERATE_SERVICE)
	if err != nil {
		report.Coverage.Status = "error"
		report.Coverage.Issues = []serviceIssue{{Operation: "open_manager", Code: serviceError(err)}}
		return json.NewEncoder(output).Encode(report)
	}
	defer windows.CloseServiceHandle(manager)
	entries, err := enumerateWindowsServices(ctx, manager)
	if ctx.Err() != nil {
		return ctx.Err()
	}
	report.Entries = entries
	if err != nil {
		report.Coverage.Status = "partial"
		if len(entries) == 0 {
			report.Coverage.Status = "error"
		}
		report.Coverage.Issues = []serviceIssue{{Operation: "enumerate_services", Code: serviceError(err)}}
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name < entries[j].Name })
	if err := collectServiceConfigs(ctx, &report, func(entry *serviceEntry) error { return queryServiceConfig(manager, entry) }); err != nil {
		return err
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
