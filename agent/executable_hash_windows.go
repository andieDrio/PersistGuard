package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	maxExecutableHashBytes = 64 * 1024 * 1024
	maxCollectorHashBytes  = 256 * 1024 * 1024
	maxCollectorHashFiles  = 512
)

var localVolumeDevice = regexp.MustCompile(`^\\Device\\HarddiskVolume[0-9]+$`)

type executableHasher struct {
	root      string
	deadline  time.Time
	remaining int64
	digests   map[string]string
	buffer    []byte
}

func newExecutableHasher() *executableHasher {
	root, _ := windows.GetWindowsDirectory()
	return &executableHasher{root: root, deadline: time.Now().Add(10 * time.Second), remaining: maxCollectorHashBytes,
		digests: make(map[string]string), buffer: make([]byte, 64*1024)}
}

func (h *executableHasher) hashCommand(ctx context.Context, command string) string {
	if command == "" || ctx.Err() != nil || time.Now().After(h.deadline) {
		return ""
	}
	args, err := windows.DecomposeCommandLine(strings.TrimSpace(command))
	if err != nil || len(args) == 0 {
		return ""
	}
	return h.hashExecutable(ctx, args[0])
}

func executablePath(command, windowsRoot string) string {
	path := strings.ReplaceAll(strings.TrimSpace(command), "/", `\`)
	if len(path) > 1 && path[0] == '"' && path[len(path)-1] == '"' {
		path = path[1 : len(path)-1]
	}
	for _, prefix := range []string{`%SystemRoot%\`, `%windir%\`, `\SystemRoot\`} {
		if len(path) >= len(prefix) && strings.EqualFold(path[:len(prefix)], prefix) && windowsRoot != "" {
			path = windowsRoot + `\` + path[len(prefix):]
			break
		}
	}
	if len(path) < 4 || path[1:3] != `:\` || !strings.ContainsRune("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz", rune(path[0])) ||
		strings.ContainsAny(path[3:], `:<>|"*?`) || !filepath.IsLocal(path[3:]) {
		return ""
	}
	for _, part := range strings.Split(path[3:], `\`) {
		if part == "" || strings.TrimRight(part, ". ") != part || strings.ContainsFunc(part, func(r rune) bool { return r < ' ' }) {
			return ""
		}
	}
	switch strings.ToLower(filepath.Ext(path)) {
	case ".exe", ".com", ".sys":
		return strings.ToUpper(path[:1]) + path[1:]
	}
	return ""
}

func openLocalExecutable(path string) *os.File {
	// Resolve only a physical volume mapping. Use the native volume device for the
	// open so a drive letter remap or a junction cannot send the read elsewhere.
	drive, _ := windows.UTF16PtrFromString(path[:2])
	var target [512]uint16
	if _, err := windows.QueryDosDevice(drive, &target[0], uint32(len(target))); err != nil {
		return nil
	}
	device := windows.UTF16ToString(target[:])
	if !localVolumeDevice.MatchString(device) {
		return nil
	}
	name, err := windows.NewNTUnicodeString(device + path[2:])
	if err != nil {
		return nil
	}
	var attributes windows.OBJECT_ATTRIBUTES
	attributes.Length = uint32(unsafe.Sizeof(attributes))
	attributes.ObjectName = name
	attributes.Attributes = windows.OBJ_CASE_INSENSITIVE | windows.OBJ_DONT_REPARSE
	var handle windows.Handle
	var status windows.IO_STATUS_BLOCK
	if err := windows.NtCreateFile(&handle, windows.FILE_GENERIC_READ, &attributes, &status, nil, 0,
		windows.FILE_SHARE_READ, windows.FILE_OPEN, windows.FILE_NON_DIRECTORY_FILE|windows.FILE_SYNCHRONOUS_IO_NONALERT, 0, 0); err != nil {
		return nil
	}
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &info); err != nil ||
		info.FileAttributes&(windows.FILE_ATTRIBUTE_REPARSE_POINT|windows.FILE_ATTRIBUTE_OFFLINE) != 0 {
		windows.CloseHandle(handle)
		return nil
	}
	return os.NewFile(uintptr(handle), path)
}

func (h *executableHasher) hashExecutable(ctx context.Context, command string) string {
	path := executablePath(command, h.root)
	if digest, ok := h.digests[path]; ok {
		return digest
	}
	if path == "" || len(h.digests) >= maxCollectorHashFiles || h.remaining <= 0 || ctx.Err() != nil || time.Now().After(h.deadline) {
		return ""
	}
	digest := h.readDigest(ctx, path)
	h.digests[path] = digest
	return digest
}

func (h *executableHasher) readDigest(ctx context.Context, path string) string {
	file := openLocalExecutable(path)
	if file == nil {
		return ""
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > maxExecutableHashBytes || info.Size() > h.remaining {
		return ""
	}
	digest := sha256.New()
	remaining := info.Size()
	for remaining > 0 {
		if ctx.Err() != nil || time.Now().After(h.deadline) {
			return ""
		}
		n, err := io.ReadFull(file, h.buffer[:min(int64(len(h.buffer)), remaining)])
		h.remaining -= int64(n)
		if err != nil {
			return ""
		}
		remaining -= int64(n)
		digest.Write(h.buffer[:n])
	}
	return hex.EncodeToString(digest.Sum(nil))
}
