package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"
)

func loadOrCreateDeviceKey(path string) (*ecdsa.PrivateKey, error) {
	key, err := readDeviceKey(path)
	if !errors.Is(err, os.ErrNotExist) {
		return key, err
	}

	key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	if err := saveDeviceKey(path, key); err != nil {
		if errors.Is(err, windows.ERROR_ALREADY_EXISTS) || errors.Is(err, windows.ERROR_FILE_EXISTS) {
			return readDeviceKey(path)
		}
		return nil, fmt.Errorf("save device key: %w", err)
	}
	return key, nil
}

func readDeviceKey(path string) (*ecdsa.PrivateKey, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	const maxProtectedKeySize = 64 * 1024
	protected, err := io.ReadAll(io.LimitReader(file, maxProtectedKeySize+1))
	if err != nil {
		return nil, err
	}
	if len(protected) == 0 || len(protected) > maxProtectedKeySize {
		return nil, errors.New("invalid protected device key size")
	}

	input := windows.DataBlob{Size: uint32(len(protected)), Data: &protected[0]}
	var output windows.DataBlob
	if err := windows.CryptUnprotectData(&input, nil, nil, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &output); err != nil {
		return nil, fmt.Errorf("decrypt device key with DPAPI: %w", err)
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(output.Data)))
	plaintext := unsafe.Slice(output.Data, int(output.Size))
	defer clear(plaintext)
	parsed, err := x509.ParsePKCS8PrivateKey(plaintext)
	if err != nil {
		return nil, fmt.Errorf("parse device key: %w", err)
	}
	key, ok := parsed.(*ecdsa.PrivateKey)
	if !ok || key.Curve != elliptic.P256() {
		return nil, errors.New("device key must use ECDSA P-256")
	}
	return key, nil
}

func saveDeviceKey(path string, key *ecdsa.PrivateKey) error {
	plaintext, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	defer clear(plaintext)
	input := windows.DataBlob{Size: uint32(len(plaintext)), Data: &plaintext[0]}
	var output windows.DataBlob
	if err := windows.CryptProtectData(&input, nil, nil, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &output); err != nil {
		return fmt.Errorf("encrypt device key with DPAPI: %w", err)
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(output.Data)))
	protected := unsafe.Slice(output.Data, int(output.Size))

	temporary, err := os.CreateTemp(filepath.Dir(path), ".device-key-*")
	if err != nil {
		return err
	}
	defer os.Remove(temporary.Name())
	defer temporary.Close()
	if _, err := temporary.Write(protected); err != nil {
		return err
	}
	if err := temporary.Sync(); err != nil {
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}

	source, err := windows.UTF16PtrFromString(temporary.Name())
	if err != nil {
		return err
	}
	destination, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	return windows.MoveFileEx(source, destination, windows.MOVEFILE_WRITE_THROUGH)
}
