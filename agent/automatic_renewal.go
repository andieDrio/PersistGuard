package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

func maintainDeviceCertificate(path string, now time.Time, request func(string, string, io.Writer) error) error {
	pending := path + ".renewal.pem"
	if _, err := os.Stat(pending); errors.Is(err, os.ErrNotExist) {
		current, err := readClientCertificate(path)
		if err != nil {
			return err
		}
		leaf := current.Leaf
		window := min(6*time.Hour, leaf.NotAfter.Sub(leaf.NotBefore)/4)
		if now.Before(leaf.NotAfter.Add(-window)) {
			return nil
		}

		var replacement bytes.Buffer
		if err := request(path, "certificate/renew", &replacement); err != nil {
			return fmt.Errorf("request replacement: %w", err)
		}
		if err := stageReplacementCertificate(pending, replacement.Bytes()); err != nil && !errors.Is(err, os.ErrExist) {
			return fmt.Errorf("save pending replacement: %w", err)
		}
	} else if err != nil {
		return fmt.Errorf("check pending replacement: %w", err)
	}

	// The pending PEM is durable before the gateway is allowed to retire its predecessor.
	if err := request(pending, "certificate/confirm", io.Discard); err != nil {
		return fmt.Errorf("confirm pending replacement: %w", err)
	}
	if err := moveCertificateFile(pending, path, true); err != nil {
		return fmt.Errorf("activate confirmed replacement: %w", err)
	}
	return nil
}

func stageReplacementCertificate(path string, contents []byte) error {
	temporary, err := os.CreateTemp(filepath.Dir(path), ".persistguard-renewal-*")
	if err != nil {
		return err
	}
	defer os.Remove(temporary.Name())
	defer temporary.Close()
	if _, err := temporary.Write(contents); err != nil {
		return err
	}
	if err := temporary.Sync(); err != nil {
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return moveCertificateFile(temporary.Name(), path, false)
}
