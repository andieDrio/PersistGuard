package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func renewalFixture(t *testing.T, notBefore, notAfter time.Time, serial int64) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(serial), NotBefore: notBefore, NotAfter: notAfter}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func TestAutomaticRenewalResumesAfterConfirmationResponseIsLost(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	path := filepath.Join(t.TempDir(), "active.pem")
	pending := path + ".renewal.pem"
	old := renewalFixture(t, now.Add(-23*time.Hour), now.Add(time.Hour), 1)
	replacement := renewalFixture(t, now, now.Add(24*time.Hour), 2)
	if err := os.WriteFile(path, old, 0600); err != nil {
		t.Fatal(err)
	}

	var operations []string
	confirmed := false
	request := func(certPath, operation string, output io.Writer) error {
		operations = append(operations, operation)
		if operation == "certificate/renew" && certPath == path {
			_, err := output.Write(replacement)
			return err
		}
		staged, err := os.ReadFile(pending)
		if operation != "certificate/confirm" || certPath != pending || err != nil || !bytes.Equal(staged, replacement) {
			t.Fatalf("confirmation attempted before saving replacement: %s %s %v", operation, certPath, err)
		}
		if !confirmed {
			confirmed = true
			return errors.New("fixture lost the confirmation response")
		}
		return nil
	}
	if err := maintainDeviceCertificate(path, now, request); err == nil || !strings.Contains(err.Error(), "lost the confirmation response") {
		t.Fatalf("expected the first confirmation failure, got %v", err)
	}
	if active, err := os.ReadFile(path); err != nil || !bytes.Equal(active, old) {
		t.Fatalf("the active certificate changed before local confirmation: %v", err)
	}
	if err := maintainDeviceCertificate(path, now, request); err != nil {
		t.Fatal(err)
	}
	if active, err := os.ReadFile(path); err != nil || !bytes.Equal(active, replacement) {
		t.Fatalf("confirmed replacement did not become active: %v", err)
	}
	if _, err := os.Stat(pending); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("pending certificate was not promoted: %v", err)
	}
	if err := maintainDeviceCertificate(path, now, request); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(operations, []string{"certificate/renew", "certificate/confirm", "certificate/confirm"}) {
		t.Fatalf("unexpected renewal operations: %v", operations)
	}
}

func TestAutomaticRenewalGatewayFailurePreservesActiveCertificate(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	path := filepath.Join(t.TempDir(), "active.pem")
	old := renewalFixture(t, now.Add(-23*time.Hour), now.Add(time.Hour), 1)
	if err := os.WriteFile(path, old, 0600); err != nil {
		t.Fatal(err)
	}
	err := maintainDeviceCertificate(path, now, func(string, string, io.Writer) error {
		return errors.New("fixture gateway offline")
	})
	if err == nil || !strings.Contains(err.Error(), "fixture gateway offline") {
		t.Fatalf("expected gateway error, got %v", err)
	}
	if active, err := os.ReadFile(path); err != nil || !bytes.Equal(active, old) {
		t.Fatalf("gateway failure changed the active file: %v", err)
	}
}
