package main

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

func TestEnrollmentUsesExistingProtectedKeyAndKeepsTokenOutOfOutput(t *testing.T) {
	const organization = "12345678-1234-1234-1234-123456789abc"
	const endpoint = "87654321-4321-4321-4321-cba987654321"
	token := strings.Repeat("T", 43)
	var received atomic.Int32
	storedKey := make(chan []byte, 2)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/agent/enroll" || r.Header.Get("Authorization") != "Bearer "+token {
			http.Error(w, "unexpected request", http.StatusBadRequest)
			return
		}
		var body struct {
			Organization string `json:"organization_id"`
			Host         string `json:"hostname"`
			OS           string `json:"os_family"`
			CSR          string `json:"csr"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Organization != organization || body.Host == "" || body.OS != "windows" {
			http.Error(w, "unexpected enrollment fields", http.StatusBadRequest)
			return
		}
		block, _ := pem.Decode([]byte(body.CSR))
		if block == nil {
			http.Error(w, "missing CSR", http.StatusBadRequest)
			return
		}
		csr, err := x509.ParseCertificateRequest(block.Bytes)
		if err != nil || csr.CheckSignature() != nil {
			http.Error(w, "invalid CSR", http.StatusBadRequest)
			return
		}
		storedKey <- csr.RawSubjectPublicKeyInfo
		if received.Add(1) != 1 {
			http.Error(w, "invitation already used", http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusCreated)
		io.WriteString(w, `{"endpoint_id":"`+endpoint+`","status":"pending"}`)
	}))
	t.Cleanup(server.Close)
	directory := t.TempDir()
	keyPath, caPath := filepath.Join(directory, "device.dpapi"), filepath.Join(directory, "ca.pem")
	if err := os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	args := []string{"--enroll", "--enrollment-url", server.URL, "--organization-id", organization, "--device-key", keyPath, "--server-ca", caPath}
	var output, diagnostics bytes.Buffer
	if code := run(context.Background(), args, strings.NewReader("invalid\n"), &output, &diagnostics); code != 1 || received.Load() != 0 {
		t.Fatalf("invalid token unexpectedly submitted, code=%d", code)
	}
	if _, err := os.Stat(keyPath); !os.IsNotExist(err) {
		t.Fatalf("invalid token unexpectedly created device key: %v", err)
	}
	diagnostics.Reset()
	if code := run(context.Background(), args, strings.NewReader(token+"\r\n"), &output, &diagnostics); code != 0 {
		t.Fatalf("enrollment exit=%d: %s", code, diagnostics.String())
	}
	if !strings.Contains(output.String(), endpoint) || strings.Contains(output.String(), token) {
		t.Fatal("invalid registration receipt or token leaked to stdout")
	}
	output.Reset()
	if code := run(context.Background(), args, strings.NewReader(token), &output, &diagnostics); code != 1 ||
		!strings.Contains(diagnostics.String(), "HTTP 401") || strings.Contains(diagnostics.String(), token) || output.Len() != 0 {
		t.Fatal("token replay was not reported safely")
	}
	if received.Load() != 2 || !bytes.Equal(<-storedKey, <-storedKey) {
		t.Fatal("enrollment did not reuse the same device key")
	}
}
