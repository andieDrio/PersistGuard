package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCheckIdentityUsesDPAPIKeyAndVerifiesGateway(t *testing.T) {
	directory := t.TempDir()
	deviceKey := filepath.Join(directory, "device-key.dpapi")
	device, err := loadOrCreateDeviceKey(deviceKey)
	if err != nil {
		t.Fatal(err)
	}
	issuer, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	issuerTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Agent test CA"},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	issuerDER, err := x509.CreateCertificate(rand.Reader, issuerTemplate, issuerTemplate, issuer.Public(), issuer)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(issuerDER)
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "Test device"},
		NotBefore: ca.NotBefore, NotAfter: ca.NotAfter, KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	certificate, err := x509.CreateCertificate(rand.Reader, leaf, ca, device.Public(), issuer)
	if err != nil {
		t.Fatal(err)
	}
	writeCert := func(name string, der []byte) string {
		t.Helper()
		path := filepath.Join(directory, name)
		if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	clientCert := writeCert("device.pem", certificate)
	wrongCA := writeCert("agent-ca.pem", issuerDER)
	clientRoots := x509.NewCertPool()
	clientRoots.AddCert(ca)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !bytes.Equal(r.TLS.PeerCertificates[0].Raw, certificate) {
			http.Error(w, "unexpected request", http.StatusBadRequest)
			return
		}
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/agent/identity":
			io.WriteString(w, `{"endpoint_id":"device-id","organization_id":"org-id"}`)
		case r.Method == http.MethodPost && r.URL.Path == "/api/agent/heartbeat":
			io.WriteString(w, `{"endpoint_id":"device-id","organization_id":"org-id","last_seen":"2026-11-15T00:00:00Z"}`)
		case r.Method == http.MethodPost && r.URL.Path == "/api/agent/scan-jobs/poll":
			io.WriteString(w, `{"id":"12345678-1234-1234-1234-123456789abc","scan_type":"persistence_full_scan","status":"dispatched"}`)
		default:
			http.Error(w, "unexpected path or method", http.StatusBadRequest)
		}
	}))
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: clientRoots}
	server.StartTLS()
	t.Cleanup(server.Close)
	serverCA := writeCert("gateway-ca.pem", server.Certificate().Raw)
	t.Setenv(serverURLEnv, server.URL)

	invoke := func(key, trust string) (int, string, string) {
		var output, diagnostics bytes.Buffer
		args := []string{"--check-identity", "--device-key", key, "--client-cert", clientCert, "--server-ca", trust}
		code := run(context.Background(), args, nil, &output, &diagnostics)
		return code, output.String(), diagnostics.String()
	}
	code, output, diagnostics := invoke(deviceKey, serverCA)
	if code != 0 {
		t.Fatalf("check identity exited %d: %s", code, diagnostics)
	}
	var identity gatewayIdentity
	if err := json.Unmarshal([]byte(output), &identity); err != nil || identity != (gatewayIdentity{EndpointID: "device-id", OrganizationID: "org-id"}) {
		t.Fatalf("unexpected identity response: %q", output)
	}
	var heartbeat, heartbeatErrors bytes.Buffer
	args := []string{"--heartbeat", "--device-key", deviceKey, "--client-cert", clientCert, "--server-ca", serverCA}
	if code := run(context.Background(), args, nil, &heartbeat, &heartbeatErrors); code != 0 {
		t.Fatalf("heartbeat exited %d: %s", code, heartbeatErrors.String())
	}
	if err := json.Unmarshal(heartbeat.Bytes(), &identity); err != nil || identity.LastSeen == nil ||
		identity.LastSeen.Format(time.RFC3339) != "2026-11-15T00:00:00Z" {
		t.Fatalf("unexpected heartbeat response: %s", heartbeat.String())
	}
	otherKey := filepath.Join(directory, "other-key.dpapi")
	var poll, pollErrors bytes.Buffer
	args[0] = "--poll-job"
	if code := run(context.Background(), args, nil, &poll, &pollErrors); code != 0 || !strings.Contains(poll.String(), "12345678-1234-1234-1234-123456789abc") {
		t.Fatalf("poll job exited %d: %s", code, pollErrors.String())
	}
	if _, err := loadOrCreateDeviceKey(otherKey); err != nil {
		t.Fatal(err)
	}
	if code, output, diagnostics := invoke(otherKey, serverCA); code != 1 || output != "" || !strings.Contains(diagnostics, "does not match") {
		t.Fatalf("mismatched key exit = %d, diagnostic = %q", code, diagnostics)
	}
	if code, output, diagnostics := invoke(deviceKey, wrongCA); code != 1 || output != "" || !strings.Contains(diagnostics, "connect to gateway") {
		t.Fatalf("untrusted CA exit = %d, diagnostic = %q", code, diagnostics)
	}
	missingKey := filepath.Join(directory, "missing-key.dpapi")
	if code, output, diagnostics := invoke(missingKey, serverCA); code != 1 || output != "" || !strings.Contains(diagnostics, "load existing device key") {
		t.Fatalf("missing key exit = %d, diagnostic = %q", code, diagnostics)
	}
	if _, err := os.Stat(missingKey); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("identity check unexpectedly created a device key")
	}
}
