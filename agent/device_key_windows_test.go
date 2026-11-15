package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
)

func readCSR(t *testing.T, output []byte) *x509.CertificateRequest {
	t.Helper()
	block, rest := pem.Decode(output)
	if block == nil || block.Type != "CERTIFICATE REQUEST" || len(rest) != 0 {
		t.Fatal("expected one PEM certificate signing request")
	}
	request, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if err := request.CheckSignature(); err != nil {
		t.Fatal(err)
	}
	key, ok := request.PublicKey.(*ecdsa.PublicKey)
	if !ok || key.Curve != elliptic.P256() {
		t.Fatal("expected an ECDSA P-256 public key")
	}
	if len(request.Subject.Names) != 0 || len(request.Extensions) != 0 {
		t.Fatal("the server should assign the endpoint identity")
	}
	return request
}

func TestGenerateCSRReusesProtectedDeviceKey(t *testing.T) {
	keyPath := filepath.Join(t.TempDir(), "device-key.dpapi")
	var publicKeys [][]byte
	for range 2 {
		var output, diagnostics bytes.Buffer
		args := []string{"--generate-csr", "--device-key", keyPath}
		if code := run(context.Background(), args, nil, &output, &diagnostics); code != 0 {
			t.Fatalf("generate CSR exited %d: %s", code, diagnostics.String())
		}
		request := readCSR(t, output.Bytes())
		publicKeys = append(publicKeys, request.RawSubjectPublicKeyInfo)
	}
	if !bytes.Equal(publicKeys[0], publicKeys[1]) {
		t.Fatal("CSR generation replaced the device key")
	}
	protected, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := x509.ParsePKCS8PrivateKey(protected); err == nil {
		t.Fatal("device key file is plaintext")
	}
}

func TestCorruptDeviceKeyIsPreserved(t *testing.T) {
	keyPath := filepath.Join(t.TempDir(), "device-key.dpapi")
	corrupt := []byte("invalid protected key")
	if err := os.WriteFile(keyPath, corrupt, 0600); err != nil {
		t.Fatal(err)
	}
	var output, diagnostics bytes.Buffer
	if code := run(context.Background(), []string{"--generate-csr", "--device-key", keyPath}, nil, &output, &diagnostics); code != 1 {
		t.Fatalf("corrupt key exit code = %d; want 1", code)
	}
	if output.Len() != 0 {
		t.Fatal("a corrupt device key produced a CSR")
	}
	stored, err := os.ReadFile(keyPath)
	if err != nil || !bytes.Equal(stored, corrupt) {
		t.Fatal("corrupt device key was replaced")
	}
}

func TestConcurrentCSRGenerationUsesOneDeviceKey(t *testing.T) {
	keyPath := filepath.Join(t.TempDir(), "device-key.dpapi")
	type result struct {
		csr []byte
		err error
	}
	ready := make(chan struct{})
	results := make(chan result, 2)
	for range 2 {
		go func() {
			<-ready
			var output bytes.Buffer
			err := writeDeviceCSR(keyPath, &output)
			results <- result{output.Bytes(), err}
		}()
	}
	close(ready)
	first, second := <-results, <-results
	if first.err != nil || second.err != nil {
		t.Fatalf("concurrent CSR generation failed: %v, %v", first.err, second.err)
	}
	firstKey := readCSR(t, first.csr).RawSubjectPublicKeyInfo
	secondKey := readCSR(t, second.csr).RawSubjectPublicKeyInfo
	if !bytes.Equal(firstKey, secondKey) {
		t.Fatal("concurrent CSR requests used different keys")
	}
}
