package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sync/atomic"
	"time"
)

func readClientCertificate(certificatePath string) (tls.Certificate, error) {
	contents, err := os.ReadFile(certificatePath)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("read client certificate: %w", err)
	}
	var certificate tls.Certificate
	for len(bytes.TrimSpace(contents)) != 0 {
		block, rest := pem.Decode(contents)
		if block == nil || block.Type != "CERTIFICATE" {
			return tls.Certificate{}, errors.New("client certificate file must contain PEM certificates")
		}
		certificate.Certificate = append(certificate.Certificate, block.Bytes)
		contents = rest
	}
	if len(certificate.Certificate) == 0 {
		return tls.Certificate{}, errors.New("client certificate file is empty")
	}
	leaf, err := x509.ParseCertificate(certificate.Certificate[0])
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("parse client certificate: %w", err)
	}
	certificate.Leaf = leaf
	return certificate, nil
}

func loadClientCertificate(keyPath, certificatePath string) (tls.Certificate, error) {
	key, err := readDeviceKey(keyPath)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("load existing device key: %w", err)
	}
	certificate, err := readClientCertificate(certificatePath)
	if err != nil {
		return tls.Certificate{}, err
	}
	publicKey, ok := certificate.Leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok || !publicKey.Equal(key.Public()) {
		return tls.Certificate{}, errors.New("client certificate does not match the device key")
	}
	certificate.PrivateKey = key
	return certificate, nil
}

type gatewayIdentity struct {
	EndpointID     string     `json:"endpoint_id"`
	OrganizationID string     `json:"organization_id"`
	LastSeen       *time.Time `json:"last_seen,omitempty"`
}

func loadServerRoots(caPath string) (*x509.CertPool, error) {
	if caPath == "" {
		return nil, nil
	}
	caPEM, err := os.ReadFile(caPath)
	if err != nil {
		return nil, fmt.Errorf("read server CA bundle: %w", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		return nil, errors.New("server CA bundle must contain a PEM certificate")
	}
	return roots, nil
}

func runGatewayCommand(ctx context.Context, server *url.URL, keyPath, certPath, caPath, operation string, output io.Writer) error {
	certificate, err := loadClientCertificate(keyPath, certPath)
	if err != nil {
		return err
	}
	roots, err := loadServerRoots(caPath)
	if err != nil {
		return err
	}

	var sentClientCertificate atomic.Bool
	transport := &http.Transport{TLSClientConfig: &tls.Config{
		MinVersion: tls.VersionTLS13,
		RootCAs:    roots,
		GetClientCertificate: func(request *tls.CertificateRequestInfo) (*tls.Certificate, error) {
			if err := request.SupportsCertificate(&certificate); err != nil {
				return nil, err
			}
			sentClientCertificate.Store(true)
			return &certificate, nil
		},
	}}
	defer transport.CloseIdleConnections()
	client := &http.Client{
		Transport: transport,
		Timeout:   10 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	method := http.MethodGet
	if operation != "identity" {
		method = http.MethodPost
	}
	send := func(method, path string, payload []byte) (int, []byte, error) {
		address := server.JoinPath("api", "agent", path)
		request, err := http.NewRequestWithContext(ctx, method, address.String(), bytes.NewReader(payload))
		if err != nil {
			return 0, nil, err
		}
		if len(payload) > 0 {
			request.Header.Set("Content-Type", "application/json")
		}
		if path == "scan-jobs/poll" {
			request.Header.Set("X-PersistGuard-Targeted-Scans", "1")
		}
		response, err := client.Do(request)
		if err != nil {
			return 0, nil, fmt.Errorf("connect to gateway: %w", err)
		}
		defer response.Body.Close()
		if !sentClientCertificate.Load() {
			return 0, nil, errors.New("gateway did not request a client certificate")
		}
		const maxResponseSize = 8192
		body, err := io.ReadAll(io.LimitReader(response.Body, maxResponseSize+1))
		if err != nil {
			return response.StatusCode, nil, fmt.Errorf("read gateway response: %w", err)
		}
		if len(body) > maxResponseSize {
			return response.StatusCode, nil, errors.New("gateway response is too large")
		}
		return response.StatusCode, body, nil
	}
	if operation == "scan-jobs/run" {
		return executeInventoryJob(ctx, send, writeWindowsScan, output)
	}
	status, body, err := send(method, operation, nil)
	if err != nil {
		return err
	}
	if operation == "scan-jobs/poll" && status == http.StatusNoContent {
		return json.NewEncoder(output).Encode(nil)
	}
	if status != http.StatusOK {
		return fmt.Errorf("gateway %s returned HTTP %d", operation, status)
	}
	switch operation {
	case "scan-jobs/poll":
		job, err := readInventoryJob(body)
		if err != nil {
			return err
		}
		return json.NewEncoder(output).Encode(job)
	case "certificate/renew":
		var renewal struct {
			CertificatePEM string `json:"certificate_pem"`
		}
		if err := json.Unmarshal(body, &renewal); err != nil {
			return errors.New("gateway returned an invalid renewal response")
		}
		block, rest := pem.Decode([]byte(renewal.CertificatePEM))
		if block == nil || block.Type != "CERTIFICATE" || len(bytes.TrimSpace(rest)) != 0 {
			return errors.New("gateway returned an invalid replacement certificate")
		}
		replacement, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return fmt.Errorf("parse replacement certificate: %w", err)
		}
		key, ok := replacement.PublicKey.(*ecdsa.PublicKey)
		if !ok || !key.Equal(certificate.Leaf.PublicKey) {
			return errors.New("replacement certificate does not match the device key")
		}
		now := time.Now()
		if now.Before(replacement.NotBefore) || !now.Before(replacement.NotAfter) {
			return errors.New("replacement certificate is outside its validity period")
		}
		return pem.Encode(output, block)
	case "certificate/confirm":
		var confirmation struct {
			Confirmed bool `json:"confirmed"`
		}
		if err := json.Unmarshal(body, &confirmation); err != nil || !confirmation.Confirmed {
			return errors.New("gateway did not confirm the replacement certificate")
		}
		return json.NewEncoder(output).Encode(confirmation)
	}
	var identity gatewayIdentity
	if json.Unmarshal(body, &identity) != nil || identity.EndpointID == "" || identity.OrganizationID == "" ||
		(operation == "heartbeat" && (identity.LastSeen == nil || identity.LastSeen.IsZero())) {
		return fmt.Errorf("gateway returned an invalid %s response", operation)
	}
	return json.NewEncoder(output).Encode(identity)
}
