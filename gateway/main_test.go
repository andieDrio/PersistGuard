package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

func TestGatewayChecksTLSAndRegisteredCredential(t *testing.T) {
	dsn := os.Getenv("PERSISTGUARD_GATEWAY_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("requires a migrated PostgreSQL test database")
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	reader := db
	if readerDSN := os.Getenv("PERSISTGUARD_GATEWAY_TEST_READER_URL"); readerDSN != "" {
		reader, err = sql.Open("pgx", readerDSN)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { reader.Close() })
	}

	ca, caKey := testCA(t, "PersistGuard gateway test CA")
	otherCA, otherKey := testCA(t, "Untrusted gateway test CA")
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatal(err)
	}
	serial.Add(serial, big.NewInt(1))
	registered := testLeaf(t, ca, caKey, serial, x509.ExtKeyUsageClientAuth)
	unregistered := testLeaf(t, ca, caKey, serial, x509.ExtKeyUsageClientAuth)
	untrusted := testLeaf(t, otherCA, otherKey, serial, x509.ExtKeyUsageClientAuth)
	serverLeaf := testLeaf(t, ca, caKey, big.NewInt(2), x509.ExtKeyUsageServerAuth)
	credential := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: registered.Certificate[0]}))
	var expected agentIdentity
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	err = db.QueryRowContext(ctx, `
		WITH organization AS (
			INSERT INTO organizations (id, name) VALUES (gen_random_uuid(), 'Gateway test') RETURNING id
		), endpoint AS (
			INSERT INTO endpoints (id, organization_id, hostname, os_family, status)
			SELECT gen_random_uuid(), id, 'gateway-test', 'windows', 'approved' FROM organization
			RETURNING id, organization_id
		), credential AS (
			INSERT INTO agent_credentials (certificate_serial, endpoint_id, certificate_pem, expires_at)
			SELECT $1, id, $2, now() + interval '1 hour' FROM endpoint
		)
		SELECT id::text, organization_id::text FROM endpoint`, serial.Text(16), credential,
	).Scan(&expected.EndpointID, &expected.OrganizationID)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, err := db.ExecContext(ctx, "DELETE FROM scan_jobs WHERE organization_id = $1", expected.OrganizationID)
		if err == nil {
			_, err = db.ExecContext(ctx, "DELETE FROM agent_credentials WHERE endpoint_id = $1", expected.EndpointID)
		}
		if err == nil {
			_, err = db.ExecContext(ctx, "DELETE FROM endpoints WHERE organization_id = $1", expected.OrganizationID)
		}
		if err == nil {
			_, err = db.ExecContext(ctx, "DELETE FROM organizations WHERE id = $1", expected.OrganizationID)
		}
		if err != nil {
			t.Error(err)
		}
	})
	var otherEndpoint string
	err = db.QueryRowContext(ctx, `
		INSERT INTO endpoints (id, organization_id, hostname, os_family, status)
		VALUES (gen_random_uuid(), $1, 'other-gateway-test', 'windows', 'approved')
		RETURNING id::text`, expected.OrganizationID).Scan(&otherEndpoint)
	if err != nil {
		t.Fatal(err)
	}

	config, err := gatewayTLSConfig(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Raw}))
	if err != nil {
		t.Fatal(err)
	}
	config.Certificates = []tls.Certificate{serverLeaf}
	server := httptest.NewUnstartedServer(gatewayHandler(reader, nil))
	server.TLS = config
	server.StartTLS()
	t.Cleanup(server.Close)
	url := server.URL + "/api/agent/identity"
	heartbeatURL := server.URL + "/api/agent/heartbeat?endpoint_id=" + otherEndpoint
	serverRoots := x509.NewCertPool()
	serverRoots.AddCert(ca)
	client := func(certificate *tls.Certificate) *http.Client {
		config := &tls.Config{RootCAs: serverRoots, MinVersion: tls.VersionTLS13}
		if certificate != nil {
			config.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
				return certificate, nil
			}
		}
		transport := &http.Transport{TLSClientConfig: config}
		t.Cleanup(transport.CloseIdleConnections)
		return &http.Client{Transport: transport, Timeout: 5 * time.Second}
	}
	for _, test := range []struct {
		name string
		cert *tls.Certificate
	}{
		{"missing certificate", nil},
		{"untrusted certificate", &untrusted},
	} {
		t.Run(test.name, func(t *testing.T) {
			response, err := client(test.cert).Get(url)
			if err == nil {
				response.Body.Close()
				t.Fatal("expected TLS handshake to fail")
			}
		})
	}
	assertStatus := func(client *http.Client, status int) {
		t.Helper()
		response, err := client.Get(url)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		if response.StatusCode != status {
			t.Fatalf("HTTP status = %d; want %d", response.StatusCode, status)
		}
		if status == http.StatusOK {
			var identity agentIdentity
			if err := json.NewDecoder(response.Body).Decode(&identity); err != nil || identity != expected {
				t.Fatalf("identity = %+v, error = %v; want %+v", identity, err, expected)
			}
		}
		io.Copy(io.Discard, response.Body)
	}
	assertStatus(client(&unregistered), http.StatusForbidden)
	device := client(&registered)
	assertStatus(device, http.StatusOK)
	assertHeartbeat := func(client *http.Client, status int) time.Time {
		t.Helper()
		response, err := client.Post(heartbeatURL, "", nil)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		if response.StatusCode != status {
			t.Fatalf("heartbeat status = %d; want %d", response.StatusCode, status)
		}
		if status != http.StatusOK {
			io.Copy(io.Discard, response.Body)
			return time.Time{}
		}
		var heartbeat struct {
			agentIdentity
			LastSeen time.Time `json:"last_seen"`
		}
		if err := json.NewDecoder(response.Body).Decode(&heartbeat); err != nil ||
			heartbeat.agentIdentity != expected || heartbeat.LastSeen.IsZero() {
			t.Fatalf("unexpected heartbeat response: %+v, error: %v", heartbeat, err)
		}
		return heartbeat.LastSeen
	}
	readLastSeen := func(endpointID string) sql.NullTime {
		t.Helper()
		var lastSeen sql.NullTime
		if err := db.QueryRowContext(ctx, "SELECT last_seen FROM endpoints WHERE id = $1", endpointID).Scan(&lastSeen); err != nil {
			t.Fatal(err)
		}
		return lastSeen
	}
	assertHeartbeat(client(&unregistered), http.StatusForbidden)
	if readLastSeen(expected.EndpointID).Valid {
		t.Fatal("identity check or rejected heartbeat updated last_seen")
	}
	lastSeen := assertHeartbeat(device, http.StatusOK)
	if stored := readLastSeen(expected.EndpointID); !stored.Valid || !stored.Time.Equal(lastSeen) {
		t.Fatal("heartbeat timestamp did not match last_seen in the database")
	}
	nextSeen := assertHeartbeat(device, http.StatusOK)
	if stored := readLastSeen(expected.EndpointID); !nextSeen.After(lastSeen) || !stored.Valid || !stored.Time.Equal(nextSeen) {
		t.Fatal("a second idle heartbeat did not advance the stored last_seen")
	}
	lastSeen = nextSeen
	if readLastSeen(otherEndpoint).Valid {
		t.Fatal("heartbeat updated another endpoint")
	}
	queueJob := func(endpoint, scanType string) string {
		t.Helper()
		var id string
		err := db.QueryRowContext(ctx, `INSERT INTO scan_jobs (id, organization_id, endpoint_id, requested_by, scan_type)
			VALUES (gen_random_uuid(), $1, $2, gen_random_uuid(), $3) RETURNING id::text`,
			expected.OrganizationID, endpoint, scanType).Scan(&id)
		if err != nil {
			t.Fatal(err)
		}
		return id
	}
	targeted := false
	poll := func(status int) dispatchedScanJob {
		t.Helper()
		request, err := http.NewRequest(http.MethodPost, server.URL+"/api/agent/scan-jobs/poll?endpoint_id="+otherEndpoint, nil)
		if err != nil {
			t.Fatal(err)
		}
		if targeted {
			request.Header.Set("X-PersistGuard-Targeted-Scans", "1")
		}
		response, err := device.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		if response.StatusCode != status {
			t.Fatalf("poll status = %d; want %d", response.StatusCode, status)
		}
		var job dispatchedScanJob
		if status == http.StatusOK {
			if err := json.NewDecoder(response.Body).Decode(&job); err != nil {
				t.Fatal(err)
			}
		}
		return job
	}
	otherJob := queueJob(otherEndpoint, "persistence_full_scan")
	poll(http.StatusNoContent)
	ownJob := queueJob(expected.EndpointID, "persistence_full_scan")
	wantJob := dispatchedScanJob{ownJob, "persistence_full_scan", "dispatched"}
	for range 2 {
		if job := poll(http.StatusOK); job != wantJob {
			t.Fatalf("poll returned %+v; want %+v", job, wantJob)
		}
	}
	for id, want := range map[string]string{otherJob: "queued", ownJob: "dispatched"} {
		var status string
		if err := db.QueryRowContext(ctx, "SELECT status FROM scan_jobs WHERE id = $1", id).Scan(&status); err != nil || status != want {
			t.Fatalf("job status = %q, error = %v; want %q", status, err, want)
		}
	}
	report := `{"schema_version":1,"os_family":"windows","status":"partial","collectors":{
		"registry":{"status":"collected","report":{"os_family":"windows","entries":[],"coverage":[{"status":"absent"}]}},
		"scheduled_tasks":{"status":"error","error":"fixture unavailable"},
		"services":{"status":"collected","report":{"os_family":"windows","entries":[],"coverage":{"status":"collected"}}}}}`
	upload := func(jobID, payload string, expectedStatus int) string {
		t.Helper()
		request, err := http.NewRequest(http.MethodPut, server.URL+"/api/agent/scan-jobs/"+jobID+"/result", strings.NewReader(payload))
		if err != nil {
			t.Fatal(err)
		}
		response, err := device.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		body, err := io.ReadAll(response.Body)
		if err != nil || response.StatusCode != expectedStatus {
			t.Fatalf("upload status=%d body=%q error=%v; want HTTP %d", response.StatusCode, body, err, expectedStatus)
		}
		return string(body)
	}
	upload(otherJob, report, http.StatusNotFound)
	upload(ownJob, "{}", http.StatusUnprocessableEntity)
	receipt := upload(ownJob, report, http.StatusOK)
	if !strings.Contains(receipt, `"status":"partial"`) || upload(ownJob, report, http.StatusOK) != receipt {
		t.Fatal("upload retry did not preserve the original receipt")
	}
	upload(ownJob, strings.Replace(report, "fixture unavailable", "different result", 1), http.StatusConflict)
	poll(http.StatusNoContent)
	targetJob := queueJob(expected.EndpointID, "persistence_services_scan")
	poll(http.StatusNoContent)
	targeted = true
	if job := poll(http.StatusOK); job != (dispatchedScanJob{targetJob, "persistence_services_scan", "dispatched"}) {
		t.Fatalf("unexpected targeted job: %+v", job)
	}
	upload(targetJob, report, http.StatusUnprocessableEntity)
	const targetReport = `{"schema_version":1,"os_family":"windows","status":"collected","collectors":{
		"services":{"status":"collected","report":{"os_family":"windows","entries":[],"coverage":{"status":"collected"}}}}}`
	upload(ownJob, targetReport, http.StatusUnprocessableEntity)
	upload(targetJob, strings.Replace(targetReport, `"services"`, `"registry"`, 1), http.StatusUnprocessableEntity)
	if receipt := upload(targetJob, targetReport, http.StatusOK); !strings.Contains(receipt, `"status":"completed"`) ||
		upload(targetJob, targetReport, http.StatusOK) != receipt {
		t.Fatal("targeted scan did not complete with a stable receipt")
	}
	if _, err := db.ExecContext(ctx, "UPDATE agent_credentials SET revoked_at = now() WHERE certificate_serial = $1", serial.Text(16)); err != nil {
		t.Fatal(err)
	}
	assertStatus(device, http.StatusForbidden)
	poll(http.StatusForbidden)
	upload(ownJob, report, http.StatusForbidden)
	assertHeartbeat(device, http.StatusForbidden)
	if stored := readLastSeen(expected.EndpointID); !stored.Valid || !stored.Time.Equal(lastSeen) {
		t.Fatal("revoked heartbeat changed last_seen")
	}
}

func TestRejectInvalidAgentCA(t *testing.T) {
	if _, err := gatewayTLSConfig([]byte("not PEM")); err == nil {
		t.Fatal("invalid agent CA was accepted")
	}
}

func testCA(t *testing.T, name string) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ca := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageCertSign,
		IsCA:         true, BasicConstraintsValid: true,
	}
	ca.Subject.CommonName = name
	der, err := x509.CreateCertificate(rand.Reader, ca, ca, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return parsed, key
}

func testLeaf(t *testing.T, ca *x509.Certificate, signer *ecdsa.PrivateKey, serial *big.Int, purpose x509.ExtKeyUsage) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{
		SerialNumber: serial,
		NotBefore:    ca.NotBefore,
		NotAfter:     ca.NotAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{purpose},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
	}
	der, err := x509.CreateCertificate(rand.Reader, leaf, ca, key.Public(), signer)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}
