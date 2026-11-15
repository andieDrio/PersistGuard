package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"encoding/pem"
	"errors"
	"log"
	"net/http"
	"os"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
)

func gatewayTLSConfig(caPEM []byte) (*tls.Config, error) {
	trustedAgents := x509.NewCertPool()
	if !trustedAgents.AppendCertsFromPEM(caPEM) {
		return nil, errors.New("agent CA file must contain a PEM certificate")
	}
	return &tls.Config{
		MinVersion:             tls.VersionTLS13,
		ClientAuth:             tls.RequireAndVerifyClientCert,
		ClientCAs:              trustedAgents,
		SessionTicketsDisabled: true,
	}, nil
}

type agentIdentity struct {
	EndpointID     string `json:"endpoint_id"`
	OrganizationID string `json:"organization_id"`
}

type deviceCredential struct {
	identity       agentIdentity
	serial         string
	certificatePEM string
	fingerprint    [sha256.Size]byte
}

const activeDeviceCredential = `
	FROM agent_credentials AS credential
	JOIN endpoints AS endpoint ON endpoint.id = credential.endpoint_id
	JOIN organizations AS organization ON organization.id = endpoint.organization_id
	WHERE credential.certificate_serial = $1
	  AND credential.revoked_at IS NULL AND credential.expires_at > now()
	  AND endpoint.status = 'approved' AND organization.status = 'active'`

func withDevice(db *sql.DB, next func(http.ResponseWriter, context.Context, deviceCredential)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 || len(r.TLS.PeerCertificates) == 0 {
			http.Error(w, "verified client certificate required", http.StatusUnauthorized)
			return
		}
		peer := r.TLS.PeerCertificates[0]
		ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
		defer cancel()
		const lookup = `SELECT endpoint.id::text, endpoint.organization_id::text, credential.certificate_pem` + activeDeviceCredential
		device := deviceCredential{serial: peer.SerialNumber.Text(16)}
		err := db.QueryRowContext(ctx, lookup, device.serial).Scan(
			&device.identity.EndpointID, &device.identity.OrganizationID, &device.certificatePEM,
		)
		if errors.Is(err, sql.ErrNoRows) {
			http.Error(w, "device credential unavailable", http.StatusForbidden)
			return
		}
		if err != nil {
			http.Error(w, "device identity unavailable", http.StatusServiceUnavailable)
			return
		}
		registered, _ := pem.Decode([]byte(device.certificatePEM))
		if registered == nil || registered.Type != "CERTIFICATE" || !bytes.Equal(registered.Bytes, peer.Raw) {
			http.Error(w, "device credential unavailable", http.StatusForbidden)
			return
		}
		device.fingerprint = sha256.Sum256(peer.Raw)
		next(w, ctx, device)
	}
}

func gatewayHandler(db *sql.DB, rotation *rotationService) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/agent/identity", withDevice(db, func(w http.ResponseWriter, _ context.Context, device deviceCredential) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(device.identity)
	}))
	mux.HandleFunc("POST /api/agent/heartbeat", withDevice(db, func(w http.ResponseWriter, ctx context.Context, device deviceCredential) {
		// Recheck authorization in the UPDATE statement after matching the certificate.
		const update = `UPDATE endpoints AS target
			SET last_seen = GREATEST(target.last_seen, statement_timestamp())
			FROM (SELECT endpoint.id, endpoint.organization_id` + activeDeviceCredential + `
			      AND credential.certificate_pem = $2
			      AND endpoint.id = $3 AND endpoint.organization_id = $4) AS authorized
			WHERE target.id = authorized.id AND target.organization_id = authorized.organization_id
			  AND target.status = 'approved'
			RETURNING target.last_seen`
		var lastSeen time.Time
		err := db.QueryRowContext(ctx, update, device.serial, device.certificatePEM,
			device.identity.EndpointID, device.identity.OrganizationID).Scan(&lastSeen)
		if errors.Is(err, sql.ErrNoRows) {
			http.Error(w, "device credential unavailable", http.StatusForbidden)
			return
		}
		if err != nil {
			http.Error(w, "heartbeat unavailable", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(struct {
			agentIdentity
			LastSeen time.Time `json:"last_seen"`
		}{device.identity, lastSeen.UTC()})
	}))
	mux.HandleFunc("POST /api/agent/scan-jobs/poll", withDevice(db, pollScanJob(db)))
	mux.HandleFunc("PUT /api/agent/scan-jobs/{job_id}/result", func(w http.ResponseWriter, r *http.Request) {
		withDevice(db, func(w http.ResponseWriter, _ context.Context, device deviceCredential) {
			storeScanResult(db, w, r, device)
		})(w, r)
	})
	mux.HandleFunc("POST /api/agent/certificate/renew", withDevice(db, rotation.handle("renew")))
	mux.HandleFunc("POST /api/agent/certificate/confirm", withDevice(db, rotation.handle("confirm")))
	return mux
}

func main() {
	caFile := os.Getenv("PERSISTGUARD_GATEWAY_AGENT_CA_FILE")
	serverCert := os.Getenv("PERSISTGUARD_GATEWAY_TLS_CERT_FILE")
	serverKey := os.Getenv("PERSISTGUARD_GATEWAY_TLS_KEY_FILE")
	databaseURL := os.Getenv("PERSISTGUARD_GATEWAY_DATABASE_URL")
	if caFile == "" || serverCert == "" || serverKey == "" || databaseURL == "" {
		log.Fatal("configure the gateway agent CA, TLS certificate and key, and database URL")
	}
	caPEM, err := os.ReadFile(caFile)
	if err != nil {
		log.Fatal("could not read the gateway agent CA file")
	}
	tlsConfig, err := gatewayTLSConfig(caPEM)
	if err != nil {
		log.Fatal(err)
	}
	db, err := sql.Open("pgx", databaseURL)
	if err != nil {
		log.Fatal("could not configure the gateway database connection")
	}
	defer db.Close()
	db.SetMaxOpenConns(10)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	err = db.PingContext(ctx)
	cancel()
	if err != nil {
		log.Fatal("could not connect to the gateway database")
	}

	address := os.Getenv("PERSISTGUARD_GATEWAY_LISTEN")
	if address == "" {
		address = "127.0.0.1:8443"
	}
	rotation, err := loadRotationService()
	if err != nil {
		log.Fatal(err)
	}
	server := &http.Server{
		Addr:              address,
		Handler:           gatewayHandler(db, rotation),
		TLSConfig:         tlsConfig,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       30 * time.Second,
	}
	log.Fatal(server.ListenAndServeTLS(serverCert, serverKey))
}
