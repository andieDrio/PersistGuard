package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"strconv"
	"time"
)

type rotationService struct {
	client *http.Client
	url    string
	secret string
}

func loadRotationService() (*rotationService, error) {
	secret := os.Getenv("PERSISTGUARD_ROTATION_SECRET")
	if secret == "" {
		return nil, nil
	}
	decoded, err := hex.DecodeString(secret)
	if err != nil || len(decoded) != 32 || hex.EncodeToString(decoded) != secret {
		return nil, errors.New("PERSISTGUARD_ROTATION_SECRET must contain 64 lowercase hex characters")
	}
	port := os.Getenv("PERSISTGUARD_ROTATION_PORT")
	if port == "" {
		port = "8000"
	}
	number, err := strconv.ParseUint(port, 10, 16)
	if err != nil || number == 0 {
		return nil, errors.New("PERSISTGUARD_ROTATION_PORT must be a valid TCP port")
	}
	return &rotationService{
		client: &http.Client{
			Transport:     &http.Transport{IdleConnTimeout: 30 * time.Second},
			Timeout:       3 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
		url:    "http://127.0.0.1:" + strconv.FormatUint(number, 10) + "/internal/agent/certificate/",
		secret: secret,
	}, nil
}

func (service *rotationService) handle(operation string) func(http.ResponseWriter, context.Context, deviceCredential) {
	return func(w http.ResponseWriter, ctx context.Context, device deviceCredential) {
		const unavailable = "certificate rotation unavailable"
		if service == nil {
			http.Error(w, unavailable, http.StatusServiceUnavailable)
			return
		}
		proof := struct {
			EndpointID  string `json:"endpoint_id"`
			Serial      string `json:"certificate_serial"`
			Fingerprint string `json:"certificate_sha256"`
		}{device.identity.EndpointID, device.serial, hex.EncodeToString(device.fingerprint[:])}
		body, err := json.Marshal(proof)
		if err != nil {
			http.Error(w, unavailable, http.StatusServiceUnavailable)
			return
		}
		request, err := http.NewRequestWithContext(ctx, http.MethodPost, service.url+operation, bytes.NewReader(body))
		if err != nil {
			http.Error(w, unavailable, http.StatusServiceUnavailable)
			return
		}
		request.Header.Set("Authorization", "Bearer "+service.secret)
		request.Header.Set("Content-Type", "application/json")
		response, err := service.client.Do(request)
		if err != nil {
			http.Error(w, unavailable, http.StatusServiceUnavailable)
			return
		}
		defer response.Body.Close()
		switch response.StatusCode {
		case http.StatusForbidden:
			http.Error(w, "device credential unavailable", http.StatusForbidden)
		case http.StatusConflict:
			http.Error(w, "certificate rotation conflict", http.StatusConflict)
		case http.StatusOK:
			const maxResponse = 8192
			payload, err := io.ReadAll(io.LimitReader(response.Body, maxResponse+1))
			if err != nil || len(payload) > maxResponse || !json.Valid(payload) {
				http.Error(w, unavailable, http.StatusServiceUnavailable)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.Write(payload)
		default:
			http.Error(w, unavailable, http.StatusServiceUnavailable)
		}
	}
}
