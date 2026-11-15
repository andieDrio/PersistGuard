package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"
)

var invitationTokenFormat = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)

func enrollDevice(ctx context.Context, server *url.URL, organization, keyPath, caPath string, input io.Reader, output io.Writer) error {
	roots, err := loadServerRoots(caPath)
	if err != nil {
		return err
	}
	line, err := bufio.NewReader(io.LimitReader(input, 256)).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return errors.New("could not read the invitation token from stdin")
	}
	token := strings.TrimSpace(line)
	if !invitationTokenFormat.MatchString(token) {
		return errors.New("provide one enrollment invitation token on stdin")
	}
	hostname, err := os.Hostname()
	if err != nil {
		return fmt.Errorf("read device hostname: %w", err)
	}
	var csr bytes.Buffer
	if err := writeDeviceCSR(keyPath, &csr); err != nil {
		return err
	}
	payload, err := json.Marshal(struct {
		OrganizationID string `json:"organization_id"`
		Hostname       string `json:"hostname"`
		OSFamily       string `json:"os_family"`
		CSR            string `json:"csr"`
	}{organization, hostname, "windows", csr.String()})
	if err != nil {
		return err
	}
	address := server.JoinPath("api", "agent", "enroll")
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, address.String(), bytes.NewReader(payload))
	if err != nil {
		return err
	}
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Content-Type", "application/json")
	transport := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 10 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	response, err := client.Do(request)
	if err != nil {
		return fmt.Errorf("connect to enrollment API: %w", err)
	}
	defer response.Body.Close()
	switch response.StatusCode {
	case http.StatusCreated:
	case http.StatusUnauthorized:
		return errors.New("enrollment invitation was rejected (HTTP 401)")
	case http.StatusConflict:
		return errors.New("device key is already registered in this organization (HTTP 409)")
	default:
		return fmt.Errorf("enrollment API returned HTTP %d", response.StatusCode)
	}
	const maxResponse = 8192
	body, err := io.ReadAll(io.LimitReader(response.Body, maxResponse+1))
	var result struct {
		EndpointID string `json:"endpoint_id"`
		Status     string `json:"status"`
	}
	if err != nil || len(body) > maxResponse || json.Unmarshal(body, &result) != nil ||
		!uuidText.MatchString(result.EndpointID) || result.Status != "pending" {
		return errors.New("enrollment API returned an invalid registration receipt")
	}
	return json.NewEncoder(output).Encode(result)
}
