package main

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

func TestCheckConfig(t *testing.T) {
	cases := []struct {
		name string
		url  string
		code int
	}{
		{"valid", "https://persistguard.example.test:8443/base", 0},
		{"missing", "", 2},
		{"plaintext", "http://persistguard.example.test", 2},
		{"missing host", "https:///base", 2},
		{"credentials", "https://user:sample-password@persistguard.example.test", 2},
		{"query", "https://persistguard.example.test/?key=sample-password", 2},
		{"fragment", "https://persistguard.example.test/#", 2},
		{"invalid port", "https://persistguard.example.test:65536", 2},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(serverURLEnv, tc.url)
			var output, errors bytes.Buffer
			if code := run(context.Background(), []string{"--check-config"}, nil, &output, &errors); code != tc.code {
				t.Fatalf("exit code = %d; want %d", code, tc.code)
			}
			if strings.Contains(errors.String(), "sample-password") {
				t.Fatal("configuration error included sensitive input")
			}
			if tc.code == 0 && !strings.Contains(output.String(), "configuration is valid") {
				t.Fatal("missing configuration check output")
			}
		})
	}
}

func TestRunStopsOnCancellation(t *testing.T) {
	t.Setenv(serverURLEnv, "https://persistguard.example.test")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var output, errors bytes.Buffer
	if code := run(ctx, nil, nil, &output, &errors); code != 0 {
		t.Fatalf("exit code = %d; want 0", code)
	}
	if !strings.Contains(output.String(), "agent started") || !strings.Contains(output.String(), "agent stopped") {
		t.Fatalf("missing startup or shutdown output: %q", output.String())
	}
}
