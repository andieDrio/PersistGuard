package main

import (
	"context"
	"fmt"
	"io"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/windows/svc"
)

func TestWindowsAgentServiceLifecycle(t *testing.T) {
	for _, control := range []struct {
		name string
		cmd  svc.Cmd
	}{{"stop", svc.Stop}, {"shutdown", svc.Shutdown}} {
		t.Run(control.name, func(t *testing.T) {
			keyPath := filepath.Join(t.TempDir(), "device.key")
			key, err := loadOrCreateDeviceKey(keyPath)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			ready := make(chan struct{})
			service := windowsAgentService{ctx, io.Discard, func(ctx context.Context, _, _ io.Writer) error {
				loaded, err := readDeviceKey(keyPath)
				if err != nil {
					return err
				}
				if !key.Equal(loaded) {
					return fmt.Errorf("service loaded a different device key")
				}
				close(ready)
				<-ctx.Done()
				return nil
			}}
			requests := make(chan svc.ChangeRequest, 1)
			statuses := make(chan svc.Status, 3)
			exit := make(chan uint32, 1)
			go func() {
				_, code := service.Execute(nil, requests, statuses)
				exit <- code
			}()
			checkStatus := func(want svc.State) svc.Status {
				t.Helper()
				select {
				case got := <-statuses:
					if got.State != want {
						t.Fatalf("service state = %v, want %v", got.State, want)
					}
					return got
				case <-ctx.Done():
					t.Fatalf("timed out waiting for service state %v", want)
					return svc.Status{}
				}
			}
			checkStatus(svc.StartPending)
			if running := checkStatus(svc.Running); running.Accepts != svc.AcceptStop|svc.AcceptShutdown {
				t.Fatalf("accepted controls = %v", running.Accepts)
			}
			select {
			case <-ready:
			case code := <-exit:
				t.Fatalf("service exited before loading the device key, exit code %d", code)
			case <-ctx.Done():
				t.Fatal("timed out loading the device key")
			}
			requests <- svc.ChangeRequest{Cmd: control.cmd}
			checkStatus(svc.StopPending)
			select {
			case code := <-exit:
				if code != 0 {
					t.Fatalf("service exit code = %d", code)
				}
			case <-ctx.Done():
				t.Fatal("timed out stopping the service")
			}
		})
	}
}
