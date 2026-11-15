package main

import (
	"context"
	"fmt"
	"io"
	"os"

	"golang.org/x/sys/windows/svc"
)

const agentServiceName = "PersistGuardAgent"

func runWindowsService(ctx context.Context, logPath string, watch func(context.Context, io.Writer, io.Writer) error) error {
	var log io.Writer = io.Discard
	if logPath != "" {
		file, err := os.OpenFile(logPath, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0600)
		if err != nil {
			return fmt.Errorf("open Windows service log: %w", err)
		}
		defer file.Close()
		log = file
	}
	return svc.Run(agentServiceName, windowsAgentService{ctx, log, watch})
}

type windowsAgentService struct {
	ctx   context.Context
	log   io.Writer
	watch func(context.Context, io.Writer, io.Writer) error
}

func (s windowsAgentService) Execute(_ []string, requests <-chan svc.ChangeRequest, statuses chan<- svc.Status) (bool, uint32) {
	statuses <- svc.Status{State: svc.StartPending}
	ctx, cancel := context.WithCancel(s.ctx)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- s.watch(ctx, s.log, s.log)
	}()

	status := svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	statuses <- status
	parentDone := s.ctx.Done()
	for {
		select {
		case err := <-done:
			if err != nil {
				fmt.Fprintf(s.log, "Windows service worker: %v\n", err)
				return true, 1
			}
			return false, 0
		case <-parentDone:
			parentDone = nil
		case request, ok := <-requests:
			if !ok {
				requests = nil
			} else {
				switch request.Cmd {
				case svc.Interrogate:
					statuses <- status
					continue
				case svc.Stop, svc.Shutdown:
				default:
					continue
				}
			}
		}
		if status.State != svc.StopPending {
			status = svc.Status{State: svc.StopPending, WaitHint: 5000}
			statuses <- status
			cancel()
		}
	}
}
