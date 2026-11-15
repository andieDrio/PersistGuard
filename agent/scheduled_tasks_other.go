//go:build !windows

package main

import (
	"context"
	"errors"
	"io"
)

func writeScheduledTasksInventory(context.Context, io.Writer) error {
	return errors.New("Scheduled Tasks inventory requires Windows")
}
