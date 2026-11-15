//go:build !windows

package main

import (
	"context"
	"fmt"
	"io"
)

func runWindowsService(context.Context, string, func(context.Context, io.Writer, io.Writer) error) error {
	return fmt.Errorf("Windows service mode requires Windows")
}
