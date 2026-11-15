//go:build !windows

package main

import (
	"context"
	"errors"
	"io"
)

func writeServicesInventory(context.Context, io.Writer) error {
	return errors.New("services inventory requires Windows")
}
