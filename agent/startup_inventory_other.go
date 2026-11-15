//go:build !windows

package main

import (
	"context"
	"errors"
	"io"
)

func writeStartupInventory(context.Context, io.Writer) error {
	return errors.New("startup Registry inventory requires Windows")
}
