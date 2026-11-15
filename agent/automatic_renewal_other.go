//go:build !windows

package main

import "errors"

func moveCertificateFile(string, string, bool) error {
	return errors.New("automatic device certificate renewal requires Windows")
}
