//go:build !windows

package main

import (
	"crypto/ecdsa"
	"errors"
)

func loadOrCreateDeviceKey(path string) (*ecdsa.PrivateKey, error) {
	return readDeviceKey(path)
}

func readDeviceKey(string) (*ecdsa.PrivateKey, error) {
	return nil, errors.New("device key storage currently requires Windows")
}
