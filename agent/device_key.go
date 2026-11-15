package main

import (
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"io"
)

func writeDeviceCSR(keyPath string, output io.Writer) error {
	key, err := loadOrCreateDeviceKey(keyPath)
	if err != nil {
		return err
	}
	// The enrollment server assigns the endpoint identity.
	request, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if err != nil {
		return err
	}
	return pem.Encode(output, &pem.Block{Type: "CERTIFICATE REQUEST", Bytes: request})
}
