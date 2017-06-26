package main

import (
	"crypto/x509"
	"errors"
)

//Load ca cert
func loadCert(filename string) (*x509.CertPool, error) {
	data := readFileWithoutErr(filename)
	certPool := x509.NewCertPool()
	if !certPool.AppendCertsFromPEM(data) {
		return certPool, errors.New("load cert file error")
	}

	return certPool, nil
}
