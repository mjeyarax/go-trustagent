/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package tasks

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"intel/isecl/go-trust-agent/constants"
	"intel/isecl/lib/common/setup"
	"io/ioutil"
	"math/big"
	"os"
	"time"

	"github.com/pkg/errors"
)

type CreateTLSKeyPair struct {
}

// Create a self signed cert based on code from
// https://golang.org/src/crypto/tls/generate_cert.go?m=text.
// This will be revamped when integrated into CMS/AAS.
func createTLSKeyPair() (key []byte, cert []byte, err error) {
	log.Trace("tasks/create_tls_keypair:createTLSKeyPair() Entering")
	defer log.Trace("tasks/create_tls_keypair:createTLSKeyPair() Leaving")

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return key, cert, errors.Wrap(err,"tasks/create_tls_keypair:createTLSKeyPair() Failed to generate private key")
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Intel"},
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().AddDate(365, 0, 0),

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return key, cert, errors.Wrap(err,"tasks/create_tls_keypair:createTLSKeyPair() Failed to create certificate")
	}

	cert = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})

	privateBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	key = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateBytes})

	return key, cert, nil
}

func (task *CreateTLSKeyPair) Run(c setup.Context) error {
	log.Trace("tasks/create_tls_keypair:Run() Entering")
	defer log.Trace("tasks/create_tls_keypair:Run() Leaving")

	key, cert, err := createTLSKeyPair()
	if err != nil {
		return errors.Wrap(err, "tasks/create_tls_keypair:Run() Could not create cert/key")
	}

	ioutil.WriteFile(constants.TLSCertFilePath, cert, 0644)
	if err != nil {
		return errors.Wrap(err, "tasks/create_tls_keypair:Run() Could not save cert file")
	}

	ioutil.WriteFile(constants.TLSKeyFilePath, key, 0644)
	if err != nil {
		return errors.Wrap(err, "tasks/create_tls_keypair:Run() Could not save key file")
	}

	return nil
}

func (task *CreateTLSKeyPair) Validate(c setup.Context) error {
	log.Trace("tasks/create_tls_keypair:Run() Entering")
	defer log.Trace("tasks/create_tls_keypair:Run() Leaving")

	_, err := os.Stat(constants.TLSCertFilePath)
	if os.IsNotExist(err) {
		return errors.Errorf("tasks/create_tls_keypair:Validate() Cert file '%s' does not exist", constants.TLSCertFilePath)
	}

	_, err = os.Stat(constants.TLSKeyFilePath)
	if os.IsNotExist(err) {
		return errors.Errorf("tasks/create_tls_keypair:Validate() Key file '%s' does not exist", constants.TLSKeyFilePath)
	}

	log.Info("tasks/create_tls_keypair:Validate() Create TLS keypair was successful.")

	return nil
}
