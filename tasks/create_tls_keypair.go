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
	"fmt"
	"io/ioutil"
	"math/big"
	"os"
	"time"
	log "github.com/sirupsen/logrus"
	"intel/isecl/go-trust-agent/constants"
	"intel/isecl/lib/common/setup"
)

type CreateTLSKeyPair struct {
	Flags 	[]string
}

// For now, create a self signed cert based on code from
// https://golang.org/src/crypto/tls/generate_cert.go?m=text.
// This will be revamped when integrated into CMS/AAS.
func createTLSKeyPair() (key []byte, cert []byte, err error) { 

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return key, cert, fmt.Errorf("Failed to generate private key [%s]", err)
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)

	template := x509.Certificate{
		SerialNumber: 			serialNumber,
		Subject: pkix.Name { 
								Organization: []string{"Intel"},
		},
		NotBefore: 				time.Now(),
		NotAfter:  				time.Now().AddDate(365, 0, 0),

		KeyUsage:              	x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           	[]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: 	true,
		IsCA:					true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return key, cert, fmt.Errorf("Failed to create certificate [%s]", err)
	}

	cert = pem.EncodeToMemory(&pem.Block { Type: "CERTIFICATE", Bytes: derBytes } )

	privateBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	key = pem.EncodeToMemory(&pem.Block {Type: "PRIVATE KEY", Bytes: privateBytes} )

	return key, cert, nil
}

func (task* CreateTLSKeyPair) Run(c setup.Context) error {

	key, cert, err := createTLSKeyPair()
	if err != nil {
		return fmt.Errorf("Setup error: Could not create cert/key [%s]", err.Error())
	}

	ioutil.WriteFile(constants.TLSCertFilePath, cert, 0644)
	if err != nil {
		return fmt.Errorf("Setup error: Could not save cert file [%s]", err.Error())
	}

	ioutil.WriteFile(constants.TLSKeyFilePath, key, 0644)
	if err != nil {
		return fmt.Errorf("Setup error: Could not save key file [%s]", err.Error())
	}

	return nil
}

func (task* CreateTLSKeyPair) Validate(c setup.Context) error {
	_, err := os.Stat(constants.TLSCertFilePath)
	if os.IsNotExist(err) {
		return fmt.Errorf("Validation error: Cert file '%s' does not exist", constants.TLSCertFilePath)
	}

	_, err = os.Stat(constants.TLSKeyFilePath)
	if os.IsNotExist(err) {
		return fmt.Errorf("Validation error: Key file '%s' does not exist", constants.TLSKeyFilePath)
	}

	log.Info("Setup: TLS files have been successfuly created.")

	return nil
}