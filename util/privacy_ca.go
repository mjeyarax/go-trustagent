/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package util

import (
	"crypto/rsa"
	"crypto/x509"
	"intel/isecl/go-trust-agent/constants"
	"io/ioutil"
	"os"
)

var privacyCAInstance *rsa.PublicKey

// This utility function returns the privacy-ca key stored at
// /opt/trustagent/confguration/privacy-ca.cer.  It assumes the file has been
// created by 'tagent setup' (in tasks.download_privacty_ca.go) and returns an error
// if the file does not exist.
func GetPrivacyCA() (*rsa.PublicKey, error) {

	if privacyCAInstance == nil {
		if _, err := os.Stat(constants.PrivacyCA); os.IsNotExist(err) {
			return nil, err
		}

		privacyCaBytes, err := ioutil.ReadFile(constants.PrivacyCA)
		if err != nil {
			return nil, err
		}

		cert, err := x509.ParseCertificate(privacyCaBytes)
		if err != nil {
			return nil, err
		}

		privacyCAInstance = cert.PublicKey.(*rsa.PublicKey)
	}

	return privacyCAInstance, nil
}
