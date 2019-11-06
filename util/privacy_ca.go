/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package util

import (
	"crypto/rsa"
	"crypto/x509"
	"io/ioutil"
	"os"
	"intel/isecl/go-trust-agent/constants"
)

var privacyCAInstance *rsa.PublicKey

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