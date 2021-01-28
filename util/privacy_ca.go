/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package util

import (
	"crypto/rsa"
	"crypto/x509"
	"intel/isecl/go-trust-agent/v3/constants"
	"io/ioutil"
	"os"

	"github.com/pkg/errors"
)

var privacyCAInstance *rsa.PublicKey

// This utility function returns the privacy-ca key stored at
// /opt/trustagent/confguration/privacy-ca.cer.  It assumes the file has been
// created by 'tagent setup' (in tasks.download_privacty_ca.go) and returns an error
// if the file does not exist.
func GetPrivacyCA() (*rsa.PublicKey, error) {
	log.Trace("util/privacy_ca:GetPrivacyCA() Entering")
	defer log.Trace("util/privacy_ca:GetPrivacyCA() Leaving")

	if privacyCAInstance == nil {
		if _, err := os.Stat(constants.PrivacyCA); os.IsNotExist(err) {
			return nil, err
		}

		privacyCaBytes, err := ioutil.ReadFile(constants.PrivacyCA)
		if err != nil {
			return nil, errors.Wrap(err, "util/privacy_ca:GetPrivacyCA() Error while reading Privacy CA Certificate file")
		}

		cert, err := x509.ParseCertificate(privacyCaBytes)
		if err != nil {
			return nil, errors.Wrap(err, "util/privacy_ca:GetPrivacyCA() Error while parsing Privacy CA Certificate")
		}

		privacyCAInstance = cert.PublicKey.(*rsa.PublicKey)
	}

	return privacyCAInstance, nil
}
