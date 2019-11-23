/*
* Copyright (C) 2019 Intel Corporation
* SPDX-License-Identifier: BSD-3-Clause
 */
package tasks

import (
	log "github.com/sirupsen/logrus"
	"intel/isecl/go-trust-agent/constants"
	"intel/isecl/lib/common/setup"
	"os"
)

type DeleteTlsKeypair struct {
}

// This task is used in conjunction with create-tls-keypair to support
// replace-tls-keypair
func (task *DeleteTlsKeypair) Run(c setup.Context) error {

	if _, err := os.Stat(constants.TLSCertFilePath); err == nil {
		err = os.Remove(constants.TLSCertFilePath)
		if err != nil {
			return err
		}
	}

	if _, err := os.Stat(constants.TLSKeyFilePath); err == nil {
		err = os.Remove(constants.TLSKeyFilePath)
		if err != nil {
			return err
		}
	}

	return nil
}

func (task *DeleteTlsKeypair) Validate(c setup.Context) error {
	log.Info("Setup: Delete tls keypair was successful.")
	return nil
}
