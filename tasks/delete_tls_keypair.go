/*
* Copyright (C) 2019 Intel Corporation
* SPDX-License-Identifier: BSD-3-Clause
 */
package tasks

import (
	"intel/isecl/go-trust-agent/constants"
	"intel/isecl/lib/common/setup"
	"os"

	"github.com/pkg/errors"
)

type DeleteTlsKeypair struct {
}

// This task is used in conjunction with create-tls-keypair to support
// replace-tls-keypair
func (task *DeleteTlsKeypair) Run(c setup.Context) error {
	log.Trace("tasks/delete_tls_keypair:Run() Entering")
	defer log.Trace("tasks/delete_tls_keypair:Run() Leaving")

	if _, err := os.Stat(constants.TLSCertFilePath); err == nil {
		err = os.Remove(constants.TLSCertFilePath)
		if err != nil {
			return errors.Wrapf(err, "tasks/delete_tls_keypair:Run() Error while removing File %s", constants.TLSCertFilePath)
		}
	}

	if _, err := os.Stat(constants.TLSKeyFilePath); err == nil {
		err = os.Remove(constants.TLSKeyFilePath)
		if err != nil {
			return errors.Wrapf(err, "tasks/delete_tls_keypair:Run() Error while removing File %s", constants.TLSKeyFilePath)
		}
	}

	return nil
}

func (task *DeleteTlsKeypair) Validate(c setup.Context) error {
	log.Trace("tasks/delete_tls_keypair:Validate() Entering")
	defer log.Trace("tasks/delete_tls_keypair:Validate() Leaving")
	log.Info("tasks/delete_tls_keypair:Validate() Delete tls keypair was successful.")
	return nil
}
