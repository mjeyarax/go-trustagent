/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package tasks

import (
	"encoding/hex"
	"fmt"
	log "github.com/sirupsen/logrus"
	"intel/isecl/go-trust-agent/config"
	"intel/isecl/lib/tpmprovider"
	"intel/isecl/lib/common/setup"
)

//
// This task is used to persist a primary public key at handle TPM_HANDLE_PRIMARY
// ()
//

type ProvisionPrimaryKey struct {
	Flags 					[]string
}

// if the TPM's public key used for WLA signing/binding has not been created, 
// do so now
func (task* ProvisionPrimaryKey) Run(c setup.Context) error {

	tpm, err := tpmprovider.NewTpmProvider()
	if err != nil {
		return fmt.Errorf("Setup error: Could not create TpmProvider: %s", err)
	}

	defer tpm.Close()

	exists, err := tpm.PublicKeyExists(tpmprovider.TPM_HANDLE_PRIMARY)
	if err != nil {
		return err
	}

	if !exists {
		ownerSecret, err := hex.DecodeString(config.GetConfiguration().Tpm.SecretKey)
		if err != nil {
			return err
		}

		err = tpm.CreatePrimaryHandle(ownerSecret, tpmprovider.TPM_HANDLE_PRIMARY)
		if err != nil {
			return err
		}
	}

	return nil
}

func (task* ProvisionPrimaryKey) Validate(c setup.Context) error {

	tpm, err := tpmprovider.NewTpmProvider()
	if err != nil {
		return fmt.Errorf("Setup error: Could not create TpmProvider: %s", err)
	}

	defer tpm.Close()

	exists, err := tpm.PublicKeyExists(tpmprovider.TPM_HANDLE_PRIMARY)
	if err != nil {
		return err
	}

	if !exists {
		return fmt.Errorf("The primary key at handle %x was not created", tpmprovider.TPM_HANDLE_PRIMARY)
	}

	// assume valid if error did not occur during 'Run'
	log.Info("Setup: Provisioning the primary key was successful.")
	return nil
}