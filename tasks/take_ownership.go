/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
 package tasks

import (
	"errors"
	"fmt"
	log "github.com/sirupsen/logrus"
	"intel/isecl/go-trust-agent/config"
	"intel/isecl/go-trust-agent/tpmprovider"
	"intel/isecl/lib/common/crypt"
	"intel/isecl/lib/common/setup"
)

type TakeOwnership struct {
	Flags 		[]string
}

// Calling this task assumes that the TPM is cleared (not currently owned).
//
// Retrieves the 'SecreteKey' value from configuration.  If it is not there, it generates a 
// new random key (or used TPM_OWNER_SECRET env var) and saves it in the configuration.  It 
// then passes the new secret key to TpmProvider.TakeOwnership.
func (task* TakeOwnership) Run(c setup.Context) error {

	// The SecretKey is either set via trustagent.env (env var) and trustagent_config.go,
	// or is empty.  If it is empty, generate a new random key.  Note:  It could also be
	// present from the config.yml, but we assume this task is only called when taking
	// ownership of a cleared tpm.
	if config.GetConfiguration().Tpm.SecretKey == "" {
		newSecretKey, err := crypt.GetHexRandomString(20)
		if err != nil {
			return errors.New("Setup error: An error occurred generating a random key")
		}

		config.GetConfiguration().Tpm.SecretKey = newSecretKey
	}

	tpmProvider, err := tpmprovider.NewTpmProvider()
	if err != nil {
		return fmt.Errorf("Setup error: Could not create TpmProvider: %s", err)
	}

	defer tpmProvider.Close()


	if(len(config.GetConfiguration().Tpm.SecretKey) == 0 || len(config.GetConfiguration().Tpm.SecretKey) > 40) {
		return errors.New("Setup error: Invalid secret key")
	}

	// KWT:  Pass in string, not byte...
	err = tpmProvider.TakeOwnership([]byte(config.GetConfiguration().Tpm.SecretKey))
	if err != nil {
		return err
	}

	// TakeOwnership didn't fail, update config, the key will be checked in Validate()
	err = config.GetConfiguration().Save()
	if err != nil {
		return fmt.Errorf("Setup error:  Error saving configuration [%s]", err)
	}
	
	return nil
}

//
// Uses the current 'SecetKey' from configuration and checks its validity using
// TpmProvider.IsOwnedWithAuth.
//
func (task* TakeOwnership) Validate(c setup.Context) error {

	if config.GetConfiguration().Tpm.SecretKey == "" {
		return errors.New("Validation error: The configuration does not contain the tpm secret key")
	}

	tpmProvider, err := tpmprovider.NewTpmProvider()
	if err != nil {
		return fmt.Errorf("Validation error: Could not create TpmProvider: %s", err)
	}

	defer tpmProvider.Close()

	ok, err := tpmProvider.IsOwnedWithAuth([]byte(config.GetConfiguration().Tpm.SecretKey))
	if err != nil {
		return fmt.Errorf("Validation error: IsOwnedWithAuth return: %s", err)
	}
	
	if !ok {
		return errors.New("Validation error: The tpm is not owned with the current secret key")
	}

	log.Info("Setup: Take ownership was successful.")
	return nil
}