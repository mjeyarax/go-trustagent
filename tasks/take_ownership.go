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
	"intel/isecl/lib/common/crypt"
	"intel/isecl/lib/common/setup"
	"intel/isecl/lib/tpmprovider"
)

type TakeOwnership struct {
	tpmFactory tpmprovider.TpmFactory
	cfg        *config.TrustAgentConfiguration
}

// Retrieves the 'OwnerSecretKey' value from configuration.  If it is not there, it generates a
// new random key (or used TPM_OWNER_SECRET env var) and saves it in the configuration.  It
// then passes the new secret key to TpmProvider.TakeOwnership.
func (task *TakeOwnership) Run(c setup.Context) error {

	// The OwnerSecretKey is either set via trustagent.env (env var) and trustagent_config.go,
	// or is empty.  If it is empty, generate a new random key.  Note:  It could also be
	// present from the config.yml, but we assume this task is only called when taking
	// ownership of a cleared tpm.
	if task.cfg.Tpm.OwnerSecretKey == "" {
		newSecretKey, err := crypt.GetHexRandomString(20)
		if err != nil {
			return errors.New("Setup error: An error occurred generating a random key")
		}

		task.cfg.Tpm.OwnerSecretKey = newSecretKey
	}

	// validate the secret key...
	if len(task.cfg.Tpm.OwnerSecretKey) == 0 || len(task.cfg.Tpm.OwnerSecretKey) > 40 {
		return errors.New("Setup error: Invalid secret key")
	}

	tpm, err := task.tpmFactory.NewTpmProvider()
	if err != nil {
		return fmt.Errorf("Setup error: Could not create TpmProvider: %s", err)
	}

	defer tpm.Close()

	// check if the tpm is already owned with the current secret key (and return)
	alreadyOwned, err := tpm.IsOwnedWithAuth(task.cfg.Tpm.OwnerSecretKey)
	if err != nil {
		return fmt.Errorf("Setup error: IsOwnedWithAuth return: %s", err)
	}

	if alreadyOwned {
		log.Trace("TPM ownership has already been established.")
		return nil
	}

	// tpm is not owned by current secret, take ownership
	err = tpm.TakeOwnership(task.cfg.Tpm.OwnerSecretKey)
	if err != nil {
		return err
	}

	// TakeOwnership didn't fail, update config, the key will be checked in Validate()
	err = task.cfg.Save()
	if err != nil {
		return fmt.Errorf("Setup error:  Error saving configuration [%s]", err)
	}

	return nil
}

//
// Uses the current 'OwnerSecetKey' from configuration and checks its validity using
// TpmProvider.IsOwnedWithAuth.
//
func (task *TakeOwnership) Validate(c setup.Context) error {

	if task.cfg.Tpm.OwnerSecretKey == "" {
		return errors.New("Validation error: The configuration does not contain the tpm secret key")
	}

	tpmProvider, err := task.tpmFactory.NewTpmProvider()
	if err != nil {
		return fmt.Errorf("Validation error: Could not create TpmProvider: %s", err)
	}

	defer tpmProvider.Close()

	ok, err := tpmProvider.IsOwnedWithAuth(task.cfg.Tpm.OwnerSecretKey)
	if err != nil {
		return fmt.Errorf("Validation error: IsOwnedWithAuth return: %s", err)
	}

	if !ok {
		return errors.New("Validation error: The tpm is not owned with the current secret key")
	}

	log.Info("Setup: Take ownership was successful.")
	return nil
}
