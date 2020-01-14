/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package tasks

import (
	"intel/isecl/go-trust-agent/config"
	"intel/isecl/lib/common/crypt"
	"intel/isecl/lib/common/setup"
	"intel/isecl/lib/tpmprovider"

	"github.com/pkg/errors"
)

type TakeOwnership struct {
	tpmFactory tpmprovider.TpmFactory
	cfg        *config.TrustAgentConfiguration
}

// Retrieves the 'OwnerSecretKey' value from configuration.  If it is not there, it generates a
// new random key (or used TPM_OWNER_SECRET env var) and saves it in the configuration.  It
// then passes the new secret key to TpmProvider.TakeOwnership.
func (task *TakeOwnership) Run(c setup.Context) error {
	log.Trace("tasks/take_ownership:Run() Entering")
	defer log.Trace("tasks/take_ownership:Run() Leaving")
	// The OwnerSecretKey is either set via trustagent.env (env var) and trustagent_config.go,
	// or is empty.  If it is empty, generate a new random key.  Note:  It could also be
	// present from the config.yml, but we assume this task is only called when taking
	// ownership of a cleared tpm.
	if task.cfg.Tpm.OwnerSecretKey == "" {
		newSecretKey, err := crypt.GetHexRandomString(20)
		if err != nil {
			return errors.Wrap(err, "tasks/take_ownership:Run() Error while generating a random key")
		}

		task.cfg.Tpm.OwnerSecretKey = newSecretKey
	}

	// validate the secret key...
	if len(task.cfg.Tpm.OwnerSecretKey) == 0 || len(task.cfg.Tpm.OwnerSecretKey) > 40 {
		return errors.New("tasks/take_ownership:Run() Invalid secret key")
	}

	tpm, err := task.tpmFactory.NewTpmProvider()
	if err != nil {
		return errors.Wrap(err, "tasks/take_ownership:Run() Error while creating NewTpmProvider")
	}

	defer tpm.Close()

	// check if the tpm is already owned with the current secret key (and return)
	alreadyOwned, err := tpm.IsOwnedWithAuth(task.cfg.Tpm.OwnerSecretKey)
	if err != nil {
		return errors.Wrap(err, "tasks/take_ownership:Run() Error while checking if the tpm is already owned with the current secret key")
	}

	if alreadyOwned {
		log.Trace("tasks/take_ownership:Run() TPM ownership has already been established.")
		return nil
	}

	// tpm is not owned by current secret, take ownership
	err = tpm.TakeOwnership(task.cfg.Tpm.OwnerSecretKey)
	if err != nil {
		return errors.Wrap(err, "tasks/take_ownership:Run() Error while performing tpm takeownership operation")
	}

	// TakeOwnership didn't fail, update config, the key will be checked in Validate()
	err = task.cfg.Save()
	if err != nil {
		return errors.Wrap(err, "tasks/take_ownership:Run() Error saving configuration")
	}

	return nil
}

//
// Uses the current 'OwnerSecetKey' from configuration and checks its validity using
// TpmProvider.IsOwnedWithAuth.
//
func (task *TakeOwnership) Validate(c setup.Context) error {
	log.Trace("tasks/take_ownership:Validate() Entering")
	defer log.Trace("tasks/take_ownership:Validate() Leaving")

	if task.cfg.Tpm.OwnerSecretKey == "" {
		return errors.New("tasks/take_ownership:Validate() The configuration does not contain the tpm secret key")
	}

	tpmProvider, err := task.tpmFactory.NewTpmProvider()
	if err != nil {
		return errors.Wrap(err, "tasks/take_ownership:Validate() Error while creating NewTpmProvider")
	}

	defer tpmProvider.Close()

	ok, err := tpmProvider.IsOwnedWithAuth(task.cfg.Tpm.OwnerSecretKey)
	if err != nil {
		return errors.Wrap(err, "tasks/take_ownership:Validate() Error while checking if the tpm is already owned with the current secret key")
	}

	if !ok {
		return errors.New("tasks/take_ownership:Validate() The tpm is not owned with the current secret key")
	}

	log.Info("tasks/take_ownership:Validate() Take ownership was successful.")
	return nil
}
