/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package tasks

import (
	"fmt"
	"intel/isecl/lib/common/v2/setup"
	"intel/isecl/lib/tpmprovider/v2"
	
	"github.com/pkg/errors"
)

type ProvisionPrimaryKey struct {
	tpmFactory tpmprovider.TpmFactory
	ownerSecretKey *string
}

// This task is used to persist a primary public key at handle TPM_HANDLE_PRIMARY
// to be used by WLA for signing/binding keys.
func (task *ProvisionPrimaryKey) Run(c setup.Context) error {
	log.Trace("tasks/provision_primary_key:Run() Entering")
	defer log.Trace("tasks/provision_primary_key:Run() Leaving")
	fmt.Println("Running setup task: provision-primary-key")
	tpm, err := task.tpmFactory.NewTpmProvider()
	if err != nil {
		log.WithError(err).Error("tasks/provision_primary_key:Run() Error while creating NewTpmProvider")
		return errors.New("Error while creating NewTpmProvider")
	}

	defer tpm.Close()

	exists, err := tpm.PublicKeyExists(tpmprovider.TPM_HANDLE_PRIMARY)
	if err != nil {
		log.WithError(err).Error("tasks/provision_primary_key:Run() Error while checking existence of tpm public key")
		return errors.New("Error while checking existence of tpm public key")
	}

	if !exists {
		err = tpm.CreatePrimaryHandle(*task.ownerSecretKey, tpmprovider.TPM_HANDLE_PRIMARY)
		if err != nil {
			log.WithError(err).Error("tasks/provision_primary_key:Run() Error while creating tpm primary handle")
			return errors.New("Error while creating tpm primary handle")
		}
	}

	return nil
}

func (task *ProvisionPrimaryKey) Validate(c setup.Context) error {
	log.Trace("tasks/provision_primary_key:Validate() Entering")
	defer log.Trace("tasks/provision_primary_key:Validate() Leaving")
	tpm, err := task.tpmFactory.NewTpmProvider()
	if err != nil {
		log.WithError(err).Error("tasks/provision_primary_key:Validate() Error while creating NewTpmProvider")
		return errors.New("Error while creating NewTpmProvider")
	}

	defer tpm.Close()

	exists, err := tpm.PublicKeyExists(tpmprovider.TPM_HANDLE_PRIMARY)
	if err != nil {
		log.WithError(err).Error("tasks/provision_primary_key:Validate() Error while checking existence of tpm public key")
		return errors.New("Error while checking existence of tpm public key")
	}

	if !exists {
		log.WithError(err).Errorf("tasks/provision_primary_key:Validate() The primary key at handle %x was not created", tpmprovider.TPM_HANDLE_PRIMARY)
		return errors.Errorf("The primary key at handle %x was not created", tpmprovider.TPM_HANDLE_PRIMARY)
	}

	// assume valid if error did not occur during 'Run'
	log.Info("tasks/provision_primary_key:Validate() Provisioning the primary key was successful.")
	return nil
}
