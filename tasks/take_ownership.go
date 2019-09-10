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
	secretKey 	[]byte
}

// Retrieves the 'SecreteKey' value from configuration.  If it is not there, it generates a 
// new random key and saves it in the configuration.  It then passes the secret key to 
// TpmProvider.TakeOwnership.
func (task* TakeOwnership) Run(c setup.Context) error {
	var err error

	tpmProvider, err := tpmprovider.NewTpmProvider()
	if err != nil {
		return fmt.Errorf("Setup error: Could not create TpmProvider: %s", err)
	}

	defer tpmProvider.Close()

	if config.GetConfiguration().Tpm.SecretKey == "" {
		config.GetConfiguration().Tpm.SecretKey, err = crypt.GetHexRandomString(20)
		if err != nil {
			return errors.New("Setup error: An error occurred generating a random key")
		}

		err = config.GetConfiguration().Save()
		if err != nil {
			return fmt.Errorf("Setup error:  Error saving configuration [%s]", err)
		}
	}
	
	err = tpmProvider.TakeOwnership([]byte(config.GetConfiguration().Tpm.SecretKey))
	if err != nil {
		return err
	}
	
	return nil
}

//
// Uses the current 'secetKey' from configuration and checks its validity using
// TpmProvider.IsOwnedWithAuth.
//
func (task* TakeOwnership) Validate(c setup.Context) error {

	tpmProvider, err := tpmprovider.NewTpmProvider()
	if err != nil {
		return fmt.Errorf("Validation error: Could not create TpmProvider: %s", err)
	}

	defer tpmProvider.Close()

	if config.GetConfiguration().Tpm.SecretKey == "" {
		return errors.New("Validation error: The configuration does not contain the tpm secret key")
	}

	ok, err := tpmProvider.IsOwnedWithAuth([]byte(config.GetConfiguration().Tpm.SecretKey))
	if err != nil {
		return fmt.Errorf("Validation error: IsOwnedWithAuth return: %s", err)
	}
	
	if !ok {
		return errors.New("Validation error: The tpm is not owned with the current secret key")
	}

	log.Infof("Setup: TakeOwnership was successfull")
	return nil
}