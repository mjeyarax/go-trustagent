/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
 package tasks

import (
	"crypto/x509"
	"fmt"
	log "github.com/sirupsen/logrus"
	"intel/isecl/go-trust-agent/config"
	"intel/isecl/go-trust-agent/tpmprovider"
	"intel/isecl/lib/common/setup"
)

//-------------------------------------------------------------------------------------------------
// P R O V I S I O N   E N D O R S E M E N T   K E Y
//-------------------------------------------------------------------------------------------------
// The endorsement key (and cert) are embedded into the TPM by the manurfacturer.
// NOTE:  This code does not currently support the scenario when the TPM does not have an EK and cert.
//
// The goal of provisioning the endorsement key is...
// 1. To register the EK with mtwilson (not exactly sure what feature that supports).
// 2. Used to generate the AIK for reports.
//
// 'ProvisionEndorsementKey'...
// 1. Pulls the ek cert from the tpm (an error occurs if it cannot be retreived or parsed into x509).
// 2. Registers the cert with mtwilson.
//
//-------------------------------------------------------------------------------------------------
type ProvisionEndorsementKey struct {
	Flags 		[]string
	ekCert      *x509.Certificate
	tpm			tpmprovider.TpmProvider
}

func (task* ProvisionEndorsementKey) Run(c setup.Context) error {
	var err error

	task.tpm, err = tpmprovider.NewTpmProvider()
	if err != nil {
		return fmt.Errorf("Setup error: Provision aik could not create TpmProvider: %s", err)
	}

	defer task.tpm.Close()

	if err = task.readEndorsementKeyCertificate(); err != nil {
		return err
	}

	if err = task.registerEndorsementKeyCertificate(); err != nil {
		return err
	}

	return nil
}

func (task* ProvisionEndorsementKey) Validate(c setup.Context) error {



	log.Info("Successfully provisioned endorsement key")
	return nil
}

func (task* ProvisionEndorsementKey) readEndorsementKeyCertificate() error {

	ekCertBytes, err := task.tpm.GetEndorsementKeyCertificate(config.GetConfiguration().Tpm.SecretKey)
	if err != nil {
		return err
	}

	if ekCertBytes == nil {
		// TODO:  If the TPM does not have EKC (ekCertBytes is null), generate a new one, sign with HVS and
		// load into nvram.  For now, this will result in an error in when attempting to parse into x509.

		// exists, err := task.tpm.PublicKeyExists(tpmprovider.NV_IDX_ENDORSEMENT_KEY)
		// if err != nil {
		// 	return err
		// }

		// if !exists {
		// 	err = task.tpm.CreateEndorsementKey(config.GetConfiguration().Tpm.SecretKey)
		// 	if err != nil {
		// 		return err
		// 	}
		// }
	}

	// make sure we can turn the certificate bytes into x509 
	task.ekCert, err = x509.ParseCertificate(ekCertBytes)
	if err != nil {
		return err
	}

	return nil
}

func (task* ProvisionEndorsementKey) registerEndorsementKeyCertificate() error {

	return nil
}