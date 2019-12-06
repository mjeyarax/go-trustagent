/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package tasks

import (
	"crypto/x509"
	"encoding/base64"
	"fmt"
	log "github.com/sirupsen/logrus"
	"intel/isecl/go-trust-agent/config"
	"intel/isecl/go-trust-agent/constants"
	"intel/isecl/go-trust-agent/vsclient"
	"intel/isecl/lib/common/setup"
	"intel/isecl/lib/platform-info/platforminfo"
	"intel/isecl/lib/tpmprovider"
	"io/ioutil"
)

//-------------------------------------------------------------------------------------------------
// P R O V I S I O N   E N D O R S E M E N T   K E Y
//-------------------------------------------------------------------------------------------------
// The endorsement key (and cert) are embedded into the TPM by the manurfacturer.
// NOTE:  This code does not currently support the scenario when the TPM does not have an EK and cert.
//
// The goal of provisioning the endorsement key is to make sure the EK is validated against the
// list of manufacturer ca certs stored in HVS.  If the EK does not verify against the list of
// certs from HVS, the EK is registered (added) to HVS.
//-------------------------------------------------------------------------------------------------
type ProvisionEndorsementKey struct {
	tpmFactory             tpmprovider.TpmFactory
	ekCert                 *x509.Certificate
	endorsementAuthorities *x509.CertPool
	cfg                    *config.TrustAgentConfiguration
	caCertificatesClient   vsclient.CACertificatesClient
	tpmEndorsementsClient  vsclient.TpmEndorsementsClient
}

func (task *ProvisionEndorsementKey) Run(c setup.Context) error {
	var err error
	var registered bool
	var isEkSigned bool

	tpmProvider, err := task.tpmFactory.NewTpmProvider()
	if err != nil {
		return err
	}

	defer tpmProvider.Close()

	// read the manufacture's endorsement key from the TPM
	if err = task.readEndorsementKeyCertificate(tpmProvider); err != nil {
		return err
	}

	// download the list of public endorsement authority certs from VS
	if err := task.downloadEndorsementAuthorities(); err != nil {
		return err
	}

	// make sure manufacture's endorsement key is signed by one of the ea certs
	// provided by VS.
	if isEkSigned, err = task.isEkSignedByEndorsementAuthority(); err != nil {
		return err
	}

	// if the ek verifies, we're done/ok
	if isEkSigned {
		log.Debug("EC is already issued by endorsement authority; no need to request new EC")
		return nil
	}

	// if the ek does not verify, see if is already registered with VS
	if registered, err = task.isEkRegisteredWithMtWilson(); err != nil {
		log.Debug("EK is already registered with Mt Wilson; no need to request an EC")
		return err
	}

	// if not registered with vs, do so now
	if !registered {
		if err = task.registerEkWithMtWilson(); err != nil {
			return err
		}
	}

	return nil
}

func (task *ProvisionEndorsementKey) Validate(c setup.Context) error {
	// assume valid if error did not occur during 'Run'
	log.Info("Setup: Provisioning the endorsement key was successful.")
	return nil
}

func (task *ProvisionEndorsementKey) readEndorsementKeyCertificate(tpm tpmprovider.TpmProvider) error {

	ekCertBytes, err := tpm.NvRead(task.cfg.Tpm.OwnerSecretKey, tpmprovider.NV_IDX_ENDORSEMENT_KEY)
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
		// 	err = task.tpm.CreateEndorsementKey(task.cfg.TpmOwnerSecretKey)
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

func (task *ProvisionEndorsementKey) downloadEndorsementAuthorities() error {

	ea, err := task.caCertificatesClient.DownloadEndorsementAuthorities()
	if err != nil {
		return err
	}

	task.endorsementAuthorities = x509.NewCertPool()
	if !task.endorsementAuthorities.AppendCertsFromPEM(ea) {
		return fmt.Errorf("Could not load endorsement authorities")
	}

	err = ioutil.WriteFile(constants.EndorsementAuthoritiesFile, ea, 0644)
	if err != nil {
		return fmt.Errorf("Error saving endorsement authority file '%s': %s", constants.EndorsementAuthoritiesFile, err)
	}

	return nil
}

func (task *ProvisionEndorsementKey) isEkSignedByEndorsementAuthority() (bool, error) {
	isEkSigned := false

	opts := x509.VerifyOptions{
		Roots: task.endorsementAuthorities,
	}

	_, err := task.ekCert.Verify(opts)

	if err == nil {
		isEkSigned = true
	} else if err.Error() == "x509: unhandled critical extension" {
		// In at least one case, the cert provided by the TPM contains...
		//      X509v3 Key Usage: critical
		// 		Key Encipherment
		// which causes go to return an 'UnhandledCriticalExtension'
		// Ignore that error and assume the cert is valid.
		isEkSigned = true
	} else {
		log.Warnf("Failed to verify endorsement authorities: " + err.Error())
	}

	return isEkSigned, nil
}

func (task *ProvisionEndorsementKey) isEkRegisteredWithMtWilson() (bool, error) {

	hardwareUUID, err := platforminfo.HardwareUUID()
	if err != nil {
		return false, err
	}

	log.Tracef("HARDWARE-UUID: %s", hardwareUUID)

	return task.tpmEndorsementsClient.IsEkRegistered(hardwareUUID)
}

func (task *ProvisionEndorsementKey) registerEkWithMtWilson() error {

	hardwareUUID, err := platforminfo.HardwareUUID()
	if err != nil {
		return err
	}

	publicKeyDer, err := x509.MarshalPKIXPublicKey(task.ekCert.PublicKey)
	if err != nil {
		return err
	}

	certificateString := base64.StdEncoding.EncodeToString([]byte(publicKeyDer))

	endorsementData := vsclient.TpmEndorsement{}
	endorsementData.HardwareUUID = hardwareUUID
	endorsementData.Issuer = task.ekCert.Issuer.ToRDNSequence().String()
	endorsementData.Revoked = false
	endorsementData.Certificate = certificateString
	endorsementData.Command = "registered by trust agent"

	return task.tpmEndorsementsClient.RegisterEk(&endorsementData)
}
