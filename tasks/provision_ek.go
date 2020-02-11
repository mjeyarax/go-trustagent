/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package tasks

import (
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"intel/isecl/go-trust-agent/constants"
	"intel/isecl/go-trust-agent/vsclient"
	"intel/isecl/lib/common/setup"
	"intel/isecl/lib/platform-info/platforminfo"
	"intel/isecl/lib/tpmprovider"
	"io/ioutil"
	"github.com/pkg/errors"
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
	clientFactory          vsclient.VSClientFactory
	tpmFactory             tpmprovider.TpmFactory
	ownerSecretKey         *string
}

func (task *ProvisionEndorsementKey) Run(c setup.Context) error {
	log.Trace("tasks/provision_ek:Run() Entering")
	defer log.Trace("tasks/provision_ek:Run() Leaving")
	fmt.Println("Running setup task: provision-ek")

	var err error
	var registered bool
	var isEkSigned bool

	if task.ownerSecretKey == nil || *task.ownerSecretKey == "" {
		return errors.New("ownerSecretKey cannot be nil or empty")
	}
	
	tpmProvider, err := task.tpmFactory.NewTpmProvider()
	if err != nil {
		log.WithError(err).Error("tasks/provision_ek:Run() Error while creating NewTpmProvider")
		return errors.Wrap(err, "Error while creating NewTpmProvider")
	}

	defer tpmProvider.Close()

	// read the manufacture's endorsement key from the TPM
	ekCert, err := task.readEndorsementKeyCertificate(tpmProvider)
	if err != nil {
		log.WithError(err).Error("tasks/provision_ek:Run() Error while creating NewTpmProvider")
		return errors.Wrap(err, "Error while reading tpm endorsement certificate")
	}

	// download the list of public endorsement authority certs from VS
	endorsementAuthorities, err := task.downloadEndorsementAuthorities()
	if err != nil {
		log.WithError(err).Error("tasks/provision_ek:Run() Error while downloading endorsement authorities")
		return errors.Wrap(err, "Error while downloading endorsement authorities")
	}

	// make sure manufacture's endorsement key is signed by one of the ea certs
	// provided by VS.
	isEkSigned, err = task.isEkSignedByEndorsementAuthority(ekCert, endorsementAuthorities)
	if err != nil {
		log.WithError(err).Error("tasks/provision_ek:Run() Error while verifying endorsement certificate is signed by endorsement authorities")
		return errors.Wrap(err, "Error while verifying endorsement certificate is signed by endorsement authorities")
	}

	// if the ek verifies, we're done/ok
	if isEkSigned {
		log.Debug("tasks/provision_ek:Run() EC is already issued by endorsement authority; no need to request new EC")
		return nil
	}

	// if the ek does not verify, see if is already registered with VS
	if registered, err = task.isEkRegisteredWithMtWilson(); err != nil {
		log.Debug("tasks/provision_ek:Run() EK is already registered with Mt Wilson; no need to request an EC")
		return err
	}

	// if not registered with vs, do so now
	if !registered {
		if err = task.registerEkWithMtWilson(ekCert); err != nil {
			return err
		}
	}

	return nil
}

func (task *ProvisionEndorsementKey) Validate(c setup.Context) error {
	log.Trace("tasks/provision_ek:Validate() Entering")
	defer log.Trace("tasks/provision_ek:Validate() Leaving")
	// assume valid if error did not occur during 'Run'
	log.Info("tasks/provision_ek:Validate() Provisioning the endorsement key was successful.")
	return nil
}

func (task *ProvisionEndorsementKey) readEndorsementKeyCertificate(tpm tpmprovider.TpmProvider) (*x509.Certificate, error) {
	log.Trace("tasks/provision_ek:readEndorsementKeyCertificate() Entering")
	defer log.Trace("tasks/provision_ek:readEndorsementKeyCertificate() Leaving")

	ekCertBytes, err := tpm.NvRead(*task.ownerSecretKey, tpmprovider.NV_IDX_ENDORSEMENT_KEY)
	if err != nil {
		return nil, errors.Wrap(err, "tasks/provision_ek:readEndorsementKeyCertificate() Error while performing NV read operation for retrieving endorsement certificate")
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
	ekCert, err := x509.ParseCertificate(ekCertBytes)
	if err != nil {
		return nil, errors.Wrap(err, "tasks/provision_ek:readEndorsementKeyCertificate() Error while parsing endorsement certificate in bytes into x509 certificate")
	}

	return ekCert, nil
}

func (task *ProvisionEndorsementKey) downloadEndorsementAuthorities() (*x509.CertPool, error) {
	log.Trace("tasks/provision_ek:downloadEndorsementAuthorities() Entering")
	defer log.Trace("tasks/provision_ek:downloadEndorsementAuthorities() Leaving")

	caCertificatesClient, err := task.clientFactory.CACertificatesClient()
	if err != nil {
		return nil, errors.Wrapf(err, "tasks/provision_ek:downloadEndorsementAuthorities() Could not ca-certificates client")
	}

	ea, err := caCertificatesClient.DownloadEndorsementAuthorities()
	if err != nil {
		return nil, errors.Wrap(err, "tasks/provision_ek:downloadEndorsementAuthorities() Error while downloading endorsement authorities")
	}

	endorsementAuthorities := x509.NewCertPool()
	if !endorsementAuthorities.AppendCertsFromPEM(ea) {
		return nil, errors.New("tasks/provision_ek:downloadEndorsementAuthorities() Error loading endorsement authorities")
	}

	err = ioutil.WriteFile(constants.EndorsementAuthoritiesFile, ea, 0644)
	if err != nil {
		return nil, errors.Wrapf(err, "tasks/provision_ek:downloadEndorsementAuthorities() Error saving endorsement authority file '%s'", constants.EndorsementAuthoritiesFile)
	}

	return endorsementAuthorities, nil
}

func (task *ProvisionEndorsementKey) isEkSignedByEndorsementAuthority(ekCert *x509.Certificate, endorsementAuthorities *x509.CertPool) (bool, error) {
	log.Trace("tasks/provision_ek:isEkSignedByEndorsementAuthority() Entering")
	defer log.Trace("tasks/provision_ek:isEkSignedByEndorsementAuthority() Leaving")
	isEkSigned := false

	opts := x509.VerifyOptions{
		Roots: endorsementAuthorities,
	}

	_, err := ekCert.Verify(opts)

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
		log.Warnf("tasks/provision_ek:isEkSignedByEndorsementAuthority() Failed to verify endorsement authorities: " + err.Error())
	}

	return isEkSigned, nil
}

func (task *ProvisionEndorsementKey) isEkRegisteredWithMtWilson() (bool, error) {
	log.Trace("tasks/provision_ek:isEkRegisteredWithMtWilson() Entering")
	defer log.Trace("tasks/provision_ek:isEkRegisteredWithMtWilson() Leaving")

	tpmEndorsementsClient, err := task.clientFactory.TpmEndorsementsClient()
	if err != nil {
		return false, errors.Wrapf(err, "tasks/provision_ek:isEkRegisteredWithMtWilson() Could not create tpm-endorsements client")
	}	

	hardwareUUID, err := platforminfo.HardwareUUID()
	if err != nil {
		return false, errors.Wrap(err, "tasks/provision_ek:isEkRegisteredWithMtWilson() Error while fetching hardware uuid")
	}

	log.Tracef("tasks/provision_ek:isEkRegisteredWithMtWilson() HARDWARE-UUID: %s", hardwareUUID)

	return tpmEndorsementsClient.IsEkRegistered(hardwareUUID)
}

func (task *ProvisionEndorsementKey) registerEkWithMtWilson(ekCert *x509.Certificate) error {
	log.Trace("tasks/provision_ek:registerEkWithMtWilson() Entering")
	defer log.Trace("tasks/provision_ek:registerEkWithMtWilson() Leaving")

	tpmEndorsementsClient, err := task.clientFactory.TpmEndorsementsClient()
	if err != nil {
		return errors.Wrapf(err, "tasks/provision_ek:registerEkWithMtWilson() Could not create tpm-endorsements client")
	}	

	hardwareUUID, err := platforminfo.HardwareUUID()
	if err != nil {
		return errors.Wrap(err, "tasks/provision_ek:registerEkWithMtWilson() Error while fetching hardware uuid")
	}

	publicKeyDer, err := x509.MarshalPKIXPublicKey(ekCert.PublicKey)
	if err != nil {
		return errors.Wrap(err, "tasks/provision_ek:registerEkWithMtWilson() Error marshalling endorsement certificate public key")
	}

	certificateString := base64.StdEncoding.EncodeToString([]byte(publicKeyDer))

	endorsementData := vsclient.TpmEndorsement{}
	endorsementData.HardwareUUID = hardwareUUID
	endorsementData.Issuer = ekCert.Issuer.ToRDNSequence().String()
	endorsementData.Revoked = false
	endorsementData.Certificate = certificateString
	endorsementData.Command = "registered by trust agent"

	return tpmEndorsementsClient.RegisterEk(&endorsementData)
}
