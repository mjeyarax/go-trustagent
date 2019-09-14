/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package tasks

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	//"encoding/pem"
	"io/ioutil"
	"net/http"
	log "github.com/sirupsen/logrus"
	"intel/isecl/go-trust-agent/config"
	"intel/isecl/go-trust-agent/constants"
	"intel/isecl/go-trust-agent/platforminfo"
	"intel/isecl/go-trust-agent/tpmprovider"
	"intel/isecl/lib/common/setup"
	commonTls "intel/isecl/lib/common/tls"
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
	Flags 					[]string
	ekCert      			*x509.Certificate
	endorsementAuthorities 	*x509.CertPool
}

func (task* ProvisionEndorsementKey) Run(c setup.Context) error {
	var err error

	if err = task.readEndorsementKeyCertificate(); err != nil {
		return err
	}

	if err = task.registerEndorsementKeyCertificate(); err != nil {
		return err
	}

	return nil
}

func (task* ProvisionEndorsementKey) Validate(c setup.Context) error {

	// WEEK2:  Validate endorsement key registration

	log.Info("Successfully provisioned endorsement key")
	return nil
}

func (task* ProvisionEndorsementKey) readEndorsementKeyCertificate() error {

	tpm, err := tpmprovider.NewTpmProvider()
	if err != nil {
		return fmt.Errorf("Setup error: Provision aik could not create TpmProvider: %s", err)
	}

	defer tpm.Close()

	ekCertBytes, err := tpm.GetEndorsementKeyCertificate(config.GetConfiguration().Tpm.SecretKey)
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

// download 'endorsement.pem' from mtwilson
// check if the ec is registed with mtwilson and if not, register it
func (task* ProvisionEndorsementKey) registerEndorsementKeyCertificate() error {

	var err error
	var registered bool
	var isEkSigned bool

	if err := task.downloadEndorsementAuthorities(); err != nil {
		return err
	}

	if isEkSigned, err = task.isEkSignedByEndorsementAuthority(); err != nil {
		return err
	}

	if isEkSigned {
		log.Info("EC is already issued by endorsement authority; no need to request new EC")
		return nil
	}

	if registered, err = task.isEkRegisteredWithMtWilson(); err != nil {
		return err
	}

	if !registered {
		if err = task.registerEkWithMtWilson(); err != nil {
			return err
		}
	}

	return nil
}

// KWT:  Merge this (or use) into mtwilson.Client
func mtwilsonClient(tls384 string) (*http.Client, error) {

	var certificateDigest [48]byte

	certDigestBytes, err := hex.DecodeString(tls384)
	if err != nil {
		return nil, fmt.Errorf("error converting certificate digest to hex: %s", err)
	}

	if len(certDigestBytes) != 48 {
		return nil, fmt.Errorf("Incorrect TLS384 string length %d", len(certDigestBytes))
	}

	copy(certificateDigest[:], certDigestBytes)

	// init http client
	tlsConfig := tls.Config{}
	if certDigestBytes != nil {
		// set explicit verification
		tlsConfig.InsecureSkipVerify = true
		tlsConfig.VerifyPeerCertificate = commonTls.VerifyCertBySha384(certificateDigest)
	}

	transport := http.Transport{
		TLSClientConfig: &tlsConfig,
	}

	client := http.Client{Transport: &transport}
	return &client, nil
}

func (task* ProvisionEndorsementKey) downloadEndorsementAuthorities() error {

	client, err := mtwilsonClient(config.GetConfiguration().HVS.TLS384)
	if err != nil {
		return err
	}

	// KWT:  Consider mtwilson client factory that returns the request (provided url)
	url := fmt.Sprintf("%s/ca-certificates?domain=ek", config.GetConfiguration().HVS.Url)
	request, _:= http.NewRequest("GET", url, nil)
	request.SetBasicAuth(config.GetConfiguration().HVS.Username, config.GetConfiguration().HVS.Password)

	response, err := client.Do(request)
    if err != nil {
        return fmt.Errorf("%s request failed with error %s\n", url, err)
    } else {
		if response.StatusCode != http.StatusOK {
			return fmt.Errorf("%s returned status %d", url, response.StatusCode)
		}

		data, err := ioutil.ReadAll(response.Body)
		if err != nil {
			return fmt.Errorf("Error reading response: %s", err)
		}

		task.endorsementAuthorities = x509.NewCertPool()
		if !task.endorsementAuthorities.AppendCertsFromPEM(data) {
			return fmt.Errorf("Could not load endorsement authorities")
		}

		// KWT:  When to save the file (now or later during validation, or at all?)
		err = ioutil.WriteFile(constants.EndorsementAuthoritiesFile, data, 0644)
		if err != nil {
			return fmt.Errorf("Error saving endorsement authority file '%s': %s", constants.EndorsementAuthoritiesFile, err)
		}
    }

	return nil
}

// WEEK2:  Needs to be debugged to see if it 'verifying'...
func (task* ProvisionEndorsementKey) isEkSignedByEndorsementAuthority() (bool, error) {
	isEkSigned := false

	opts := x509.VerifyOptions{
		//DNSName: "mail.google.com",
		Roots:   task.endorsementAuthorities,
	}

	if _, err := task.ekCert.Verify(opts); err != nil {
		log.Warnf("Failed to verify endorsement authorities: " + err.Error())
	} else {
		isEkSigned = true
	}

	return isEkSigned, nil
}

// WEEK2: debug
func (task* ProvisionEndorsementKey) isEkRegisteredWithMtWilson() (bool, error) {

	hardwareUUID, err := platforminfo.HardwareUUID()
	if err != nil {
		return false, err
	}

	log.Debugf("HARDWARE-UUID: %s", hardwareUUID)

	client, err := mtwilsonClient(config.GetConfiguration().HVS.TLS384)
	if err != nil {
		return false, err
	}

	url := fmt.Sprintf("%s/tpm-endorsements?hardware_uuid=%s", config.GetConfiguration().HVS.Url, hardwareUUID)
	request, _:= http.NewRequest("GET", url, nil)
	request.SetBasicAuth(config.GetConfiguration().HVS.Username, config.GetConfiguration().HVS.Password)

	response, err := client.Do(request)
    if err != nil {
        return false, fmt.Errorf("%s request failed with error %s\n", url, err)
    } else {
		if response.StatusCode != http.StatusOK {
			return false, fmt.Errorf("IsEkRegistered: %s returned status %d", url, response.StatusCode)
		}

		data, err := ioutil.ReadAll(response.Body)
		if err != nil {
			return false, fmt.Errorf("Error reading response: %s", err)
		}

		// WEEK2:  Parse json and see if this hardware-id is in the list (return true)

		log.Info(string(data))
	}

	return false, nil
}

// WEEK2:  move
type TpmEndorsement struct {
	HardwareUUID 	string 	`json:"hardware_uuid"`
	Issuer 			string 	`json:"issuer"`
	Revoked			bool	`json:"revoked"`
	Certificate		string 	`json:"certificate"`
	Command			string 	`json:"command"`
}

func (task* ProvisionEndorsementKey) registerEkWithMtWilson() error {

	hardwareUUID, err := platforminfo.HardwareUUID()
	if err != nil {
		return err
	}

	publicKeyDer, err := x509.MarshalPKIXPublicKey(task.ekCert.PublicKey)
	if err != nil {
		return err
	}

	certificateString := base64.StdEncoding.EncodeToString([]byte(publicKeyDer))
	

	endorsementData := TpmEndorsement {}
	endorsementData.HardwareUUID = hardwareUUID
	endorsementData.Issuer = task.ekCert.Issuer.ToRDNSequence().String()
	endorsementData.Revoked = false
	endorsementData.Certificate = certificateString
	endorsementData.Command = "registered by trust agent"

	jsonData, err := json.Marshal(endorsementData)
	if err != nil {
		return err
	}

	log.Info(string(jsonData))

	client, err := mtwilsonClient(config.GetConfiguration().HVS.TLS384)
	if err != nil {
		return err
	}

	url := fmt.Sprintf("%s/tpm-endorsements", config.GetConfiguration().HVS.Url)
	request, _:= http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	request.SetBasicAuth(config.GetConfiguration().HVS.Username, config.GetConfiguration().HVS.Password)
	request.Header.Set("Content-Type", "application/json")

	response, err := client.Do(request)
    if err != nil {
        return fmt.Errorf("RegisterEndorsementKey: %s request failed with error %s\n", url, err)
    } else {
		if response.StatusCode != http.StatusOK {
			return fmt.Errorf("RegisterEndorsementKey: %s returned status %d", url, response.StatusCode)
		}
	}

	return nil
}
