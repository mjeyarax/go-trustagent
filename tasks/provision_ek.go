/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package tasks

import (
	"bytes"
// /	"crypto/tls"
	"crypto/x509"
	"fmt"
	"encoding/base64"
//	"encoding/hex"
	"encoding/json"
//	"encoding/pem"
	"io/ioutil"
	"net/http"
	log "github.com/sirupsen/logrus"
	"intel/isecl/go-trust-agent/config"
	"intel/isecl/go-trust-agent/constants"
	"intel/isecl/go-trust-agent/platforminfo"
	"intel/isecl/go-trust-agent/tpmprovider"
	"intel/isecl/lib/common/setup"
//	commonTls "intel/isecl/lib/common/tls"
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
	var registered bool
	var isEkSigned bool

	if err = task.readEndorsementKeyCertificate(); err != nil {
		return err
	}

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
		log.Info("EK is already registered with Mt Wilson; no need to request an EC")
		return err
	}

	if !registered {
		if err = task.registerEkWithMtWilson(); err != nil {
			return err
		}
	}

	return nil
}

func (task* ProvisionEndorsementKey) Validate(c setup.Context) error {

	// assume valid if error did not occur during 'Run'
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

	// WEEK2: Remove
	err = ioutil.WriteFile("/opt/trustagent/configuration/ek.der", ekCertBytes, 0644)
	if err != nil {
		return fmt.Errorf("Error %s", err)
	}
	return nil
}

func (task* ProvisionEndorsementKey) downloadEndorsementAuthorities() error {

	client, err := newMtwilsonClient()
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

// WEEK2:  Getting 'X509: Unhandled critical extension'
func (task* ProvisionEndorsementKey) isEkSignedByEndorsementAuthority() (bool, error) {
	isEkSigned := false


	opts := x509.VerifyOptions {
		Roots:   task.endorsementAuthorities,
	}



	_, err := task.ekCert.Verify(opts);

	if err == nil {
		isEkSigned = true
	}else if err.Error() == "x509: unhandled critical extension" {
		// In at least one case, the cert provided by the TPM contains...
		//      X509v3 Key Usage: critical
		// 		Key Encipherment
		// which causes go to return an 'UnhandledCriticalExtension'
		// Going to ignore that error and assume the cert is valid.

		isEkSigned = true
	} else {
		log.Warnf("Failed to verify endorsement authorities: " + err.Error())
	}


// 	eaBytes, err := ioutil.ReadFile(constants.EndorsementAuthoritiesFile)
// 	if err != nil {
// 		return false, err
// 	}

// 	i := 0
// 	for {
// 		block, next := pem.Decode(eaBytes)
// 		if block == nil {
// 			break
// 		}

// 		if block.Type == "CERTIFICATE" {
// 			caCert, err := x509.ParseCertificate(block.Bytes)
// 			if err != nil {
// 				log.Warnf("Could not parse block %d", i)
// 			} else {

// //				log.Infof("%s ==> %s", task.ekCert.Issuer.ToRDNSequence().String(), caCert.Subject.ToRDNSequence().String())
// 				if (task.ekCert.Issuer.ToRDNSequence().String() == caCert.Subject.ToRDNSequence().String()) {
// 					log.Info("CERT MATCH")

// 					certPool := x509.NewCertPool()
// 					certPool.AddCert(caCert)
			
// 					opts := x509.VerifyOptions {
// 						Roots: certPool,
// 						//Intermediates : certPool,
// 					}
				
// 					if _, err := task.ekCert.Verify(opts); err != nil {
// 						log.Warnf("Failed to verify endorsement authorities: " + err.Error())
// 					} else {
// 						log.Info("EK MATCH")
// 						isEkSigned = true
// 						break
// 					}
// 				}
// 			}
// 		}

// 		eaBytes = next
// 		i++
// 	}

	// for i, derBytes := range task.endorsementAuthorities.Subjects() {

	// 	log.Info("%d: %s", i, base64.StdEncoding.EncodeToString(derBytes))

	// 	eaCert, err := x509.ParseCertificate(derBytes)
	// 	if err != nil {
	// 		log.Warnf("Failed to load ca at index %d", i)
	// 		continue
	// 	}

	// 	certPool := x509.NewCertPool()
	// 	certPool.AddCert(eaCert)

	// 	opts := x509.VerifyOptions {
	// 		Roots: certPool,
	// 	}
	
	// 	if _, err := task.ekCert.Verify(opts); err != nil {
	// 		log.Warnf("Failed to verify endorsement authorities: " + err.Error())
	// 	} else {
	// 		isEkSigned = true
	// 		break
	// 	}

	// }

	// opts := x509.VerifyOptions {
	// 	//DNSName: "10.105.168.60",
	// 	Roots:   task.endorsementAuthorities,
	// }

	// if _, err := task.ekCert.Verify(opts); err != nil {
	// 	log.Warnf("Failed to verify endorsement authorities: " + err.Error())
	// } else {
	// 	isEkSigned = true
	// }

	return isEkSigned, nil
}

func (task* ProvisionEndorsementKey) isEkRegisteredWithMtWilson() (bool, error) {

	hardwareUUID, err := platforminfo.HardwareUUID()
	if err != nil {
		return false, err
	}

	log.Debugf("HARDWARE-UUID: %s", hardwareUUID)

	client, err := newMtwilsonClient()
	if err != nil {
		return false, err
	}

	url := fmt.Sprintf("%s/tpm-endorsements?hardwareUuidEqualTo=%s", config.GetConfiguration().HVS.Url, hardwareUUID)
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

//		log.Infof("Endorsements: %s", string(data))

		var objmap map[string]interface{}
		if err := json.Unmarshal(data, &objmap); err != nil {
			return false, fmt.Errorf("Error parsing json: %s", err)
		}

		if(objmap["tpm_endorsements"] != nil && len(objmap["tpm_endorsements"].([]interface{})) > 0) {
			// a endorsement was found with this hardware uuid
			return true, nil
		}

	}

	return false, nil
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

	client, err := newMtwilsonClient()
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
