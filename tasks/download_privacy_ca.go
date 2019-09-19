/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package tasks

import (
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	log "github.com/sirupsen/logrus"
	"intel/isecl/go-trust-agent/config"
	"intel/isecl/go-trust-agent/constants"
	"intel/isecl/lib/common/setup"
)
 
type DownloadPrivacyCA struct {
	 Flags 	[]string
}


func (task *DownloadPrivacyCA) Run(c setup.Context) error {
	client, err := newMtwilsonClient()
	if err != nil {
		return err
	}

	// KWT:  Consider mtwilson client factory that returns the request (provided url)
	url := fmt.Sprintf("%s/ca-certificates/privacy", config.GetConfiguration().HVS.Url)
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

		err = ioutil.WriteFile(constants.PrivacyCA, data, 0644)
		if err != nil {
			return fmt.Errorf("Error saving privacy ca file '%s': %s", constants.PrivacyCA, err)
		}
	}

	return nil
}

func (task *DownloadPrivacyCA) Validate(c setup.Context) error {
	_, err := GetPrivacyCA() 
	if err != nil {
		return err
	}

	log.Info("Setup: DownloadPrivacyCA was successfull")

	return nil
}

var privacyCAInstance *rsa.PublicKey

// KWT: Refactor this -- where should it live?  Currently only used by provision_aik.go
func GetPrivacyCA() (*rsa.PublicKey, error) {

	if privacyCAInstance == nil {
		if _, err := os.Stat(constants.PrivacyCA); os.IsNotExist(err) {
			return nil, err
		}

		privacyCaBytes, err := ioutil.ReadFile(constants.PrivacyCA)
		if err != nil {
			return nil, err
		}

		cert, err := x509.ParseCertificate(privacyCaBytes)
		if err != nil {
            return nil, err
		}

		privacyCAInstance = cert.PublicKey.(*rsa.PublicKey)

	}

	return privacyCAInstance, nil
}