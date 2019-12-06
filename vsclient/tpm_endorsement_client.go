/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package vsclient

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	log "github.com/sirupsen/logrus"
)
//-------------------------------------------------------------------------------------------------
// Public interface/structures
//-------------------------------------------------------------------------------------------------

type TpmEndorsementsClient interface {
	IsEkRegistered(hardwareUUID string) (bool, error)
	RegisterEk(tpmEndorsement *TpmEndorsement) error
}

type TpmEndorsement struct {
	HardwareUUID 	string 	`json:"hardware_uuid"`
	Issuer 			string 	`json:"issuer"`
	Revoked			bool	`json:"revoked"`
	Certificate		string 	`json:"certificate"`
	Command			string 	`json:"command"`
}

//-------------------------------------------------------------------------------------------------
// Implementation
//-------------------------------------------------------------------------------------------------

type tpmEndorsementsClientImpl struct {
	httpClient *http.Client
	cfg *VSClientConfig
}

func (client *tpmEndorsementsClientImpl) IsEkRegistered(hardwareUUID string) (bool, error) {

	url := fmt.Sprintf("%s/tpm-endorsements?hardwareUuidEqualTo=%s", client.cfg.BaseURL, hardwareUUID)
	request, _ := http.NewRequest("GET", url, nil)
	request.SetBasicAuth(client.cfg.Username, client.cfg.Password)

	response, err := client.httpClient.Do(request)
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

		var objmap map[string]interface{}
		if err := json.Unmarshal(data, &objmap); err != nil {
			return false, fmt.Errorf("Error parsing json: %s", err)
		}

		if objmap["tpm_endorsements"] != nil && len(objmap["tpm_endorsements"].([]interface{})) > 0 {
			// a endorsement was found with this hardware uuid
			return true, nil
		}
	}

	return false, nil
}

func (client *tpmEndorsementsClientImpl) RegisterEk(tpmEndorsement *TpmEndorsement) error {

	jsonData, err := json.Marshal(tpmEndorsement)
	if err != nil {
		return err
	}

	log.Tracef("vsclient.RegisterEk: %s", string(jsonData))

	url := fmt.Sprintf("%s/tpm-endorsements", client.cfg.BaseURL)
	request, _ := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	request.SetBasicAuth(client.cfg.Username, client.cfg.Password)
	request.Header.Set("Content-Type", "application/json")

	response, err := client.httpClient.Do(request)
	if err != nil {
		return fmt.Errorf("RegisterEndorsementKey: %s request failed with error %s\n", url, err)
	} else {
		if response.StatusCode != http.StatusOK {
			return fmt.Errorf("RegisterEndorsementKey: %s returned status %d", url, response.StatusCode)
		}
	}

	return nil
}