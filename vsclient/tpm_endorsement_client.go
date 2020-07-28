/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package vsclient

import (
	"bytes"
	"encoding/json"
	"fmt"
	"intel/isecl/lib/common/v2/log/message"
	"io/ioutil"
	"net/http"
	"github.com/pkg/errors"
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
	cfg *vsClientConfig
}

func (client *tpmEndorsementsClientImpl) IsEkRegistered(hardwareUUID string) (bool, error) {
	log.Trace("vsclient/tpm_endorsement_client:IsEkRegistered() Entering")
	defer log.Trace("vsclient/tpm_endorsement_client:IsEkRegistered() Leaving")

	url := fmt.Sprintf("%s/tpm-endorsements?hardwareUuidEqualTo=%s", client.cfg.BaseURL, hardwareUUID)
	request, _ := http.NewRequest("GET", url, nil)
	request.Header.Set("Authorization", "Bearer "+client.cfg.BearerToken)
	request.Header.Set("Accept", "application/json")

	response, err := client.httpClient.Do(request)
	if err != nil {
		secLog.Warn(message.BadConnection)
		return false, errors.Wrapf(err, "vsclient/tpm_endorsement_client:IsEkRegistered() Error while sending request to %s ", url)
	} else {
		if response.StatusCode != http.StatusOK {
			return false, errors.Errorf("vsclient/tpm_endorsement_client:IsEkRegistered() Request sent to %s returned status %d", url, response.StatusCode)
		}

		data, err := ioutil.ReadAll(response.Body)
		if err != nil {
			return false, errors.Wrap(err, "vsclient/tpm_endorsement_client:IsEkRegistered() Error reading response")
		}

		var objmap map[string]interface{}
		if err := json.Unmarshal(data, &objmap); err != nil {
			return false, errors.Wrap(err, "vsclient/tpm_endorsement_client:IsEkRegistered() Error while unmarshalling response body")
		}

		if objmap["tpm_endorsements"] != nil && len(objmap["tpm_endorsements"].([]interface{})) > 0 {
			// a endorsement was found with this hardware uuid
			return true, nil
		}
	}

	return false, nil
}

func (client *tpmEndorsementsClientImpl) RegisterEk(tpmEndorsement *TpmEndorsement) error {
	log.Trace("vsclient/tpm_endorsement_client:RegisterEk() Entering")
	defer log.Trace("vsclient/tpm_endorsement_client:RegisterEk() Leaving")

	jsonData, err := json.Marshal(tpmEndorsement)
	if err != nil {
		return err
	}

	log.Tracef("vsclient/tpm_endorsement_client:RegisterEk() Request body %s", string(jsonData))

	url := fmt.Sprintf("%s/tpm-endorsements", client.cfg.BaseURL)
	request, _ := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	request.Header.Set("Authorization", "Bearer "+client.cfg.BearerToken)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")

	response, err := client.httpClient.Do(request)
	if err != nil {
		secLog.Warn(message.BadConnection)
		return errors.Wrapf(err, "vsclient/tpm_endorsement_client:RegisterEk() Error while sending request to %s ", url)
	} else {
		if response.StatusCode != http.StatusOK {
			return errors.Errorf("vsclient/tpm_endorsement_client:RegisterEk() Request sent to %s returned status %d", url, response.StatusCode)
		}
	}

	return nil
}
