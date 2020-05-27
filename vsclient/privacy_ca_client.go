/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package vsclient

import (
	"bytes"
	"encoding/json"
	"fmt"
	taModel "github.com/intel-secl/intel-secl/v3/pkg/model/ta"
	"intel/isecl/lib/common/v2/log/message"
	"io/ioutil"
	"net/http"
	"github.com/pkg/errors"
)

//-------------------------------------------------------------------------------------------------
// Public interface/structures
//-------------------------------------------------------------------------------------------------

type PrivacyCAClient interface {
	DownloadPrivacyCa() ([]byte, error)
	GetIdentityProofRequest(identityChallengeRequest *taModel.IdentityChallengePayload) (*taModel.IdentityProofRequest, error)
	GetIdentityProofResponse(identityChallengeResponse *taModel.IdentityChallengePayload) (*taModel.IdentityProofRequest, error)
}

//-------------------------------------------------------------------------------------------------
// Implementation
//-------------------------------------------------------------------------------------------------

type privacyCAClientImpl struct {
	httpClient *http.Client
	cfg        *vsClientConfig
}

func (client *privacyCAClientImpl) DownloadPrivacyCa() ([]byte, error) {
	log.Trace("vsclient/privacy_ca_client:DownloadPrivacyCa() Entering")
	defer log.Trace("vsclient/privacy_ca_client:DownloadPrivacyCa() Leaving")

	var ca []byte

	url := fmt.Sprintf("%s/ca-certificates/privacy", client.cfg.BaseURL)
	request, _ := http.NewRequest("GET", url, nil)
	request.Header.Set("Authorization", "Bearer "+client.cfg.BearerToken)

	response, err := client.httpClient.Do(request)
	if err != nil {
		secLog.Warn(message.BadConnection)
		return nil, errors.Wrapf(err, "vsclient/privacy_ca_client:DownloadPrivacyCa() Error while sending request to %s ", url)
	} else {
		if response.StatusCode != http.StatusOK {
			return nil, errors.Errorf("vsclient/privacy_ca_client:DownloadPrivacyCa() Request sent to %s returned status %d", url, response.StatusCode)
		}

		ca, err = ioutil.ReadAll(response.Body)
		if err != nil {
			return nil, errors.Wrap(err, "vsclient/privacy_ca_client:DownloadPrivacyCa() Error reading response")
		}
	}

	return ca, nil
}

func (client *privacyCAClientImpl) GetIdentityProofRequest(identityChallengeRequest *taModel.IdentityChallengePayload) (*taModel.IdentityProofRequest, error) {
	log.Trace("vsclient/privacy_ca_client:GetIdentityProofRequest() Entering")
	defer log.Trace("vsclient/privacy_ca_client:GetIdentityProofRequest() Leaving")

	var identityProofRequest taModel.IdentityProofRequest

	jsonData, err := json.Marshal(*identityChallengeRequest)
	if err != nil {
		return nil, err
	}

	log.Debugf("ChallengeRequest: %s", jsonData)

	url := fmt.Sprintf("%s/privacyca/identity-challenge-request", client.cfg.BaseURL)
	request, _ := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	request.Header.Set("Authorization", "Bearer "+client.cfg.BearerToken)
	request.Header.Set("Content-Type", "application/json")

	response, err := client.httpClient.Do(request)
	if err != nil {
		secLog.Warn(message.BadConnection)
		return nil, errors.Wrapf(err, "vsclient/privacy_ca_client:GetIdentityProofRequest() Error sending request to %s", url)
	} else {
		if response.StatusCode != http.StatusOK {
			b, _ := ioutil.ReadAll(response.Body)
			return nil, errors.Errorf("vsclient/privacy_ca_client:GetIdentityProofRequest() Request sent to %s returned status '%d', Response: %s", url, response.StatusCode, string(b))
		}

		data, err := ioutil.ReadAll(response.Body)
		if err != nil {
			return nil, errors.Wrap(err, "vsclient/privacy_ca_client:GetIdentityProofRequest() Error reading response")
		}

		err = json.Unmarshal(data, &identityProofRequest)
		if err != nil {
			return nil, errors.Wrap(err, "vsclient/privacy_ca_client:GetIdentityProofRequest() Error while unmarshalling response")
		}
	}

	return &identityProofRequest, nil
}

func (client *privacyCAClientImpl) GetIdentityProofResponse(identityChallengeResponse *taModel.IdentityChallengePayload) (*taModel.IdentityProofRequest, error) {
	log.Trace("vsclient/privacy_ca_client:GetIdentityProofResponse() Entering")
	defer log.Trace("vsclient/privacy_ca_client:GetIdentityProofResponse() Leaving")

	var identityProofRequest taModel.IdentityProofRequest

	jsonData, err := json.Marshal(*identityChallengeResponse)
	if err != nil {
		return nil, err
	}

	log.Debugf("vsclient/privacy_ca_client:GetIdentityProofResponse() identityChallengeResponse: %s\n", string(jsonData))

	url := fmt.Sprintf("%s/privacyca/identity-challenge-response", client.cfg.BaseURL)
	request, _ := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	request.Header.Set("Authorization", "Bearer "+client.cfg.BearerToken)
	request.Header.Set("Content-Type", "application/json")

	response, err := client.httpClient.Do(request)
	if err != nil {
		secLog.Warn(message.BadConnection)
		return nil, errors.Wrapf(err, "vsclient/privacy_ca_client:GetIdentityProofResponse() Error while sending request to %s ", url)
	} else {
		if response.StatusCode != http.StatusOK {
			b, _ := ioutil.ReadAll(response.Body)
			return nil, errors.Errorf("vsclient/privacy_ca_client:GetIdentityProofResponse() Request sent to %s returned status: '%d', Response: %s", url, response.StatusCode, string(b))
		}

		data, err := ioutil.ReadAll(response.Body)
		if err != nil {
			return nil, errors.Wrapf(err, "vsclient/privacy_ca_client:GetIdentityProofResponse() Error reading response ")
		}

		log.Debugf("vsclient/privacy_ca_client:GetIdentityProofResponse() Proof Response: %s\n", string(data))

		err = json.Unmarshal(data, &identityProofRequest)
		if err != nil {
			return nil, errors.Wrap(err, "vsclient/privacy_ca_client:GetIdentityProofResponse() Error while unmarshalling response body")
		}
	}

	return &identityProofRequest, nil
}
