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
	"github.com/pkg/errors"
)

//-------------------------------------------------------------------------------------------------
// Public interface/structures
//-------------------------------------------------------------------------------------------------

type PrivacyCAClient interface {
	DownloadPrivacyCa() ([]byte, error)
	GetIdentityProofRequest(identityChallengeRequest *IdentityChallengeRequest) (*IdentityProofRequest, error)
	GetIdentityProofResponse(identityChallengeResponse *IdentityChallengeResponse) (*IdentityProofRequest, error)
}

// {
//   "identity_request":{
//     "tpm_version":"2.0",
//     "identity_request_blob":[identityRequest blob],
//     "aik_modulus":[aikModulus blob],
//     "aik_blob":[aik blob],
//     "aik_name":[aikName blob]
//   },
//   "endorsement_certificate": [blob of endorsement certificate]
// }
type IdentityRequest struct {
	TpmVersion 				string `json:"tpm_version"`
	IdentityRequestBlock	[]byte `json:"identity_request_blob"`
	AikModulus				[]byte `json:"aik_modulus"`
	AikBlob					[]byte `json:"aik_blob"`
	AikName					[]byte `json:"aik_name"`
}

type IdentityChallengeRequest struct {
	IdentityRequest 			IdentityRequest `json:"identity_request"`
	EndorsementCertificate 		[]byte 			`json:"endorsement_certificate"`
}

// {
//   "identity_request":{
//     "tpm_version":"2.0",
//     "identity_request_blob":[identityRequest blob],
//     "aik_modulus":[aikModulus blob],
//     "aik_blob":[aik blob],
//     "aik_name":[aikName blob]
//   },
//   "response_to_challenge": [responseToChallenge blob ]
// }
type IdentityChallengeResponse struct {
	IdentityRequest 			IdentityRequest `json:"identity_request"`
	ResponseToChallenge 		[]byte 			`json:"response_to_challenge"`
}

// {
// 	           "secret"        :      "AAGB9Xr+ti6dsDSph9FqM1tOM8LLWLLhUhb89R6agQ/hA+eQDF2FpcfOM/98J95ywwYpxzYS8N
// 	                                   x6c7ud5e6SVVgLldcc3/m9xfsCC7tEmfQRyc+pydbgnCHQ9E/TQoyV/VgiE5ssV+lGX171+lN+
// 	                                   2RSO0HC8er+jN52bh31M4S09sv6+Qk2Fm2efDsF2NbFI4eyLcmtFEwKfDyAiZ3zeXqPNQWpUzV
// 	                                   ZzR3zfxpd6u6ZonYmfOn/fLDPIHwTFv8cYHSIRailTQXP+VmQuyR7YOI8oe/NC/cr7DIYTJD7G
// 	                                   LFNDXk+sybf9j9Ttng4RRyb0WXgIcfIWW1oZD+i4wqu9OdV1",
// 	           "credential"    :      "NAAAIBVuOfmXFbgcbBA2fLtnl38KQ7fIRGwUSf5kQ+UwIAw8ElXsYfoBoUB11BWKkc4uo9WRAA
// 	                                   AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
// 	                                   AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
// 	           "sym_blob"      :      "AAAAQAAAAAYAAQAAAAAAAMlZgTkKMlujW0vDUrhcE8Ixut12y5yXXP7nyx8wSUSHIaNz419fpy
// 	                                   AiQdsCG3PMJGvsNtiInB1zjGqQOtt77zM=",
// 	           "ek_blob"       :      "Tb3zQv6oW8/dUg45qofJFsIZV1XHTADZgeVjH7BI/ph+6ERJTlxBjK7zkxHJh54QlCi5h0f1rM
// 	                                   kYqtAyCmmyyUdewP4xFaVmjm8JcWaAzeOfb3vhamWr9xGecfJ34D58cy2Att7VAzXoWe2GthAb
// 	                                   lM+Rjsy9wiXfyOe9IjfC5jngjPHfwyi8IvV+FZHTG8wq7R8lcAQdurMmOzMZJT+vkzBq1TEGLu
// 	                                   rE3h4Rf84X3H/um4sQ2mqo+r5ZIsm+6lhb6PjU4S9Cp3j4RZ5nU/uVvgTWzviNUPYBbd3AypQo
// 	                                   9Kv5ij8UqHk2P1DzWjCBvwCqHTzRsuf9b9FeT+f4aWgLNQ=="
// 	}
type IdentityProofRequest struct {
	Secret						[]byte `json:"secret"`
	Credential					[]byte `json:"credential"`
	SymetricBlob				[]byte `json:"sym_blob"`
	EndorsementCertificateBlob	[]byte `json:"ek_blob"`
}

//-------------------------------------------------------------------------------------------------
// Implementation
//-------------------------------------------------------------------------------------------------

type privacyCAClientImpl struct {
	httpClient *http.Client
	cfg *VSClientConfig
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
		return nil, errors.Wrapf(err, "vsclient/privacy_ca_client:DownloadPrivacyCa() Error while sending request to %s ", url)
	} else {
		if response.StatusCode != http.StatusOK {
			return nil, errors.Errorf("vsclient/privacy_ca_client:DownloadPrivacyCa() Request sent to %s returned status %d", url, response.StatusCode)
		}

		ca, err = ioutil.ReadAll(response.Body)
		if err != nil {
			return nil, errors.Wrap(err,"vsclient/privacy_ca_client:DownloadPrivacyCa() Error reading response")
		}
	}

	return ca, nil
}

func (client *privacyCAClientImpl) GetIdentityProofRequest(identityChallengeRequest *IdentityChallengeRequest) (*IdentityProofRequest, error) {
	log.Trace("vsclient/privacy_ca_client:GetIdentityProofRequest() Entering")
	defer log.Trace("vsclient/privacy_ca_client:GetIdentityProofRequest() Leaving")

	var identityProofRequest IdentityProofRequest

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
		return nil, errors.Wrapf(err,"vsclient/privacy_ca_client:GetIdentityProofRequest() Error sending request to %s", url)
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

func (client *privacyCAClientImpl) GetIdentityProofResponse(identityChallengeResponse *IdentityChallengeResponse) (*IdentityProofRequest, error) {
	log.Trace("vsclient/privacy_ca_client:GetIdentityProofResponse() Entering")
	defer log.Trace("vsclient/privacy_ca_client:GetIdentityProofResponse() Leaving")

	var identityProofRequest IdentityProofRequest

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
