/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package vsclient

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	commonTls "intel/isecl/lib/common/tls"
	"intel/isecl/lib/common/validation"
	log "github.com/sirupsen/logrus"
)

//-------------------------------------------------------------------------------------------------
// Default VS Client factory that is used in vsclient::CreateDefaultVSClientFactory
//-------------------------------------------------------------------------------------------------

type defaultVSClientFactory struct {
	vsClientConfig *VSClientConfig
}

func (vsClientFactory *defaultVSClientFactory) NewVSClient() (VSClient, error) {
	tlsConfig := tls.Config{}
	if vsClientFactory.vsClientConfig.CertSha384 != nil {
		// set explicit verification
		tlsConfig.InsecureSkipVerify = true
		tlsConfig.VerifyPeerCertificate = commonTls.VerifyCertBySha384(*vsClientFactory.vsClientConfig.CertSha384)
	}

	transport := http.Transport{
		TLSClientConfig: &tlsConfig,
	}

	httpClient := &http.Client{Transport: &transport}

	vsClient := vsClientImpl {httpClient, vsClientFactory.vsClientConfig}
	return &vsClient, nil
}

//-------------------------------------------------------------------------------------------------
// Implementation of VSClient interface
//-------------------------------------------------------------------------------------------------

type vsClientImpl struct {
	httpClient *http.Client
	config *VSClientConfig
}


func (vsClient *vsClientImpl) SearchHosts(hostFilterCriteria *HostFilterCriteria) (*HostCollection, error) {

	hosts := HostCollection {}

	url := fmt.Sprintf("%s/hosts", vsClient.config.BaseURL)
	request, _:= http.NewRequest("GET", url, nil)
	request.SetBasicAuth(vsClient.config.Username, vsClient.config.Password)

	query := request.URL.Query()

	if len(hostFilterCriteria.Id) > 0 {
		query.Add("id", hostFilterCriteria.Id)
	}

	if len(hostFilterCriteria.NameEqualTo) > 0 {
		query.Add("nameEqualTo", hostFilterCriteria.NameEqualTo)
	}

	if len(hostFilterCriteria.NameContains) > 0 {
		query.Add("nameContains", hostFilterCriteria.NameContains)
	}

	if len(hostFilterCriteria.DescriptionContains) > 0 {
		query.Add("descriptionContains", hostFilterCriteria.DescriptionContains)
	}

	if len(query) == 0 {
		return nil, errors.New("At least filter parameter must be provided")
	}

	request.URL.RawQuery = query.Encode()

	response, err := vsClient.httpClient.Do(request)
    if err != nil {
        return nil, fmt.Errorf("%s request failed with error %s\n", url, err)
	}
	
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s returned status %d", url, response.StatusCode)
	}

	data, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return nil, fmt.Errorf("Error reading response: %s", err)
	}

	log.Infof("Results: %s", string(data))

	err = json.Unmarshal(data, &hosts)
	if err != nil {
		return nil, err
	}

	return &hosts, nil
}


//
// 
//  https://server.com:8443/mtwilson/v2/tls-policies
//
//  Input: 
//  {
//       "name":"vcenter1_shared_policy",
//       "descriptor":{
//           "policy_type":"certificate-digest",
//           "data":["d0 8f 07 b0 5c 6d 78 62 b9 27 48 ff 35 da 27 bf f2 03 b3 c1"],
//           "meta":{"digest_algorithm":"SHA-1"}
//       },
//       "private":false
//  }
// 
//  Output: 
//  {
//       "id":"3e75091f-4657-496c-a721-8a77931ee9da",
//       "name":"vcenter1_shared_policy",
//       "descriptor":{
//           "policy_type":"certificate-digest",
//           "data":["d0 8f 07 b0 5c 6d 78 62 b9 27 48 ff 35 da 27 bf f2 03 b3 c1"],
//           "meta":{"digest_algorithm":"SHA-1"}
//       },
//       "private":false
//  }
//
// func GetTlsPolicyFromVS() (TlsPolicy, error) {
// 	var tlsPolicy TlsPolicy
//
// 	return tlsPolicy, errors.New("GetHVsTlsPolicy not implemented")
// }


func (vsClient *vsClientImpl) CreateHost(hostCreateCriteria *HostCreateCriteria) (*Host, error) {

	var host Host

	jsonData, err := json.Marshal(hostCreateCriteria)
	if err != nil {
		return nil, err
	}

	log.Infof("json: %s", string(jsonData))

	url := fmt.Sprintf("%s/hosts", vsClient.config.BaseURL)
	request, _:= http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	request.Header.Set("Content-Type", "application/json")
	request.SetBasicAuth(vsClient.config.Username, vsClient.config.Password)

	response, err := vsClient.httpClient.Do(request)
    if err != nil {
        return nil, fmt.Errorf("%s request failed with error %s\n", url, err)
    }

	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s returned status %d", url, response.StatusCode)
	}

	data, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return nil, fmt.Errorf("Error reading response: %s", err)
	}

	err = json.Unmarshal(data, &host)
	if err != nil {
		return nil, err
	}

	return &host, nil
}

func (vsClient *vsClientImpl) UpdateHost(host *Host) (*Host, error) {

	var updatedHost Host

	err := validation.ValidateUUIDv4(host.Id)
	if err != nil {
		return nil, err
	}

	jsonData, err := json.Marshal(host)
	if err != nil {
		return nil, err
	}

	url := fmt.Sprintf("%s/hosts/%s", vsClient.config.BaseURL, host.Id)
	request, _:= http.NewRequest("PUT", url, bytes.NewBuffer(jsonData))
	request.SetBasicAuth(vsClient.config.Username, vsClient.config.Password)

	response, err := vsClient.httpClient.Do(request)
    if err != nil {
        return nil, fmt.Errorf("%s request failed with error %s\n", url, err)
    }

	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s returned status %d", url, response.StatusCode)
	}

	data, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return nil, fmt.Errorf("Error reading response: %s", err)
	}

	err = json.Unmarshal(data, &updatedHost)
	if err != nil {
		return nil, err
	}

	return &updatedHost, nil
}