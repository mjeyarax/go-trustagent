/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
 package vsclient

 import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"intel/isecl/lib/common/validation"
	log "github.com/sirupsen/logrus"
 )

//-------------------------------------------------------------------------------------------------
// Public structures for Hosts
//-------------------------------------------------------------------------------------------------

// {
// 	"id": "068b5e88-1886-4ac2-a908-175cf723723d",
// 	"host_name": "10.105.167.153",
// 	"description": "GTA RHEL 8.0",
// 	"connection_string": "https://10.105.167.153:1443",
// 	"hardware_uuid": "8032632b-8fa4-e811-906e-00163566263e",
// 	"tls_policy_id": "e1a1c631-e006-4ff2-aed1-6b42a2f5be6c"
// }
type Host struct {
	Id string `json:"id"`
	HostName string `json:"host_name"`
	Description string `json:"description"`
	ConnectionString string `json:"connection_string"`
	HardwareUUID string `json:"hardware_uuid"`
	TlsPolicyId string `json:"tls_policy_id"`
}

type HostCollection struct {
	Hosts []Host `json:"hosts"`
}

type HostCreateCriteria struct {
	ConnectionString string `json:"connection_string"`
	HostName string `json:"host_name"`
	TlsPolicyId string `json:"tls_policy_id"`
}

type HostFilterCriteria struct {
	Id string `json:"id"`
	NameEqualTo string `json:"nameEqualTo"`
	NameContains string `json:"nameContains"`
	DescriptionContains string `json:"descriptionContains"`
}

//-------------------------------------------------------------------------------------------------
// Private implementation of HostClient
//-------------------------------------------------------------------------------------------------

 
type hostsClientImpl struct {
	 httpClient *http.Client
	 config *VSClientConfig
}


func (hostsClient *hostsClientImpl) SearchHosts(hostFilterCriteria *HostFilterCriteria) (*HostCollection, error) {

	hosts := HostCollection {}

	url := fmt.Sprintf("%s/hosts", hostsClient.config.BaseURL)
	request, _:= http.NewRequest("GET", url, nil)
	request.SetBasicAuth(hostsClient.config.Username, hostsClient.config.Password)

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

	log.Debugf("SearchHosts: %s", request.URL.RawQuery)

	response, err := hostsClient.httpClient.Do(request)
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

	log.Debugf("SearchHosts returned json: %s", string(data))

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


func (hostsClient *hostsClientImpl) CreateHost(hostCreateCriteria *HostCreateCriteria) (*Host, error) {

	var host Host

	jsonData, err := json.Marshal(hostCreateCriteria)
	if err != nil {
		return nil, err
	}


	url := fmt.Sprintf("%s/hosts", hostsClient.config.BaseURL)
	request, _:= http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	request.Header.Set("Content-Type", "application/json")
	request.SetBasicAuth(hostsClient.config.Username, hostsClient.config.Password)

	log.Debugf("CreateHost: Posting to url %s, json: %s ", url, string(jsonData))

	response, err := hostsClient.httpClient.Do(request)
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

	log.Debugf("CreateHost returned json: %s", string(data))

	err = json.Unmarshal(data, &host)
	if err != nil {
		return nil, err
	}

	return &host, nil
}

func (hostsClient *hostsClientImpl) UpdateHost(host *Host) (*Host, error) {

	var updatedHost Host

	err := validation.ValidateUUIDv4(host.Id)
	if err != nil {
		return nil, err
	}

	jsonData, err := json.Marshal(host)
	if err != nil {
		return nil, err
	}

	url := fmt.Sprintf("%s/hosts/%s", hostsClient.config.BaseURL, host.Id)
	request, _:= http.NewRequest("PUT", url, bytes.NewBuffer(jsonData))
	request.SetBasicAuth(hostsClient.config.Username, hostsClient.config.Password)

	log.Debugf("CreateHost: Posting to url %s, json: %s ", url, string(jsonData))

	response, err := hostsClient.httpClient.Do(request)
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

	log.Debugf("UpdateHost returned json: %s", string(data))

	err = json.Unmarshal(data, &updatedHost)
	if err != nil {
		return nil, err
	}

	return &updatedHost, nil
}