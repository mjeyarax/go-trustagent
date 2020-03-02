/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package vsclient

import (
	"bytes"
	"encoding/json"
	"fmt"
	"intel/isecl/lib/common/validation"
	"intel/isecl/lib/common/log/message"
	"io/ioutil"
	"net/http"

	"github.com/pkg/errors"
)

//-------------------------------------------------------------------------------------------------
// Public interface/structures
//-------------------------------------------------------------------------------------------------

type HostsClient interface {

	//  Searches for the hosts with the specified criteria.
	//
	//  https://server.com:8181/mtwilson/v2/hosts?nameContains=192
	//
	//  Output: {"hosts":[{"id":"de07c08a-7fc6-4c07-be08-0ecb2f803681","name":"192.168.0.2", "connection_url":"https://192.168.0.1:443/sdk;admin;pwd",
	//  "bios_mle_uuid":"823a4ae6-b8cd-4c14-b89b-2a3be2d13985","vmm_mle_uuid":"45c03402-e33d-4b54-9893-de3bbd1f1681"}]}
	SearchHosts(hostFilterCriteria *HostFilterCriteria) (*HostCollection, error)

	// Registers the specified host with the Verfication Service.
	//
	// https://server.com:8181/mtwilson/v2/hosts/
	//
	// Input (HostCreateCriteria):
	// {
	// 	 "connection_string":"intel:https://0.0.0.0:1443;u=user;p=password",
	// 	 "host_name":"MyHost",
	// 	 "tls_policy_id":"TRUST_FIRST_CERTIFICATE"
	// }
	//
	// Output (Host):
	// {
	// 	  "id":"6208006d-1101-4ca6-8855-8542cfa3f66a",
	// 	  "host_name":"MyHost",
	// 	  "connection_string":"https://0.0.0.0:1443",
	// 	  "hardware_uuid":"8032632b-8fa4-e811-906e-00163566263e",
	// 	  "tls_policy_id":"TRUST_FIRST_CERTIFICATE",
	// 	  "flavorgroup_names":["automatic","platform_software"]
	// }
	CreateHost(hostCreateCriteria *HostCreateCriteria) (*Host, error)

	//  Updates the host with the specified attributes. Except for the host name, all other attributes can be updated.
	//
	//  https://server.com:8181/mtwilson/v2/hosts/e43424ca-9e00-4cb9-b038-9259d0307888
	//
	//  Input: {"name":"192.168.0.2","connection_url":"https://192.168.0.1:443/sdk;admin;pwd","bios_mle_uuid":"823a4ae6-b8cd-4c14-b89b-2a3be2d13985",
	//           "vmm_mle_uuid":"98101211-b617-4f59-8132-a5d05360acd6","tls_policy_id":"e1a527b5-2020-49c1-83be-6bd8bf641258"}
	//
	//  Output: {"id":"e43424ca-9e00-4cb9-b038-9259d0307888","name":"192.168.0.2",
	//           "connection_url":"https://192.168.0.1:443/sdk;admin;pwd","bios_mle_uuid":"823a4ae6-b8cd-4c14-b89b-2a3be2d13985",
	//           "vmm_mle_uuid":"98101211-b617-4f59-8132-a5d05360acd6","tls_policy_id":"e1a527b5-2020-49c1-83be-6bd8bf641258"}
	//UpdateHost(host *Host) (*Host, error)
}

// {
// 	"id": "068b5e88-1886-4ac2-a908-175cf723723d",
// 	"host_name": "10.105.167.153",
// 	"description": "GTA RHEL 8.0",
// 	"connection_string": "https://10.105.167.153:1443",
// 	"hardware_uuid": "8032632b-8fa4-e811-906e-00163566263e",
// 	"tls_policy_id": "e1a1c631-e006-4ff2-aed1-6b42a2f5be6c"
// }
type Host struct {
	Id               string `json:"id"`
	HostName         string `json:"host_name"`
	Description      string `json:"description"`
	ConnectionString string `json:"connection_string"`
	HardwareUUID     string `json:"hardware_uuid"`
	TlsPolicyId      string `json:"tls_policy_id"`
}

type HostCollection struct {
	Hosts []Host `json:"hosts"`
}

type HostCreateCriteria struct {
	ConnectionString string `json:"connection_string"`
	HostName         string `json:"host_name"`
	TlsPolicyId      string `json:"tls_policy_id"`
}

type HostFilterCriteria struct {
	Id                  string `json:"id"`
	NameEqualTo         string `json:"nameEqualTo"`
	NameContains        string `json:"nameContains"`
	DescriptionContains string `json:"descriptionContains"`
}

//-------------------------------------------------------------------------------------------------
// Implementation
//-------------------------------------------------------------------------------------------------

type hostsClientImpl struct {
	httpClient *http.Client
	cfg        *vsClientConfig
}

func (client *hostsClientImpl) SearchHosts(hostFilterCriteria *HostFilterCriteria) (*HostCollection, error) {
	log.Trace("vsclient/hosts_client:SearchHosts() Entering")
	defer log.Trace("vsclient/hosts_client:SearchHosts() Leaving")

	hosts := HostCollection{}

	url := fmt.Sprintf("%s/hosts", client.cfg.BaseURL)
	request, _ := http.NewRequest("GET", url, nil)
	request.Header.Set("Authorization", "Bearer "+client.cfg.BearerToken)

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
		return nil, errors.New("vsclient/hosts_client:SearchHosts() At least filter parameter must be provided")
	}

	request.URL.RawQuery = query.Encode()

	log.Debugf("SearchHosts: %s", request.URL.RawQuery)

	response, err := client.httpClient.Do(request)
        if err != nil {
		secLog.Warn(message.BadConnection)
        	return nil, errors.Wrapf(err, "vsclient/hosts_client:SearchHosts() Error making request to %s", url)
	}

	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return nil, errors.Errorf("vsclient/hosts_client:SearchHosts() Request made to %s returned status %d", url, response.StatusCode)
	}

	data, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return nil, errors.Wrapf(err, "vsclient/hosts_client:SearchHosts() Error reading response")
	}

	log.Debugf("vsclient/hosts_client:SearchHosts() SearchHosts returned json: %s", string(data))

	err = json.Unmarshal(data, &hosts)
	if err != nil {
		return nil, errors.Wrap(err, "vsclient/hosts_client:SearchHosts() Error while unmarshaling the response")
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

func (client *hostsClientImpl) CreateHost(hostCreateCriteria *HostCreateCriteria) (*Host, error) {
	log.Trace("vsclient/hosts_client:CreateHost() Entering")
	defer log.Trace("vsclient/hosts_client:CreateHost() Leaving")

	var host Host

	jsonData, err := json.Marshal(hostCreateCriteria)
	if err != nil {
		return nil, errors.Wrap(err, "vsclient/hosts_client:CreateHost() Error while marshalling hostcreate criteria")
	}

	url := fmt.Sprintf("%s/hosts", client.cfg.BaseURL)
	request, _ := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer "+ client.cfg.BearerToken)

	log.Debugf("vsclient/hosts_client:CreateHost() Sending Post request to url %s with json body: %s ", url, string(jsonData))

	response, err := client.httpClient.Do(request)
        if err != nil {
		secLog.Warn(message.BadConnection)
    		return nil, errors.Wrapf(err, "vsclient/hosts_client:CreateHost() Error while making request to %s ", url)
        }

	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return nil, errors.Errorf("vsclient/hosts_client:CreateHost() Request made to %s returned status %d", url, response.StatusCode)
	}

	data, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return nil, errors.Wrap(err, "vsclient/hosts_client:CreateHost() Error reading response ")
	}

	log.Debugf("vsclient/hosts_client:CreateHost() CreateHost returned json: %s", string(data))

	err = json.Unmarshal(data, &host)
	if err != nil {
		return nil, errors.Wrap(err, "vsclient/hosts_client:CreateHost() Error while unmarshalling the response body")
	}

	return &host, nil
}

//TODO Seems this function is not being used it can be cleaned  if not being used
func (client *hostsClientImpl) UpdateHost(host *Host) (*Host, error) {
	log.Trace("vsclient/hosts_client:UpdateHost() Entering")
	defer log.Trace("vsclient/hosts_client:UpdateHost() Leaving")

	var updatedHost Host

	err := validation.ValidateUUIDv4(host.Id)
	if err != nil {
		return nil, errors.Wrap(err, "vsclient/hosts_client:UpdateHost() Host id is not a valid uuid")
	}

	jsonData, err := json.Marshal(host)
	if err != nil {
		return nil, errors.Wrap(err, "vsclient/hosts_client:UpdateHost() Error while marshalling request body")
	}

	url := fmt.Sprintf("%s/hosts/%s", client.cfg.BaseURL, host.Id)
	request, _ := http.NewRequest("PUT", url, bytes.NewBuffer(jsonData))
	request.Header.Set("Authorization", "Bearer "+client.cfg.BearerToken)

	log.Debugf("vsclient/hosts_client:UpdateHost() Sending PUT request to url %s, json: %s ", url, string(jsonData))

	response, err := client.httpClient.Do(request)
	if err != nil {
		secLog.Warn(message.BadConnection)
        	return nil, errors.Wrapf(err,"vsclient/hosts_client:UpdateHost() Error while sending request to %s", url)
	}

	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return nil, errors.Errorf("vsclient/hosts_client:UpdateHost() Request made to %s returned status %d", url, response.StatusCode)
	}

	data, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return nil, errors.Wrap(err,"vsclient/hosts_client:UpdateHost() Error reading response ")
	}

	log.Debugf("vsclient/hosts_client:UpdateHost() UpdateHost returned json: %s", string(data))

	err = json.Unmarshal(data, &updatedHost)
	if err != nil {
		return nil, errors.Wrap(err, "vsclient/hosts_client:UpdateHost() Error while unmarshalling response body")
	}

	return &updatedHost, nil
}
