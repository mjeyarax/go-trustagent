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

type FlavorsClient interface {

	//
	// TODO:  Document fx 
	//
	// KWT:  Does not return 'flavor' structure at this time (just json data)
	CreateFlavor(flavorCreateCriteria *FlavorCreateCriteria) ([]byte, error)
}

type FlavorCreateCriteria struct {
	ConnectionString string `json:"connection_string"`
	FlavorGroupName string `json:"flavor_group_name"`
	PartialFlavorTypes []string `json:"partial_flavor_types"`
	TlsPolicyId string `json:"tls_policy_id"`
}

//-------------------------------------------------------------------------------------------------
// Implementation
//-------------------------------------------------------------------------------------------------

type flavorsClientImpl struct {
	httpClient *http.Client
	cfg *VSClientConfig
}

func (client *flavorsClientImpl) CreateFlavor(flavorCreateCriteria *FlavorCreateCriteria) ([]byte, error) {

	jsonData, err := json.Marshal(flavorCreateCriteria)
	if err != nil {
		return nil, err
	}

	url := fmt.Sprintf("%s/flavors", client.cfg.BaseURL)
	request, _:= http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	request.Header.Set("Content-Type", "application/json")
	request.SetBasicAuth(client.cfg.Username, client.cfg.Password)

	log.Debugf("CreateFlavor: Posting to url %s, json: %s ", url, string(jsonData))

	response, err := client.httpClient.Do(request)
    if err != nil {
        return nil, fmt.Errorf("%s request failed with error %s\n", url, err)
    }

	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s returned status %d", url, response.StatusCode)
	}

	jsonData, err = ioutil.ReadAll(response.Body)
	if err != nil {
		return nil, fmt.Errorf("Error reading response: %s", err)
	}

	log.Debugf("CreateFlavor returned json: %s", string(jsonData))

	return jsonData, nil
}