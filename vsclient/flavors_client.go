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

type FlavorCreateCriteria struct {
	ConnectionString string `json:"connection_string"`
	FlavorGroupName string `json:"flavor_group_name"`
	PartialFlavorTypes []string `json:"partial_flavor_types"`
	TlsPolicyId string `json:"tls_policy_id"`
}

type flavorsClientImpl struct {
	httpClient *http.Client
	config *VSClientConfig
}

func (flavorsClient *flavorsClientImpl) CreateFlavor(flavorCreateCriteria *FlavorCreateCriteria) error {

	jsonData, err := json.Marshal(flavorCreateCriteria)
	if err != nil {
		return err
	}

	url := fmt.Sprintf("%s/flavors", flavorsClient.config.BaseURL)
	request, _:= http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	request.Header.Set("Content-Type", "application/json")
	request.SetBasicAuth(flavorsClient.config.Username, flavorsClient.config.Password)

	log.Debugf("CreateFlavor: Posting to url %s, json: %s ", url, string(jsonData))

	response, err := flavorsClient.httpClient.Do(request)
    if err != nil {
        return fmt.Errorf("%s request failed with error %s\n", url, err)
    }

	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("%s returned status %d", url, response.StatusCode)
	}

	data, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return fmt.Errorf("Error reading response: %s", err)
	}

	log.Debugf("CreateFlavor returned json: %s", string(data))

	return nil
}