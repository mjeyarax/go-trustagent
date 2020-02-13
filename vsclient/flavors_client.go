/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package vsclient

import (
	"bytes"
	"encoding/json"
	"fmt"
	"intel/isecl/lib/common/log/message"
	"io/ioutil"
	"net/http"

	"github.com/pkg/errors"
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
	ConnectionString   string   `json:"connection_string"`
	FlavorGroupName    string   `json:"flavor_group_name"`
	PartialFlavorTypes []string `json:"partial_flavor_types"`
	TlsPolicyId        string   `json:"tls_policy_id"`
}

//-------------------------------------------------------------------------------------------------
// Implementation
//-------------------------------------------------------------------------------------------------

type flavorsClientImpl struct {
	httpClient *http.Client
	cfg        *vsClientConfig
}

func (client *flavorsClientImpl) CreateFlavor(flavorCreateCriteria *FlavorCreateCriteria) ([]byte, error) {
	log.Trace("vsclient/flavors_client:CreateFlavor() Entering")
	defer log.Trace("vsclient/flavors_client:CreateFlavor() Leaving")

	jsonData, err := json.Marshal(flavorCreateCriteria)
	if err != nil {
		return nil, err
	}

	url := fmt.Sprintf("%s/flavors", client.cfg.BaseURL)
	request, _ := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer " + client.cfg.BearerToken)

	log.Debugf("vsclient/flavors_client:CreateFlavor() Posting to url %s, json: %s ", url, string(jsonData))

	response, err := client.httpClient.Do(request)
	if err != nil {
		secLog.Warn(message.BadConnection)
		return nil, errors.Wrapf(err, "vsclient/flavors_client:CreateFlavor() Error while making request to %s", url)
	}

	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return nil, errors.Errorf("vsclient/flavors_client:CreateFlavor() request made to %s returned status %d", url, response.StatusCode)
	}

	jsonData, err = ioutil.ReadAll(response.Body)
	if err != nil {
		return nil, errors.Errorf("vsclient/flavors_client:CreateFlavor() Error reading response")
	}

	log.Debugf("vsclient/flavors_client:CreateFlavor() Json response body returned: %s", string(jsonData))

	return jsonData, nil
}
