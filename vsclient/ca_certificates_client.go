/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package vsclient

import (
	"intel/isecl/lib/common/setup"
	"fmt"
	"github.com/pkg/errors"
	"intel/isecl/go-trust-agent/constants"
	"io/ioutil"
	"net/http"
	"os"
)

//-------------------------------------------------------------------------------------------------
// Public interface/structures
//-------------------------------------------------------------------------------------------------

type CACertificatesClient interface {
	DownloadEndorsementAuthorities() ([]byte, error)
}

//-------------------------------------------------------------------------------------------------
// Implementation
//-------------------------------------------------------------------------------------------------

type caCertificatesClientImpl struct {
	httpClient *http.Client
	cfg *VSClientConfig
}

var context setup.Context

func (client *caCertificatesClientImpl) DownloadEndorsementAuthorities() ([]byte, error) {

	var ea []byte

	url := fmt.Sprintf("%s/ca-certificates?domain=ek", client.cfg.BaseURL)
	request, _ := http.NewRequest("GET", url, nil)
	jwtToken, err := context.GetenvString(constants.BearerTokenEnv)
	if jwtToken == "" || err != nil {
		fmt.Fprintln(os.Stderr, "BEARER_TOKEN is not defined in environment")
		return nil, errors.Wrap(err, "BEARER_TOKEN is not defined in environment")
	}
	request.Header.Set("Authorization", "Bearer "+ jwtToken)
	response, err := client.httpClient.Do(request)
	if err != nil {
		return nil, fmt.Errorf("%s request failed with error %s\n", url, err)
	} else {
		if response.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("%s returned status %d", url, response.StatusCode)
		}

		ea, err = ioutil.ReadAll(response.Body)
		if err != nil {
			return nil, fmt.Errorf("Error reading response: %s", err)
		}
	}

	return ea, nil
}

