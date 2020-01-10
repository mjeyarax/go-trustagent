/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package vsclient

import (
	"fmt"
	"intel/isecl/lib/common/setup"
	commLog "intel/isecl/lib/common/log"
	"io/ioutil"
	"net/http"
)

var log = commLog.GetDefaultLogger()
var secLog = commLog.GetSecurityLogger()

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
	cfg        *VSClientConfig
}

var context setup.Context

func (client *caCertificatesClientImpl) DownloadEndorsementAuthorities() ([]byte, error) {
	log.Trace("vsclient/ca_certificates_client:DownloadEndorsementAuthorities() Entering")
	defer log.Trace("vsclient/ca_certificates_client:DownloadEndorsementAuthorities() Leaving")

	var ea []byte

	url := fmt.Sprintf("%s/ca-certificates?domain=ek", client.cfg.BaseURL)
	request, _ := http.NewRequest("GET", url, nil)
	request.Header.Set("Authorization", "Bearer "+client.cfg.BearerToken)
	response, err := client.httpClient.Do(request)
	if err != nil {
		return nil, errors.Wrapf(err,"vsclient/ca_certificates_client:DownloadEndorsementAuthorities() Error sending request", err)
	} else {
		if response.StatusCode != http.StatusOK {
			return nil, errors.Errorf("vsclient/ca_certificates_client:DownloadEndorsementAuthorities() Request made to %s returned status %d", url, response.StatusCode)
		}

		ea, err = ioutil.ReadAll(response.Body)
		if err != nil {
			return nil, errors.Errorf(err, "vsclient/ca_certificates_client:DownloadEndorsementAuthorities() Error reading response")
		}
	}

	return ea, nil
}
