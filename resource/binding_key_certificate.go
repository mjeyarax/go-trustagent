/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package resource

import (
	"bytes"
	log "github.com/sirupsen/logrus"
	"intel/isecl/go-trust-agent/constants"
	"io/ioutil"
	"net/http"
	"os"
)

// Returns the WLA provisioned binding key certificate from /etc/workload-agent/bindingkey.pem
//
// Ex. curl --request GET --user tagentadmin:TAgentAdminPassword https://localhost:1443/v2/binding-key-certificate -k --noproxy "*"
func getBindingKeyCertificate() endpointHandler {
	return func(httpWriter http.ResponseWriter, httpRequest *http.Request) error {
		log.Trace("resource/asset_tag:setAssetTag() Entering")
		defer log.Trace("resource/asset_tag:setAssetTag() Leaving")

		log.Debugf("resource/binding_key_certificate:getBindingKeyCertificate() Request: %s", httpRequest.URL.Path)

		if _, err := os.Stat(constants.BindingKeyCertificatePath); os.IsNotExist(err) {
			log.WithError(err).Errorf("resource/binding_key_certificate:getBindingKeyCertificate() %s does not exist", constants.BindingKeyCertificatePath)
			return &endpointError{Message: "Error processing request", StatusCode: http.StatusInternalServerError}
		}

		bindingKeyBytes, err := ioutil.ReadFile(constants.BindingKeyCertificatePath)
		if err != nil {
			log.Errorf("resource/binding_key_certificate:getBindingKeyCertificate() Error reading %s", constants.BindingKeyCertificatePath)
			return &endpointError{Message: "Error processing request", StatusCode: http.StatusInternalServerError}

		}

		httpWriter.WriteHeader(http.StatusOK)
		_, _ = bytes.NewBuffer(bindingKeyBytes).WriteTo(httpWriter)
		return nil
	}
}
