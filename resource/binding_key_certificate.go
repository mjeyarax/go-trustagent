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
func getBindingKeyCertificate(httpWriter http.ResponseWriter, httpRequest *http.Request) {

	log.Debugf("Request: %s", httpRequest.URL.Path)

	if _, err := os.Stat(constants.BindingKeyCertificatePath); os.IsNotExist(err) {
		log.Errorf("%s: %s does not exist", httpRequest.URL.Path, constants.BindingKeyCertificatePath)
		httpWriter.WriteHeader(http.StatusInternalServerError)
		return
	}

	bindingKeyBytes, err := ioutil.ReadFile(constants.BindingKeyCertificatePath)
	if err != nil {
		log.Errorf("%s: There was an error reading %s", httpRequest.URL.Path, constants.BindingKeyCertificatePath)
		httpWriter.WriteHeader(http.StatusInternalServerError)
		return
	}

	httpWriter.WriteHeader(http.StatusOK)
	_, _ = bytes.NewBuffer(bindingKeyBytes).WriteTo(httpWriter)
	return
}
