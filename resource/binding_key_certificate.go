/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
 package resource

 import (
	"bytes"
	"io/ioutil"
	"net/http"
	"os"
	log "github.com/sirupsen/logrus"
	"intel/isecl/go-trust-agent/constants"
)

 // curl --request GET --user tagentadmin:TAgentAdminPassword https://localhost:1443/v2/binding-key-certificate -k --noproxy "*"
func getBindingKeyCertificate(httpWriter http.ResponseWriter, httpRequest *http.Request) {
	log.Trace("getBindingKeyCertificate")

	if _, err := os.Stat(constants.BindingKeyCertificatePath); os.IsNotExist(err) {
		log.Errorf("%s does not exist", constants.BindingKeyCertificatePath)
		httpWriter.WriteHeader(http.StatusInternalServerError)
		return
	}

	bindingKeyBytes, err := ioutil.ReadFile(constants.BindingKeyCertificatePath)
	if err != nil {
		log.Errorf("There was an error reading %s", constants.BindingKeyCertificatePath)
		httpWriter.WriteHeader(http.StatusInternalServerError)
		return
	}

	httpWriter.WriteHeader(http.StatusOK)
	_, _ = bytes.NewBuffer(bindingKeyBytes).WriteTo(httpWriter)
	return
}