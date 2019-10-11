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

// curl --request GET --user tagentadmin:TAgentAdminPassword https://localhost:1443/v2/aik -k --noproxy "*"
func getAik(httpWriter http.ResponseWriter, httpRequest *http.Request) {
	log.Debug("GetAik")

	if _, err := os.Stat(constants.AikCert); os.IsNotExist(err) {
		log.Errorf("%s does not exist", constants.AikCert)
		httpWriter.WriteHeader(http.StatusInternalServerError)
		return
	}

	aikBytes, err := ioutil.ReadFile(constants.AikCert)
	if err != nil {
		log.Errorf("There was an error reading %s", constants.AikCert)
		httpWriter.WriteHeader(http.StatusInternalServerError)
		return
	}

	httpWriter.WriteHeader(http.StatusOK)
	_, _ = bytes.NewBuffer(aikBytes).WriteTo(httpWriter)
	return
}