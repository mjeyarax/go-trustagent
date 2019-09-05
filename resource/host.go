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

	"github.com/gorilla/mux"
	log "github.com/sirupsen/logrus"

	"intel/isecl/go-trust-agent/constants"
)

func SetHostRoutes(router *mux.Router) {
	router.HandleFunc("/host", func(w http.ResponseWriter, r *http.Request) {
		GetPlatformInfo(w, r)
	}).Methods("GET")
}

// curl --request GET http://localhost:1443/v2/host -k --noproxy "*"

// Assuming that the /opt/trustagent/var/system-info/platform-info file has been create
// during startup, just read the contents of the json file and return it to the http
// writer
func GetPlatformInfo(httpWriter http.ResponseWriter, httpRequest *http.Request) {
	log.Info("GetPlatformInfo")

	if _, err := os.Stat(constants.PlatformInfoFilePath); os.IsNotExist(err) {
		log.Errorf("%s does not exist", constants.PlatformInfoFilePath)
		httpWriter.WriteHeader(http.StatusInternalServerError)
		return
	}

	b, err := ioutil.ReadFile(constants.PlatformInfoFilePath)
	if err != nil {
		log.Errorf("There was an error reading %s", constants.PlatformInfoFilePath)
		httpWriter.WriteHeader(http.StatusInternalServerError)
		return
	}

	if _, err := bytes.NewBuffer(b).WriteTo(httpWriter); err != nil {
		log.Errorf("There was an error writing platform-info")
		httpWriter.WriteHeader(http.StatusInternalServerError)
		return
	}

	httpWriter.WriteHeader(http.StatusOK)
}