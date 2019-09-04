/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
 package resource

 import (
	"encoding/json"
	"net/http"
	"github.com/gorilla/mux"
	log "github.com/sirupsen/logrus"
	"intel/isecl/go-trust-agent/platforminfo"
)

func SetHostRoutes(router *mux.Router) {
	router.HandleFunc("/host", func(w http.ResponseWriter, r *http.Request) {
		GetPlatformInfo(w, r)
	}).Methods("GET")
}

// curl --request GET http://localhost:8446/v2/host -k --noproxy "*"
func GetPlatformInfo(httpWriter http.ResponseWriter, httpRequest *http.Request) {
	log.Info("GetPlatformInfo")

	platformInfo, err := platforminfo.GetPlatformInfo()
	if err != nil {
		httpWriter.WriteHeader(http.StatusInternalServerError)
	}

	json.NewEncoder(httpWriter).Encode(platformInfo)
	httpWriter.WriteHeader(http.StatusOK)
}