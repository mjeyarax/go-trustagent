/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
 package resource

 import (
	"net/http"
	"github.com/gorilla/mux"
	log "github.com/sirupsen/logrus"
)

func SetAikRoutes(router *mux.Router) {

	router.HandleFunc("/aik", func(w http.ResponseWriter, r *http.Request) {
		GetAik(w, r)
	}).Methods("GET")
}

// curl --request GET http://localhost:8450/trustagent/aik -k
func GetAik(httpWriter http.ResponseWriter, httpRequest *http.Request) {
	log.Info("GetAik")
	httpWriter.WriteHeader(http.StatusOK)
}