/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
 package resource

 import (
	"net/http"
	log "github.com/sirupsen/logrus"
)

// curl --request GET --user user:pass https://localhost:1443/v2/aik -k --noproxy "*"
func GetAik(httpWriter http.ResponseWriter, httpRequest *http.Request) {
	log.Info("GetAik")
	httpWriter.WriteHeader(http.StatusOK)
}