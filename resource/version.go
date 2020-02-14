/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package resource

import (
	"bytes"
	"encoding/json"
	"intel/isecl/go-trust-agent/util"
	"net/http"
	"intel/isecl/lib/common/log/message"
)

// GetVersion handles GET /version
func getVersion() endpointHandler {
	return func(httpWriter http.ResponseWriter, httpRequest *http.Request) error {
		log.Trace("resource/version:getVersion() Entering")
		defer log.Trace("resource/version:getVersion() Leaving")

		versionInfo, err := util.GetVersionInfo()
		if err != nil {
			log.Errorf("resource/version:getVersion() %s - There was an error retrieving version info: %s", message.AppRuntimeErr, err)
			return &endpointError{Message: "Unable to get version info", StatusCode: http.StatusInternalServerError}
		}

		// serialize to json
		jsonData, err := json.Marshal(versionInfo)
		if err != nil {
			log.Errorf("resource/version:getVersion() %s Error while serializing version info: %s", message.AppRuntimeErr, err)
			return &endpointError{Message: "Error while serializing version info", StatusCode: http.StatusInternalServerError}
		}

		log.Debugf("resource/version:getVersion() Trust Agent Version:\n %s", string(jsonData))

		httpWriter.Header().Set("Content-Type", "application/json")
		httpWriter.WriteHeader(http.StatusOK)
		_, _ = bytes.NewBuffer(jsonData).WriteTo(httpWriter)
		return nil
	}
}
