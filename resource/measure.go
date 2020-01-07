/*
* Copyright (C) 2019 Intel Corporation
* SPDX-License-Identifier: BSD-3-Clause
 */
package resource

import (
	"bytes"
	"encoding/xml"
	log "github.com/sirupsen/logrus"
	"intel/isecl/go-trust-agent/constants"
	"io/ioutil"
	"net/http"
	"os"
	"os/exec"
)

const WML_LOG_FILE = constants.LogDir + "wml.log"

// Uses /opt/tbootxml/bin/measure to measure the supplied manifest
func getApplicationMeasurement() endpointHandler {
	return func(httpWriter http.ResponseWriter, httpRequest *http.Request) error {

		log.Debugf("Request: %s", httpRequest.URL.Path)

		// receive a manifest from hvs in the request body
		manifestXml, err := ioutil.ReadAll(httpRequest.Body)
		if err != nil {
			log.Errorf("%s: Error reading manifest xml: %s", httpRequest.URL.Path, err)
			return &endpointError{Message: "Error reading manifest xml", StatusCode: http.StatusBadRequest}

		}

		// make sure the xml is well formed, all other validation will be
		// peformed by 'measure' cmd line below
		err = xml.Unmarshal(manifestXml, new(interface{}))
		if err != nil {
			log.Errorf("%s: Invalid xml format: %s", httpRequest.URL.Path, err)
			return &endpointError{Message: "Error: Invalid XML format", StatusCode: http.StatusBadRequest}
		}

		// this should probably be done in wml --> if the wml log file is not yet created,
		// 'measure' will fail.  for now, create the file before calling 'measure'.
		if _, err := os.Stat(WML_LOG_FILE); os.IsNotExist(err) {
			os.OpenFile(WML_LOG_FILE, os.O_RDONLY|os.O_CREATE, 0600)
		}

		// call /opt/tbootxml/bin/measure and return the xml from stdout
		// 'measure <manifestxml> /'
		cmd := exec.Command(constants.TBootXmMeasurePath, string(manifestXml), "/")
		cmd.Env = append(os.Environ(), "WML_LOG_FILE="+WML_LOG_FILE)

		stdout, err := cmd.StdoutPipe()
		if err != nil {
			log.Errorf("%s: Error getting measure output: %s", httpRequest.URL.Path, err)
			return &endpointError{Message: "Error processing request", StatusCode: http.StatusInternalServerError}
		}

		err = cmd.Start()
		if err != nil {
			log.Errorf("%s: %s failed to start: %s", httpRequest.URL.Path, constants.TBootXmMeasurePath, err)
			return &endpointError{Message: "Error processing request", StatusCode: http.StatusInternalServerError}

		}

		measureBytes, _ := ioutil.ReadAll(stdout)
		err = cmd.Wait()
		if err != nil {
			log.Errorf("%s: %s returned '%s': %s", httpRequest.URL.Path, constants.TBootXmMeasurePath, err, string(measureBytes))
			return &endpointError{Message: "Error processing request", StatusCode: http.StatusInternalServerError}
		}

		// make sure we got valid xml from measure
		err = xml.Unmarshal(measureBytes, new(interface{}))
		if err != nil {
			log.Errorf("%s: Invalid measurement xml: %s", httpRequest.URL.Path, err)
			log.Errorf("%s: %s", httpRequest.URL.Path, string(measureBytes))
			return &endpointError{Message: "Error processing request", StatusCode: http.StatusInternalServerError}
		}

		httpWriter.WriteHeader(http.StatusOK)
		_, _ = bytes.NewBuffer(measureBytes).WriteTo(httpWriter)
		return nil
	}
}
