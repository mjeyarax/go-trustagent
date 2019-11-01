/*
* Copyright (C) 2019 Intel Corporation
* SPDX-License-Identifier: BSD-3-Clause
*/
package resource

import (
	"encoding/xml"
	"io/ioutil"
	"net/http"
	"strings"
	log "github.com/sirupsen/logrus"
	"intel/isecl/go-trust-agent/constants"
	"intel/isecl/lib/common/validation"
)

// The Manifest xml (below) is pretty extensive, this endpoint just needs the UUID and Label
// for validating the request body.
//
// <?xml version="1.0" encoding="UTF-8" standalone="yes"?>
// <Manifest xmlns="lib:wml:manifests:1.0" Label="ISecL_Default_Application_Flavor_v4.6_TPM2.0" Uuid="1fe1b7fc-99e6-4e7e-ba3d-d9aeeb03d227" DigestAlg="SHA384">
// <File Path="/opt/trustagent/.*" SearchType="regex"/>
// </Manifest>
type Manifest struct {
	UUID  string `xml:"Uuid,attr"`
	Label string `xml:"Label,attr"`
}

const (
	DEFAULT_APPLICATION_FLAVOR_PREFIX 	= "ISecL_Default_Application_Flavor_v"
    DEFAULT_WORKLOAD_FLAVOR_PREFIX 		= "ISecL_Default_Workload_Flavor_v"
)


func deployManifest(httpWriter http.ResponseWriter, httpRequest *http.Request) {

	log.Debugf("Request: %s", httpRequest.URL.Path)

	// receive a manifest from hvs in the request body
	manifestXml, err := ioutil.ReadAll(httpRequest.Body)
	if err != nil {
		log.Errorf("Deploy manifest: Error reading manifest xml: %s", err)
		httpWriter.WriteHeader(http.StatusBadRequest)
		return
	}

	// make sure the xml is well formed
	manifest := Manifest{}
	err = xml.Unmarshal(manifestXml, &manifest)
	if err != nil {
		log.Errorf("Deploy manifest: Invalid xml format: %s", err)
		httpWriter.WriteHeader(http.StatusBadRequest)
		return
	}

	err = validation.ValidateUUIDv4(manifest.UUID)
	if err != nil {
		log.Errorf("Deploy manifest: Invalid uuid %s", err)
		httpWriter.WriteHeader(http.StatusBadRequest)
		return
	}

	if len(manifest.Label) == 0 {
		log.Error("Deploy manifest: The manifest did not contain a label")
		httpWriter.WriteHeader(http.StatusBadRequest)
		return
	}

	if (strings.Contains(manifest.Label, DEFAULT_APPLICATION_FLAVOR_PREFIX) || 
		strings.Contains(manifest.Label, DEFAULT_WORKLOAD_FLAVOR_PREFIX)) {
		log.Errorf("Default flavor's manifest (%s) is part of installation, no need to deploy default flavor's manifest", manifest.Label)
		httpWriter.WriteHeader(http.StatusBadRequest)
		return
	}

	// establish the name of the manifest file and write the file
	manifestFile := constants.VarDir + "manifest_" + manifest.UUID + ".xml"
	err = ioutil.WriteFile(manifestFile, manifestXml, 0600)
	if err != nil {
		log.Errorf("Deploy manifest: Could not write manifest: %s", err)
		httpWriter.WriteHeader(http.StatusInternalServerError)
		return
	}

	httpWriter.WriteHeader(http.StatusOK)
}