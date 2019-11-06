/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
 package vsclient

 import (
	 "fmt"
	 "io/ioutil"
	 "net/http"
	 "intel/isecl/lib/common/validation"
	 log "github.com/sirupsen/logrus"
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


type manifestsClientImpl struct {
	httpClient *http.Client
	config *VSClientConfig
}

func (manifestsClient * manifestsClientImpl) getManifestXml(params map[string]string) ([]byte, error) {

	url := fmt.Sprintf("%s/manifests", manifestsClient.config.BaseURL)
	request, _:= http.NewRequest("GET", url, nil)
	request.SetBasicAuth(manifestsClient.config.Username, manifestsClient.config.Password)

	query := request.URL.Query()

	for key := range params {
		query.Add(key, params[key])
	}

	request.URL.RawQuery = query.Encode()

	log.Debugf("GetManifestXml: %s", request.URL.RawQuery)

	response, err := manifestsClient.httpClient.Do(request)
    if err != nil {
        return nil, fmt.Errorf("%s request failed with error %s\n", url, err)
	}
	
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s returned status %d", url, response.StatusCode)
	}

	xml, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return nil, fmt.Errorf("Error reading response: %s", err)
	}

	log.Debugf("GetManifestXml returned xml: %s", string(xml))

	return xml, nil
}

func (manifestsClient *manifestsClientImpl) GetManifestXmlById(manifestUUID string) ([]byte, error) {

	err := validation.ValidateUUIDv4(manifestUUID)
	if err != nil {
		return nil, err
	}

	params := map[string]string{ "id" : manifestUUID, };
	return manifestsClient.getManifestXml(params)
}

func (manifestsClient *manifestsClientImpl) GetManifestXmlByLabel(manifestLabel string) ([]byte, error) {
	params := map[string]string{ "key" : "label", "value" : manifestLabel };
	return manifestsClient.getManifestXml(params)
}