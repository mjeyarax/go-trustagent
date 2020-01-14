/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
 package vsclient

 import (
	 "common/log/message"
	 "fmt"
	 "io/ioutil"
	 "net/http"
	 "github.com/pkg/errors"
	 log "github.com/sirupsen/logrus"
 )

//-------------------------------------------------------------------------------------------------
// Public interface/structures
//-------------------------------------------------------------------------------------------------

type ManifestsClient interface {
	//
	// TODO:  Document fx 
	//
	GetManifestXmlById(manifestUUID string) ([]byte, error)

	//
	// TODO:  Document fx 
	//
	GetManifestXmlByLabel(manifestLabel string) ([]byte, error)
}

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

//-------------------------------------------------------------------------------------------------
// Implementation
//-------------------------------------------------------------------------------------------------

type manifestsClientImpl struct {
	httpClient *http.Client
	cfg *VSClientConfig
}

func (client * manifestsClientImpl) getManifestXml(params map[string]string) ([]byte, error) {
	log.Trace("vsclient/manifests_client:getManifestXml() Entering")
	defer log.Trace("vsclient/manifests_client:getManifestXml() Leaving")

	url := fmt.Sprintf("%s/manifests", client.cfg.BaseURL)
	request, _:= http.NewRequest("GET", url, nil)
	request.Header.Set("Authorization", "Bearer "+client.cfg.BearerToken)

	query := request.URL.Query()

	for key := range params {
		query.Add(key, params[key])
	}

	request.URL.RawQuery = query.Encode()

	log.Debugf("vsclient/manifests_client:getManifestXml() Request URL raw query %s", request.URL.RawQuery)

	response, err := client.httpClient.Do(request)
    if err != nil {
        return nil, errors.Wrapf(err,"vsclient/manifests_client:getManifestXml() Error while sending request to %s", url)
	}
	
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return nil, errors.Errorf("vsclient/manifests_client:getManifestXml() Request made to %s returned status %d", url, response.StatusCode)
	}

	xml, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return nil, fmt.Errorf("vsclient/manifests_client:getManifestXml() Error reading response: %s", err)
	}

	log.Debugf("vsclient/manifests_client:getManifestXml() returned xml response: %s", string(xml))

	return xml, nil
}

func (client *manifestsClientImpl) GetManifestXmlById(manifestUUID string) ([]byte, error) {
	log.Trace("vsclient/manifests_client:GetManifestXmlById() Entering")
	defer log.Trace("vsclient/manifests_client:GetManifestXmlById() Leaving")

	params := map[string]string{ "id" : manifestUUID, };
	return client.getManifestXml(params)
}

func (client *manifestsClientImpl) GetManifestXmlByLabel(manifestLabel string) ([]byte, error) {
	log.Trace("vsclient/manifests_client:GetManifestXmlByLabel() Entering")
	defer log.Trace("vsclient/manifests_client:GetManifestXmlByLabel() Leaving")

	params := map[string]string{ "key" : "label", "value" : manifestLabel };
	return client.getManifestXml(params)
}
