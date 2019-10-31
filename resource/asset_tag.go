/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
 package resource

 import (
	"encoding/json"
	"io/ioutil"
	"net/http"
	log "github.com/sirupsen/logrus"
	"intel/isecl/go-trust-agent/config"
	"intel/isecl/lib/tpmprovider"
)

// json request format sent from HVS...
// { 
//		"tag"             : "tHgfRQED1+pYgEZpq3dZC9ONmBCZKdx10LErTZs1k/k=", 
//		"hardware_uuid"   : "7a569dad-2d82-49e4-9156-069b0065b262" 
//  }
type TagWriteRequest struct {
	Tag				[]byte		`json:"tag"`
	hardware_uuid	string		`json:"hardware_uuid"`
}

// 
// Provided the TagWriteRequest from, delete any existing tags, define/write
// tag to the TPM's nvram.  The receiving side of this equation is in 'quote.go'
// where the asset tag is used to hash the nonce and is also appended to the 
// quote xml.
//
func setAssetTag(httpWriter http.ResponseWriter, httpRequest *http.Request) {

	log.Debugf("Request: %s", httpRequest.URL.Path)

	var tagWriteRequest TagWriteRequest
	tpmSecretKey := config.GetConfiguration().Tpm.SecretKey

	data, err := ioutil.ReadAll(httpRequest.Body)
	if err != nil {
		log.Errorf("Error reading request body: %s", err)
		httpWriter.WriteHeader(http.StatusBadRequest)
		return
	}

	err = json.Unmarshal(data, &tagWriteRequest)
	if err != nil {
		log.Errorf("Error marshaling json data: %s...\n%s", err, string(data))
		httpWriter.WriteHeader(http.StatusBadRequest)
		return
	}

	tpm, err := tpmprovider.NewTpmProvider()
	if err != nil {
		log.Errorf("Error creating tpm provider: %s", err)
		return
	}

	defer tpm.Close()

	// check if an asset tag already exists and delete it if needed
	nvExists, err := tpm.NvIndexExists(tpmprovider.NV_IDX_ASSET_TAG)
	if err != nil {
		log.Errorf("Error checking if asset tag exists: %s", err)
		httpWriter.WriteHeader(http.StatusInternalServerError)
		return
	}

	if nvExists {
		err = tpm.NvRelease(tpmSecretKey, tpmprovider.NV_IDX_ASSET_TAG)
		if err != nil {
			log.Errorf("Could not release asset tag nvram: %s", err)
			httpWriter.WriteHeader(http.StatusInternalServerError)
			return
		}
	}

	// create an index for the data
	tpm.NvDefine(tpmSecretKey, tpmprovider.NV_IDX_ASSET_TAG, uint16(len(tagWriteRequest.Tag)))
	if err != nil {
		log.Errorf("Could not define tag nvram: %s", err)
		httpWriter.WriteHeader(http.StatusInternalServerError)
		return
	}

	// write the data
	err = tpm.NvWrite(tpmSecretKey, tpmprovider.NV_IDX_ASSET_TAG, tagWriteRequest.Tag)
	if err != nil {
		log.Errorf("Error writing asset tag: %s", err)
		return
	}

	httpWriter.WriteHeader(http.StatusOK)
	return
}