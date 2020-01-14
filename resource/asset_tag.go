/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package resource

import (
	"encoding/json"
	"intel/isecl/go-trust-agent/config"
	"intel/isecl/lib/tpmprovider"
	"io/ioutil"
	"net/http"

	log "github.com/sirupsen/logrus"
)

// json request format sent from HVS...
// {
//		"tag"             : "tHgfRQED1+pYgEZpq3dZC9ONmBCZKdx10LErTZs1k/k=",
//		"hardware_uuid"   : "7a569dad-2d82-49e4-9156-069b0065b262"
//  }
type TagWriteRequest struct {
	Tag           []byte `json:"tag"`
	hardware_uuid string `json:"hardware_uuid"`
}

//
// Provided the TagWriteRequest from, delete any existing tags, define/write
// tag to the TPM's nvram.  The receiving side of this equation is in 'quote.go'
// where the asset tag is used to hash the nonce and is also appended to the
// quote xml.
//
func setAssetTag(cfg *config.TrustAgentConfiguration, tpmFactory tpmprovider.TpmFactory) endpointHandler {
	return func(httpWriter http.ResponseWriter, httpRequest *http.Request) error {
		log.Trace("resource/asset_tag:setAssetTag() Entering")
		defer log.Trace("resource/asset_tag:setAssetTag() Leaving")

		log.Debugf("resource/asset_tag:setAssetTag() Request: %s", httpRequest.URL.Path)

		var tagWriteRequest TagWriteRequest
		tpmSecretKey := cfg.Tpm.OwnerSecretKey

		data, err := ioutil.ReadAll(httpRequest.Body)
		if err != nil {
			log.WithError(err).Errorf("resource/asset_tag:setAssetTag() Error reading request body for request: %s", httpRequest.URL.Path)
			return &endpointError{Message: "Error parsing request", StatusCode: http.StatusBadRequest}
		}

		err = json.Unmarshal(data, &tagWriteRequest)
		if err != nil {
			log.WithError(err).Errorf("resource/asset_tag:setAssetTag() Error marshaling json data: %s for request: %s", string(data), httpRequest.URL.Path)
			return &endpointError{Message: "Error processing request", StatusCode: http.StatusBadRequest}
		}

		tpm, err := tpmFactory.NewTpmProvider()
		if err != nil {
			log.WithError(err).Error("resource/asset_tag:setAssetTag() Error creating tpm provider")
			return &endpointError{Message: "Error processing request", StatusCode: http.StatusInternalServerError}
		}

		defer tpm.Close()

		// check if an asset tag already exists and delete it if needed
		nvExists, err := tpm.NvIndexExists(tpmprovider.NV_IDX_ASSET_TAG)
		if err != nil {
			log.WithError(err).Errorf("resource/asset_tag:setAssetTag() Error checking if asset tag exists")
			return &endpointError{Message: "Error processing request", StatusCode: http.StatusInternalServerError}
		}

		if nvExists {
			err = tpm.NvRelease(tpmSecretKey, tpmprovider.NV_IDX_ASSET_TAG)
			if err != nil {
				log.WithError(err).Errorf("resource/asset_tag:setAssetTag() Could not release asset tag nvram")
				return &endpointError{Message: "Error processing request", StatusCode: http.StatusInternalServerError}
			}
		}

		// create an index for the data
		err = tpm.NvDefine(tpmSecretKey, tpmprovider.NV_IDX_ASSET_TAG, uint16(len(tagWriteRequest.Tag)))
		if err != nil {
			log.Errorf("resource/asset_tag:setAssetTag() Could not define tag nvram")
			return &endpointError{Message: "Error processing request", StatusCode: http.StatusInternalServerError}
		}

		// write the data
		err = tpm.NvWrite(tpmSecretKey, tpmprovider.NV_IDX_ASSET_TAG, tagWriteRequest.Tag)
		if err != nil {
			log.WithError(err).Error("resource/asset_tag:setAssetTag() Error writing asset tag")
			return &endpointError{Message: "Error processing request", StatusCode: http.StatusInternalServerError}
		}

		httpWriter.WriteHeader(http.StatusOK)
		return nil
	}
}
