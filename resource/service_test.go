// XXXXbuild integration

/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package resource

import (
	"bytes"
	"encoding/json"
	"fmt"
	"testing"
	"net/http"
	"net/http/httptest"
	"github.com/stretchr/testify/assert"
	"intel/isecl/go-trust-agent/config"
)

const (
	TestUser		= "test"
	TestPassword	= "test"
)

func TestAik(t *testing.T) {
	assert := assert.New(t)

	config.GetConfiguration().TrustAgentService.Username = TestUser
	config.GetConfiguration().TrustAgentService.Password = TestPassword
	trustAgentService, err := CreateTrustAgentService(8450)
	assert.NoError(err)

	request, err := http.NewRequest("GET", "/v2/aik", nil)
	assert.NoError(err)

	request.SetBasicAuth(TestUser, TestPassword)

	recorder := httptest.NewRecorder()
	trustAgentService.router.ServeHTTP(recorder, request)
	response := recorder.Result()
	fmt.Printf("StatusCode: %d\n", response.StatusCode)
	assert.Equal(response.StatusCode, http.StatusOK)
}

func TestQuoteService(t *testing.T) {
	assert := assert.New(t)

	config.GetConfiguration().TrustAgentService.Username = TestUser
	config.GetConfiguration().TrustAgentService.Password = TestPassword
	trustAgentService, err := CreateTrustAgentService(8450)
	assert.NoError(err)

	tpmQuoteRequest := TpmQuoteRequest {
		Nonce:    []byte {1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,7,8,9,0},
		Pcrs: 	  []int {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23},
		PcrBanks: []string {"SHA1", "SHA256"},
	}

	jsonData, err := json.Marshal(&tpmQuoteRequest)
	assert.NoError(err)
	fmt.Printf("json: %s", jsonData)

	jsonString := "{ \"nonce\":\"VfZ5QjqFfD2yajuuxLcKrzKa7IE=\", \"pcrs\": [0,1,2,3,18,19,22] , \"pcrbanks\" : [\"SHA1\", \"SHA256\"]}"

	request, err := http.NewRequest("POST", "/v2/tpm/quote", bytes.NewBuffer([]byte(jsonString)))
//	request, err := http.NewRequest("POST", "/v2/tpm/quote", bytes.NewBuffer(jsonData))
	assert.NoError(err)

	request.Header.Set("Content-Type", "application/json")
	request.SetBasicAuth(TestUser, TestPassword)

	recorder := httptest.NewRecorder()
	trustAgentService.router.ServeHTTP(recorder, request)
	response := recorder.Result()
	fmt.Printf("StatusCode: %d\n", response.StatusCode)
	assert.Equal(response.StatusCode, http.StatusOK)
}