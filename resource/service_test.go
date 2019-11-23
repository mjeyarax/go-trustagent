// +build unit_test

/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package resource

import (
	"bytes"
	//	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	//	"strings"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"intel/isecl/go-trust-agent/config"
	"intel/isecl/lib/tpmprovider"

	log "github.com/sirupsen/logrus"
)

const (
	TestUser     = "test"
	TestPassword = "test"
	TpmSecretKey = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
	TestPort     = 8450
)

func CreateTestConfig() *config.TrustAgentConfiguration {

	cfg := config.TrustAgentConfiguration{}
	cfg.LogLevel = log.TraceLevel
	cfg.TrustAgentService.Port = TestPort
	cfg.TrustAgentService.Username = TestUser
	cfg.TrustAgentService.Password = TestPassword
	cfg.Tpm.OwnerSecretKey = TpmSecretKey

	return &cfg
}

// func TestAik(t *testing.T) {
// 	assert := assert.New(t)

// 	mockedTpmProvider := new(tpmprovider.MockedTpmProvider)
// 	mockedTpmProvider.On("Version", mock.Anything).Return(tpmprovider.V20)
// 	mockedTpmFactory := tpmprovider.MockedTpmFactory{TpmProvider : mockedTpmProvider}

// 	trustAgentService, err := CreateTrustAgentService(CreateTestConfig(), mockedTpmFactory)
// 	assert.NoError(err)

// 	request, err := http.NewRequest("GET", "/v2/aik", nil)
// 	assert.NoError(err)

// 	request.SetBasicAuth(TestUser, TestPassword)

// 	recorder := httptest.NewRecorder()
// 	trustAgentService.router.ServeHTTP(recorder, request)
// 	response := recorder.Result()
// 	fmt.Printf("StatusCode: %d\n", response.StatusCode)
// 	assert.Equal(response.StatusCode, http.StatusOK)
// }

// func TestQuoteService(t *testing.T) {
// 	assert := assert.New(t)

// 	mockedTpmProvider := new(tpmprovider.MockedTpmProvider)
// 	mockedTpmProvider.On("Version", mock.Anything).Return(tpmprovider.V20)
// 	mockedTpmFactory := tpmprovider.MockedTpmFactory{TpmProvider : mockedTpmProvider}

// 	trustAgentService, err := CreateTrustAgentService(CreateTestConfig(), mockedTpmFactory)
// 	assert.NoError(err)

// 	jsonString := "{ \"nonce\":\"VfZ5QjqFfD2yajuuxLcKrzKa7IE=\", \"pcrs\": [0,1,2,3,18,19,22] , \"pcrbanks\" : [\"SHA1\", \"SHA256\"]}"

// 	request, err := http.NewRequest("POST", "/v2/tpm/quote", bytes.NewBuffer([]byte(jsonString)))
// 	assert.NoError(err)

// 	request.Header.Set("Content-Type", "application/json")
// 	request.SetBasicAuth(TestUser, TestPassword)

// 	recorder := httptest.NewRecorder()
// 	trustAgentService.router.ServeHTTP(recorder, request)
// 	response := recorder.Result()
// 	fmt.Printf("StatusCode: %d\n", response.StatusCode)
// 	assert.Equal(response.StatusCode, http.StatusOK)
// }

func TestAssetTagServiceNoExistingTags(t *testing.T) {
	assert := assert.New(t)

	mockedTpmProvider := new(tpmprovider.MockedTpmProvider)
	mockedTpmProvider.On("Close").Return(nil)
	mockedTpmProvider.On("NvIndexExists", mock.Anything).Return(false, nil)
	mockedTpmProvider.On("NvRelease", mock.Anything, mock.Anything).Return(nil)
	mockedTpmProvider.On("NvDefine", mock.Anything, mock.Anything, mock.Anything).Return(nil)
	mockedTpmProvider.On("NvWrite", mock.Anything, mock.Anything, mock.Anything).Return(nil)

	mockedTpmFactory := tpmprovider.MockedTpmFactory{TpmProvider: mockedTpmProvider}

	trustAgentService, err := CreateTrustAgentService(CreateTestConfig(), mockedTpmFactory)
	assert.NoError(err)

	jsonString := `{"tag" : "tHgfRQED1+pYgEZpq3dZC9ONmBCZKdx10LErTZs1k/k=", "hardware_uuid" : "7a569dad-2d82-49e4-9156-069b0065b262"}`

	request, err := http.NewRequest("POST", "/v2/tag", bytes.NewBuffer([]byte(jsonString)))
	assert.NoError(err)

	request.Header.Set("Content-Type", "application/json")
	request.SetBasicAuth(TestUser, TestPassword)

	recorder := httptest.NewRecorder()
	trustAgentService.router.ServeHTTP(recorder, request)
	response := recorder.Result()
	fmt.Printf("StatusCode: %d\n", response.StatusCode)
	assert.Equal(response.StatusCode, http.StatusOK)
}

func TestAssetTagServiceExistingTags(t *testing.T) {
	assert := assert.New(t)

	mockedTpmProvider := new(tpmprovider.MockedTpmProvider)
	mockedTpmProvider.On("Close").Return(nil)
	mockedTpmProvider.On("NvIndexExists", mock.Anything).Return(true, nil)
	mockedTpmProvider.On("NvRelease", mock.Anything, mock.Anything).Return(nil)
	mockedTpmProvider.On("NvDefine", mock.Anything, mock.Anything, mock.Anything).Return(nil)
	mockedTpmProvider.On("NvWrite", mock.Anything, mock.Anything, mock.Anything).Return(nil)

	mockedTpmFactory := tpmprovider.MockedTpmFactory{TpmProvider: mockedTpmProvider}

	trustAgentService, err := CreateTrustAgentService(CreateTestConfig(), mockedTpmFactory)
	assert.NoError(err)

	jsonString := `{"tag" : "tHgfRQED1+pYgEZpq3dZC9ONmBCZKdx10LErTZs1k/k=", "hardware_uuid" : "7a569dad-2d82-49e4-9156-069b0065b262"}`

	request, err := http.NewRequest("POST", "/v2/tag", bytes.NewBuffer([]byte(jsonString)))
	assert.NoError(err)

	request.Header.Set("Content-Type", "application/json")
	request.SetBasicAuth(TestUser, TestPassword)

	recorder := httptest.NewRecorder()
	trustAgentService.router.ServeHTTP(recorder, request)
	response := recorder.Result()
	fmt.Printf("StatusCode: %d\n", response.StatusCode)
	assert.Equal(response.StatusCode, http.StatusOK)
}

// func TestLocalIpAddress(t *testing.T) {
// 	assert := assert.New(t)

// 	ipString,err := util.GetLocalIpAsString()
// 	assert.NoError(err)

// 	// not local ip address or private address
// 	assert.False(strings.HasPrefix(ipString, "127"))
// 	assert.False(strings.HasPrefix(ipString, "192"))
// 	assert.Equal(strings.Index(ipString, "/"), -1)	// does not have /24 or /16

// 	fmt.Printf("Local ip string %s\n", ipString)

// 	ipBytes,err := util.GetLocalIpAsBytes()
// 	assert.NoError(err)
// 	assert.Equal(len(ipBytes), 4)

// 	fmt.Printf("Local ip bytes: %s\n", hex.EncodeToString(ipBytes))
// }

// func TestApplicationMeasurement(t *testing.T) {
// 	assert := assert.New(t)

// 	config.InitConfiguration()
// 	config.GetConfiguration().TrustAgentService.Username = TestUser
// 	config.GetConfiguration().TrustAgentService.Password = TestPassword
// 	config.GetConfiguration().Tpm.OwnerSecretKey = TpmSecretKey
// 	trustAgentService, err := CreateTrustAgentService(8450)
// 	assert.NoError(err)

// 	manifestXml := `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
// 	<Manifest xmlns="lib:wml:measurements:1.0" Label="ISecL_Default_Workload_Flavor_v1.0" Uuid="7a9ac586-40f9-43b2-976b-26667431efca" DigestAlg="SHA384">
// 	   <Dir Exclude="" FilterType="regex" Include=".*" Path="/opt/workload-agent/bin"/>
// 	   <Symlink Path="/opt/workload-agent/bin/wlagent"/>
// 	   <File Path="/opt/workload-agent/bin/.*" SearchType="regex"/>
// 	</Manifest>`

// 	request, err := http.NewRequest("POST", "/v2/host/application-measurement", bytes.NewBuffer([]byte(manifestXml)))
// 	assert.NoError(err)

// 	request.Header.Set("Content-Type", "application/xml")
// 	request.SetBasicAuth(TestUser, TestPassword)

// 	recorder := httptest.NewRecorder()
// 	trustAgentService.router.ServeHTTP(recorder, request)
// 	response := recorder.Result()
// 	fmt.Printf("StatusCode: %d\n", response.StatusCode)
// 	assert.Equal(response.StatusCode, http.StatusOK)
// }

// func TestDeployManifest(t *testing.T) {
// 	assert := assert.New(t)

// 	config.InitConfiguration()
// 	config.GetConfiguration().TrustAgentService.Username = TestUser
// 	config.GetConfiguration().TrustAgentService.Password = TestPassword
// 	config.GetConfiguration().Tpm.OwnerSecretKey = TpmSecretKey
// 	trustAgentService, err := CreateTrustAgentService(8450)
// 	assert.NoError(err)

// 	manifestXml := `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
// 	<Manifest xmlns="lib:wml:manifests:1.0" Label="New_Software_Flavor" Uuid="1fe1b7fc-99e6-4e7e-ba3d-d9aeeb03d227" DigestAlg="SHA384">
// 	<File Path="/opt/trustagent/.*" SearchType="regex"/>
// 	</Manifest>`

// 	request, err := http.NewRequest("POST", "/v2/deploy/manifest", bytes.NewBuffer([]byte(manifestXml)))
// 	assert.NoError(err)

// 	request.Header.Set("Content-Type", "application/xml")
// 	request.SetBasicAuth(TestUser, TestPassword)

// 	recorder := httptest.NewRecorder()
// 	trustAgentService.router.ServeHTTP(recorder, request)
// 	response := recorder.Result()
// 	fmt.Printf("StatusCode: %d\n", response.StatusCode)
// 	assert.Equal(response.StatusCode, http.StatusOK)
// }
