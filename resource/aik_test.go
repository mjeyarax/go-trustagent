// +build integration

/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package resource

import (
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