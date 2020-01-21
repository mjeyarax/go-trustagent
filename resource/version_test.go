/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
 package resource

 import (
	 "net/http"
	 "net/http/httptest"
	 "testing"
 
	 "github.com/stretchr/testify/assert"
 )
 
 func TestGetVersion(t *testing.T) {
	 log.Trace("resource/version_test:TestGetVersion() Entering")
	 defer log.Trace("resource/version_test:TestGetVersion() Leaving")
	 assert := assert.New(t)
	 req, err := http.NewRequest("GET", "/version", nil)
	 if err != nil {
		 t.Fatal(err)
	 }
	 recorder := httptest.NewRecorder()
	 handler := http.HandlerFunc(getVersion)
	 handler.ServeHTTP(recorder, req)
	 assert.Equal(recorder.Code, http.StatusOK)
 
	 assert.NotEmpty(recorder.Body.String())
 }
 