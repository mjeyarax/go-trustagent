/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package vsclient

import (
	"crypto/tls"
	"net/http"
	commonTls "intel/isecl/lib/common/tls"
)

//-------------------------------------------------------------------------------------------------
// Implementation of VS Client factory created by vsclient::NewVSClientFactory
//-------------------------------------------------------------------------------------------------

type defaultVSClientFactory struct {
	config *VSClientConfig
}

func (vsClientFactory *defaultVSClientFactory) FlavorsClient() FlavorsClient {
	return &flavorsClientImpl {vsClientFactory.createHttpClient(), vsClientFactory.config}
}

func (vsClientFactory *defaultVSClientFactory) HostsClient() HostsClient {
	return &hostsClientImpl {vsClientFactory.createHttpClient(), vsClientFactory.config}
}

func (vsClientFactory *defaultVSClientFactory) ManifestsClient() ManifestsClient {
	return &manifestsClientImpl {vsClientFactory.createHttpClient(), vsClientFactory.config}
}

func (vsClientFactory *defaultVSClientFactory) createHttpClient() *http.Client {
	tlsConfig := tls.Config{}

	if vsClientFactory.config.CertSha384 != nil {
		// set explicit verification
		tlsConfig.InsecureSkipVerify = true
		tlsConfig.VerifyPeerCertificate = commonTls.VerifyCertBySha384(*vsClientFactory.config.CertSha384)
	}

	transport := http.Transport{
		TLSClientConfig: &tlsConfig,
	}

	return &http.Client{Transport: &transport}
}