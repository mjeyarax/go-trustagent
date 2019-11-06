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
// Default VS Client factory that is used in vsclient::CreateDefaultVSClientFactory
//-------------------------------------------------------------------------------------------------

type defaultVSClientFactory struct {
	vsClientConfig *VSClientConfig
}

func (vsClientFactory *defaultVSClientFactory) NewVSClient() (VSClient, error) {
	tlsConfig := tls.Config{}
	if vsClientFactory.vsClientConfig.CertSha384 != nil {
		// set explicit verification
		tlsConfig.InsecureSkipVerify = true
		tlsConfig.VerifyPeerCertificate = commonTls.VerifyCertBySha384(*vsClientFactory.vsClientConfig.CertSha384)
	}

	transport := http.Transport{
		TLSClientConfig: &tlsConfig,
	}

	httpClient := &http.Client{Transport: &transport}

	vsClient := vsClientImpl {httpClient, vsClientFactory.vsClientConfig}
	return &vsClient, nil
}

//-------------------------------------------------------------------------------------------------
// Implementation of VSClient interface
//-------------------------------------------------------------------------------------------------

type vsClientImpl struct {
	httpClient *http.Client
	config *VSClientConfig
}

func (vsClient *vsClientImpl) Flavors() FlavorsClient {
	return &flavorsClientImpl {vsClient.httpClient, vsClient.config}
}

func (vsClient *vsClientImpl) Hosts() HostsClient {
	return &hostsClientImpl {vsClient.httpClient, vsClient.config}
}

func (vsClient *vsClientImpl) Manifests() ManifestsClient {
	return &manifestsClientImpl {vsClient.httpClient, vsClient.config}
}