/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package vsclient

import (
	"intel/isecl/go-trust-agent/constants"
	"intel/isecl/lib/clients"
	"net/http"
	"net/url"

)

type VSClientFactory interface {
	HostsClient() HostsClient
	FlavorsClient() FlavorsClient
	ManifestsClient() ManifestsClient
	TpmEndorsementsClient() TpmEndorsementsClient
	PrivacyCAClient() PrivacyCAClient
	CACertificatesClient() CACertificatesClient
}

type VSClientConfig struct {
	// BaseURL specifies the URL base for the HVS, for example https://hvs.server:8443/v2
	BaseURL string
	// BearerToken is the JWT token required for authentication with external services
	BearerToken string
}

func NewVSClientFactory(vsClientConfig *VSClientConfig) (VSClientFactory, error) {

	_, err := url.ParseRequestURI(vsClientConfig.BaseURL)
	if err != nil {
		return nil, err
	}

	defaultFactory := defaultVSClientFactory{vsClientConfig}
	return &defaultFactory, nil
}

//-------------------------------------------------------------------------------------------------
// Implementation
//-------------------------------------------------------------------------------------------------

type defaultVSClientFactory struct {
	cfg *VSClientConfig
}

func (vsClientFactory *defaultVSClientFactory) FlavorsClient() FlavorsClient {
	return &flavorsClientImpl{vsClientFactory.createHttpClient(), vsClientFactory.cfg}
}

func (vsClientFactory *defaultVSClientFactory) HostsClient() HostsClient {
	return &hostsClientImpl{vsClientFactory.createHttpClient(), vsClientFactory.cfg}
}

func (vsClientFactory *defaultVSClientFactory) ManifestsClient() ManifestsClient {
	return &manifestsClientImpl{vsClientFactory.createHttpClient(), vsClientFactory.cfg}
}

func (vsClientFactory *defaultVSClientFactory) TpmEndorsementsClient() TpmEndorsementsClient {
	return &tpmEndorsementsClientImpl{vsClientFactory.createHttpClient(), vsClientFactory.cfg}
}

func (vsClientFactory *defaultVSClientFactory) PrivacyCAClient() PrivacyCAClient {
	return &privacyCAClientImpl{vsClientFactory.createHttpClient(), vsClientFactory.cfg}
}

func (vsClientFactory *defaultVSClientFactory) CACertificatesClient() CACertificatesClient {
	return &caCertificatesClientImpl{vsClientFactory.createHttpClient(), vsClientFactory.cfg}
}

func (vsClientFactory *defaultVSClientFactory) createHttpClient() *http.Client {
	log.Trace("vsclient/vsclient_factory:createHttpClient() Entering")
	defer log.Trace("vsclient/vsclient_factory:createHttpClient() Leaving")
	// Here we need to return a client which has validated the HVS TLS cert-chain
	client, err := clients.HTTPClientWithCADir(constants.TrustedCaCertsDir)

	if err != nil {
		log.WithError(err).Error("vsclient/vsclient_factory:createHttpClient() Error while creating http client")
		return nil
	}
	return &http.Client{Transport: client.Transport}
}
