/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package vsclient

import (
	"crypto/tls"
	"errors"
	"net/http"
	"net/url"
	commonTls "intel/isecl/lib/common/tls"
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
	// Username used to authenticate with the HVS.
	Username string
	// Password to supply for the Username
	Password string
	// CertSha384 is a pointer to a 48 byte array that specifies the fingerprint of the immediate TLS certificate to trust.
	// If the value is a non nil pointer to a 48 byte array, custom TLS verification will be used, where any valid chain of X509 certificates
	// with a self signed CA at the root will be accepted as long as the Host Certificates Fingerprint matches what is provided here
	// If the value is a nil pointer, then system standard TLS verification will be used.
	CertSha384 *[48]byte
}

func NewVSClientFactory(vsClientConfig *VSClientConfig) (VSClientFactory, error) {

	_, err := url.ParseRequestURI(vsClientConfig.BaseURL)
	if err != nil {
		return nil, err
	}

	if len(vsClientConfig.Username) == 0 {
		return nil, errors.New("The VS client must have a user name")
	}

	if len(vsClientConfig.Password) == 0 {
		return nil, errors.New("The VS client must have a password")
	}

	defaultFactory := defaultVSClientFactory {vsClientConfig}
	return &defaultFactory, nil
}

//-------------------------------------------------------------------------------------------------
// Implementation
//-------------------------------------------------------------------------------------------------

type defaultVSClientFactory struct {
	cfg *VSClientConfig
}

func (vsClientFactory *defaultVSClientFactory) FlavorsClient() FlavorsClient {
	return &flavorsClientImpl {vsClientFactory.createHttpClient(), vsClientFactory.cfg}
}

func (vsClientFactory *defaultVSClientFactory) HostsClient() HostsClient {
	return &hostsClientImpl {vsClientFactory.createHttpClient(), vsClientFactory.cfg}
}

func (vsClientFactory *defaultVSClientFactory) ManifestsClient() ManifestsClient {
	return &manifestsClientImpl {vsClientFactory.createHttpClient(), vsClientFactory.cfg}
}

func (vsClientFactory *defaultVSClientFactory) TpmEndorsementsClient() TpmEndorsementsClient {
	return &tpmEndorsementsClientImpl {vsClientFactory.createHttpClient(), vsClientFactory.cfg}
}

func (vsClientFactory *defaultVSClientFactory) PrivacyCAClient() PrivacyCAClient {
	return &privacyCAClientImpl {vsClientFactory.createHttpClient(), vsClientFactory.cfg}
}

func (vsClientFactory *defaultVSClientFactory) CACertificatesClient() CACertificatesClient {
	return &caCertificatesClientImpl {vsClientFactory.createHttpClient(), vsClientFactory.cfg}
}

func (vsClientFactory *defaultVSClientFactory) createHttpClient() *http.Client {
	tlsConfig := tls.Config{}

	if vsClientFactory.cfg.CertSha384 != nil {
		// set explicit verification
		tlsConfig.InsecureSkipVerify = true
		tlsConfig.VerifyPeerCertificate = commonTls.VerifyCertBySha384(*vsClientFactory.cfg.CertSha384)
	}

	transport := http.Transport {
		TLSClientConfig: &tlsConfig,
	}

	return &http.Client{Transport: &transport}
}