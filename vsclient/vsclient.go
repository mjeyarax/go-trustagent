
/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package vsclient

//-------------------------------------------------------------------------------------------------
// KWT:  THIS IS AN INTERMEDIATE STEP TO ALIGN WITH THE MTWILSON CLIENT REPO
// WILL RECONCILE AFTER AAS/CMS INTEGRATION IS DONE IN 1.6
//-------------------------------------------------------------------------------------------------

import (
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	commonTls "intel/isecl/lib/common/tls"
	"intel/isecl/go-trust-agent/config"
)

const (
	TRUST_POLICY_TRUST_FIRST_CERTIFICATE 	= "TRUST_FIRST_CERTIFICATE"
	FLAVOR_HOST_UNIQUE						= "HOST_UNIQUE"
	FLAVOR_SOFTWARE							= "SOFTWARE"
	FLAVOR_OS								= "OS"
	FLAVOR_PLATFORM							= "PLATFORM"
)


// type TlsPolicy struct {
// 	Id string `json:"Id"`
// }

type TpmEndorsement struct {
	HardwareUUID 	string 	`json:"hardware_uuid"`
	Issuer 			string 	`json:"issuer"`
	Revoked			bool	`json:"revoked"`
	Certificate		string 	`json:"certificate"`
	Command			string 	`json:"command"`
}

// From PrivacyCA.java...
// {
//   "identity_request":{
//     "tpm_version":"2.0",
//     "identity_request_blob":[identityRequest blob],
//     "aik_modulus":[aikModulus blob],
//     "aik_blob":[aik blob],
//     "aik_name":[aikName blob]
//   },
//   "endorsement_certificate": [blob of endorsement certificate]
// }
type IdentityRequest struct {
	TpmVersion 				string `json:"tpm_version"`
	IdentityRequestBlock	[]byte `json:"identity_request_blob"`
	AikModulus				[]byte `json:"aik_modulus"`
	AikBlob					[]byte `json:"aik_blob"`
	AikName					[]byte `json:"aik_name"`
}

type IdentityChallengeRequest struct {
	IdentityRequest 			IdentityRequest `json:"identity_request"`
	EndorsementCertificate 		[]byte 			`json:"endorsement_certificate"`
}

// From PrivacyCA.java...
// {
//   "identity_request":{
//     "tpm_version":"2.0",
//     "identity_request_blob":[identityRequest blob],
//     "aik_modulus":[aikModulus blob],
//     "aik_blob":[aik blob],
//     "aik_name":[aikName blob]
//   },
//   "response_to_challenge": [responseToChallenge blob ]
// }
type IdentityChallengeResponse struct {
	IdentityRequest 			IdentityRequest `json:"identity_request"`
	ResponseToChallenge 		[]byte 			`json:"response_to_challenge"`
}

// From PrivacyCA.java...
// {
// 	           "secret"        :      "AAGB9Xr+ti6dsDSph9FqM1tOM8LLWLLhUhb89R6agQ/hA+eQDF2FpcfOM/98J95ywwYpxzYS8N
// 	                                   x6c7ud5e6SVVgLldcc3/m9xfsCC7tEmfQRyc+pydbgnCHQ9E/TQoyV/VgiE5ssV+lGX171+lN+
// 	                                   2RSO0HC8er+jN52bh31M4S09sv6+Qk2Fm2efDsF2NbFI4eyLcmtFEwKfDyAiZ3zeXqPNQWpUzV
// 	                                   ZzR3zfxpd6u6ZonYmfOn/fLDPIHwTFv8cYHSIRailTQXP+VmQuyR7YOI8oe/NC/cr7DIYTJD7G
// 	                                   LFNDXk+sybf9j9Ttng4RRyb0WXgIcfIWW1oZD+i4wqu9OdV1",
// 	           "credential"    :      "NAAAIBVuOfmXFbgcbBA2fLtnl38KQ7fIRGwUSf5kQ+UwIAw8ElXsYfoBoUB11BWKkc4uo9WRAA
// 	                                   AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
// 	                                   AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
// 	           "sym_blob"      :      "AAAAQAAAAAYAAQAAAAAAAMlZgTkKMlujW0vDUrhcE8Ixut12y5yXXP7nyx8wSUSHIaNz419fpy
// 	                                   AiQdsCG3PMJGvsNtiInB1zjGqQOtt77zM=",
// 	           "ek_blob"       :      "Tb3zQv6oW8/dUg45qofJFsIZV1XHTADZgeVjH7BI/ph+6ERJTlxBjK7zkxHJh54QlCi5h0f1rM
// 	                                   kYqtAyCmmyyUdewP4xFaVmjm8JcWaAzeOfb3vhamWr9xGecfJ34D58cy2Att7VAzXoWe2GthAb
// 	                                   lM+Rjsy9wiXfyOe9IjfC5jngjPHfwyi8IvV+FZHTG8wq7R8lcAQdurMmOzMZJT+vkzBq1TEGLu
// 	                                   rE3h4Rf84X3H/um4sQ2mqo+r5ZIsm+6lhb6PjU4S9Cp3j4RZ5nU/uVvgTWzviNUPYBbd3AypQo
// 	                                   9Kv5ij8UqHk2P1DzWjCBvwCqHTzRsuf9b9FeT+f4aWgLNQ=="
// 	}
type IdentityProofRequest struct {
	Secret						[]byte `json:"secret"`
	Credential					[]byte `json:"credential"`
	SymetricBlob				[]byte `json:"sym_blob"`
	EndorsementCertificateBlob	[]byte `json:"ek_blob"`
}

type VSClient interface {
	Hosts() HostsClient
	Flavors() FlavorsClient
	Manifests() ManifestsClient
}

type HostsClient interface {
	// TODO
	SearchHosts(hostFilterCriteria *HostFilterCriteria) (*HostCollection, error)

	// Registers the specified host with the Verfication Service. 
	//
	// https://server.com:8181/mtwilson/v2/hosts/
	//  
	// Input (HostCreateCriteria): 
	// {
	// 	 "connection_string":"intel:https://0.0.0.0:1443;u=user;p=password",
	// 	 "host_name":"MyHost",
	// 	 "tls_policy_id":"TRUST_FIRST_CERTIFICATE"
	// }
	// 
	// Output (Host): 
	// {
	// 	  "id":"6208006d-1101-4ca6-8855-8542cfa3f66a",
	// 	  "host_name":"MyHost",
	// 	  "connection_string":"https://0.0.0.0:1443",
	// 	  "hardware_uuid":"8032632b-8fa4-e811-906e-00163566263e",
	// 	  "tls_policy_id":"TRUST_FIRST_CERTIFICATE",
	// 	  "flavorgroup_names":["automatic","platform_software"]
	// }
	CreateHost(hostCreateCriteria *HostCreateCriteria) (*Host, error) 

	//  Updates the host with the specified attributes. Except for the host name, all other attributes can be updated.
	//
	//  https://server.com:8181/mtwilson/v2/hosts/e43424ca-9e00-4cb9-b038-9259d0307888
	//
	//  KWT: UPDATE JSON...
	//
	//  Input: {"name":"192.168.0.2","connection_url":"https://192.168.0.1:443/sdk;admin;pwd","bios_mle_uuid":"823a4ae6-b8cd-4c14-b89b-2a3be2d13985",
	//           "vmm_mle_uuid":"98101211-b617-4f59-8132-a5d05360acd6","tls_policy_id":"e1a527b5-2020-49c1-83be-6bd8bf641258"}
	// 
	//  Output: {"id":"e43424ca-9e00-4cb9-b038-9259d0307888","name":"192.168.0.2",
	//           "connection_url":"https://192.168.0.1:443/sdk;admin;pwd","bios_mle_uuid":"823a4ae6-b8cd-4c14-b89b-2a3be2d13985",
	//           "vmm_mle_uuid":"98101211-b617-4f59-8132-a5d05360acd6","tls_policy_id":"e1a527b5-2020-49c1-83be-6bd8bf641258"}
	UpdateHost(host *Host) (*Host, error)	
}

type FlavorsClient interface {

	//
	// TODO:  Document fx 
	//
	// Will not include a return 'flavor' structure at this time
	CreateFlavor(flavorCreateCriteria *FlavorCreateCriteria) error

}

type ManifestsClient interface {
	//
	// TODO:  Document fx 
	//
	GetManifestXmlById(manifestUUID string) ([]byte, error)

	//
	// TODO:  Document fx 
	//
	GetManifestXmlByLabel(manifestLabel string) ([]byte, error)
}

type VSClientFactory interface {
	NewVSClient() (VSClient, error)
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


// KWT:  Remove
func NewVSClient() (*http.Client, error) {

	var certificateDigest [48]byte

	tls384 := config.GetConfiguration().HVS.TLS384

	certDigestBytes, err := hex.DecodeString(tls384)
	if err != nil {
		return nil, fmt.Errorf("error converting certificate digest to hex: %s", err)
	}

	if len(certDigestBytes) != 48 {
		return nil, fmt.Errorf("Incorrect TLS384 string length %d", len(certDigestBytes))
	}

	copy(certificateDigest[:], certDigestBytes)

	// init http client
	tlsConfig := tls.Config{}
	if certDigestBytes != nil {
		// set explicit verification
		tlsConfig.InsecureSkipVerify = true
		tlsConfig.VerifyPeerCertificate = commonTls.VerifyCertBySha384(certificateDigest)
	}

	transport := http.Transport{
		TLSClientConfig: &tlsConfig,
	}

	client := http.Client{Transport: &transport}
	return &client, nil
}

