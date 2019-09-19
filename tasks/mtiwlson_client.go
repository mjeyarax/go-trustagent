
package tasks

import (
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"net/http"
	commonTls "intel/isecl/lib/common/tls"
	"intel/isecl/go-trust-agent/config"
)

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
	responseToChallenge 		[]byte 			`json:"response_to_challenge"`
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
	Secret						string `json:"secret"`
	Credential					string `json:"credential"`
	SystemBlob					string `json:"sym_blob"`
	EndorsementCertificateBlob	string `json:"ek_blob"`
}

// KWT:  Merge this (or use) into mtwilson.Client
func newMtwilsonClient() (*http.Client, error) {

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
