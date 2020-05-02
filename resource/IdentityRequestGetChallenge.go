package resource

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"github.com/pkg/errors"
	"intel-secl/pkg/lib/privacyca"
	"intel-secl/pkg/lib/privacyca/tpm2utils"
	tpmidentityrequest "intel-secl/pkg/model/ta"
	"intel/isecl/go-trust-agent/v2/constants"
	"intel/isecl/lib/common/v2/crypt"
	"intel/isecl/lib/common/v2/log/message"
	"io/ioutil"
	"net/http"
	"strings"
)

func identityRequestGetChallenge() endpointHandler {
	return func(httpWriter http.ResponseWriter, httpRequest *http.Request) *endpointError {
		data, err := ioutil.ReadAll(httpRequest.Body)
		if err != nil {
			log.Errorf("resource/identity_request_challenge:identityRequestGetChallenge() %s - Error reading request body: %s for request %s", message.AppRuntimeErr, string(data), httpRequest.URL.Path)
			return &endpointError{Message: "Error reading request body", StatusCode: http.StatusBadRequest}
		}

		var identityChallengePayload tpmidentityrequest.IdentityChallengePayload
		dec := json.NewDecoder(bytes.NewReader(data))
		dec.DisallowUnknownFields()
		err = dec.Decode(&identityChallengePayload)
		if err != nil {
			seclog.WithError(err).Errorf("resource/identity_request_challenge:identityRequestGetChallenge() %s - Error marshaling json data: %s", message.InvalidInputProtocolViolation, string(data))
			return &endpointError{Message: "Error marshaling json data", StatusCode: http.StatusBadRequest}

		}

		privacyCAKeyBytes, err := ioutil.ReadFile(constants.PrivacyCAKey)
		if err != nil{
			log.WithError(err).Error("Unable to read privacyca key file")
			return &endpointError{Message: "Unable to read privacyca key file", StatusCode: http.StatusBadRequest}
		}

		block, _ := pem.Decode(privacyCAKeyBytes)
		privacycaKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil{
			log.WithError(err).Error("Unable to parse privacyca key")
			return &endpointError{Message: "Unable to parse privacyca key", StatusCode: http.StatusBadRequest}
		}

		privacyCACertBytes, err := ioutil.ReadFile(constants.PrivacyCACert)
		if err != nil{
			log.WithError(err).Error("Unable to read privacyca key file")
			return &endpointError{Message: "Error marshaling json data", StatusCode: http.StatusBadRequest}
		}

		block, _ = pem.Decode(privacyCACertBytes)

		privacycaCert, err := x509.ParseCertificate(block.Bytes)
		if err != nil{
			log.WithError(err).Error("Unable to parse privacyca cert")
			return &endpointError{Message: "Error marshaling json data", StatusCode: http.StatusBadRequest}
		}

		privacycaTpm2, err := privacyca.NewPrivacyCA(identityChallengePayload.IdentityRequest)
		if err != nil{
			return &endpointError{Message: "Error creating privacyca instance", StatusCode: http.StatusBadRequest}
		}
		ekCertBytes, err := privacycaTpm2.GetEkCert(identityChallengePayload, privacycaKey)
		if err != nil{
			log.WithError(err).Error("Unable to read privacyca key file")
			return &endpointError{Message: "Error while extracting ekcert from identityChallengePayload", StatusCode: http.StatusBadRequest}
		}

		ekCert, err :=  x509.ParseCertificate(ekCertBytes)
		if err != nil{
			return &endpointError{Message: "Error creating privacyca instance", StatusCode: http.StatusBadRequest}
		}

		endorsementCerts, err := getEndorsementCerts()
		if err != nil{
			log.WithError(err).Error("Unable to retrieve endorsement certs")
			return &endpointError{Message: "Error marshaling json data", StatusCode: http.StatusBadRequest}
		}

		endorsementCertsToVerify := endorsementCerts[strings.ReplaceAll(ekCert.Subject.ToRDNSequence().String(), "\\x00","")]
		if !isEkCertificateVerifiedByAuthority(ekCert, endorsementCertsToVerify) {
			log.WithError(err).Error("EC is not trusted")
			return &endpointError{Message: "EC is not trusted", StatusCode: http.StatusBadRequest}
		}

		identityRequestChallenge, err := crypt.GetRandomBytes(32)
		if err != nil{
			log.WithError(err).Error("Unable to generate random bytes for identityRequestChallenge")
			return &endpointError{Message: "EC is not trusted", StatusCode: http.StatusBadRequest}
		}
		httpWriter.Header().Set("Content-Type", "application/json")
		httpWriter.WriteHeader(http.StatusOK)
		_, _ = bytes.NewBuffer(b).WriteTo(httpWriter)
		return nil
	}
}

func getEndorsementCerts() (map[string]x509.Certificate, error){
	endorsementCerts := make(map[string]x509.Certificate)
	endorsementCABytes, err := ioutil.ReadFile(constants.EndorsementCAFile)
	if err != nil{
		return nil, err
	}
	block, rest := pem.Decode([]byte(endorsementCABytes))
	if block == nil {
		return nil, errors.New("Unable to decode pem bytes")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, errors.Wrap(err,"Failed to parse certificate")
	}
	endorsementCerts[cert.Subject.ToRDNSequence().String()] = *cert
	if rest != nil{
		for ;rest!=nil;{
			block, rest = pem.Decode([]byte(endorsementCABytes))
			if block == nil {
				return nil, errors.New("Unable to decode pem bytes")
			}
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, errors.Wrap(err,"Failed to parse certificate")
			}
			endorsementCerts[cert.Subject.ToRDNSequence().String()] = *cert
		}
	}

	return endorsementCerts, nil
}

func isEkCertificateVerifiedByAuthority(cert *x509.Certificate, authority x509.Certificate) bool{
	rsaPublicKey := cert.PublicKey.(*rsa.PublicKey)
	sigAlg := cert.SignatureAlgorithm
	switch sigAlg {
	case x509.SHA1WithRSA:
		h := sha1.New()
		h.Write(authority.RawTBSCertificate)
		digest := h.Sum(nil)
		err := rsa.VerifyPKCS1v15(rsaPublicKey, crypto.SHA1, digest, authority.Signature)

		if err != nil {
			log.Errorf("Error while verifying the ek cert signature against the Endorsement authority, Error: %v", err)
			return false
		}
		break
	case x509.SHA256WithRSA:
		h := sha256.New()
		h.Write(authority.RawTBSCertificate)
		digest := h.Sum(nil)
		err := rsa.VerifyPKCS1v15(rsaPublicKey, crypto.SHA256, digest, authority.Signature)

		if err != nil {
			log.Errorf("Error while verifying the ek cert signature against the Endorsement authority, Error: %v", err)
			return false
		}
		break
	case x509.SHA384WithRSA:
		h := sha512.New384()
		h.Write(authority.RawTBSCertificate)
		digest := h.Sum(nil)
		err := rsa.VerifyPKCS1v15(rsaPublicKey, crypto.SHA384, digest, authority.Signature)

		if err != nil {
			log.Errorf("Error while verifying the ek cert signature against the Endorsement authority, Error: %v", err)
			return false
		}
		break
	default:
		log.Errorf("Error while verifying the ek cert signature against the Endorsement authority, unsupported signature algorithm")
		return false
		break
	}

	return true
}

//TODO after implementation of TpmEndoresment API
func isEkCertificateRegistered() bool{

}
