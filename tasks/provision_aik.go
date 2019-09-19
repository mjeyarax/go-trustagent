
/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package tasks

import (
	"math/big"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/binary"
//	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	log "github.com/sirupsen/logrus"
	"intel/isecl/go-trust-agent/config"
	"intel/isecl/go-trust-agent/constants"
	"intel/isecl/go-trust-agent/tpmprovider"
	"intel/isecl/lib/common/crypt"
	"intel/isecl/lib/common/setup"
)

//-------------------------------------------------------------------------------------------------
// P R O V I S I O N   A I K 
//-------------------------------------------------------------------------------------------------
// ==> POST IdentityChallengeRequest to https://server.com:8443/mtwilson/v2/privacyca/identity-challenge-request
// 	  RETURNS --> IdentityProofRequest
//
// ==> Passed results to TPM 'activateIdentity' (generate/save aik to nvram) and returns 
//     'decrypted bytes' (TBD)
//
// ==> POST 'decrypted bytes' to https://server.com:8443/mtwilson/v2/privacyca/identity-challenge-response, 
//     use results to 'activateIdentity' again (???) --> save 'blob' to aik.blob and 'cert' to aik.pem
//
// ==> /aik returns 'aik.pem'
//-------------------------------------------------------------------------------------------------
type ProvisionAttestationIdentityKey struct {
	Flags 					[]string
}

func (task* ProvisionAttestationIdentityKey) Run(c setup.Context) error {

	identityChallengeRequest := IdentityChallengeRequest {}
	err := task.populateIdentityRequest(&identityChallengeRequest.IdentityRequest)
	if err != nil {
		return err
	} 

	ekCertBytes, err := task.getEndorsementKeyBytes()
	if err != nil {
		return err
	}

	identityChallengeRequest.EndorsementCertificate, err = task.getEncryptedEndorsementCertificate(ekCertBytes)
	if err != nil {
		return err
	}

	identityProofRequest, err := task.getIdentityProofRequest(&identityChallengeRequest)
	if err != nil {
		return err
	}

	decrypted1, err := task.activateIdentity(identityProofRequest)
	if err != nil {
		return err
	}

	identityProofRequest2, err := task.getIdentityProofResponse(decrypted1)
	if err != nil {
		return err
	}

	decrypted2, err := task.activateIdentity(identityProofRequest2);
	if err != nil {
		return err
	}

	// make sure the bytes are a certificates...
	_, err = x509.ParseCertificate(decrypted2)
	if err != nil {
		return err
	}

	err = ioutil.WriteFile(constants.AikCert, decrypted2, 0600)
	if err != nil {
		return err
	}

	err = ioutil.WriteFile(constants.AikBlob, identityChallengeRequest.IdentityRequest.AikBlob, 0600)
	if err != nil {
		return err
	}

	return nil
}


func (task* ProvisionAttestationIdentityKey) Validate(c setup.Context) error {

	log.Info("Successfully provisioned aik")
	return nil
}

func (task* ProvisionAttestationIdentityKey) getTpmSymetricKey(key []byte) ([]byte, error) {
	privacyCa, err := GetPrivacyCA()
	if err != nil {
		return nil, err
	}

	// EncryptOAEP requires a 20 byte key (not 16)
	asymKey, err := crypt.GetRandomBytes(20)
	if err != nil {
		return nil, err
	}

	//---------------------------------------------------------------------------------------------
	// Build the binary structure similar to TpmSymmetricKey.java and encrypt it with the public.
	// The algorithm meta data fields are set in TpmIdentityRequest.encryptSym()
	//
	// byte[] algoId = TpmUtils.intToByteArray(algorithmId);
	// byte[] encSchm = TpmUtils.shortToByteArray(encScheme);
	// byte[] size = TpmUtils.shortToByteArray((short)keyBlob.length);
	// + bytes from 'keblob'
	//---------------------------------------------------------------------------------------------
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.BigEndian, uint32(6))				// TpmKeyParams.TPM_ALG_AES
	binary.Write(buf, binary.BigEndian, uint16(255))			// TpmKeyParams.TPM_ES_SYM_CBC_PKCS5PAD
	binary.Write(buf, binary.BigEndian, uint16(len(key)))		// length of key
	binary.Write(buf, binary.BigEndian, key)					// key bytes

	// padding
	binary.Write(buf, binary.BigEndian, []byte("TCPA"))	// 24-28
	binary.Write(buf, binary.BigEndian, []byte("TCPA"))	// 28-32
	binary.Write(buf, binary.BigEndian, []byte("TCPA"))	// 32-36
	binary.Write(buf, binary.BigEndian, []byte("TCPA"))	// 36-40

//	fmt.Printf("===\n%s\n\n", hex.EncodeToString(buf.Bytes()))

	// TODO:  Sha1 is being used for compatability with HVS --> needs to be fixed before release
	ekAsymetricBytes, err := rsa.EncryptOAEP(sha1.New(), bytes.NewBuffer(asymKey), privacyCa, buf.Bytes(), []byte("TCPA"))
	if err != nil {
		return nil, fmt.Errorf("Error encrypting tpm symetric key: %s", err)
	}

//	fmt.Printf("RSA[%x]: %s\n\n", len(ekAsymetricBytes), hex.EncodeToString(ekAsymetricBytes))
	return ekAsymetricBytes, nil
}

func (task* ProvisionAttestationIdentityKey) getEndorsementKeyBytes() ([]byte, error) {
	//---------------------------------------------------------------------------------------------
	// Get the endorsement key certificate from the tpm
	//---------------------------------------------------------------------------------------------
	tpm, err := tpmprovider.NewTpmProvider()
	if err != nil {
		return nil, fmt.Errorf("Setup error: getEncryptedEndorsementCertificate could not create TpmProvider: %s", err)
	}

	defer tpm.Close()

	ekCertBytes, err := tpm.GetEndorsementKeyCertificate(config.GetConfiguration().Tpm.SecretKey)
	if err != nil {
		return nil, err
	}

	return ekCertBytes, nil
}

//
// Creates an encrypted EndorsementKey similar to gov.niarl.his.privacyca.TpmIdentityRequest
//
// Asymetric encryption:  RSA, RSAESOAEP_SHA1_MGF1?, 2048 (see TpmIdentityRequest.createDefaultAsymAlgorithm)
// Symetric encryption: 16 random bytes, RSA, TPM_ES_RSAESOAEP_SHA1_MGF1, 2048 (see createDefaultSymAlgorithm)
//
func (task* ProvisionAttestationIdentityKey) getEncryptedEndorsementCertificate(ekCertBytes []byte) ([]byte, error) {

	//---------------------------------------------------------------------------------------------
	// Encrypt the ek cert bytes using aes
	// From https://golang.org/pkg/crypto/cipher/#example_NewCBCEncrypter
	//---------------------------------------------------------------------------------------------
	log.Infof("EKCERTBYTES LEN: %d", len(ekCertBytes))
	if len(ekCertBytes) % aes.BlockSize != 0 {
		return nil, fmt.Errorf("byte length (%x) is not a multiple of the block size", len(ekCertBytes))
	}

	cipherKey, err := crypt.GetRandomBytes(16)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(cipherKey)
	if err != nil {
		return nil, err
	}

	iv, err := crypt.GetRandomBytes(16)		// aes.Blocksize == 16
	if err != nil {
		return nil, err
	}

	mode := cipher.NewCBCEncrypter(block, iv)

	// this 'hand padding' is necessary for the java/niarl to 
	// successully decrypt the symetric data (ek pub cert)
	padding := block.BlockSize() - len(ekCertBytes)%block.BlockSize()
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	withPadding  := append(ekCertBytes, padtext...)

	ekSymetricBytes := make([]byte, len(withPadding))
	mode.CryptBlocks(ekSymetricBytes, withPadding)

	// fmt.Printf("EK Cert   [%x]: %s\n\n", len(ekCertBytes), hex.EncodeToString(ekCertBytes))
	// fmt.Printf("Encrypted [%x]: %s\n\n", len(ekSymetricBytes), hex.EncodeToString(ekSymetricBytes))
	// fmt.Printf("Decrypted [%x]: %s\n\n", len(decrypted), hex.EncodeToString(decrypted))

	ekAsymetricBytes, err := task.getTpmSymetricKey(cipherKey)
	if err != nil {
		return nil, err
	}

	//---------------------------------------------------------------------------------------------
	// The TrustAgent submits a very specific byte sequence for the encrypted 'endorsement_certificate', 
	// that must be compatible with HVS...
	//
	// - 4 bytes for int length of aysmetric key
	// - 4 bytes for int length of symetric key
	// - asymAlgorithmBytes (TpmKeyParams.java from TpmIdentityRequest.java::createDefaultAsymAlgorithm)
	//   - 4 bytes for int length of 'algoId' (TPM_ALG_RSA: 1)
	//   - 2 bytes for short length of 'encScheme' (TPM_ES_RSAESOAEP_SHA1_MGF1: 3)
	//   - 2 bytes for short length of 'sigScheme' (TPM_SS_NONE: 1)
	//   - 4 bytes for int length of 'sub params length' (12 from TpmRsaKeyparams below)
	//   - SubParams (TpmRsaKeyParams.java)
	//     - 4 bytes for int value of 'keylength' (2048)
	//     - 4 bytes for int value of 'numPrimes' (2)
	//	   - 4 bytes for int value of 'size' (0 and no exponent set in createDefaultAsymAlgorithm)
	// symAlgorithmBytes (TpmKeyParams.java from TpmIdentityRequest.java::createDefaultSymAlgorithm)
	//   - 4 bytes for int length of 'algoId' (TPM_ALG_AES: 6)
	//   - 2 bytes for short length of 'encScheme' (TPM_ES_SYM_CBC_PKCS5PAD: 255)
	//   - 2 bytes for short length of 'sigScheme' (TPM_SS_NONE: 1)
	//   - 4 bytes for int length of 'sub params length' (28 for size of TpmSymmetricKeyParams below)
	//   - SubParams (TpmSymmetricKeyParams.java)
	//     - 4 bytes for int value of 'keylength' (128)
	//     - 4 bytes for int value of 'blockSize' (128)
	//     - 4 bytes for int value length 'iv' (16 bytes used in TpmIdentityRequest constructor)
	//	   - 16 bytes for 'iv'
	// asymBlob (bytes of aysmetric key)
	// symBlob (bytes of symetric key)
	//
	buf := new(bytes.Buffer)

	binary.Write(buf, binary.BigEndian, uint32(len(ekAsymetricBytes)))	// length of encrypted symetric key data
	binary.Write(buf, binary.BigEndian, uint32(len(ekSymetricBytes)))	// length of encrypted ek cert 

	// TpmKeyParams.java
	binary.Write(buf, binary.BigEndian, uint32(1))						// TpmKeyParams.TPM_ALG_RSA
	binary.Write(buf, binary.BigEndian, uint16(3))						// TpmKeyParams.TPM_ES_RSAESOAEP_SHA1_MGF1
	binary.Write(buf, binary.BigEndian, uint16(1))						// TPM_SS_NONE
	binary.Write(buf, binary.BigEndian, uint32(12))						// Size of params
	binary.Write(buf, binary.BigEndian, uint32(2048))					// Param keylength (2048 RSA)
	binary.Write(buf, binary.BigEndian, uint32(2))						// Param num of primes
	binary.Write(buf, binary.BigEndian, uint32(0))						// Param exponent size

	// TpmKeyParams.java
	binary.Write(buf, binary.BigEndian, uint32(6))						// TpmKeyParams.TPM_ALG_AES
	binary.Write(buf, binary.BigEndian, uint16(255))					// TpmKeyParams.TPM_ES_SYM_CBC_PKCS5PAD
	binary.Write(buf, binary.BigEndian, uint16(1))						// TpmKeyParams.TPM_SS_NONE
	binary.Write(buf, binary.BigEndian, uint32(28))						// Size of params (following data in TpmSymetricKeyParams)
	// TpmSymetrictKeyParams.java
	binary.Write(buf, binary.BigEndian, uint32(128))					// Param keylength (128 AES)
	binary.Write(buf, binary.BigEndian, uint32(128))					// Param block size (128 AES)
	binary.Write(buf, binary.BigEndian, uint32(len(iv)))				// length of iv
	binary.Write(buf, binary.BigEndian, iv)								// iv (16 bytes)

	// actual bytes
	binary.Write(buf, binary.BigEndian, ekAsymetricBytes)
	binary.Write(buf, binary.BigEndian, ekSymetricBytes)

	b := buf.Bytes()
	//fmt.Printf("===\n%s\n\n", hex.EncodeToString(b))
	return b, nil
}

func (task* ProvisionAttestationIdentityKey) populateIdentityRequest(identityRequest *IdentityRequest) error {

	tpm, err := tpmprovider.NewTpmProvider()
	if err != nil {
		return fmt.Errorf("Setup error: populateIdentityRequest not create TpmProvider: %s", err)
	}

	defer tpm.Close()

	present, err := tpm.IsAikPresent(config.GetConfiguration().Tpm.SecretKey) 
	if err != nil {
		return err
	}

	if !present {
		err := tpm.CreateAik(config.GetConfiguration().Tpm.SecretKey)
		if err != nil {
			return err
		}
	}

	// get the aik's public key and populate into the identityRequest
	aikPublicKeyBytes, err := tpm.GetAikBytes(config.GetConfiguration().Tpm.SecretKey)
	if err != nil {
		return err
	}

	identityRequest.IdentityRequestBlock = aikPublicKeyBytes
	identityRequest.AikModulus = aikPublicKeyBytes

	identityRequest.TpmVersion = "2.0" // KWT: utility function that converts TPM_VERSION_LINUX_20
	identityRequest.AikBlob = new(big.Int).SetInt64(tpmprovider.TPM_HANDLE_AIK).Bytes()

	identityRequest.AikName, err = tpm.GetAikName(config.GetConfiguration().Tpm.SecretKey)
	if err != nil {
		return err
	}

	return nil
}

func (task* ProvisionAttestationIdentityKey) getIdentityProofRequest(identityChallengeRequest *IdentityChallengeRequest) (*IdentityProofRequest, error) {
	var identityProofRequest IdentityProofRequest

	client, err := newMtwilsonClient()
	if err != nil {
		return nil, err
	}

	jsonData, err := json.Marshal(*identityChallengeRequest)
	if err != nil {
		return nil, err
	}

	url := fmt.Sprintf("%s/privacyca/identity-challenge-request", config.GetConfiguration().HVS.Url)
	request, _:= http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	request.SetBasicAuth(config.GetConfiguration().HVS.Username, config.GetConfiguration().HVS.Password)
	request.Header.Set("Content-Type", "application/json")

//	fmt.Printf("JSON: %s\n", string(jsonData))

	response, err := client.Do(request)
    if err != nil {
        return nil, fmt.Errorf("%s request failed with error %s\n", url, err)
    } else {
		if response.StatusCode != http.StatusOK {
			b, _ := ioutil.ReadAll(response.Body)
			return nil, fmt.Errorf("%s returned status '%d': %s", url, response.StatusCode, string(b))
		}

		data, err := ioutil.ReadAll(response.Body)
		if err != nil {
			return nil, fmt.Errorf("Error reading response: %s", err)
		}

		err = json.Unmarshal(data, &identityProofRequest)
		if err != nil {
			return nil, err
		}
	}

	return &identityProofRequest, nil
}

func (task* ProvisionAttestationIdentityKey) activateIdentity(identityProofRequest *IdentityProofRequest) ([]byte, error) {
	return nil, fmt.Errorf("Not implemented")
}

func (task* ProvisionAttestationIdentityKey) getIdentityProofResponse(decrypted []byte) (*IdentityProofRequest, error) {

	var identityProofRequest IdentityProofRequest

	identityChallengeResponse := IdentityChallengeResponse {}
	identityChallengeResponse.responseToChallenge = decrypted
	err := task.populateIdentityRequest(&identityChallengeResponse.IdentityRequest)
	if err != nil {
		return nil, err
	}

	// HVS API

	return &identityProofRequest, fmt.Errorf("Not implemneted")
}