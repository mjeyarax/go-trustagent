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
	//"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	log "github.com/sirupsen/logrus"
	"intel/isecl/go-trust-agent/config"
	"intel/isecl/go-trust-agent/constants"
	"intel/isecl/lib/tpmprovider"
	"intel/isecl/lib/common/crypt"
	"intel/isecl/lib/common/setup"
)

// KWT:  This file needs TLC

//-------------------------------------------------------------------------------------------------
// P R O V I S I O N   A I K 
//-------------------------------------------------------------------------------------------------
// The goal of ProvisionAttestationIdentityKey task is to create an aik that can be used to support
// tpm quotes.  This includes a number of 'handshakes' with HVS where nonces are exchanged to make 
// sure the TPM/aik is valid.
//
// The handshake steps are...
// 1.) Send HVS an IdentityChallengeRequest that contains aik data and encrypted EK data (using HVS'
// privacy-ca) in niarl binary format.
// 2.) Receive back an IdentityProofRequest that includes an encrypted nonce that is decrypted by 
// the TPM/aik ('ActivateCredential'). 
// 3.) Send the nonce back to HVS (encrypted by the HVS privacy-ca). If the nonce checks out, HVS
// responds with an (encrypted) aik cert that is saved to /opt/trustagent/configuration/aik.cer.
//
// The 'aik.cer' is served via the /v2/aik endpoint and included in /tpm/quote.  
// 
// Throughout this process, the TPM is being provisioned with the aik so that calls to /tpm/quote
// will be successful.  QUOTES WILL NOT WORK IF THE TPM IS NO PROVISIONED CORRECTLY.
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

	var err error

	// generate the aik in the tpm
	err = task.createAik()
	if err != nil {
		return err
	} 

	// create an IdentiryChallengeRequest and populate it with aik information
	identityChallengeRequest := IdentityChallengeRequest {}
	err = task.populateIdentityRequest(&identityChallengeRequest.IdentityRequest)
	if err != nil {
		return err
	} 

	// get the EK cert from the tpm
	ekCertBytes, err := task.getEndorsementKeyBytes()
	if err != nil {
		return err
	}

	// encrypt the EK cert into binary that is acceptable to HVS/NAIRL
	identityChallengeRequest.EndorsementCertificate, err = task.getEncryptedBytes(ekCertBytes)
	if err != nil {
		return err
	}

	// send the 'challenge request' to HVS and get an 'proof request' back
	identityProofRequest, err := task.getIdentityProofRequest(&identityChallengeRequest)
	if err != nil {
		return err
	}

	// pass the HVS response to the TPM to 'activate' the 'credential' and decrypt
	// the nonce created by HVS (IdentityProofRequest 'sym_blob')
	decrypted1, err := task.activateCredential(identityProofRequest)
	if err != nil {
		return err
	}

	// log.Debugf("Decrypted1[%x]: %s", len(decrypted1), hex.EncodeToString(decrypted1))
	// log.Debugf("Decrypted1[%x]: %s", len(decrypted1), string(decrypted1))

	// create an IdentityChallengeResponse to send back to HVS
	identityChallengeResponse := IdentityChallengeResponse {}
	identityChallengeResponse.ResponseToChallenge, err = task.getEncryptedBytes(decrypted1)
	if err != nil {
		return err
	}

	// KWT: refactor so that the call to get AIK info is done once
	err = task.populateIdentityRequest(&identityChallengeResponse.IdentityRequest)
	if err != nil {
		return err
	}

	// send the decrypted nonce data back to HVS and get a 'proof request' back
	identityProofRequest2, err := task.getIdentityProofResponse(&identityChallengeResponse)
	if err != nil {
		return err
	}

	// decrypt the 'proof request' from HVS into the 'aik' cert
	decrypted2, err := task.activateCredential(identityProofRequest2);
	if err != nil {
		return err
	}

	// make sure the decrypted bytes are a valid certificates...
	_, err = x509.ParseCertificate(decrypted2)
	if err != nil {
		return err
	}

	// save the aik cert to disk
	err = ioutil.WriteFile(constants.AikCert, decrypted2, 0600)
	if err != nil {
		return err
	}

	// // save the aik blob to disk
	// err = ioutil.WriteFile(constants.AikBlob, identityChallengeRequest.IdentityRequest.AikBlob, 0600)
	// if err != nil {
	// 	return err
	// }

	// 'finalize' the aik in the tpm....
	// err = task.finalizeAik()
	// if err != nil {
	// 	return err
	// }

	return nil
}


func (task* ProvisionAttestationIdentityKey) Validate(c setup.Context) error {

	if _, err := os.Stat(constants.AikCert); os.IsNotExist(err) {
		return fmt.Errorf("The aik certficate was not created")
	}

	log.Info("Setup: Provisioning the AIK was successful.")
	return nil
}

func (task* ProvisionAttestationIdentityKey) createAik() error {

	var err error

	// if the configuration's aik secret has not been set, do it now...
	if config.GetConfiguration().Tpm.AikSecretKey == "" {
		config.GetConfiguration().Tpm.AikSecretKey, err = crypt.GetHexRandomString(20)
		err = config.GetConfiguration().Save()
		if err != nil {
			return fmt.Errorf("Setup error:  Error saving config [%s]", err)
		}

		log.Debug("Generated new AIK secret key")
	}

	tpm, err := tpmprovider.NewTpmProvider()
	if err != nil {
		return fmt.Errorf("Setup error: createAik not create TpmProvider: %s", err)
	}

	defer tpm.Close()

	// present, err := tpm.IsAikPresent(config.GetConfiguration().Tpm.SecretKey) 
	// if err != nil {
	// 	return err
	// }

	// if !present {
		err = tpm.CreateAik(config.GetConfiguration().Tpm.SecretKey, config.GetConfiguration().Tpm.AikSecretKey)
		if err != nil {
			return err
		}
	//}

	return nil
}

// func (task* ProvisionAttestationIdentityKey) finalizeAik() error {
// 	var err error

// 	tpm, err := tpmprovider.NewTpmProvider()
// 	if err != nil {
// 		return fmt.Errorf("Setup error: finalizeAik not create TpmProvider: %s", err)
// 	}

// 	defer tpm.Close()

// 	err = tpm.FinalizeAik(config.GetConfiguration().Tpm.AikSecretKey)
// 	if err != nil {
// 		return err
// 	}

// 	return nil
// }

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
	// binary.Write(buf, binary.BigEndian, []byte("TCPA"))	// 24-28
	// binary.Write(buf, binary.BigEndian, []byte("TCPA"))	// 28-32
	// binary.Write(buf, binary.BigEndian, []byte("TCPA"))	// 32-36
	// binary.Write(buf, binary.BigEndian, []byte("TCPA"))	// 36-40

	// KWT:  Sha1 is being used for compatability with HVS --> needs to be fixed before release
	//ekAsymetricBytes, err := rsa.EncryptOAEP(sha1.New(), bytes.NewBuffer(asymKey), privacyCa, buf.Bytes(), []byte("TCPA"))
	ekAsymetricBytes, err := rsa.EncryptOAEP(sha1.New(), bytes.NewBuffer(asymKey), privacyCa, buf.Bytes(), nil)
	if err != nil {
		return nil, fmt.Errorf("Error encrypting tpm symetric key: %s", err)
	}

//	log.Debugf("RSA[%x]: %s\n\n", len(ekAsymetricBytes), hex.EncodeToString(ekAsymetricBytes))
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

	ekCertBytes, err := tpm.NvRead(config.GetConfiguration().Tpm.SecretKey, tpmprovider.NV_IDX_ENDORSEMENT_KEY)
	if err != nil {
		return nil, err
	}
	
	return ekCertBytes, nil 

}

//
// Creates a byte structure with encrpted data similar to gov.niarl.his.privacyca.TpmIdentityRequest
//
// Asymetric encryption:  RSA, RSAESOAEP_SHA1_MGF1?, 2048 (see TpmIdentityRequest.createDefaultAsymAlgorithm)
// Symetric encryption: 16 random bytes, RSA, TPM_ES_RSAESOAEP_SHA1_MGF1, 2048 (see createDefaultSymAlgorithm)
//
func (task* ProvisionAttestationIdentityKey) getEncryptedBytes(unencrypted []byte) ([]byte, error) {

	//---------------------------------------------------------------------------------------------
	// Encrypt the bytes using aes from https://golang.org/pkg/crypto/cipher/#example_NewCBCEncrypter
	//---------------------------------------------------------------------------------------------
	if len(unencrypted) % aes.BlockSize != 0 {
		return nil, fmt.Errorf("byte length (%x) is not a multiple of the block size (%x)", len(unencrypted), aes.BlockSize)
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
	padding := block.BlockSize() - len(unencrypted)%block.BlockSize()
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	withPadding  := append(unencrypted, padtext...)

	symmetricBytes := make([]byte, len(withPadding))
	mode.CryptBlocks(symmetricBytes, withPadding)

	asymmetricBytes, err := task.getTpmSymetricKey(cipherKey)
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

	binary.Write(buf, binary.BigEndian, uint32(len(asymmetricBytes)))	// length of encrypted symetric key data
	binary.Write(buf, binary.BigEndian, uint32(len(symmetricBytes)))	// length of encrypted ek cert 

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
	binary.Write(buf, binary.BigEndian, asymmetricBytes)
	binary.Write(buf, binary.BigEndian, symmetricBytes)

	b := buf.Bytes()
	//log.Infof("===\n%s\n\n", hex.EncodeToString(b))
	return b, nil
}

func (task* ProvisionAttestationIdentityKey) populateIdentityRequest(identityRequest *IdentityRequest) error {

	tpm, err := tpmprovider.NewTpmProvider()
	if err != nil {
		return fmt.Errorf("Setup error: populateIdentityRequest not create TpmProvider: %s", err)
	}

	defer tpm.Close()

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

	log.Debugf("ChallengeRequest: %s", jsonData)

	url := fmt.Sprintf("%s/privacyca/identity-challenge-request", config.GetConfiguration().HVS.Url)
	request, _:= http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	request.SetBasicAuth(config.GetConfiguration().HVS.Username, config.GetConfiguration().HVS.Password)
	request.Header.Set("Content-Type", "application/json")

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

		//log.Debugf("Proof Request: %s\n", string(data))

		err = json.Unmarshal(data, &identityProofRequest)
		if err != nil {
			return nil, err
		}
	}

	return &identityProofRequest, nil
}


//
// - Input: IdentityProofRequest (Secret, Credential, SymmetricBlob, EndorsementCertifiateBlob)
//		HVS has encrypted a nonce in the SymmetricBlob
// - Pass the Credential and Secret to TPM (ActivateCredential) and get the symmetric key back
// - Proof Request Data
//	 - Secret: made from this host's public EK in Tpm2.makeCredential
//	 - Credential: made from this host's public EK in Tpm2.makeCredential
//   - SymmetricBlob
//     - int32 length of encrypted blob
//     - TpmKeyParams
//       - int32 algo id (TpmKeyParams.TPM_ALG_AES)
//       - short encoding scheme (TpmKeyParams.TPM_ES_NONE)
//       - short signature scheme (0)
//       - size of params (0)
//     - Encrypted Blob
//       - iv (16 bytes)
//       - encrypted byted (encrypted blob length - 16 (iv))
//   - EndorsementKeyBlob:  SHA256 of this node's EK public using the Aik modules (TODO:  Verify hash)
// - Use the symmetric key to decrypt the nonce (also requires iv) created by PrivacyCa.java::processV20

//
func (task* ProvisionAttestationIdentityKey) activateCredential(identityProofRequest *IdentityProofRequest) ([]byte, error) {

	tpm, err := tpmprovider.NewTpmProvider()
	if err != nil {
		return nil, fmt.Errorf("Setup error: activateCredential not create TpmProvider: %s", err)
	}

	defer tpm.Close()

	//
	// Read the credential bytes
	// The bytes returned by HVS hava 2 byte short of the length of the credential (TCG spec).
	// Could probably do a slice (i.e. [2:]) but let's read the length and validate the length.
	//
//	log.Debugf("identityProofRequest.Credentials[%d]: %s", len(identityProofRequest.Credential), hex.EncodeToString(identityProofRequest.Credential))
	var credentialSize uint16
	buf := bytes.NewBuffer(identityProofRequest.Credential)
	binary.Read(buf, binary.BigEndian, &credentialSize)
	if (credentialSize == 0 || int(credentialSize) > len(identityProofRequest.Credential)) {
		return nil, fmt.Errorf("Invalid credential size %d", credentialSize)
	}

	credentialBytes := buf.Next(int(credentialSize))
//	log.Debugf("credentialBytes: %s",  hex.EncodeToString(credentialBytes))


	//
	// Read the secret bytes similar to credential (i.e. with 2 byte size header)
	//
//	log.Debugf("identityProofRequest.Secret[%d]: %s", len(identityProofRequest.Secret), hex.EncodeToString(identityProofRequest.Secret))
	var secretSize uint16
	buf = bytes.NewBuffer(identityProofRequest.Secret)
	binary.Read(buf, binary.BigEndian, &secretSize)
	if (secretSize == 0 || int(secretSize) > len(identityProofRequest.Secret)) {
		return nil, fmt.Errorf("Invalid secretSize size %d", secretSize)
	}

	secretBytes := buf.Next(int(secretSize))
	log.Debugf("secretBytes: %d",  len(secretBytes))

	//
	// Now decrypt the symetric key using ActivateCredential
	//
	symmetricKey, err := tpm.ActivateCredential(config.GetConfiguration().Tpm.SecretKey, config.GetConfiguration().Tpm.AikSecretKey, credentialBytes, secretBytes)
	if err != nil {
		return nil, err
	}


//   - SymmetricBlob
//     - int32 length of encrypted blob
//     - TpmKeyParams
//       - int32 algo id (TpmKeyParams.TPM_ALG_AES)
//       - short encoding scheme (TpmKeyParams.TPM_ES_NONE)
//       - short signature scheme (0)
//       - int32 size of params (0)
//     - Encrypted Blob
//       - iv (16 bytes)
//       - encrypted byted (encrypted blob length - 16 (iv))

	var encryptedBlobLength int32
	var algoId int32
	var encSchem int16
	var sigSchem int16
	var size int32
//	var paramSize int32
	var iv []byte
	var encryptedBytes []byte

	buf = bytes.NewBuffer(identityProofRequest.SymetricBlob)
	binary.Read(buf, binary.BigEndian, &encryptedBlobLength)
	binary.Read(buf, binary.BigEndian, &algoId)	
	binary.Read(buf, binary.BigEndian, &encSchem)	
	binary.Read(buf, binary.BigEndian, &sigSchem)	
	binary.Read(buf, binary.BigEndian, &size)
//	binary.Read(buf, binary.BigEndian, &paramSize)
	iv = buf.Next(16)
	encryptedBytes = buf.Next(int(encryptedBlobLength) - len(iv))
//	encryptedBytes = buf.Next(int(encryptedBlobLength))
//	iv = encryptedBytes[:16]

	log.Debugf("sym_blob[%d]: %s", len(identityProofRequest.SymetricBlob), hex.EncodeToString(identityProofRequest.SymetricBlob))
	log.Debugf("symmetric[%d]: %s", len(symmetricKey), hex.EncodeToString(symmetricKey))
	log.Debugf("Len[%d], Algo[%d], Enc[%d], sig[%d], size[%d]", encryptedBlobLength, algoId, encSchem, sigSchem, size)
	log.Debugf("iv[%d]: %s", len(iv), hex.EncodeToString(iv))
	log.Debugf("encrypted[%d]: %s", len(encryptedBytes), hex.EncodeToString(encryptedBytes))

	// padding := block.BlockSize() - len(encryptedBytes)%block.BlockSize()
	// padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	// withPadding  := append(encryptedBytes, padtext...)
	// log.Debugf("Padding: %d", padding)

	// decrypted := make([]byte, len(withPadding))
	// mode := cipher.NewCBCDecrypter(block, iv)
	// mode.CryptBlocks(decrypted, withPadding)

	// decrypt the symblob using the symmetric key
	block, err := aes.NewCipher(symmetricKey)
	if err != nil {
		return nil, err
	}

	decrypted := make([]byte, len(encryptedBytes))
	log.Debugf("==> decrypted[%d]: %s", len(decrypted), hex.EncodeToString(decrypted))

	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(decrypted, encryptedBytes)

	// log.Debugf("==> decrypted[%d]: %s", len(decrypted), hex.EncodeToString(decrypted))
	// decrypted = decrypted[:32]
	// log.Debugf("==> decrypted[%d]: %s", len(decrypted), hex.EncodeToString(decrypted))

	length := len(decrypted)
	unpadding := int(decrypted[length-1])
	decrypted = decrypted[:(length - unpadding)]

	return decrypted, nil

}

func (task* ProvisionAttestationIdentityKey) getIdentityProofResponse(identityChallengeResponse* IdentityChallengeResponse) (*IdentityProofRequest, error) {

	var identityProofRequest IdentityProofRequest

	client, err := newMtwilsonClient()
	if err != nil {
		return nil, err
	}

	jsonData, err := json.Marshal(*identityChallengeResponse)
	if err != nil {
		return nil, err
	}

	log.Debugf("identityChallengeResponse: %s\n", string(jsonData))


	url := fmt.Sprintf("%s/privacyca/identity-challenge-response", config.GetConfiguration().HVS.Url)
	request, _:= http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	request.SetBasicAuth(config.GetConfiguration().HVS.Username, config.GetConfiguration().HVS.Password)
	request.Header.Set("Content-Type", "application/json")

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

		log.Debugf("Proof Response: %s\n", string(data))

		err = json.Unmarshal(data, &identityProofRequest)
		if err != nil {
			return nil, err
		}
	}

	return &identityProofRequest, nil
}