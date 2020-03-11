/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package tasks

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"intel/isecl/go-trust-agent/constants"
	"intel/isecl/go-trust-agent/util"
	"intel/isecl/go-trust-agent/vsclient"
	"intel/isecl/lib/common/crypt"
	"intel/isecl/lib/common/setup"
	"intel/isecl/lib/common/log/message"
	"intel/isecl/lib/tpmprovider"
	"io/ioutil"
	"math/big"
	"os"

	"github.com/pkg/errors"
)

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
//     POST IdentityChallengeRequest to https://server.com:8443/mtwilson/v2/privacyca/identity-challenge-request
// 2.) Receive back an IdentityProofRequest that includes an encrypted nonce that is decrypted by
// the TPM/aik (via 'ActivateCredential').
// 3.) Send the nonce back to HVS (encrypted by the HVS privacy-ca). If the nonce checks out, HVS
// responds with an (encrypted) aik cert that is saved to /opt/trustagent/configuration/aik.cer.
//    POST 'decrypted bytes' to https://server.com:8443/mtwilson/v2/privacyca/identity-challenge-response
//
// The 'aik.cer' is served via the /v2/aik endpoint and included in /tpm/quote.
//
// Throughout this process, the TPM is being provisioned with the aik so that calls to /tpm/quote
// will be successful.  QUOTES WILL NOT WORK IF THE TPM IS NOT PROVISIONED CORRECTLY.
//-------------------------------------------------------------------------------------------------

type ProvisionAttestationIdentityKey struct {
	clientFactory vsclient.VSClientFactory
	tpmFactory tpmprovider.TpmFactory
	ownerSecretKey *string
	aikSecretKey *string	// out variable that can be set during setup
}

func (task *ProvisionAttestationIdentityKey) Run(c setup.Context) error {
	log.Trace("tasks/provision_aik:Run() Entering")
	defer log.Trace("tasks/provision_aik:Run() Leaving")
	fmt.Println("Running setup task: provision-aik")
	var err error

	privacyCAClient, err := task.clientFactory.PrivacyCAClient()
	if err != nil {
		log.WithError(err).Error("tasks/provision_aik:Run() Could not create privacy- client")
		return err
	}

	// generate the aik in the tpm
	err = task.createAik()
	if err != nil {
		return err
	}

	// create an IdentityChallengeRequest and populate it with aik information
	identityChallengeRequest := vsclient.IdentityChallengeRequest{}
	err = task.populateIdentityRequest(&identityChallengeRequest.IdentityRequest)
	if err != nil {
		log.WithError(err).Error("tasks/provision_aik:Run() Error while populating identity request")
		return errors.New("Error while populating identity request")
	}

	// get the EK cert from the tpm
	ekCertBytes, err := task.getEndorsementKeyBytes()
	if err != nil {
		log.WithError(err).Error("tasks/provision_aik:Run() Error while getting endorsement certificate in bytes from tpm")
		return errors.New("Error while getting endorsement certificate in bytes from tpm")
	}

	// encrypt the EK cert into binary that is acceptable to HVS/NAIRL
	identityChallengeRequest.EndorsementCertificate, err = task.getEncryptedBytes(ekCertBytes)
	if err != nil {
		log.WithError(err).Error("tasks/provision_aik:Run() Error while encrypting the endorsement certificate bytes")
		return errors.New("Error while encrypting the endorsement certificate bytes")
	}

	// send the 'challenge request' to HVS and get an 'proof request' back
	identityProofRequest, err := privacyCAClient.GetIdentityProofRequest(&identityChallengeRequest)
	if err != nil {
		log.WithError(err).Error("tasks/provision_aik:Run() Error while getting identity proof request from VS for a given challenge request with ek")
		return errors.New("Error while getting identity proof request from VS for a given challenge request with ek")
	}

	// pass the HVS response to the TPM to 'activate' the 'credential' and decrypt
	// the nonce created by HVS (IdentityProofRequest 'sym_blob')
	decrypted1, err := task.activateCredential(identityProofRequest)
	if err != nil {
		return errors.Wrap(err, "tasks/provision_aik:Run() Error while performing activate credential task")
	}

	// create an IdentityChallengeResponse to send back to HVS
	identityChallengeResponse := vsclient.IdentityChallengeResponse{}
	identityChallengeResponse.ResponseToChallenge, err = task.getEncryptedBytes(decrypted1)
	if err != nil {
		log.WithError(err).Error("tasks/provision_aik:Run() Error while encrypting nonce")
		return errors.New("Error while encrypting nonce")
	}

	// KWT: refactor so that the call to get AIK info is done once
	err = task.populateIdentityRequest(&identityChallengeResponse.IdentityRequest)
	if err != nil {
		log.WithError(err).Error("tasks/provision_aik:Run() Error while populating identity request with identity challenge response")
		return errors.New("Error while populating identity request with identity challenge response")
	}

	// send the decrypted nonce data back to HVS and get a 'proof request' back
	identityProofRequest2, err := privacyCAClient.GetIdentityProofResponse(&identityChallengeResponse)
	if err != nil {
		log.WithError(err).Error("tasks/provision_aik:Run() Error while retrieving identity proof response from HVS")
		return errors.New("Error while retrieving identity proof response from HVS")
	}

	// decrypt the 'proof request' from HVS into the 'aik' cert
	decrypted2, err := task.activateCredential(identityProofRequest2)
	if err != nil {
		log.WithError(err).Error("tasks/provision_aik:Run() Error while retrieving aik certificate bytes from identity proof request from HVS")
		return errors.New("Error while retrieving aik certificate bytes from identity proof request from HVS")
	}

	// make sure the decrypted bytes are a valid certificates...
	_, err = x509.ParseCertificate(decrypted2)
	if err != nil {
		log.WithError(err).Error("tasks/provision_aik:Run() Error while parsing the aik certificate")
		return errors.New("Error while parsing the aik certificate")
	}

	// save the aik pem cert to disk
	err = ioutil.WriteFile(constants.AikCert, decrypted2, 0600)
	if err != nil {
		log.WithError(err).Errorf("tasks/provision_aik:Run() Error while writing aik certificate file %s", constants.AikCert)
		return errors.Errorf("Error while writing aik certificate file %s", constants.AikCert)
	}

	certOut, err := os.OpenFile(constants.AikCert, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0)
	if err != nil {
		log.WithError(err).Error("tasks/provision_aik:Run() Error Could not open file for writing")
		return errors.New("Error: Could not open file for writing")
	}
	defer certOut.Close()

	os.Chmod(constants.AikCert, 0640)
	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: decrypted2}); err != nil {
		log.WithError(err).Error("tasks/provision_aik:Run() Error Could not pem encode cert: ")
		return errors.New("Error: Could not pem encode cert")
	}

	return nil
}

func (task *ProvisionAttestationIdentityKey) Validate(c setup.Context) error {
	log.Trace("tasks/provision_aik:Validate() Entering")
	defer log.Trace("tasks/provision_aik:Validate() Leaving")

	if _, err := os.Stat(constants.AikCert); os.IsNotExist(err) {
		log.WithError(err).Error("tasks/provision_aik:Validate() The aik certificate was not created ")
		return errors.New("The aik certificate was not created")
	}

	log.Info("tasks/provision_aik:Validate() Provisioning the AIK was successful.")
	return nil
}

func (task *ProvisionAttestationIdentityKey) createAik() error {
	log.Trace("tasks/provision_aik:createAik() Entering")
	defer log.Trace("tasks/provision_aik:createAik() Leaving")

	var err error

	if task.aikSecretKey == nil {
		return errors.New("aikSecretKey cannot be nil")
	}

	// if the configuration's aik secret has not been set, do it now...
	if *task.aikSecretKey == "" {
		*task.aikSecretKey, err = crypt.GetHexRandomString(20)
		log.Debug("tasks/provision_aik:createAik() Generated new AIK secret key")
	}

	tpm, err := task.tpmFactory.NewTpmProvider()
	if err != nil {
		return errors.Wrap(err,"tasks/provision_aik:createAik() createAik not create TpmProvider")
	}

	defer tpm.Close()
	err = tpm.CreateAik(*task.ownerSecretKey, *task.aikSecretKey)
	if err != nil {
		return errors.Wrap(err, "tasks/provision_aik:createAik() Error while creating Aik Key")
	}

	return nil
}

func (task *ProvisionAttestationIdentityKey) getTpmSymetricKey(key []byte) ([]byte, error) {
	log.Trace("tasks/provision_aik:getTpmSymetricKey() Entering")
	defer log.Trace("tasks/provision_aik:getTpmSymetricKey() Leaving")

	privacyCa, err := util.GetPrivacyCA()
	if err != nil {
		return nil, errors.Wrap(err, "tasks/provision_aik:getTpmSymetricKey() Error while retrieving PrivacyCA certificate")
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
	binary.Write(buf, binary.BigEndian, uint32(6))        // TpmKeyParams.TPM_ALG_AES
	binary.Write(buf, binary.BigEndian, uint16(255))      // TpmKeyParams.TPM_ES_SYM_CBC_PKCS5PAD
	binary.Write(buf, binary.BigEndian, uint16(len(key))) // length of key
	binary.Write(buf, binary.BigEndian, key)              // key bytes

	// ISECL-7702: Sha1 is being used for compatability with HVS --> needs to be fixed before release
	ekAsymetricBytes, err := rsa.EncryptOAEP(sha1.New(), bytes.NewBuffer(asymKey), privacyCa, buf.Bytes(), nil)
	if err != nil {
		return nil, errors.Wrap(err,"tasks/provision_aik:getTpmSymetricKey() Error encrypting tpm symmetric key")
	}
	secLog.Infof("%s tasks/provision_aik:getTpmSymetricKey() Returning encrypted tpm symmetric key", message.EncKeyUsed)

	return ekAsymetricBytes, nil
}

func (task *ProvisionAttestationIdentityKey) getEndorsementKeyBytes() ([]byte, error) {
	log.Trace("tasks/provision_aik:getEndorsementKeyBytes() Entering")
	defer log.Trace("tasks/provision_aik:getEndorsementKeyBytes() Leaving")

	//---------------------------------------------------------------------------------------------
	// Get the endorsement key certificate from the tpm
	//---------------------------------------------------------------------------------------------
	tpm, err := task.tpmFactory.NewTpmProvider()
	if err != nil {
		return nil, errors.Wrap(err, "tasks/provision_aik:getEndorsementKeyBytes() Error while creating NewTpmProvider")
	}

	defer tpm.Close()

	ekCertBytes, err := tpm.NvRead(*task.ownerSecretKey, tpmprovider.NV_IDX_ENDORSEMENT_KEY)
	if err != nil {
		return nil, errors.Wrap(err, "tasks/provision_aik:getEndorsementKeyBytes() Error while performing tpm Nv read operation for getting endorsement certificate in bytes")
	}

	return ekCertBytes, nil

}

//
// Creates a byte structure with encrpted data similar to gov.niarl.his.privacyca.TpmIdentityRequest
//
// Asymetric encryption:  RSA, RSAESOAEP_SHA1_MGF1?, 2048 (see TpmIdentityRequest.createDefaultAsymAlgorithm)
// Symetric encryption: 16 random bytes, RSA, TPM_ES_RSAESOAEP_SHA1_MGF1, 2048 (see createDefaultSymAlgorithm)
//
func (task *ProvisionAttestationIdentityKey) getEncryptedBytes(unencrypted []byte) ([]byte, error) {
	log.Trace("tasks/provision_aik:getEncryptedBytes() Entering")
	defer log.Trace("tasks/provision_aik:getEncryptedBytes() Leaving")
	//---------------------------------------------------------------------------------------------
	// Encrypt the bytes using aes from https://golang.org/pkg/crypto/cipher/#example_NewCBCEncrypter
	//---------------------------------------------------------------------------------------------
	if len(unencrypted)%aes.BlockSize != 0 {
		return nil, errors.Errorf( "tasks/provision_aik:getEncryptedBytes() byte length (%d) is not a multiple of the block size (%d)", len(unencrypted), aes.BlockSize)
	}

	cipherKey, err := crypt.GetRandomBytes(16)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(cipherKey)
	if err != nil {
		return nil, err
	}

	iv, err := crypt.GetRandomBytes(16) // aes.Blocksize == 16
	if err != nil {
		return nil, err
	}

	mode := cipher.NewCBCEncrypter(block, iv)

	// this 'hand padding' is necessary for the java/niarl to
	// successully decrypt the symetric data (ek pub cert)
	padding := block.BlockSize() - len(unencrypted)%block.BlockSize()
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	withPadding := append(unencrypted, padtext...)

	symmetricBytes := make([]byte, len(withPadding))
	mode.CryptBlocks(symmetricBytes, withPadding)

	asymmetricBytes, err := task.getTpmSymetricKey(cipherKey)
	if err != nil {
		return nil, errors.Wrap(err, "tasks/provision_aik:getEncryptedBytes() Error while retrieving tpm symmetric key")
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
	//---------------------------------------------------------------------------------------------
	buf := new(bytes.Buffer)

	binary.Write(buf, binary.BigEndian, uint32(len(asymmetricBytes))) // length of encrypted symetric key data
	binary.Write(buf, binary.BigEndian, uint32(len(symmetricBytes)))  // length of encrypted ek cert

	// TpmKeyParams.java
	binary.Write(buf, binary.BigEndian, uint32(1))    // TpmKeyParams.TPM_ALG_RSA
	binary.Write(buf, binary.BigEndian, uint16(3))    // TpmKeyParams.TPM_ES_RSAESOAEP_SHA1_MGF1
	binary.Write(buf, binary.BigEndian, uint16(1))    // TPM_SS_NONE
	binary.Write(buf, binary.BigEndian, uint32(12))   // Size of params
	binary.Write(buf, binary.BigEndian, uint32(2048)) // Param keylength (2048 RSA)
	binary.Write(buf, binary.BigEndian, uint32(2))    // Param num of primes
	binary.Write(buf, binary.BigEndian, uint32(0))    // Param exponent size

	// TpmKeyParams.java
	binary.Write(buf, binary.BigEndian, uint32(6))   // TpmKeyParams.TPM_ALG_AES
	binary.Write(buf, binary.BigEndian, uint16(255)) // TpmKeyParams.TPM_ES_SYM_CBC_PKCS5PAD
	binary.Write(buf, binary.BigEndian, uint16(1))   // TpmKeyParams.TPM_SS_NONE
	binary.Write(buf, binary.BigEndian, uint32(28))  // Size of params (following data in TpmSymetricKeyParams)
	// TpmSymetrictKeyParams.java
	binary.Write(buf, binary.BigEndian, uint32(128))     // Param keylength (128 AES)
	binary.Write(buf, binary.BigEndian, uint32(128))     // Param block size (128 AES)
	binary.Write(buf, binary.BigEndian, uint32(len(iv))) // length of iv
	binary.Write(buf, binary.BigEndian, iv)              // iv (16 bytes)

	// actual bytes
	binary.Write(buf, binary.BigEndian, asymmetricBytes)
	binary.Write(buf, binary.BigEndian, symmetricBytes)

	b := buf.Bytes()
	return b, nil
}

func (task *ProvisionAttestationIdentityKey) populateIdentityRequest(identityRequest *vsclient.IdentityRequest) error {
	log.Trace("tasks/provision_aik:populateIdentityRequest() Entering")
	defer log.Trace("tasks/provision_aik:populateIdentityRequest() Leaving")

	tpm, err := task.tpmFactory.NewTpmProvider()
	if err != nil {
		return errors.Wrap(err,"tasks/provision_aik:populateIdentityRequest() Error while creating new TpmProvider")
	}

	defer tpm.Close()

	// get the aik's public key and populate into the identityRequest
	aikPublicKeyBytes, err := tpm.GetAikBytes(*task.ownerSecretKey)
	if err != nil {
		return err
	}

	identityRequest.IdentityRequestBlock = aikPublicKeyBytes
	identityRequest.AikModulus = aikPublicKeyBytes

	identityRequest.TpmVersion = "2.0" // Assume TPM 2.0 for GTA (1.2 is no longer supported)
	identityRequest.AikBlob = new(big.Int).SetInt64(tpmprovider.TPM_HANDLE_AIK).Bytes()

	identityRequest.AikName, err = tpm.GetAikName(*task.ownerSecretKey)
	if err != nil {
		return errors.Wrap(err, "tasks/provision_aik:populateIdentityRequest() Error while retrieving Aik Name from tpm")
	}

	return nil
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
//   - EndorsementKeyBlob:  SHA256 of this node's EK public using the Aik modules
// - Use the symmetric key to decrypt the nonce (also requires iv) created by PrivacyCa.java::processV20
//
func (task *ProvisionAttestationIdentityKey) activateCredential(identityProofRequest *vsclient.IdentityProofRequest) ([]byte, error) {
	log.Trace("tasks/provision_aik:activateCredential() Entering")
	defer log.Trace("tasks/provision_aik:activateCredential() Leaving")

	tpm, err := task.tpmFactory.NewTpmProvider()
	if err != nil {
		return nil, errors.Wrap(err, "tasks/provision_aik:activateCredential() Error while creating NewTpmProvider")
	}

	defer tpm.Close()

	//
	// Read the credential bytes from the identityProofRequest
	// The bytes returned by HVS hava 2 bytes short of the length of the credential (TCG spec).
	// Could probably do a slice (i.e. [2:]) but let's read the length and validate the length.
	//
	var credentialSize uint16
	buf := bytes.NewBuffer(identityProofRequest.Credential)
	binary.Read(buf, binary.BigEndian, &credentialSize)
	if credentialSize == 0 || int(credentialSize) > len(identityProofRequest.Credential) {
		return nil, errors.Errorf("tasks/provision_aik:activateCredential() Invalid credential size %d", credentialSize)
	}

	credentialBytes := buf.Next(int(credentialSize))

	//
	// Read the secret bytes similar to credential (i.e. with 2 byte size header)
	//
	var secretSize uint16
	buf = bytes.NewBuffer(identityProofRequest.Secret)
	binary.Read(buf, binary.BigEndian, &secretSize)
	if secretSize == 0 || int(secretSize) > len(identityProofRequest.Secret) {
		return nil, errors.Errorf("tasks/provision_aik:activateCredential() Invalid secretSize size %d", secretSize)
	}

	secretBytes := buf.Next(int(secretSize))
	log.Debugf("tasks/provision_aik:activateCredential() secretBytes: %d", len(secretBytes))

	//
	// Now decrypt the symetric key using ActivateCredential
	//
	symmetricKey, err := tpm.ActivateCredential(*task.ownerSecretKey, *task.aikSecretKey, credentialBytes, secretBytes)
	if err != nil {
		return nil, errors.Wrap(err, "tasks/provision_aik:activateCredential() Error while performing tpm activate credential operation")
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
	var iv []byte
	var encryptedBytes []byte

	buf = bytes.NewBuffer(identityProofRequest.SymetricBlob)
	binary.Read(buf, binary.BigEndian, &encryptedBlobLength)
	binary.Read(buf, binary.BigEndian, &algoId)
	binary.Read(buf, binary.BigEndian, &encSchem)
	binary.Read(buf, binary.BigEndian, &sigSchem)
	binary.Read(buf, binary.BigEndian, &size)
	iv = buf.Next(16)
	encryptedBytes = buf.Next(int(encryptedBlobLength) - len(iv))

	log.Debugf("tasks/provision_aik:activateCredential() sym_blob[%d]: %s", len(identityProofRequest.SymetricBlob), hex.EncodeToString(identityProofRequest.SymetricBlob))
	log.Debugf("tasks/provision_aik:activateCredential() symmetric[%d]: %s", len(symmetricKey), hex.EncodeToString(symmetricKey))
	log.Debugf("tasks/provision_aik:activateCredential() Len[%d], Algo[%d], Enc[%d], sig[%d], size[%d]", encryptedBlobLength, algoId, encSchem, sigSchem, size)
	log.Debugf("tasks/provision_aik:activateCredential() iv[%d]: %s", len(iv), hex.EncodeToString(iv))
	log.Debugf("tasks/provision_aik:activateCredential() encrypted[%d]: %s", len(encryptedBytes), hex.EncodeToString(encryptedBytes))

	// decrypt the symblob using the symmetric key
	block, err := aes.NewCipher(symmetricKey)
	if err != nil {
		return nil, err
	}

	decrypted := make([]byte, len(encryptedBytes))
	log.Debugf("tasks/provision_aik:activateCredential() ==> decrypted[%d]: %s", len(decrypted), hex.EncodeToString(decrypted))

	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(decrypted, encryptedBytes)

	length := len(decrypted)
	unpadding := int(decrypted[length-1])
	decrypted = decrypted[:(length - unpadding)]

	return decrypted, nil
}
