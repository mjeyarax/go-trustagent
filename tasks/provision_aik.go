/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package tasks

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/privacyca"
	"io/ioutil"
	"math/big"

	"fmt"
	taModel "github.com/intel-secl/intel-secl/v3/pkg/model/ta"
	"intel/isecl/go-trust-agent/v2/constants"
	"intel/isecl/go-trust-agent/v2/util"
	"intel/isecl/go-trust-agent/v2/vsclient"
	"intel/isecl/lib/common/v2/crypt"
	"intel/isecl/lib/common/v2/setup"
	"intel/isecl/lib/tpmprovider/v2"
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
	clientFactory  vsclient.VSClientFactory
	tpmFactory     tpmprovider.TpmFactory
	ownerSecretKey *string
	aikSecretKey   *string // out variable that can be set during setup
}

func (task *ProvisionAttestationIdentityKey) Run(c setup.Context) error {
	log.Trace("tasks/provision_aik:Run() Entering")
	defer log.Trace("tasks/provision_aik:Run() Leaving")
	fmt.Println("Running setup task: provision-aik")
	var err error

	// generate the aik in the tpm
	err = task.createAik()
	if err != nil {
		return err
	}

	// create an IdentityChallengeRequest and populate it with aik information
	identityChallengeRequest := taModel.IdentityChallengePayload{}
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

	privacyCaCert, err := util.GetPrivacyCA()
	if err != nil {
		log.WithError(err).Error("tasks/provision_aik:Run() Error while retrieving privacyca certificate")
		return errors.Wrap(err, "Error while retrieving privacyca certificate")
	}

	privacycaTpm2, err := privacyca.NewPrivacyCA(identityChallengeRequest.IdentityRequest)
	if err != nil{
		log.WithError(err).Error("tasks/provision_aik:Run() Unable to get new privacyca instance")
		return errors.Wrap(err, "Unable to get new privacyca instance")
	}
	identityChallengeRequest, err = privacycaTpm2.GetIdentityChallengeRequest(ekCertBytes, privacyCaCert, identityChallengeRequest.IdentityRequest)
	if err != nil {
		log.WithError(err).Error("tasks/provision_aik:Run() Error while encrypting the endorsement certificate bytes")
		return errors.Wrap(err,"Error while encrypting the endorsement certificate bytes")
	}

	privacyCAClient, err := task.clientFactory.PrivacyCAClient()
	if err != nil {
		log.WithError(err).Error("tasks/provision_aik:Run() Could not create privacy- client")
		return err
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
	log.Info("tasks/provision_aik:Run() Activate credential is successful for identity challenge request")

	// create an IdentityChallengeResponse to send back to HVS
	identityChallengeResponse := taModel.IdentityChallengePayload{}

	// KWT: refactor so that the call to get AIK info is done once
	err = task.populateIdentityRequest(&identityChallengeResponse.IdentityRequest)
	if err != nil {
		log.WithError(err).Error("tasks/provision_aik:Run() Error while populating identity request with identity challenge response")
		return errors.New("Error while populating identity request with identity challenge response")
	}

	identityChallengeResponse, err = privacycaTpm2.GetIdentityChallengeRequest(decrypted1, privacyCaCert, identityChallengeResponse.IdentityRequest)

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

	log.Info("tasks/provision_aik:Run() Activate credential is successful for identity challenge response")
	// The aik cert bytes is padded before AES CBC encryption, padded bytes must be removed to retrieve the aik certificate bytes
	length := len(decrypted2)
	unpadding := int(decrypted2[length-1])
	decrypted2 = decrypted2[:(length - unpadding)]
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
		return errors.Wrap(err, "tasks/provision_aik:createAik() createAik not create TpmProvider")
	}

	defer tpm.Close()
	err = tpm.CreateAik(*task.ownerSecretKey, *task.aikSecretKey)
	if err != nil {
		return errors.Wrap(err, "tasks/provision_aik:createAik() Error while creating Aik Key")
	}

	return nil
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

func (task *ProvisionAttestationIdentityKey) populateIdentityRequest(identityRequest *taModel.IdentityRequest) error {
	log.Trace("tasks/provision_aik:populateIdentityRequest() Entering")
	defer log.Trace("tasks/provision_aik:populateIdentityRequest() Leaving")

	tpm, err := task.tpmFactory.NewTpmProvider()
	if err != nil {
		return errors.Wrap(err, "tasks/provision_aik:populateIdentityRequest() Error while creating new TpmProvider")
	}

	defer tpm.Close()

	// get the aik's public key and populate into the identityRequest
	aikPublicKeyBytes, err := tpm.GetAikBytes()
	if err != nil {
		return err
	}

	identityRequest.IdentityRequestBlock = aikPublicKeyBytes
	identityRequest.AikModulus = aikPublicKeyBytes

	identityRequest.TpmVersion = "2.0" // Assume TPM 2.0 for GTA (1.2 is no longer supported)
	identityRequest.AikBlob = new(big.Int).SetInt64(tpmprovider.TPM_HANDLE_AIK).Bytes()

	identityRequest.AikName, err = tpm.GetAikName()
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
func (task *ProvisionAttestationIdentityKey) activateCredential(identityProofRequest *taModel.IdentityProofRequest) ([]byte, error) {
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
	log.Info("Now decrypt the symetric key using ActivateCredential")

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

	encryptedBytes := identityProofRequest.SymmetricBlob
	algoId := identityProofRequest.TpmSymmetricKeyParams.TpmAlgId
	encSchem := identityProofRequest.TpmSymmetricKeyParams.TpmAlgEncScheme
	sigSchem := identityProofRequest.TpmSymmetricKeyParams.TpmAlgSignatureScheme
	iv := identityProofRequest.TpmSymmetricKeyParams.IV

	log.Debugf("tasks/provision_aik:activateCredential() Algo[%d], Enc[%d], sig[%d]", algoId, encSchem, sigSchem)

	// decrypt the symblob using the symmetric key
	block, err := aes.NewCipher(symmetricKey)
	if err != nil {
		return nil, err
	}

	decrypted := make([]byte, len(encryptedBytes))
	
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(decrypted, encryptedBytes)

	return decrypted, nil
}
