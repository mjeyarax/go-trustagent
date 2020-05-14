/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package tasks

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"encoding/hex"
	"math/big"

	//"encoding/pem"
	"fmt"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/privacyca"
	"github.com/intel-secl/intel-secl/v3/pkg/lib/privacyca/tpm2utils"
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

	identityChallengeRequest.TpmSymmetricKeyParams, identityChallengeRequest.SymBlob, err = tpm2utils.GetTpmSymmetricKeyParams(ekCertBytes)
	if err != nil {
		log.WithError(err).Error("tasks/provision_aik:Run() Error while encrypting the endorsement certificate bytes")
		return errors.New("Error while encrypting the endorsement certificate bytes")
	}
	privacyCaCert, _ := util.GetPrivacyCA()
	identityChallengeRequest.TpmAsymmetricKeyParams, identityChallengeRequest.AsymBlob, err = tpm2utils.GetTpmAsymmetricKeyParams(identityChallengeRequest.SymBlob, privacyCaCert)
	privacyCa, _ := privacyca.NewPrivacyCA(identityChallengeRequest.IdentityRequest)

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
	log.Info("===========")
	log.Infof("secret %v", identityProofRequest)
	log.Info("===========")
	log.Infof("Credential %v", identityProofRequest.Credential)
	log.Info("===========")
	log.Info("symblob %v", identityProofRequest.SymmetricBlob)
	log.Info("===========")

	// pass the HVS response to the TPM to 'activate' the 'credential' and decrypt
	// the nonce created by HVS (IdentityProofRequest 'sym_blob')
	decrypted1, err := task.activateCredential(identityProofRequest)
	if err != nil {
		return errors.Wrap(err, "tasks/provision_aik:Run() Error while performing activate credential task")
	}
	log.Info("activate credential is successful")

	// create an IdentityChallengeResponse to send back to HVS
	identityChallengeResponse := taModel.IdentityChallengePayload{}

	identityChallengeResponse.TpmSymmetricKeyParams, identityChallengeResponse.SymBlob, err = tpm2utils.GetTpmSymmetricKeyParams(decrypted1)
	if err != nil {
		log.WithError(err).Error("tasks/provision_aik:Run() Error while encrypting the endorsement certificate bytes")
		return errors.New("Error while encrypting the endorsement certificate bytes")
	}
	identityChallengeResponse.TpmAsymmetricKeyParams, identityChallengeResponse.AsymBlob, err = tpm2utils.GetTpmAsymmetricKeyParams(identityChallengeRequest.SymBlob, privacyCa)
	if err != nil {
		log.WithError(err).Error("tasks/provision_aik:Run() Error while encrypting nonce")
		return errors.New("Error while encrypting nonce")
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
	log.Infof("credentialSize %d", int(credentialSize))
	credentialBytes := buf.Next(int(credentialSize))
	//	credentialBytes = append(credentialBytes, byte(0x33))
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
	log.Infof("credentialBytes %v", credentialBytes)
	log.Infof("credentialBytes len %d", len(credentialBytes))
	log.Info("========================")
	log.Infof("secretBytes %v", secretBytes)
	log.Infof("secretBytes len %d", len(secretBytes))

	symmetricKey, err := tpm.ActivateCredential(*task.ownerSecretKey, *task.aikSecretKey, credentialBytes, secretBytes)
	if err != nil {
		return nil, errors.Wrap(err, "tasks/provision_aik:activateCredential() Error while performing tpm activate credential operation")
	}

	log.Info("ActivateCredential successful")
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

	log.Debugf("tasks/provision_aik:activateCredential() sym_blob[%d]: %s", len(identityProofRequest.SymmetricBlob), hex.EncodeToString(identityProofRequest.SymmetricBlob))
	log.Debugf("tasks/provision_aik:activateCredential() symmetric[%d]: %s", len(symmetricKey), hex.EncodeToString(symmetricKey))
	log.Debugf("tasks/provision_aik:activateCredential() Algo[%d], Enc[%d], sig[%d]", algoId, encSchem, sigSchem)
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

	return decrypted, nil
}
