/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
 package tpmprovider

// #include "tpm.h"
import "C"

import (
	"crypto"
)

type CertifiedKey struct {
//	Version        constants.Version
//	Usage          constants.Usage
	PublicKey      []byte
	PrivateKey     []byte
	KeySignature   []byte
	KeyAttestation []byte
	// KeyName may be nil if the key comes from a TPM 1.2 chip
	KeyName []byte
}

// provides go visibility to values defined in tpm.h (shared with c code)
const (
	NV_IDX_ENDORSEMENT_KEY = C.NV_IDX_ENDORSEMENT_KEY
	TPM_HANDLE_AIK		   = C.TPM_HANDLE_AIK
	TPM_HANDLE_EK		   = C.TPM_HANDLE_EK_CERT
)

type TpmProvider interface {
	Close()

	Version() C.TPM_VERSION
	CreateCertifiedKey(/*usage constants.Usage, */ keyAuth []byte, aikAuth []byte) (*CertifiedKey, error)
	Unbind(ck *CertifiedKey, keyAuth []byte, encData []byte) ([]byte, error)
	Sign(ck *CertifiedKey, keyAuth []byte, alg crypto.Hash, hashed []byte) ([]byte, error)
//	GetModuleLog() (string, error)
//	GetTcbMeasurement() (string, error)



	// Overview of function here
	TakeOwnership(tpmSecretKey []byte) error
	IsOwnedWithAuth(ownerAuth []byte) (bool, error)
	
	GetEndorsementKeyCertificate(tpmSecretKey string) ([]byte, error)

	IsAikPresent(tpmSecretKey string) (bool, error)
	CreateAik(tpmSecretKey string, aikSecretKey string) error
	GetAikBytes(tpmSecretKey string) ([]byte, error)
	GetAikName(tpmSecretKey string) ([]byte, error)

	ActivateCredential(tpmSecretKey string, aikSecretKey string, credentialBytes []byte, secretBytes []byte) ([]byte, error)

	CreateEndorsementKey(tpmSecretKey string) error
	NvIndexExists(nvIndex uint32) (bool, error)
	PublicKeyExists(handle uint32) (bool, error)
	ReadPublic(secretKey string, handle uint32) ([]byte, error)
	
	
	SetCredential(authHandle uint, ownerAuth []byte, /*credentialType constants.CredentialType,*/ credentialBlob []byte) error
	GetCredential(authHandle uint, /*credentialType constants.CredentialType*/) ([]byte, error)
	GetAssetTag(authHandle uint) ([]byte, error)
	GetAssetTagIndex() (uint, error)
	//GetPcrBanks() ([]constants.PcrBank, error)
	//Getquote(pcrBanks []constants.PcrBank, pcrs []constants.Pcr, aikBlob []byte, aikAuth []byte, nonce []byte)
}