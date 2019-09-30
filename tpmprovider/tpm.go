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

// KWT: Document interface 

type TpmProvider interface {
	Close()

	// KWT:  These functions need to be implemented to support VM-C/WLA
	Version() C.TPM_VERSION
	CreateCertifiedKey(/*usage constants.Usage, */ keyAuth []byte, aikAuth []byte) (*CertifiedKey, error)
	Unbind(ck *CertifiedKey, keyAuth []byte, encData []byte) ([]byte, error)
	Sign(ck *CertifiedKey, keyAuth []byte, alg crypto.Hash, hashed []byte) ([]byte, error)

	//
	// TODO
	//
	TakeOwnership(tpmOwnerSecretKey []byte) error

	//
	// TODO
	//
	IsOwnedWithAuth(tpmOwnerSecretKey []byte) (bool, error)
	
	//
	// TODO
	//
	GetEndorsementKeyCertificate(tpmOwnerSecretKey string) ([]byte, error)

	// Probably a keeper for error checking (TBD)
//	IsAikPresent(tpmOwnerSecretKey string) (bool, error)

	//
	// Used in tasks.provision_aik.go
	//
	CreateAik(tpmOwnerSecretKey string, aikSecretKey string) error

	//
	// Used in tasks.provision_aik.go to facilitate handshakes with HVS
	//
	GetAikBytes(tpmOwnerSecretKey string) ([]byte, error)

	//
	// Used in tasks.provision_aik.go to facilitate handshakes with HVS
	//
	GetAikName(tpmOwnerSecretKey string) ([]byte, error)

	//
	// ActivateCredential uses the TPM to decrypt 'secretBytes'. 
	//
	// Used in tasks.provision_aik.go to decrypt HVS data.
	//
	ActivateCredential(tpmOwnerSecretKey string, aikSecretKey string, credentialBytes []byte, secretBytes []byte) ([]byte, error)

	//
	// TODO
	//
	GetTpmQuote(aikSecretKey string, nonce []byte, pcrBanks []string, pcrs []int) ([]byte, error)

	// KWT:  These are not being used (clean up)
	NvIndexExists(nvIndex uint32) (bool, error)
	PublicKeyExists(handle uint32) (bool, error)
	ReadPublic(secretKey string, handle uint32) ([]byte, error)
		
	// TODO: Asset tags
	GetAssetTag(authHandle uint) ([]byte, error)
	GetAssetTagIndex() (uint, error)
}