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
	NV_IDX_ASSET_TAG	   = C.NV_IDX_ASSET_TAG
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
	TakeOwnership(tpmOwnerSecretKey string) error

	//
	// TODO
	//
	IsOwnedWithAuth(tpmOwnerSecretKey string) (bool, error)
	

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

	//
	// Checks to see if data has been written to nvram at 'nvIndex'
	//
	NvIndexExists(nvIndex uint32) (bool, error)

	//
	// Allocate nvram of size 'indexSize' at 'nvIndex'
	//
	NvDefine(tpmOwnerSecretKey string, nvIndex uint32, indexSize uint16) error

	//
	// Deletes data at nvram index 'nvIndex'
	//
	NvRelease(tpmOwnerSecretKey string, nvIndex uint32) error

	//
	// Reads data at nvram index 'nvIndex'
	//
	NvRead(tpmOwnerSecretKey string, nvIndex uint32) ([]byte, error)

	//
	// Writes data to nvram index 'nvIndex'
	//
	NvWrite(tpmOwnerSecretKey string, nvIndex uint32, data []byte) error

	// KWT:  These are not being used (clean up)
	PublicKeyExists(handle uint32) (bool, error)
	ReadPublic(secretKey string, handle uint32) ([]byte, error)
}