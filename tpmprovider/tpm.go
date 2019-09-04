package tpmprovider

// #include "tpm.h"
import "C"

import (
	"crypto"
	"errors"
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

type TpmProvider interface {
	Close()

	Version() C.TPM_VERSION
	CreateCertifiedKey(/*usage constants.Usage, */ keyAuth []byte, aikAuth []byte) (*CertifiedKey, error)
	Unbind(ck *CertifiedKey, keyAuth []byte, encData []byte) ([]byte, error)
	Sign(ck *CertifiedKey, keyAuth []byte, alg crypto.Hash, hashed []byte) ([]byte, error)
//	GetModuleLog() (string, error)
//	GetTcbMeasurement() (string, error)
	TakeOwnership(newOwnerAuth []byte) error
	IsOwnedWithAuth(ownerAuth []byte) (bool, error)
	SetCredential(authHandle uint, ownerAuth []byte, /*credentialType constants.CredentialType,*/ credentialBlob []byte) error
	GetCredential(authHandle uint, /*credentialType constants.CredentialType*/) ([]byte, error)
	GetAssetTag(authHandle uint) ([]byte, error)
	GetAssetTagIndex() (uint, error)
	//GetPcrBanks() ([]constants.PcrBank, error)
	//Getquote(pcrBanks []constants.PcrBank, pcrs []constants.Pcr, aikBlob []byte, aikAuth []byte, nonce []byte)
}

func NewTpmProvider() (TpmProvider, error) {
	var tpm* C.tpm
	tpm = C.TpmCreate()

	if(tpm == nil) {
		return nil, errors.New("Could not allocate native tpm")
	}

	tpmProvider := Tpm20Linux {tpm: tpm}
	return &tpmProvider, nil
}