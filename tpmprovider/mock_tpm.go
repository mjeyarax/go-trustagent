package tpmprovider

// #include "tpm.h"
import "C"

import (
	"crypto"
)

type MockTpm struct {
}

func NewMockTpm() (TpmProvider, error) {
	tpmMock := MockTpm {}
	return &tpmMock, nil
}

func (t MockTpm) Close() {
}

func (t MockTpm) Version() C.TPM_VERSION {
	return C.TPM_VERSION_UNKNOWN
}

func (t MockTpm) CreateCertifiedKey(keyAuth []byte, aikAuth []byte) (*CertifiedKey, error) {
	var ck CertifiedKey
	return &ck, nil
}

func (t MockTpm) Unbind(ck *CertifiedKey, keyAuth []byte, encData []byte) ([]byte, error) {
	var b[] byte
	b = make([]byte, 20, 20)
	return b, nil
}

func (t MockTpm) Sign(ck *CertifiedKey, keyAuth []byte, alg crypto.Hash, hashed []byte) ([]byte, error) {
	var b[] byte
	b = make([]byte, 20, 20)
	return b, nil
}

// These don't touch the TPM --> Should they be in the interface...?
//func (t TpmShim) GetModuleLog() (string, error) {
//	return `modulelog`, nil
//}

//func (t TpmShim) GetTcbMeasurement() (string, error) {
//	return `tcbmeasurment`, nil
//}

func (t MockTpm) TakeOwnership(newOwnerAuth []byte) error {
	return nil
}

func (t MockTpm) IsOwnedWithAuth(ownerAuth []byte) (bool, error) {
	return true, nil
}

func (t MockTpm) SetCredential(authHandle uint, ownerAuth []byte, credentialBlob []byte) error {
	return nil
}

func (t MockTpm) GetCredential(authHandle uint) ([]byte, error) {
	var b[] byte
	b = make([]byte, 20, 20)
	return b, nil
}

func (t MockTpm) GetAssetTag(authHandle uint) ([]byte, error) {
	var b[] byte
	b = make([]byte, 20, 20)
	return b, nil
}

func (t MockTpm) GetAssetTagIndex() (uint, error) {
	return 0, nil
}

//func GetPcrBanks() ([]constants.PcrBank, error) {
////
//}

//func (t Tpm20Linux) Getquote(pcrBanks []constants.PcrBank, pcrs []constants.Pcr, aikBlob []byte, aikAuth []byte, nonce []byte) {
//	
//}