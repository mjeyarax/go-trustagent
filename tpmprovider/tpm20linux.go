// +build linux

/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package tpmprovider

// #cgo LDFLAGS: -ltss2-sys -ltss2-tcti-tabrmd
// #include "tpm.h"
import "C"

import (
	"crypto"
	"errors"
	"fmt"
)

type Tpm20Linux struct {
	tpmCtx *C.tpmCtx
}

func NewTpmProvider() (TpmProvider, error) {
	var ctx* C.tpmCtx
	ctx = C.TpmCreate()

	if(ctx == nil) {
		return nil, errors.New("Could not create tpm context")
	}

	tpmProvider := Tpm20Linux {tpmCtx: ctx}
	return &tpmProvider, nil
}

func (t* Tpm20Linux) Close() {
	C.TpmDelete(t.tpmCtx)
	t.tpmCtx = nil
}

func (t* Tpm20Linux) Version() C.TPM_VERSION {
	return C.Version(t.tpmCtx)
}

func (t* Tpm20Linux) CreateCertifiedKey(keyAuth []byte, aikAuth []byte) (*CertifiedKey, error) {
	var ck CertifiedKey
	return &ck, nil
}

func (t* Tpm20Linux) Unbind(ck *CertifiedKey, keyAuth []byte, encData []byte) ([]byte, error) {
	var b[] byte
	b = make([]byte, 20, 20)
	return b, nil
}

func (t* Tpm20Linux) Sign(ck *CertifiedKey, keyAuth []byte, alg crypto.Hash, hashed []byte) ([]byte, error) {
	var b[] byte
	b = make([]byte, 20, 20)
	return b, nil
}

// These don't touch the TPM --> Should they be in the interface...?
//func (t* TpmShim) GetModuleLog() (string, error) {
//	return `modulelog`, nil
//}

//func (t* TpmShim) GetTcbMeasurement() (string, error) {
//	return `tcbmeasurment`, nil
//}

func (t* Tpm20Linux) TakeOwnership(newOwnerAuth []byte) error {
	// review/refine how to best pass bytes and other values to C...
	rc := C.TakeOwnership(t.tpmCtx, C.CString(string(newOwnerAuth)), C.size_t(len(newOwnerAuth)))

	if(rc != 0) {
		return fmt.Errorf("TakeOwnership returned error code %d", rc)
	}

	return nil
}

func (t* Tpm20Linux) IsOwnedWithAuth(ownerAuth []byte) (bool, error) {

	// IsOwnedWithAuth returns 0 (true) if 'owned', negative on error, 'false' if > 0
	rc := C.IsOwnedWithAuth(t.tpmCtx, C.CString(string(ownerAuth)), C.size_t(len(ownerAuth)))

	if(rc != 0) {
		return false, fmt.Errorf("IsOwnedWithAuth returned error code %d", rc)
	}

	return true, nil
}

func (t* Tpm20Linux) SetCredential(authHandle uint, ownerAuth []byte, credentialBlob []byte) error {
	return nil
}

func (t* Tpm20Linux) GetCredential(authHandle uint) ([]byte, error) {
	var b[] byte
	b = make([]byte, 20, 20)
	return b, nil
}

func (t* Tpm20Linux) GetAssetTag(authHandle uint) ([]byte, error) {
	var b[] byte
	b = make([]byte, 20, 20)
	return b, nil
}

func (t* Tpm20Linux) GetAssetTagIndex() (uint, error) {
	return 0, nil
}

//func (t* Tpm20Linux) GetPcrBanks() ([]constants.PcrBank, error) {
////
//}

//func (t* Tpm20Linux) Getquote(pcrBanks []constants.PcrBank, pcrs []constants.Pcr, aikBlob []byte, aikAuth []byte, nonce []byte) {
//	
//}