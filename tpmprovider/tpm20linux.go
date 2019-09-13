// +build linux

/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package tpmprovider

// #cgo LDFLAGS: -ltss2-sys -ltss2-tcti-tabrmd -ltss2-mu
// #include "tpm.h"
import "C"

import (
	"crypto"
	"errors"
	"fmt"
	"unsafe"
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

func (t* Tpm20Linux) TakeOwnership(secretKey []byte) error {

	rc := C.TakeOwnership(t.tpmCtx, C.CString(string(secretKey)), C.size_t(len(secretKey)))
	if rc != 0 {
		return fmt.Errorf("TakeOwnership returned error code 0x%X", rc)
	}

	return nil
}

func (t* Tpm20Linux) IsOwnedWithAuth(secretKey []byte) (bool, error) {

	// IsOwnedWithAuth returns 0 (true) if 'owned', false/error if not zero
	rc := C.IsOwnedWithAuth(t.tpmCtx, C.CString(string(secretKey)), C.size_t(len(secretKey)))

	if rc != 0 {
		return false, fmt.Errorf("IsOwnedWithAuth returned error code 0x%X", rc)
	}

	return true, nil
}

func (t* Tpm20Linux) GetEndorsementKeyCertificate(tpmSecretKey string) ([]byte, error) {
	var returnValue []byte
	var ekBytes *C.char
	var ekBytesLength C.int
	
	rc := C.GetEndorsementKeyCertificate(t.tpmCtx, C.CString(tpmSecretKey), C.size_t(len(tpmSecretKey)), &ekBytes, &ekBytesLength)
	defer C.free(unsafe.Pointer(ekBytes))

	if rc != 0 {
		return nil, fmt.Errorf("GetEndorsementKeyCertificate returned error code 0x%X", rc)
	}

	if ekBytesLength <= 0 || ekBytesLength > 4000 {
		return nil, fmt.Errorf("The buffer size is incorrect")
	}

	returnValue = C.GoBytes(unsafe.Pointer(ekBytes), ekBytesLength)
	return returnValue, nil
}

func (tpm *Tpm20Linux) CreateEndorsementKey(tpmSecretKey string) error {
	rc := C.CreateEndorsementKey(tpm.tpmCtx, C.CString(tpmSecretKey), C.size_t(len(tpmSecretKey)))
	if rc != 0 {
		return fmt.Errorf("CreateEndorsementKey returned error code 0x%X", rc)
	}

	return nil
}

func (tpm *Tpm20Linux) NvIndexExists(nvIndex uint32) (bool, error) {
	rc := C.NvIndexExists(tpm.tpmCtx, C.uint(nvIndex))
	if rc == -1 {
		return false, nil	// KWT:  Differentiate between and error and index not there
	}

	if rc != 0 {
		return false, fmt.Errorf("NvIndexExists returned error code 0x%X", rc)
	}

	return true, nil
}

func (tpm *Tpm20Linux) PublicKeyExists(handle uint32) (bool, error) {
	rc := C.PublicKeyExists(tpm.tpmCtx, C.uint(handle))
	if rc != 0 {
		return false, nil	// KWT:  Differentiate between and error and index not there
	}

	// if rc != 0 {
	// 	return false, fmt.Errorf("NvIndexExists returned error code 0x%X", rc)
	// }

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