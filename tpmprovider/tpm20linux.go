// +build linux

/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package tpmprovider

// #cgo LDFLAGS: -ltss2-sys -ltss2-tcti-tabrmd -ltss2-mu -lssl -lcrypto
// #include "tpm.h"
import "C"

import (
	"crypto"
	"errors"
	"fmt"
	"unsafe"
//	log "github.com/sirupsen/logrus"
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
	if rc != 0 {
		return nil, fmt.Errorf("GetEndorsementKeyCertificate returned error code 0x%X", rc)
	}

	defer C.free(unsafe.Pointer(ekBytes))

	if ekBytesLength <= 0 || ekBytesLength > 4000 {	// KWT max?
		return nil, fmt.Errorf("The buffer size is incorrect")
	}

	returnValue = C.GoBytes(unsafe.Pointer(ekBytes), ekBytesLength)
	return returnValue, nil
}

func (t *Tpm20Linux) GetAikBytes(tpmSecretKey string) ([]byte, error) {
	var returnValue []byte
	var aikPublicBytes *C.char
	var aikPublicBytesLength C.int
	
	rc := C.GetAikBytes(t.tpmCtx, C.CString(tpmSecretKey), C.size_t(len(tpmSecretKey)), &aikPublicBytes, &aikPublicBytesLength)
	if rc != 0 {
		return nil, fmt.Errorf("GetAikBytes returned error code 0x%X", rc)
	}

	defer C.free(unsafe.Pointer(aikPublicBytes))

	if (aikPublicBytesLength <= 0)  { // max size is checked in native/c code call to GetAikBytes
		return nil, fmt.Errorf("The buffer size is incorrect")
	}

	returnValue = C.GoBytes(unsafe.Pointer(aikPublicBytes), aikPublicBytesLength)
	return returnValue, nil
}

func (t *Tpm20Linux) GetAikName(tpmSecretKey string) ([]byte, error) {
	var returnValue []byte
	var aikName *C.char
	var aikNameLength C.int
	
	rc := C.GetAikName(t.tpmCtx, C.CString(tpmSecretKey), C.size_t(len(tpmSecretKey)), &aikName, &aikNameLength)
	if rc != 0 {
		return nil, fmt.Errorf("GetAikName returned error code 0x%X", rc)
	}

	defer C.free(unsafe.Pointer(aikName))

	if (aikNameLength <= 0) { // max size is checked in native/c code call to GetAikName
		return nil, fmt.Errorf("The buffer size is incorrect")
	}

	returnValue = C.GoBytes(unsafe.Pointer(aikName), aikNameLength)
	return returnValue, nil
}

func (t *Tpm20Linux) IsAikPresent(tpmSecretKey string) (bool, error) {
	rval := C.IsAikPresent(t.tpmCtx, C.CString(tpmSecretKey), C.size_t(len(tpmSecretKey)))
	if rval == 0 {
		return true, nil
	} else if rval < 0 {
		return false, nil
	} else {
		return false, fmt.Errorf("IsAikPresent returned error code 0x%x", rval)
	}
}

func (t *Tpm20Linux) CreateAik(tpmSecretKey string, aikSecretKey string) error {
	rc := C.CreateAik(t.tpmCtx, C.CString(tpmSecretKey), C.size_t(len(tpmSecretKey)), C.CString(aikSecretKey), C.size_t(len(aikSecretKey)))
	if rc != 0 {
		return fmt.Errorf("CreateAik return 0x%x", rc)
	}

	return nil
}

func (t *Tpm20Linux) ActivateCredential(tpmSecretKey string, aikSecretKey string, credentialBytes []byte, secretBytes []byte) ([]byte, error) {

	var returnValue []byte
	var decrypted *C.char
	var decryptedLength C.int
	
	rc := C.ActivateCredential(t.tpmCtx, 
							   C.CString(tpmSecretKey),  
							   C.size_t(len(tpmSecretKey)), 
							   C.CString(aikSecretKey),  
							   C.size_t(len(aikSecretKey)),
							   C.CString(string(credentialBytes)),
							   C.size_t(len(credentialBytes)),
							   C.CString(string(secretBytes)),
							   C.size_t(len(secretBytes)),
							   &decrypted, 
							   &decryptedLength)
	if rc != 0 {
		return nil, fmt.Errorf("C.ActivateCredential returned error code 0x%X", rc)
	}

	defer C.free(unsafe.Pointer(decrypted))

	if (decryptedLength <= 0) { // max size is checked in native/c code call to GetAikName
		return nil, fmt.Errorf("The buffer size is incorrect")
	}

	returnValue = C.GoBytes(unsafe.Pointer(decrypted), decryptedLength)
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


func (tpm *Tpm20Linux) ReadPublic(secretKey string, handle uint32) ([]byte, error) {

	var returnValue []byte
	var public *C.char
	var publicLength C.int

	rc := C.ReadPublic(tpm.tpmCtx, C.uint(handle), &public, &publicLength)
	if rc != 0 {
		return nil, fmt.Errorf("C.ReadPublic returned %x", rc)
	}

	defer C.free(unsafe.Pointer(public))

	if (publicLength <= 0) {
		return nil, fmt.Errorf("The public size is incorrect")
	}

	returnValue = C.GoBytes(unsafe.Pointer(public), publicLength)
	return returnValue, nil

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