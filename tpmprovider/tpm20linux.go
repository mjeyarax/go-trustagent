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
//	"bytes"
	"crypto"
	"encoding/binary"
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

// func (t *Tpm20Linux) IsAikPresent(tpmSecretKey string) (bool, error) {
// 	rval := C.IsAikPresent(t.tpmCtx, C.CString(tpmSecretKey), C.size_t(len(tpmSecretKey)))
// 	if rval == 0 {
// 		return true, nil
// 	} else if rval < 0 {
// 		return false, nil
// 	} else {
// 		return false, fmt.Errorf("IsAikPresent returned error code 0x%x", rval)
// 	}
// }

func (t *Tpm20Linux) CreateAik(tpmSecretKey string, aikSecretKey string) error {
	rc := C.CreateAik(t.tpmCtx, C.CString(tpmSecretKey), C.size_t(len(tpmSecretKey)), C.CString(aikSecretKey), C.size_t(len(aikSecretKey)))
	if rc != 0 {
		return fmt.Errorf("CreateAik return 0x%x", rc)
	}

	return nil
}

// func (t *Tpm20Linux) FinalizeAik(aikSecretKey string) error {
// 	rc := C.FinalizeAik(t.tpmCtx, C.CString(aikSecretKey), C.size_t(len(aikSecretKey)))
// 	if rc != 0 {
// 		return fmt.Errorf("FinalizeAik return 0x%x", rc)
// 	}

// 	return nil
// }

// This is the pcr selection structure that tss2 wants when performing a quote...
//
// typedef struct {																		[[Total Size 132: 4 + (8 (i.e. sizeof(TPMS_SELECTION)) * 16)]]
// 	UINT32 count; /* number of selection structures. A value of zero is allowed. */		[[number of banks]]
// 	TPMS_PCR_SELECTION pcrSelections[TPM2_NUM_PCR_BANKS]; /* list of selections */		[[see structure below]]
// } TPML_PCR_SELECTION;
//
// And substructures/defines...
//
// typedef struct {																		[[TOTAL: 8 bytes]]
// 	TPMI_ALG_HASH hash; /* the hash algorithm associated with the selection */ 			[[2 byte uint16, ex "SHA1" --> 0x4 below]]
// 	UINT8 sizeofSelect; /* the size in octets of the pcrSelect array */					[[1 byte]]
// 	BYTE pcrSelect[TPM2_PCR_SELECT_MAX]; /* the bit map of selected PCR */				[[4 byte bit mask]]
// } TPMS_PCR_SELECTION;
//
// #define TPM2_PCR_SELECT_MAX      ((TPM2_MAX_PCRS + 7) / 8) 							[[4]]
// #define TPM2_MAX_PCRS           32
// #define TPM2_NUM_PCR_BANKS      16
//
// #define TPM2_ALG_SHA1                0x0004											[["SHA1"]]
// #define TPM2_ALG_SHA256              0x000B											[["SHA256"]]
// #define TPM2_ALG_SHA384              0x000C											[["SHA384"]]
//
// Design goals were to keep the go code 'application specific' (i.e. fx that 
// were needed by GTA -- no a general use TPM library).  So, we're keeping this function's
// parameters similar to the /tpm/quote endpoint (it receives a string array of pcrBanks
// and int array of pcrs).
//
// Provided it's easier to adapt those parameters to what Tss2 wants, let's do the conversion 
// here.  
// 
// Yes, we could reference tss2_tpm2_types.h and build those structures directly
// in go.  But, this is the only application specific function that requires structured
// parameters -- the intent was to hide the Tss2 dependencies in tpm20linux.h (not tpm.h)
// so that we could plug in other native implementations (ex. tpm20windows.h could use
// TSS MSR c++).
// 
// Is it the right approach for layering? Maybe not, but we're in the red zone and we're
// gonna stick with it.  Let's build the TPML_PCR_SELECTION structure and pass it in as
// bytes, c will cast it to the structure.
//
// KWT:  Reevaluate layering.  Could be tpm.go (interface) -> tpm20linux.go (translates go
// parameters tss2 structures) -> tss2 call. Right now it is tpm.go -> tpm20linux.go -> c code 
// (translation of raw buffers to tss structures) -> tss2 call.
func getPcrSelectionBytes(pcrBanks []string, pcrs []int) ([]byte, error) {

//	buf := bytes.NewBuffer(make([]byte, 128)) // create a fixed size buffer for TPML_PCR_SELECTION
//	binary.Write(buf, binary.LittleEndian, uint32(len(pcrBanks)))	// TPML_PCR_SELECTION.count
//	buf.Write()
	buf := make([]byte, 132) // create a fixed size buffer for TPML_PCR_SELECTION
	offset := 0

	binary.LittleEndian.PutUint32(buf, uint32(len(pcrBanks)))
	offset += 4 // uint32

	for i, bank := range pcrBanks {
		var hash uint16
		var pcrBitMask uint32

		switch bank {
		case "SHA1":
			hash = 0x04
		case "SHA256":
			hash = 0x0B
		case "SHA384":
			hash = 0x0C
		default:
			return nil, fmt.Errorf("Invalid pcr bank type: %s", pcrBanks[i])
		}

		// binary.Write(buf, binary.LittleEndian, hash)		// TPMS_PCR_SELECTION.hash
		// binary.Write(buf, binary.LittleEndian, uint8(4))	// TPMS_PCR_SELECTION.sizeofSelect (going to stick with 4 that acomodates pcrs 1 through 32, 24 is common)
		binary.LittleEndian.PutUint16(buf[offset:], uint16(hash))
		offset += 2	// uint16

		buf[offset] = 0x03 // KWT: 3 for 24 bits of pcrs
		offset += 1	// byte

		// build a 32bit bit mask that will be applied to TPMS_PCR_SELECTION.pcrSelect
		pcrBitMask = 0
		for _, pcr := range pcrs {
			if pcr < 0 || pcr > 31 {
				return nil, fmt.Errorf("Invalid pcr value: %d", pcr)
			}

			pcrBitMask |= (1 << uint32(pcr))
		}

		//binary.Write(buf, binary.LittleEndian, pcrBitMask)	// TPMS_PCR_SELECTION.pcrSelect
		binary.LittleEndian.PutUint32(buf[offset:], pcrBitMask)
		offset += 5 // uint32
	}

//	return buf.Bytes(), nil
	return buf, nil
}

func (t *Tpm20Linux) GetTpmQuote(aikSecretKey string, nonce []byte, pcrBanks []string, pcrs []int) ([]byte, error) {

	var quoteBytes []byte
	var cQuote *C.char
	var cQuoteLength C.int

	cNonceBytes := C.CBytes(nonce)
	defer C.free(cNonceBytes)

	pcrSelectionBytes, err := getPcrSelectionBytes(pcrBanks, pcrs)
	if err != nil {
		return nil, err
	}

	rc := C.GetTpmQuote(t.tpmCtx, 
						C.CString(aikSecretKey),  
						C.size_t(len(aikSecretKey)),
						C.CBytes(pcrSelectionBytes),
						C.size_t(len(pcrSelectionBytes)),
						cNonceBytes,
						C.size_t(len(nonce)),
						&cQuote, 
						&cQuoteLength)
		
	if rc != 0 {
		return nil, fmt.Errorf("C.GetTpmQuote returned error code 0x%X", rc)
	}

	defer C.free(unsafe.Pointer(cQuote))

	if (cQuoteLength <= 0) { // max size is checked in native/c code call to GetAikName
		return nil, fmt.Errorf("The quote buffer size is incorrect")
	}

	quoteBytes = C.GoBytes(unsafe.Pointer(cQuote), cQuoteLength)
	return quoteBytes, nil
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

// func (tpm *Tpm20Linux) CreateEndorsementKey(tpmSecretKey string) error {
// 	rc := C.CreateEndorsementKey(tpm.tpmCtx, C.CString(tpmSecretKey), C.size_t(len(tpmSecretKey)))
// 	if rc != 0 {
// 		return fmt.Errorf("CreateEndorsementKey returned error code 0x%X", rc)
// 	}

// 	return nil
// }

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