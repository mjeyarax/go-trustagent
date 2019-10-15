// +build !integration

/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
 package tpmprovider

import (
	//"encoding/base64"
	"encoding/hex"
	"io/ioutil"
	"testing"
	"github.com/stretchr/testify/assert"
	log "github.com/sirupsen/logrus"
)

const (
	TpmSecretKey	= "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
	AikSecretKey	= "beeffeedbeeffeedbeeffeedbeeffeedbeeffeed"
)

func TestTpmVersion(t *testing.T) {
	tpmProvider, _ := NewTpmProvider()
	defer tpmProvider.Close()
	version := tpmProvider.Version()
	t.Logf("Version %d\n", version)
	assert.NotEqual(t, version, 0)
}

func TestTpmTakeOwnership(t *testing.T) {
	tpmProvider, _ := NewTpmProvider()
	defer tpmProvider.Close()

	rc := tpmProvider.TakeOwnership("deadbeefdeadbeefdeadbeefdeadbeefdeadbeef")
	assert.Equal(t, rc, nil)
}

// To run this test (more of a c debugging tool)...
// Where:
// - TPM owner key is: deadbeefdeadbeefdeadbeefdeadbeefdeadbeef
// - AIK secret key is: beefbeefbeefbeefbeefbeefbeefbeefbeefbeef
//
// Reset simulator: cicd/start-tpm-simulator.sh
// tpm2_takeownership -o hex:deadbeefdeadbeefdeadbeefdeadbeefdeadbeef -e hex:deadbeefdeadbeefdeadbeefdeadbeefdeadbeef -l hex:deadbeefdeadbeefdeadbeefdeadbeefdeadbeef
// tpm2_createprimary -H o -P hex:deadbeefdeadbeefdeadbeefdeadbeefdeadbeef -g 0x000B -G 0x0001 -C /tmp/primaryKey.context
// tpm2_evictcontrol -A o -P  hex:deadbeefdeadbeefdeadbeefdeadbeefdeadbeef -c /tmp/primaryKey.context -S 0x81000000
// tpm2_getpubek -e hex:deadbeefdeadbeefdeadbeefdeadbeefdeadbeef -o hex:deadbeefdeadbeefdeadbeefdeadbeefdeadbeef -H 0x81010000 -g 0x1 -f /tmp/endorsementKey
// tpm2_readpublic -H 0x81010000 -o /tmp/endorsementkeyecpub
// tpm2_getpubak -e hex:deadbeefdeadbeefdeadbeefdeadbeefdeadbeef -o hex:deadbeefdeadbeefdeadbeefdeadbeefdeadbeef -P hex:beefbeefbeefbeefbeefbeefbeefbeefbeefbeef -E 0x81010000 -k 0x81018000 -f /tmp/aik -n /tmp/aikName -g 0x1 -D 0x000B -s 0x14
// Run /tmp/makecredential.sh
// X: tpm2_activatecredential -e hex:deadbeefdeadbeefdeadbeefdeadbeefdeadbeef -P hex:beefbeefbeefbeefbeefbeefbeefbeefbeefbeef -H 0x81018000 -k 0x81010000 -f /tmp/makecredential.out -o /tmp/decrypted.out
// X: tpm2_create -H 0x81000000 -g 0x0B -G 0x1 -A 0x00020072 -u /tmp/bindingKey.pub -r /tmp/bindingKey.priv
// X: tpm2_load -H 0x81000000 -u /tmp/bindingKey.pub -r /tmp/bindingKey.priv -C /tmp/bk.context -n /tmp/bkFilename
// X: tpm2_certify -k 0x81018000 -H 0x81000000 -K hex:beefbeefbeefbeefbeefbeefbeefbeefbeefbeef -g 0x0B -a /tmp/out.attest -s /tmp/out.sig -C /tmp/bk.context
// X: tpm2_quote -k 0x81018000 -P hex:beefbeefbeefbeefbeefbeefbeefbeefbeefbeef -L 0x04:0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23+0x0B:0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23 -q b4781f450103d7ea58804669ab77590bd38d98109929dc75d0b12b4d9b3593f9
//
// cd to /tpmprovider and run 'go test -c' (compiles to tpmprovider/tpmprovider.test)
// Run gbd unit test against tpmprovider.test (see launch.json)
//
func TestTpmActivateCredential(t *testing.T) {
	assert := assert.New(t)

	tpmProvider, err := NewTpmProvider()
	assert.NoError(err)
	defer tpmProvider.Close()


	// secret := "AQBZ4n0tHyIbb5watAUuGg+L4mL/z9r7LzoX8ujGtVST7OcoGU5enm5wMsA90Ufcfj7UxDv6FpYLqonxtl8LFvCB+4QNAA1EG4eGXIdzAXGU3JbTlXyr2DlRSBObMe/lf3pxiTPQctjoSsLQWw7BtOPpAVbp+OS+lTD8Dut+sva1TYoBnW9KAkU5qkLsKn8uBtb7ozX1rVteHDh1CPGYnKC3nfg5rdOuLlq3xGafE8osEHD/cXEKddtoUwMY+6zroJ7XwsaYvpsa7ArRhARViHKZFwtw9hMmBXR28E93iZDqthaQvfMxjrXBmsFbGptq91EaNp+G0XVH4mP0sJmlQpbI"
	// secretBytes, err := base64.StdEncoding.DecodeString(secret)
	// assert.NoError(err)

	//credential := "ADQAID2qrkbHKt9ZEBb4RdhMh6esz52AHxuqd6LDDtI3pxwxMyYyEGNq0usYQAnW2H4hmggl"


	credentialBytes, err := ioutil.ReadFile("/tmp/aikName")
	secretBytes, err := ioutil.ReadFile("/tmp/secret.data") //[]byte("12345678")

	// a2 := []byte("000b6c73dbc157be97f6ee0169b23e608486529cc30becbe7dd277b6822f407a6d53")
	// n2 := []byte("12345678")

	// log.Infof("aikName[%x]: %s\n\n", len(aikName), hex.EncodeToString(aikName))
	// log.Infof("a2     [%x]: %s\n\n", len(a2), hex.EncodeToString(a2))
	// log.Infof("nonce  [%x]: %s\n\n", len(nonce), hex.EncodeToString(nonce))
	// log.Infof("n2     [%x]: %s\n\n", len(n2), hex.EncodeToString(n2))


	decrypted, err := tpmProvider.ActivateCredential(TpmSecretKey, AikSecretKey, credentialBytes, secretBytes)
	//decrypted, err := tpmProvider.ActivateIdentity(TpmSecretKey, AikSecretKey, a2, n2)
	assert.NoError(err)

	//log.Infof("Decrypted: %d", len(decrypted))
	log.Infof("Decrypted[%x]: %s\n\n", len(decrypted), hex.EncodeToString(decrypted))
}


// To run/debug this test (more of a c debugging tool)...
// Where:
// - TPM owner key is: deadbeefdeadbeefdeadbeefdeadbeefdeadbeef
// - AIK secret key is: beefbeefbeefbeefbeefbeefbeefbeefbeefbeef
//
// Reset simulator: cicd/start-tpm-simulator.sh
// tpm2_takeownership -o hex:deadbeefdeadbeefdeadbeefdeadbeefdeadbeef -e hex:deadbeefdeadbeefdeadbeefdeadbeefdeadbeef -l hex:deadbeefdeadbeefdeadbeefdeadbeefdeadbeef
// tpm2_createprimary -H o -P hex:deadbeefdeadbeefdeadbeefdeadbeefdeadbeef -g 0x000B -G 0x0001 -C /tmp/primaryKey.context
// tpm2_evictcontrol -A o -P  hex:deadbeefdeadbeefdeadbeefdeadbeefdeadbeef -c /tmp/primaryKey.context -S 0x81000000
// tpm2_getpubek -e hex:deadbeefdeadbeefdeadbeefdeadbeefdeadbeef -o hex:deadbeefdeadbeefdeadbeefdeadbeefdeadbeef -H 0x81010000 -g 0x1 -f /tmp/endorsementKey
// tpm2_readpublic -H 0x81010000 -o /tmp/endorsementkeyecpub
// tpm2_getpubak -e hex:deadbeefdeadbeefdeadbeefdeadbeefdeadbeef -o hex:deadbeefdeadbeefdeadbeefdeadbeefdeadbeef -P hex:beefbeefbeefbeefbeefbeefbeefbeefbeefbeef -E 0x81010000 -k 0x81018000 -f /tmp/aik -n /tmp/aikName -g 0x1 -D 0x000B -s 0x14
// Run /tmp/makecredential.sh
// tpm2_activatecredential -e hex:deadbeefdeadbeefdeadbeefdeadbeefdeadbeef -P hex:beefbeefbeefbeefbeefbeefbeefbeefbeefbeef -H 0x81018000 -k 0x81010000 -f /tmp/makecredential.out -o /tmp/decrypted.out
//
// Compile the unit test (so it can be debugged in vscode)
// cd tpmprovider
// go test -c
// Update launch.json 'GTA: (gdb) Unit Test to call this unit test (TestTpmFinalizeAik)
//
// Run this unit test
// func TestTpmFinalizeAik(t *testing.T) {
// 	assert := assert.New(t)

// 	tpmProvider, err := NewTpmProvider()
// 	assert.NoError(err)
// 	defer tpmProvider.Close()

// 	err = tpmProvider.FinalizeAik("beefbeefbeefbeefbeefbeefbeefbeefbeefbeef")
// 	assert.NoError(err)
// }

func TestTpmQuote(t *testing.T) {
	assert := assert.New(t)

	tpmProvider, err := NewTpmProvider()
	assert.NoError(err)
	defer tpmProvider.Close()

	nonce := []byte {1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,7,8,9,0}
	pcrs := []int {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23}
	pcrBanks := []string {"SHA1", "SHA256"}
	

//	quoteBytes, err := tpmProvider.GetTpmQuote("66ac6e73e910bdba42d2197a20ab2e91590c5498", nonce, pcrBanks, pcrs)
	quoteBytes, err := tpmProvider.GetTpmQuote("beefbeefbeefbeefbeefbeefbeefbeefbeefbeef", nonce, pcrBanks, pcrs)
	assert.NoError(err)

	log.Infof("Quote[%x]: %s\n\n", len(quoteBytes), hex.EncodeToString(quoteBytes))

}

func TestPcrSelectionParsing(t *testing.T) {
	assert := assert.New(t)

	// common
	pcrSelectionBytes, err := getPcrSelectionBytes([]string{"SHA1", "SHA256"}, []int {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23})
	assert.NoError(err)
	log.Infof("pcrSelectionBytes[%x]: %s", len(pcrSelectionBytes), hex.EncodeToString(pcrSelectionBytes))
	assert.Equal(len(pcrSelectionBytes), 132)
	
	// minimal
	pcrSelectionBytes, err = getPcrSelectionBytes([]string{"SHA1"}, []int {0})
	assert.NoError(err)
	log.Infof("pcrSelectionBytes[%x]: %s", len(pcrSelectionBytes), hex.EncodeToString(pcrSelectionBytes))
	assert.Equal(len(pcrSelectionBytes), 132)

	// max
	pcrSelectionBytes, err = getPcrSelectionBytes([]string{"SHA1", "SHA256", "SHA384"}, []int {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31})
	assert.NoError(err)
	log.Infof("pcrSelectionBytes[%x]: %s", len(pcrSelectionBytes), hex.EncodeToString(pcrSelectionBytes))
	assert.Equal(len(pcrSelectionBytes), 132)

	// bank error
	pcrSelectionBytes, err = getPcrSelectionBytes([]string{"SHA7"}, []int {0})
	assert.Error(err)

	// pcr range error
	pcrSelectionBytes, err = getPcrSelectionBytes([]string{"SHA1"}, []int {32})
	assert.Error(err)
	
}

// assumes TPM is cleared and has ownership using TpmSecretKey value
// Reset simulator: cicd/start-tpm-simulator.sh
// tpm2_takeownership -o hex:deadbeefdeadbeefdeadbeefdeadbeefdeadbeef -e hex:deadbeefdeadbeefdeadbeefdeadbeefdeadbeef -l hex:deadbeefdeadbeefdeadbeefdeadbeefdeadbeef
//
// Simulates commands...
//
// tpm2_nvdefine -P hex:deadbeefdeadbeefdeadbeefdeadbeefdeadbeef -x 0x1c10110 -a 0x40000001 -s 1024 -t 0x2000a # (ownerread|ownerwrite|policywrite)
// tpm2_nvwrite -P hex:deadbeefdeadbeefdeadbeefdeadbeefdeadbeef -x 0x1c10110 -a 0x40000001 -o 0 /tmp/quote.bin
// tpm2_nvread -P hex:deadbeefdeadbeefdeadbeefdeadbeefdeadbeef -x 0x1c10110 -a 0x40000001 -o 0 -f /tmp/quote_nv.bin
func TestNvRAM(t *testing.T) {
	assert := assert.New(t)

	var handle uint32

	tpm, err := NewTpmProvider()
	assert.NoError(err)
	defer tpm.Close()

	data := []byte("Wlf4sABZ1GvQ9dGHjACHSioLedYfsbRSk2CqztFrjJpH1gCblyjtZw822YwEQCAc")
	handle = NV_IDX_ASSET_TAG;

	// if the index already exists, delete it
	nvExists, err := tpm.NvIndexExists(handle)
	if assert.NoError(err) == false { return }

	if nvExists {
		err = tpm.NvRelease(TpmSecretKey, handle)
		if assert.NoError(err) == false { return }
	}

	// create an index for the data
	tpm.NvDefine(TpmSecretKey, handle, uint16(len(data)))
	if assert.NoError(err) == false { return }

	// write the data
	err = tpm.NvWrite(TpmSecretKey, handle, data)
	if assert.NoError(err) == false { return }

	// make sure the index exists
	nvExists, err = tpm.NvIndexExists(handle)
	if assert.NoError(err) == false { return }
	if assert.Equal(nvExists, true) == false { return }	// index should exist

	// make sure the data from the index matches the original
	copy, err := tpm.NvRead(TpmSecretKey, handle)
	assert.NoError(err)
	assert.Equal(data, copy)
}