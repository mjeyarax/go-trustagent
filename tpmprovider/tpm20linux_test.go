// +build !integration

/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
 package tpmprovider

import (
	"encoding/base64"
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

	var b[] byte
	b = make([]byte, 20, 20)

	rc := tpmProvider.TakeOwnership(b)
	assert.Equal(t, rc, nil)
}

// To run this test (more of a c debugging tool)...
//
// Reset simulator: cicd/start-tpm-simulator.sh
// tpm2_takeownership -o hex:deadbeefdeadbeefdeadbeefdeadbeefdeadbeef -e hex:deadbeefdeadbeefdeadbeefdeadbeefdeadbeef -l hex:deadbeefdeadbeefdeadbeefdeadbeefdeadbeef
// tpm2_createprimary -H o -P hex:deadbeefdeadbeefdeadbeefdeadbeefdeadbeef -g 0x000B -G 0x0001 -C /tmp/primaryKey.context
// tpm2_evictcontrol -A o -P  hex:deadbeefdeadbeefdeadbeefdeadbeefdeadbeef -c /tmp/primaryKey.context -S 0x81000000
// tpm2_getpubek -e hex:deadbeefdeadbeefdeadbeefdeadbeefdeadbeef -o hex:deadbeefdeadbeefdeadbeefdeadbeefdeadbeef -H 0x81010000 -g 0x1 -f /tmp/endorsementKey
// tpm2_readpublic -H 0x81010000 -o /tmp/endorsementkeyecpub
// tpm2_getpubak -e hex:deadbeefdeadbeefdeadbeefdeadbeefdeadbeef -o hex:deadbeefdeadbeefdeadbeefdeadbeefdeadbeef -P hex:beeffeedbeeffeedbeeffeedbeeffeedbeeffeed -E 0x81010000 -k 0x81018000 -f /tmp/aik -n /tmp/aikName
// 
// cd to /tpmprovider and run 'go test -c' (compiles to tpmprovider/tpmprovider.test)
// Run gbd unit test against tpmprovider.test (see launch.json)
//
func TestTpmActivateCredential(t *testing.T) {
	assert := assert.New(t)

	tpmProvider, err := NewTpmProvider()
	assert.NoError(err)
	defer tpmProvider.Close()


	secret := "AQBZ4n0tHyIbb5watAUuGg+L4mL/z9r7LzoX8ujGtVST7OcoGU5enm5wMsA90Ufcfj7UxDv6FpYLqonxtl8LFvCB+4QNAA1EG4eGXIdzAXGU3JbTlXyr2DlRSBObMe/lf3pxiTPQctjoSsLQWw7BtOPpAVbp+OS+lTD8Dut+sva1TYoBnW9KAkU5qkLsKn8uBtb7ozX1rVteHDh1CPGYnKC3nfg5rdOuLlq3xGafE8osEHD/cXEKddtoUwMY+6zroJ7XwsaYvpsa7ArRhARViHKZFwtw9hMmBXR28E93iZDqthaQvfMxjrXBmsFbGptq91EaNp+G0XVH4mP0sJmlQpbI")
	secretBytes, err := base64.StdEncoding.DecodeString(secret)
	assert.NoError(err)

	credential := "ADQAID2qrkbHKt9ZEBb4RdhMh6esz52AHxuqd6LDDtI3pxwxMyYyEGNq0usYQAnW2H4hmggl"


	// credentialBytes, err := ioutil.ReadFile("/tmp/aikName")
	// secretBytes, err := ioutil.ReadFile("/tmp/secret.data") //[]byte("12345678")

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
