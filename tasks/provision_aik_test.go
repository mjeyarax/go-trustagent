// +build !integration

/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
 package tasks

 import (
//	"encoding/hex"
	"io/ioutil"
	"testing"
	"github.com/stretchr/testify/assert"
//	"intel/isecl/go-trust-agent/config"
)

func TestGetTpmSymetricKey(t *testing.T) {
	assert := assert.New(t)

	provisionAik := ProvisionAttestationIdentityKey { Flags: nil }

	key := []byte("aaaabbbbaaaabbbb")

	_, err := provisionAik.getTpmSymetricKey(key)
	assert.NoError(err)
}

func TestGetEncryptedEndorsementCertificate(t *testing.T) {
	assert := assert.New(t)

	provisionAik := ProvisionAttestationIdentityKey { Flags: nil }

	ekCertBytes, err := ioutil.ReadFile("/tmp/ek.der")
	assert.NoError(err)

	_, err = provisionAik.getEncryptedEndorsementCertificate(ekCertBytes)
	assert.NoError(err)
}