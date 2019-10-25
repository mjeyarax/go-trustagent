// +build !integration

/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
 package tasks

 import (
	"testing"
	"github.com/stretchr/testify/assert"
	"intel/isecl/go-trust-agent/config"
)

const (
	TpmSecretKey	= "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
	AikSecretKey	= "beefbeefbeefbeefbeefbeefbeefbeefbeefbeef"
)

func TestTakeOwnership(t *testing.T) {
	assert := assert.New(t)

	config.InitConfiguration()
	config.GetConfiguration().Tpm.SecretKey = TpmSecretKey

	registry, err := CreateTaskRegistry(nil)
	assert.NoError(err)

	err = registry.RunCommand(TakeOwnershipCommand)
	assert.NoError(err)

	// run it a second time -- it should not fail
	err = registry.RunCommand(TakeOwnershipCommand)
	assert.NoError(err)
}

func TestGetTpmSymetricKey(t *testing.T) {
	assert := assert.New(t)

	provisionAik := ProvisionAttestationIdentityKey { Flags: nil }

	key := []byte("aaaabbbbaaaabbbb")

	_, err := provisionAik.getTpmSymetricKey(key)
	assert.NoError(err)
}

func TestProvisionPrimaryKey(t *testing.T) {
	assert := assert.New(t)

	config.InitConfiguration()
	config.GetConfiguration().Tpm.SecretKey = TpmSecretKey

	registry, err := CreateTaskRegistry(nil)
	assert.NoError(err)

	//registry.RunCommand(TakeOwnershipCommand)
	err = registry.RunCommand(ProvisionPrimaryKeyCommand)
	assert.NoError(err)
}

// func TestGetEncryptedEndorsementCertificate(t *testing.T) {
// 	assert := assert.New(t)

// 	provisionAik := ProvisionAttestationIdentityKey { Flags: nil }

// 	ekCertBytes, err := ioutil.ReadFile("/tmp/ek.der")
// 	assert.NoError(err)

// 	_, err = provisionAik.getEncryptedBytes(ekCertBytes)
// 	assert.NoError(err)
// }

func TestRegisterDownloadEndorsementAuthorities(t *testing.T) {
	assert := assert.New(t)

	config.GetConfiguration().HVS.Url = "https://10.105.168.60:8443/mtwilson/v2"
	config.GetConfiguration().HVS.Username = "admin"
	config.GetConfiguration().HVS.Password = "password"
	config.GetConfiguration().HVS.TLS384 = "7ff464fdd47192d7218e9bc7a80043641196762b840c5c79b7fdaaae471cbffb0ee893c23bca63197b8a863f516a7d8b"

	provisionEndorsementKey := ProvisionEndorsementKey { Flags: nil }

	err := provisionEndorsementKey.downloadEndorsementAuthorities()
	assert.NoError(err)
}