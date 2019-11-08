// +build !integration

/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
 package tasks

 import (
	"testing"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"intel/isecl/go-trust-agent/config"
	"intel/isecl/go-trust-agent/vsclient"
	"intel/isecl/lib/common/setup"
)

const (
	TpmSecretKey	= "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
	AikSecretKey	= "beefbeefbeefbeefbeefbeefbeefbeefbeefbeef"
	TAgentUser		= "tagent"
	TAgentPassword  = "TAgentAdminPassword"
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

	config.InitConfiguration()
	config.GetConfiguration().HVS.Url = "https://10.105.168.60:8443/mtwilson/v2"
	config.GetConfiguration().HVS.Username = "admin"
	config.GetConfiguration().HVS.Password = "password"
	config.GetConfiguration().HVS.TLS384 = "7ff464fdd47192d7218e9bc7a80043641196762b840c5c79b7fdaaae471cbffb0ee893c23bca63197b8a863f516a7d8b"

	provisionEndorsementKey := ProvisionEndorsementKey { Flags: nil }

	err := provisionEndorsementKey.downloadEndorsementAuthorities()
	assert.NoError(err)
}

func TestCreateHostDefault(t *testing.T) {
	assert := assert.New(t)

	config.InitConfiguration()
	config.GetConfiguration().TrustAgentService.Username = TAgentUser
	config.GetConfiguration().TrustAgentService.Password = TAgentPassword 

	// create mocks that return no hosts on 'SearchHosts' (i.e. host does not exist in hvs) and
	// host with an new id for 'CreateHost'
	mockedHostsClient := new(vsclient.MockedHostsClient)
	mockedHostsClient.On("SearchHosts", mock.Anything).Return(&vsclient.HostCollection {Hosts: []vsclient.Host{}}, nil)
	mockedHostsClient.On("CreateHost", mock.Anything).Return(&vsclient.Host{Id:"068b5e88-1886-4ac2-a908-175cf723723f"}, nil)

	context := setup.Context {}
	createHost := CreateHost { Flags: nil, hostsClient : mockedHostsClient }
	err := createHost.Run(context)
	assert.NoError(err)
}

func TestCreateHostExisting(t *testing.T) {
	assert := assert.New(t)

	config.InitConfiguration()
	config.GetConfiguration().TrustAgentService.Username = TAgentUser
	config.GetConfiguration().TrustAgentService.Password = TAgentPassword

	existingHost := vsclient.Host {
		Id : "068b5e88-1886-4ac2-a908-175cf723723d",
		HostName : "10.105.167.153",
		Description : "GTA RHEL 8.0",
		ConnectionString : "https://10.105.167.153:1443",
		HardwareUUID : "8032632b-8fa4-e811-906e-00163566263e",
		TlsPolicyId : "e1a1c631-e006-4ff2-aed1-6b42a2f5be6c",
	}

	// create mocks that return a host (i.e. it exists in hvs)
	mockedHostsClient := new(vsclient.MockedHostsClient)
	mockedHostsClient.On("SearchHosts", mock.Anything).Return(&vsclient.HostCollection {Hosts: []vsclient.Host{existingHost,}}, nil)	
	mockedHostsClient.On("CreateHost", mock.Anything).Return(&vsclient.Host{Id:"068b5e88-1886-4ac2-a908-175cf723723f"}, nil)

	context := setup.Context {}
	createHost := CreateHost { Flags: nil, hostsClient : mockedHostsClient }
	err := createHost.Run(context)
	assert.Error(err)
}
