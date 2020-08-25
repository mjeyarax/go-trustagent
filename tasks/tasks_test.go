// +build unit_test

/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package tasks


import (
	"os"
	"github.com/google/uuid"
	"github.com/intel-secl/intel-secl/v3/pkg/clients/hvsclient"
	"github.com/intel-secl/intel-secl/v3/pkg/model/hvs"
	"intel/isecl/go-trust-agent/v3/constants"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"intel/isecl/go-trust-agent/v3/config"
	"intel/isecl/lib/common/v3/setup"
	"intel/isecl/lib/tpmprovider/v3"
	"testing"
)

const (
	TpmSecretKey   = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
	AikSecretKey   = "beefbeefbeefbeefbeefbeefbeefbeefbeefbeef"
)

func TestTakeOwnership(t *testing.T) {
	assert := assert.New(t)

	cfg := &config.TrustAgentConfiguration{}
	cfg.Tpm.OwnerSecretKey = TpmSecretKey

	mockedTpmProvider := new(tpmprovider.MockedTpmProvider)
	mockedTpmProvider.On("Close").Return(nil)
	mockedTpmProvider.On("Version", mock.Anything).Return(tpmprovider.V20)
	mockedTpmProvider.On("TakeOwnership", mock.Anything).Return(nil)
	mockedTpmProvider.On("IsOwnedWithAuth", mock.Anything).Return(true, nil)
	mockedTpmFactory := tpmprovider.MockedTpmFactory{TpmProvider: mockedTpmProvider}

	context := setup.Context{}
	createHost := TakeOwnership{tpmFactory: mockedTpmFactory, ownerSecretKey: &cfg.Tpm.OwnerSecretKey}

	err := createHost.Run(context)
	assert.NoError(err)

	err = createHost.Validate(context)
	assert.NoError(err)
}

// func TestProvisionPrimaryKey(t *testing.T) {
// 	assert := assert.New(t)

// 	cfg := &config.TrustAgentConfiguration{}
// 	cfg.Tpm.OwnerSecretKey = TpmSecretKey

// 	mockedTpmProvider := new(tpmprovider.MockedTpmProvider)
// 	mockedTpmProvider.On("Version", mock.Anything).Return(tpmprovider.V20)
// 	mockedTpmFactory := tpmprovider.MockedTpmFactory{TpmProvider : mockedTpmProvider}

// 	context := setup.Context {}
// 	provisionPrimaryKey := ProvisionPrimaryKey {tpmFactory : mockedTpmFactory, cfg : cfg}

// 	err := provisionPrimaryKey.Run(context)
// 	assert.NoError(err)

// 	err = provisionPrimaryKey.Validate(context)
// 	assert.NoError(err)
// }

// func TestGetEncryptedEndorsementCertificate(t *testing.T) {
// 	assert := assert.New(t)

// 	provisionAik := ProvisionAttestationIdentityKey { Flags: nil }

// 	ekCertBytes, err := ioutil.ReadFile("/tmp/ek.der")
// 	assert.NoError(err)

// 	_, err = provisionAik.getEncryptedBytes(ekCertBytes)
// 	assert.NoError(err)
// }

// func TestRegisterDownloadEndorsementAuthorities(t *testing.T) {
// 	assert := assert.New(t)

// 	cfg := &config.TrustAgentConfiguration {}
// 	cfg.HVS.Url = "https://vs.server.com:8443/mtwilson/v2"
// 	cfg.HVS.Username = "admin"
// 	cfg.HVS.Password = "password"
// 	cfg.HVS.TLS384 = "7ff464fdd47192d7218e9bc7a80043641196762b840c5c79b7fdaaae471cbffb0ee893c23bca63197b8a863f516a7d8b"

// 	provisionEndorsementKey := ProvisionEndorsementKey {}

// 	err := provisionEndorsementKey.downloadEndorsementAuthorities()
// 	assert.NoError(err)
// }

func TestCreateHostDefault(t *testing.T) {
	assert := assert.New(t)

	cfg := &config.TrustAgentConfiguration{}
	cfg.WebService.Port = 8045

	// create mocks that return no hosts on 'SearchHosts' (i.e. host does not exist in hvs) and
	// host with an new id for 'CreateHost'
	mockedHostsClient := new(hvsclient.MockedHostsClient)
	mockedHostsClient.On("SearchHosts", mock.Anything).Return(&hvs.HostCollection{Hosts: []*hvs.Host{}}, nil)
	mockedHostsClient.On("CreateHost", mock.Anything).Return(&hvs.Host{Id: uuid.MustParse("068b5e88-1886-4ac2-a908-175cf723723f")}, nil)

	mockedVSClientFactory := hvsclient.MockedVSClientFactory {MockedHostsClient : mockedHostsClient}

	context := setup.Context{}

	os.Setenv(constants.EnvCurrentIP, "99.99.99.99")
	createHost := CreateHost{clientFactory: mockedVSClientFactory, trustAgentPort: cfg.WebService.Port}
	err := createHost.Run(context)
	assert.NoError(err)
}

func TestCreateHostExisting(t *testing.T) {
	assert := assert.New(t)

	cfg := &config.TrustAgentConfiguration{}
	cfg.WebService.Port = 8045
	hwUuid := uuid.MustParse("8032632b-8fa4-e811-906e-00163566263e")
	existingHost := hvs.Host{
		Id:               uuid.MustParse("068b5e88-1886-4ac2-a908-175cf723723d"),
		HostName:         "ta.server.com",
		Description:      "GTA RHEL 8.0",
		ConnectionString: "https://ta.server.com:1443",
		HardwareUuid:     &hwUuid,
	}

	// create mocks that return a host (i.e. it exists in hvs)
	mockedHostsClient := new(hvsclient.MockedHostsClient)
	mockedHostsClient.On("SearchHosts", mock.Anything).Return(&hvs.HostCollection{Hosts: []*hvs.Host{&existingHost}}, nil)
	mockedHostsClient.On("CreateHost", mock.Anything).Return(&hvs.Host{Id: uuid.MustParse("068b5e88-1886-4ac2-a908-175cf723723f")}, nil)

	mockedVSClientFactory := hvsclient.MockedVSClientFactory {MockedHostsClient : mockedHostsClient}

	context := setup.Context{}
	os.Setenv(constants.EnvCurrentIP, "99.99.99.99")
	createHost := CreateHost{clientFactory: mockedVSClientFactory, trustAgentPort: cfg.WebService.Port}
	err := createHost.Run(context)
	assert.Error(err)
}
