// +build unit_test

/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package vsclient

import (
	"github.com/stretchr/testify/mock"
)

//-------------------------------------------------------------------------------------------------
// Mocked Client Factory:  Assumes that unit tests will populate the factory with mocked 
// implementations of the clients as needed.
//-------------------------------------------------------------------------------------------------
type MockedVSClientFactory struct {
	MockedHostsClient HostsClient
	MockedFlavorsClient FlavorsClient
	MockedManifestsClient ManifestsClient
	MockedTpmEndorsementClient TpmEndorsementsClient
	MockedPrivacyCAClient PrivacyCAClient
	MockedCACertificatesClient CACertificatesClient
}

func (factory MockedVSClientFactory) HostsClient() (HostsClient, error) {
	return factory.MockedHostsClient, nil
}

func (factory MockedVSClientFactory) FlavorsClient() (FlavorsClient, error) {
	return factory.MockedFlavorsClient, nil
}

func (factory MockedVSClientFactory) ManifestsClient() (ManifestsClient, error) {
	return factory.MockedManifestsClient, nil
}

func (factory MockedVSClientFactory) TpmEndorsementsClient() (TpmEndorsementsClient, error) {
	return factory.MockedTpmEndorsementClient, nil
}

func (factory MockedVSClientFactory) PrivacyCAClient() (PrivacyCAClient, error) {
	return factory.MockedPrivacyCAClient, nil
}

func (factory MockedVSClientFactory) CACertificatesClient() (CACertificatesClient, error) {
	return factory.MockedCACertificatesClient, nil
}

//-------------------------------------------------------------------------------------------------
// Mocked Hosts interface
//-------------------------------------------------------------------------------------------------
type MockedHostsClient struct {
	mock.Mock
}

// Can be mocked in unit tests similar to...
// mockedHostsClient := new(vsclient.MockedHostsClient)
// mockedHostsClient.On("SearchHosts", mock.Anything).Return(&vsclient.HostCollection {Hosts: []vsclient.Host{}}, nil)
func (mock MockedHostsClient) SearchHosts(hostFilterCriteria *HostFilterCriteria) (*HostCollection, error) {
	args := mock.Called(hostFilterCriteria)
	return args.Get(0).(*HostCollection), args.Error(1)
}

// Can be mocked in unit tests similar to...
// mockedHostsClient := new(vsclient.MockedHostsClient)
// mockedHostsClient.On("CreateHost", mock.Anything).Return(&vsclient.Host{Id:"068b5e88-1886-4ac2-a908-175cf723723f"}, nil)
func (mock MockedHostsClient) CreateHost(hostCreateCriteria *HostCreateCriteria) (*Host, error) {
	args := mock.Called(hostCreateCriteria)
	return args.Get(0).(*Host), args.Error(1)
}

// func (mock MockedHostsClient) UpdateHost(host *Host) (*Host, error) {
// 	args := mock.Called(host)
// 	return args.Get(0).(*Host), args.Error(1)
// }

//-------------------------------------------------------------------------------------------------
// Mocked Flavors interface
//-------------------------------------------------------------------------------------------------
type MockedFlavorsClient struct {
	mock.Mock
}

func (mock MockedFlavorsClient) CreateFlavor(flavorCreateCriteria *FlavorCreateCriteria) error {
	args := mock.Called(flavorCreateCriteria)
	return args.Error(0)	
}

//-------------------------------------------------------------------------------------------------
// Mocked Manifests interface
//-------------------------------------------------------------------------------------------------
type MockedManifestsClient struct {
	mock.Mock
}

func (mock MockedManifestsClient) GetManifestXmlById(manifestUUID string) ([]byte, error) {
	args := mock.Called(manifestUUID)
	return args.Get(0).([]byte), args.Error(1)
}

func (mock MockedManifestsClient)GetManifestXmlByLabel(manifestLabel string) ([]byte, error) {
	args := mock.Called(manifestLabel)
	return args.Get(0).([]byte), args.Error(1)
}
