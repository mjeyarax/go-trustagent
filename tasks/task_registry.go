/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package tasks

import (
	"encoding/hex"
	"errors"
	"fmt"
	"intel/isecl/lib/common/setup"
	"intel/isecl/go-trust-agent/config"
	"intel/isecl/go-trust-agent/vsclient"
)

type TaskRegistry struct {
	taskMap map[string][]setup.Task
}

const (
	DefaultSetupCommand						= "all"
	TakeOwnershipCommand 					= "takeownership"
	TrustAgentConfigCommand					= "config"
	CreateTLSKeyPairCommand					= "createtlskeypair"
	ReplaceTLSKeyPairCommand				= "replace-tls-keypair"
	ProvisionEndorsementKeyCommand			= "provisionek"
	ProvisionAttestationIdentityKeyCommand	= "provisionaik"
	DownloadPrivacyCACommand				= "downloadprivacyca"
	ProvisionPrimaryKeyCommand				= "provisionprimarykey"
	CreateHostCommand						= "create-host"
	CreateHostUniqueFlavorCommand			= "create-host-unique-flavor"
	GetConfiguredManifestCommand			= "get-configured-manifest"
)

func CreateTaskRegistry(flags []string) (*TaskRegistry, error) {

	var registry TaskRegistry
	registry.taskMap = make(map[string][]setup.Task)

	// assumes that configuration has been populated
	vsClientFactory, err := registry.newVSClientFactory()
	if err != nil {
		return nil, err
	}

	takeOwnership := TakeOwnership { Flags : flags }
	createTLSKeyPair := CreateTLSKeyPair { Flags: flags }
	provisionEndorsementKey := ProvisionEndorsementKey { Flags: flags }
	provisionAttestationIdentityKey := ProvisionAttestationIdentityKey { Flags: flags }
	downloadPrivacyCA := DownloadPrivacyCA { Flags: flags }
	provisionPrimaryKey := ProvisionPrimaryKey { Flags: flags }

	registry.taskMap[TakeOwnershipCommand] = []setup.Task { &takeOwnership, }
	registry.taskMap[CreateTLSKeyPairCommand] = []setup.Task { &createTLSKeyPair, }
	registry.taskMap[ProvisionEndorsementKeyCommand] = []setup.Task { &provisionEndorsementKey, }
	registry.taskMap[ProvisionAttestationIdentityKeyCommand] = []setup.Task { &provisionAttestationIdentityKey, }
	registry.taskMap[DownloadPrivacyCACommand] = []setup.Task { &downloadPrivacyCA, }
	registry.taskMap[ProvisionPrimaryKeyCommand] = []setup.Task { &provisionPrimaryKey, }

	registry.taskMap[DefaultSetupCommand] = []setup.Task {
		&createTLSKeyPair,
		&downloadPrivacyCA,
		&takeOwnership,
		&provisionEndorsementKey,
		&provisionAttestationIdentityKey,
		&provisionPrimaryKey,
	}

	// these are individual commands that are not included of setup
	registry.taskMap[CreateHostCommand] = []setup.Task { &CreateHost { Flags: flags, hostsClient : vsClientFactory.HostsClient() }}
	registry.taskMap[CreateHostUniqueFlavorCommand] = []setup.Task { &CreateHostUniqueFlavor { Flags: flags, flavorsClient : vsClientFactory.FlavorsClient() }}
	registry.taskMap[ReplaceTLSKeyPairCommand] = []setup.Task { &DeleteTlsKeypair { Flags: flags }, &createTLSKeyPair,}
	registry.taskMap[GetConfiguredManifestCommand] = []setup.Task { &GetConfiguredManifest { Flags: flags, manifestsClient : vsClientFactory.ManifestsClient() }}

	return &registry, nil
}

func (registry *TaskRegistry) RunCommand(command string) error {
	tasks, ok := registry.taskMap[command]
	if !ok {
		return errors.New("Command '" + command +"' is not a valid setup option")
	}

	setupRunner := &setup.Runner {
		Tasks: tasks,
		AskInput: false,
	}

	err := setupRunner.RunTasks()
	if err != nil {
		return err
	}

	return nil
}

func (registry *TaskRegistry) newVSClientFactory() (vsclient.VSClientFactory, error) {

	var certificateDigest [48]byte

	cfg := config.GetConfiguration()

	certDigestBytes, err := hex.DecodeString(cfg.HVS.TLS384)
	if err != nil {
		return nil, fmt.Errorf("error converting certificate digest to hex: %s", err)
	}

	if len(certDigestBytes) != 48 {
		return nil, fmt.Errorf("Incorrect TLS384 string length %d", len(certDigestBytes))
	}

	copy(certificateDigest[:], certDigestBytes)

	vsClientConfig := vsclient.VSClientConfig {
		BaseURL: cfg.HVS.Url,
		Username : cfg.HVS.Username,
		Password : cfg.HVS.Password,
		CertSha384 : &certificateDigest,
	}

	vsClientFactory, err := vsclient.NewVSClientFactory(&vsClientConfig)
	if err != nil {
		return nil, err
	}

	return vsClientFactory, nil
}