/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package tasks

import (
	"errors"
	"intel/isecl/lib/common/setup"
)

type TaskRegistry struct {
	taskMap map[string][]setup.Task
}

const (
	DefaultSetupCommand						= "all"
	TakeOwnershipCommand 					= "takeownership"
	TrustAgentConfigCommand					= "config"
	CreateTLSKeyPairCommand					= "createtlskeypair"
	ProvisionEndorsementKeyCommand			= "provisionek"
	ProvisionAttestationIdentityKeyCommand	= "provisionaik"
	DownloadPrivacyCACommand				= "downloadprivacyca"
)

func CreateTaskRegistry(flags []string) (TaskRegistry, error) {

	var registry TaskRegistry
	registry.taskMap = make(map[string][]setup.Task)

	takeOwnership := TakeOwnership { Flags : flags }
	trustAgentConfig := TrustAgentConfig {Flags : flags }
	createTLSKeyPair := CreateTLSKeyPair { Flags: flags }
	provisionEndorsementKey := ProvisionEndorsementKey { Flags: flags }
	provisionAttestationIdentityKey := ProvisionAttestationIdentityKey { Flags: flags }
	downloadPrivacyCA := DownloadPrivacyCA { Flags: flags }

	registry.taskMap[TakeOwnershipCommand] = []setup.Task { &takeOwnership, }
	registry.taskMap[TrustAgentConfigCommand] = []setup.Task { &trustAgentConfig, }
	registry.taskMap[CreateTLSKeyPairCommand] = []setup.Task { &createTLSKeyPair, }
	registry.taskMap[ProvisionEndorsementKeyCommand] = []setup.Task { &provisionEndorsementKey, }
	registry.taskMap[ProvisionAttestationIdentityKeyCommand] = []setup.Task { &provisionAttestationIdentityKey, }
	registry.taskMap[DownloadPrivacyCACommand] = []setup.Task { &downloadPrivacyCA, }

	registry.taskMap[DefaultSetupCommand] = []setup.Task {
		&trustAgentConfig,
		&createTLSKeyPair,
		&downloadPrivacyCA,
		&takeOwnership,
		&provisionEndorsementKey,
		&provisionAttestationIdentityKey,
	}

	return registry, nil
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