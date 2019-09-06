/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package tasks

import (
	"errors"
	log "github.com/sirupsen/logrus"
	"intel/isecl/lib/common/setup"
)

type TaskRegistry struct {
	taskMap map[string][]setup.Task
}

const (
	SetupAllCommand				= "all"
	TakeOwnershipCommand 		= "takeownership"
	ServerConfigCommand			= "serverconfig"
	CreateTLSKeyPairCommand		= "createtlskeypair"
)

func CreateTaskRegistry(flags []string) (TaskRegistry, error) {

	var registry TaskRegistry
	registry.taskMap = make(map[string][]setup.Task)

	takeOwnership := TakeOwnership { Flags : flags }
	serverConfig := ServerConfig {Flags : flags }
	createTLSKeyPair := CreateTLSKeyPair { Flags: flags }

	registry.taskMap[TakeOwnershipCommand] = []setup.Task { &takeOwnership, }
	registry.taskMap[ServerConfigCommand] = []setup.Task { &serverConfig, }

	registry.taskMap[SetupAllCommand] = []setup.Task {
		&serverConfig,
		&createTLSKeyPair,
		&takeOwnership,
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
		log.WithError(err).Error("Error running setup")
		return err
	}

	return nil
}