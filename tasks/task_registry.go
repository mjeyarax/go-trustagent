/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package tasks

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"intel/isecl/go-trust-agent/config"
	"intel/isecl/go-trust-agent/constants"
	"intel/isecl/lib/common/setup"
	"intel/isecl/lib/common/validation"
)

type TaskRegistry struct {
	taskMap map[string][]setup.Task
}

const (
	SetupAllCommand					= "all"
	TakeOwnershipCommand 			= "takeownership"
	ServerConfigCommand				= "serverconfig"
	CreateTLSKeyPairCommand			= "createtlskeypair"
	ProvisionEndorsementKeyCommand	= "provisionendorsementkey"
)

func CreateTaskRegistry(flags []string) (TaskRegistry, error) {

	var registry TaskRegistry
	registry.taskMap = make(map[string][]setup.Task)

	takeOwnership := TakeOwnership { Flags : flags }
	serverConfig := ServerConfig {Flags : flags }
	createTLSKeyPair := CreateTLSKeyPair { Flags: flags }
	provisionEndorsementKey := ProvisionEndorsementKey { Flags: flags }

	registry.taskMap[TakeOwnershipCommand] = []setup.Task { &takeOwnership, }
	registry.taskMap[ServerConfigCommand] = []setup.Task { &serverConfig, }
	registry.taskMap[CreateTLSKeyPairCommand] = []setup.Task { &createTLSKeyPair, }
	registry.taskMap[ProvisionEndorsementKeyCommand] = []setup.Task { &provisionEndorsementKey, }

	registry.taskMap[SetupAllCommand] = []setup.Task {
		&serverConfig,
		&createTLSKeyPair,
		&takeOwnership,
		&provisionEndorsementKey,
	}

	return registry, nil
}

func (registry *TaskRegistry) RunCommand(command string) error {
	tasks, ok := registry.taskMap[command]
	if !ok {
		return errors.New("Command '" + command +"' is not a valid setup option")
	}

	err := registry.oneStopShopping() 
	if err != nil {
		return err
	}

	setupRunner := &setup.Runner {
		Tasks: tasks,
		AskInput: false,
	}

	err = setupRunner.RunTasks()
	if err != nil {
		return err
	}

	return nil
}

// WEEK2:  move to 'config' setup task
// this is lame code that attempts to apply all of the env variables
// to configuration.  Common isn't cutting it
func (registry *TaskRegistry) oneStopShopping() error {

	var err error
	dirty := false
	cfg := config.GetConfiguration()

	//---------------------------------------------------------------------------------------------
	// TPM_OWNER_SECRET
	//---------------------------------------------------------------------------------------------
	environmentVariable := os.Getenv("TPM_OWNER_SECRET")
	if environmentVariable != "" && cfg.Tpm.SecretKey != environmentVariable {
		cfg.Tpm.SecretKey = environmentVariable
		dirty = true
	}

	// SecretKey is not required since it may be set in tasks.take_ownership.go

	//---------------------------------------------------------------------------------------------
	// MTWILSON_API_URL
	//---------------------------------------------------------------------------------------------
	environmentVariable = os.Getenv("MTWILSON_API_URL")
	if environmentVariable != "" && cfg.HVS.Url != environmentVariable {
		cfg.HVS.Url = environmentVariable
		dirty = true
	}

	if cfg.HVS.Url == "" {
		return fmt.Errorf("Mtwilson api url is required")
	}

	//---------------------------------------------------------------------------------------------
	// MTWILSON_API_USERNAME
	//---------------------------------------------------------------------------------------------
	environmentVariable = os.Getenv("MTWILSON_API_USERNAME")
	if environmentVariable != "" && cfg.HVS.Username != environmentVariable {
		cfg.HVS.Username = environmentVariable
		dirty = true
	}

	if cfg.HVS.Username == "" {
		return fmt.Errorf("Mtwilson user is required")
	}

	//---------------------------------------------------------------------------------------------
	// MTWILSON_API_PASSWORD
	//---------------------------------------------------------------------------------------------
	environmentVariable = os.Getenv("MTWILSON_API_PASSWORD")
	if environmentVariable != "" && cfg.HVS.Password != environmentVariable {
		cfg.HVS.Password = environmentVariable
		dirty = true
	}

	if cfg.HVS.Password == "" {
		return fmt.Errorf("Mtwilson password is required")
	}

	//---------------------------------------------------------------------------------------------
	// MTWILSON_TLS_CERT_SHA384
	//---------------------------------------------------------------------------------------------
	environmentVariable = os.Getenv("MTWILSON_TLS_CERT_SHA384")
	if environmentVariable != "" {
		if len(environmentVariable) != 96 {
			return fmt.Errorf("Setup error:  Invalid length MTWILSON_TLS_CERT_SHA384: %d", len(environmentVariable))
		} 
	
		if err = validation.ValidateHexString(environmentVariable); err != nil {
			return fmt.Errorf("Setup error:  MTWILSON_TLS_CERT_SHA384 is not a valid hex string: %s", environmentVariable)
		}

		if cfg.HVS.TLS384 != environmentVariable {
			cfg.HVS.TLS384 = environmentVariable
			dirty = true
		}
	}

	if cfg.HVS.TLS384 == "" {
		return fmt.Errorf("Mtwilson tls 384 is required")
	}

	//---------------------------------------------------------------------------------------------
	// TRUSTAGENT_PORT
	//---------------------------------------------------------------------------------------------
	port := 0
	environmentVariable = os.Getenv("TRUSTAGENT_PORT")
	if environmentVariable != "" {
		port, err = strconv.Atoi(environmentVariable)
		if err != nil {
			return fmt.Errorf("Setup error: Invalid TRUSTAGENT_PORT value '%s' [%s]", environmentVariable, err.Error())
		}
	}
	
	// always apply the default port of 1443
	if port == 0 {
		port = constants.DefaultPort
	}

	if cfg.TrustAgentService.Port != port {
		cfg.TrustAgentService.Port = port
		dirty = true
	}

	//---------------------------------------------------------------------------------------------
	// TRUSTAGENT_ADMIN_USERNAME
	//---------------------------------------------------------------------------------------------
	environmentVariable = os.Getenv("TRUSTAGENT_ADMIN_USERNAME")
	if environmentVariable != "" && cfg.TrustAgentService.Username != environmentVariable {
		cfg.TrustAgentService.Username = environmentVariable
		dirty = true
	}

	if cfg.TrustAgentService.Username == "" {
		return fmt.Errorf("Trust agent user is required")
	}

	//---------------------------------------------------------------------------------------------
	// TRUSTAGENT_ADMIN_PASSWORD
	//---------------------------------------------------------------------------------------------
	environmentVariable = os.Getenv("TRUSTAGENT_ADMIN_PASSWORD")
	if environmentVariable != "" && cfg.TrustAgentService.Password != environmentVariable {
		cfg.TrustAgentService.Password = environmentVariable
		dirty = true
	}

	if cfg.TrustAgentService.Password == "" {
		return fmt.Errorf("Trust agen password is required")
	}

	//---------------------------------------------------------------------------------------------
	// Save config if 'dirty'
	//---------------------------------------------------------------------------------------------
	if dirty {
		err = config.GetConfiguration().Save()
		if err != nil {
			return fmt.Errorf("Setup error:  Error saving configuration [%s]", err.Error())
		}
	}

	return nil
}