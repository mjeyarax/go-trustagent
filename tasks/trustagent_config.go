/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
 package tasks

import (
	"fmt"
	"os"
	"strconv"
	"intel/isecl/go-trust-agent/config"
	"intel/isecl/go-trust-agent/constants"
	"intel/isecl/lib/common/setup"
	"intel/isecl/lib/common/validation"
)

// Applies environment variables to the configuration
type TrustAgentConfig struct {
	Flags 	[]string
}

func (task* TrustAgentConfig) Run(c setup.Context) error {

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

	//---------------------------------------------------------------------------------------------
	// MTWILSON_API_URL
	//---------------------------------------------------------------------------------------------
	environmentVariable = os.Getenv("MTWILSON_API_URL")
	if environmentVariable != "" && cfg.HVS.Url != environmentVariable {
		cfg.HVS.Url = environmentVariable
		dirty = true
	}

	//---------------------------------------------------------------------------------------------
	// MTWILSON_API_USERNAME
	//---------------------------------------------------------------------------------------------
	environmentVariable = os.Getenv("MTWILSON_API_USERNAME")
	if environmentVariable != "" && cfg.HVS.Username != environmentVariable {
		cfg.HVS.Username = environmentVariable
		dirty = true
	}

	//---------------------------------------------------------------------------------------------
	// MTWILSON_API_PASSWORD
	//---------------------------------------------------------------------------------------------
	environmentVariable = os.Getenv("MTWILSON_API_PASSWORD")
	if environmentVariable != "" && cfg.HVS.Password != environmentVariable {
		cfg.HVS.Password = environmentVariable
		dirty = true
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

	//---------------------------------------------------------------------------------------------
	// TRUSTAGENT_ADMIN_PASSWORD
	//---------------------------------------------------------------------------------------------
	environmentVariable = os.Getenv("TRUSTAGENT_ADMIN_PASSWORD")
	if environmentVariable != "" && cfg.TrustAgentService.Password != environmentVariable {
		cfg.TrustAgentService.Password = environmentVariable
		dirty = true
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

func (task* TrustAgentConfig) Validate(c setup.Context) error {
	cfg := config.GetConfiguration()

	if cfg.TrustAgentService.Port == 0 || cfg.TrustAgentService.Port > 65535 {
		return fmt.Errorf("Validation error: Invalid TrustAgent port value: '%d'", cfg.TrustAgentService.Port)
	}

	err := validation.ValidateAccount(cfg.TrustAgentService.Username, cfg.TrustAgentService.Password)
	if err != nil {
		return fmt.Errorf("Validation error: Invalid TrustAgent username or password [%s]", err.Error())
	}

	if cfg.HVS.Url == "" {
		return fmt.Errorf("Validation error: Mtwilson api url is required")
	}

	if cfg.HVS.Username == "" {
		return fmt.Errorf("Validation error: Mtwilson user is required")
	}

	if cfg.HVS.Password == "" {
		return fmt.Errorf("Validation error: Mtwilson password is required")
	}

	if cfg.HVS.TLS384 == "" {
		return fmt.Errorf("Validation error: Mtwilson tls 384 is required")
	}

	return nil
}