/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
 package tasks

import (
	"fmt"
	"os"
	"strconv"
	log "github.com/sirupsen/logrus"
	"intel/isecl/go-trust-agent/config"
	"intel/isecl/go-trust-agent/constants"
	"intel/isecl/lib/common/setup"
	"intel/isecl/lib/common/validation"
)

// Applies environment variables to the service configuration (i.e. port and 
// basic auth).
type ServerConfig struct {
	Flags 	[]string
}

func (task* ServerConfig) Run(c setup.Context) error {
	var err error
	var env string
	var port int

	log.Info("Running server setup/configuration")

	port = 0

	// would have used common.setup.GetenvInt if it didn't error when the
	// env var is not present
	env = os.Getenv("TRUSTAGENT_PORT")
	if env != "" {
		port, err = strconv.Atoi(env)
		if err != nil {
			return fmt.Errorf("Setup error: Invalid TRUSTAGENT_PORT value '%s' [%s]", env, err.Error())
		}
	}
	
	if port == 0 {
		port = constants.DefaultPort
	}

	// GetenvString will return an error if the env var is not
	username, err := c.GetenvString("TRUSTAGENT_ADMIN_USERNAME", "TrustAgent admin user")
	if err != nil {
		return fmt.Errorf("Setup error: Could not retrieve TRUSTAGENT_ADMIN_USERNAME [%s]", err.Error())
	}

	// GetenvSecret will return an error if the env var is not
	password, err := c.GetenvSecret("TRUSTAGENT_ADMIN_PASSWORD", "TrustAgent admin password")
	if err != nil {
		return fmt.Errorf("Setup error:  Could not retrieve TRUSTAGENT_ADMIN_PASSWORD [%s]", err.Error())
	}

	config.GetConfiguration().TrustAgentService.Port = port
	config.GetConfiguration().TrustAgentService.Username = username
	config.GetConfiguration().TrustAgentService.Password = password

	err = config.GetConfiguration().Save()
	if err != nil {
		return fmt.Errorf("Setup error:  Error saving configuration [%s]", err.Error())
	}

	return nil
}

func (task* ServerConfig) Validate(c setup.Context) error {
	if config.GetConfiguration().TrustAgentService.Port == 0 || config.GetConfiguration().TrustAgentService.Port > 65535 {
		return fmt.Errorf("Invalid port value: '%d'", config.GetConfiguration().TrustAgentService.Port)
	}

	err := validation.ValidateAccount(config.GetConfiguration().TrustAgentService.Username, config.GetConfiguration().TrustAgentService.Password)
	if err != nil {
		return fmt.Errorf("Validation error: Invalid username or password [%s]", err.Error())
	}

	log.Infof("Setup: TrustAgent service has been successfully configured (port %d).", config.GetConfiguration().TrustAgentService.Port)

	return nil
}