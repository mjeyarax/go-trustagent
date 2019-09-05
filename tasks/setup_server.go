/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
 package tasks

import (
	"errors"
	log "github.com/sirupsen/logrus"
	"intel/isecl/go-trust-agent/config"
	"intel/isecl/go-trust-agent/constants"
	"intel/isecl/lib/common/setup"
)

type SetupServer struct {
	Flags 	[]string
}

func (task* SetupServer) Run(c setup.Context) error {
	log.Info("SetupServer Run")

	var err error

	port, err := c.GetenvInt("TRUSTAGENT_PORT", "trustagent service http port")
	if err != nil {
		port = constants.DefaultPort
	}

	if config.GetConfiguration().Port == 0 || config.GetConfiguration().Port != port {
		config.GetConfiguration().Port = port
		err = config.GetConfiguration().Save()
		if err != nil {
			log.Errorf("Error saving config.yaml: %s", err.Error())
		}
	} else {
		log.Infof("Did not configure port value '%d'", port)
	}

	return nil
}

func (task* SetupServer) Validate(c setup.Context) error {
	log.Info("SetupServer Validate")

	if config.GetConfiguration().Port == 0 {
		return errors.New("Invalid port value '0'")
	}

	log.Infof("trustagent is configured to run on port %d", config.GetConfiguration().Port)

	return nil
}