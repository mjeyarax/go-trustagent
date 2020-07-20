/*
* Copyright (C) 2020 Intel Corporation
* SPDX-License-Identifier: BSD-3-Clause
 */
package tasks

import (
	"fmt"
	"intel/isecl/go-trust-agent/v2/vsclient"
	"intel/isecl/lib/common/v2/setup"

	"github.com/pkg/errors"
)

type CreateHostUniqueFlavor struct {
	clientFactory vsclient.VSClientFactory
	connectionString string
}

// Communicates with HVS to establish the host-unique-flavor from the current compute node.
func (task *CreateHostUniqueFlavor) Run(c setup.Context) error {
	log.Trace("tasks/create_host_unique_flavor:Run() Entering")
	defer log.Trace("tasks/create_host_unique_flavor:Run() Leaving")
	var err error
	fmt.Println("Running setup task: create-host-unique-flavor")

	flavorsClient, err := task.clientFactory.FlavorsClient()
	if err != nil {
		log.WithError(err).Error("tasks/create_host_unique_flavor:Run() Could not create flavor client")
		return err
	}

	flavorCreateCriteria := vsclient.FlavorCreateCriteria{
		ConnectionString:   task.connectionString,
		FlavorGroupName:    "",
		PartialFlavorTypes: []string{vsclient.FLAVOR_HOST_UNIQUE},
	}

	_, err = flavorsClient.CreateFlavor(&flavorCreateCriteria)
	if err != nil {
		log.WithError(err).Error("tasks/create_host_unique_flavor:Run() Error while creating host unique flavor")
		return errors.New("Error while creating host unique flavor")
	}

	return nil
}

func (task *CreateHostUniqueFlavor) Validate(c setup.Context) error {
	log.Trace("tasks/create_host_unique_flavor:Validate() Entering")
	defer log.Trace("tasks/create_host_unique_flavor:Validate() Leaving")
	
	// no validation is currently implemented (i.e. as long as Run did not fail)
	log.Info("tasks/create_host_unique_flavor:Validate() Create host unique flavor was successful.")
	return nil
}
