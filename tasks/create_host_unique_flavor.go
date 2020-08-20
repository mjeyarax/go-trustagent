/*
* Copyright (C) 2020 Intel Corporation
* SPDX-License-Identifier: BSD-3-Clause
 */
package tasks

import (
	"fmt"
	"github.com/intel-secl/intel-secl/v3/pkg/clients/hvsclient"
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/domain/models"
	cf "github.com/intel-secl/intel-secl/v3/pkg/lib/flavor/common"
	"intel/isecl/lib/common/v3/setup"

	"github.com/pkg/errors"
)

type CreateHostUniqueFlavor struct {
	clientFactory    hvsclient.HVSClientFactory
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
		return errors.Wrap(err, "Could not create flavor client")
	}

	flavorCreateCriteria := models.FlavorCreateRequest{
			ConnectionString:       task.connectionString,
			FlavorParts:            []cf.FlavorPart{cf.FlavorPartHostUnique},
	}

	_, err = flavorsClient.CreateFlavor(&flavorCreateCriteria)
	if err != nil {
		return errors.Wrap(err, "Error while creating host unique flavor")
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
