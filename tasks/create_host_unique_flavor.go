/*
* Copyright (C) 2019 Intel Corporation
* SPDX-License-Identifier: BSD-3-Clause
 */
package tasks

import (
	"fmt"
	"intel/isecl/go-trust-agent/config"
	"intel/isecl/go-trust-agent/util"
	"intel/isecl/go-trust-agent/vsclient"
	"intel/isecl/lib/common/setup"

	"github.com/pkg/errors"
)

type CreateHostUniqueFlavor struct {
	clientFactory vsclient.VSClientFactory
	flavorsClient vsclient.FlavorsClient
	cfg           *config.TrustAgentConfiguration
	ip            string
}

// Communicates with HVS to create the host-unique-flavor from the current compute node.
func (task *CreateHostUniqueFlavor) Run(c setup.Context) error {
	log.Trace("tasks/create_host_unique_flavor:Run() Entering")
	defer log.Trace("tasks/create_host_unique_flavor:Run() Leaving")
	var err error
	fmt.Println("Running setup task: create-host-unique-flavor")
	// initialize if nil
	if task.flavorsClient == nil {
		task.flavorsClient = task.clientFactory.FlavorsClient()
	}

	task.ip, err = util.GetLocalIpAsString()
	if err != nil {
		log.WithError(err).Error("tasks/create_host_unique_flavor:Run() Error while retrieving local IP")
		return errors.New("Error while retrieving local IP")
	}

	connectionString, err := util.GetConnectionString(task.cfg)
	if err != nil {
		log.WithError(err).Error("tasks/create_host_unique_flavor:Run() Error while getting connection string")
		return errors.New("Error while getting connection string")
	}

	flavorCreateCriteria := vsclient.FlavorCreateCriteria{
		ConnectionString:   connectionString,
		FlavorGroupName:    "",
		PartialFlavorTypes: []string{vsclient.FLAVOR_HOST_UNIQUE},
		TlsPolicyId:        vsclient.TRUST_POLICY_TRUST_FIRST_CERTIFICATE,
	}

	_, err = task.flavorsClient.CreateFlavor(&flavorCreateCriteria)
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
