/*
* Copyright (C) 2019 Intel Corporation
* SPDX-License-Identifier: BSD-3-Clause
*/
package tasks

import (
	log "github.com/sirupsen/logrus"
	"intel/isecl/lib/common/setup"
	"intel/isecl/go-trust-agent/vsclient"
	"intel/isecl/go-trust-agent/util"
)

type CreateHostUniqueFlavor struct {
	Flags 	[]string
	vsClientFactory vsclient.VSClientFactory
	flavorsClient vsclient.FlavorsClient
	ip string
}

func (task* CreateHostUniqueFlavor) Run(c setup.Context) error {
	var err error

	task.ip, err = util.GetLocalIpAsString()
	if err != nil {
		return err
	}

	vsClient, err := task.vsClientFactory.NewVSClient()
	if err != nil {
		return err
	}

	task.flavorsClient = vsClient.Flavors()

	connectionString, err := util.GetConnectionString()
	if err != nil {
		return err
	}
	
	flavorCreateCriteria := vsclient.FlavorCreateCriteria {
		ConnectionString : connectionString,
		FlavorGroupName : "",
		PartialFlavorTypes : []string {vsclient.FLAVOR_HOST_UNIQUE,},
		TlsPolicyId : vsclient.TRUST_POLICY_TRUST_FIRST_CERTIFICATE,
	}

	err = task.flavorsClient.CreateFlavor(&flavorCreateCriteria)
	if err != nil {
		return err
	}

	return nil
}

func (task* CreateHostUniqueFlavor) Validate(c setup.Context) error {
	// no validation implemented
	log.Info("Setup: Create host unique flavor was successful.")
	return nil
}