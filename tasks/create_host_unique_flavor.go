/*
* Copyright (C) 2019 Intel Corporation
* SPDX-License-Identifier: BSD-3-Clause
 */
package tasks

import (
	log "github.com/sirupsen/logrus"
	"intel/isecl/go-trust-agent/config"
	"intel/isecl/go-trust-agent/util"
	"intel/isecl/go-trust-agent/vsclient"
	"intel/isecl/lib/common/setup"
)

type CreateHostUniqueFlavor struct {
	flavorsClient vsclient.FlavorsClient
	cfg           *config.TrustAgentConfiguration
	ip            string
}

// Communicates with HVS to create the host-unique-flavor from the current compute node.
func (task *CreateHostUniqueFlavor) Run(c setup.Context) error {
	var err error

	task.ip, err = util.GetLocalIpAsString()
	if err != nil {
		return err
	}

	connectionString, err := util.GetConnectionString(task.cfg)
	if err != nil {
		return err
	}

	flavorCreateCriteria := vsclient.FlavorCreateCriteria{
		ConnectionString:   connectionString,
		FlavorGroupName:    "",
		PartialFlavorTypes: []string{vsclient.FLAVOR_HOST_UNIQUE},
		TlsPolicyId:        vsclient.TRUST_POLICY_TRUST_FIRST_CERTIFICATE,
	}

	_, err = task.flavorsClient.CreateFlavor(&flavorCreateCriteria)
	if err != nil {
		return err
	}

	return nil
}

func (task *CreateHostUniqueFlavor) Validate(c setup.Context) error {
	// no validation is currently implemented (i.e. as long as Run did not fail)
	log.Info("Setup: Create host unique flavor was successful.")
	return nil
}
