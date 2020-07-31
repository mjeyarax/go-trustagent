/*
* Copyright (C) 2020 Intel Corporation
* SPDX-License-Identifier: BSD-3-Clause
 */
package tasks

import (
	"fmt"
	"intel/isecl/go-trust-agent/v2/util"
	"intel/isecl/go-trust-agent/v2/vsclient"
	"intel/isecl/lib/common/v2/setup"
	"github.com/pkg/errors"
)

type CreateHost struct {
	clientFactory vsclient.VSClientFactory
	connectionString string
}

//
// Registers (or updates) HVS with information about the current compute
// node (providing the connection string, hostname (ip addr) and tls policy).
//
// If the host already exists, create-host will return an error.
//
func (task *CreateHost) Run(c setup.Context) error {
	log.Trace("tasks/create_host:Run() Entering")
	defer log.Trace("tasks/create_host:Run() Leaving")

	var err error
	fmt.Println("Running setup task: create-host")

	hostsClient, err := task.clientFactory.HostsClient()
	if err != nil {
		return errors.Wrap(err, "Could not create host client")
	}

	ip, err := util.GetLocalIpAsString()
	if err != nil {
		return errors.Wrap(err, "Error while getting Local IP address")
	}

	hostFilterCriteria := vsclient.HostFilterCriteria{NameEqualTo: ip}
	hostCollection, err := hostsClient.SearchHosts(&hostFilterCriteria)
	if err != nil {
		return errors.Wrap(err, "Error while retrieving host collection")
	}

	if len(hostCollection.Hosts) == 0 {
		// no host present, create a new one
		hostCreateCriteria := vsclient.HostCreateCriteria{}
		hostCreateCriteria.HostName = ip
		hostCreateCriteria.ConnectionString = task.connectionString
		hostCreateCriteria.TlsPolicyId = vsclient.TRUST_POLICY_TRUST_FIRST_CERTIFICATE // tlsPolicy.Id

		host, err := hostsClient.CreateHost(&hostCreateCriteria)
		if err != nil {
			return err
		}

		log.Debugf("tasks/create_host:Run() Successfully created host, host id %s", host.Id)
	} else {
		return errors.Errorf("Host with IP address %s already exists", ip)
	}

	return nil
}

// Using the ip address, query VS to verify if this host is registered
func (task *CreateHost) Validate(c setup.Context) error {
	log.Trace("tasks/create_host:Validate() Entering")
	defer log.Trace("tasks/create_host:Validate() Leaving")

	// Initialize the PrivacyCA client using the factory - this will be reused in Run
	hostsClient, err := task.clientFactory.HostsClient()
	if err != nil {
		return errors.Wrap(err, "Could not create host client")
	}

	ip, err := util.GetLocalIpAsString()
	if err != nil {
		return errors.Wrap(err, "Error while getting Local IP address")
	}

	hostFilterCriteria := vsclient.HostFilterCriteria{NameEqualTo: ip}
	hostCollection, err := hostsClient.SearchHosts(&hostFilterCriteria)
	if err != nil {
		return errors.Wrap(err, "Error searching for host collection")
	}

	if len(hostCollection.Hosts) == 0 {
		return errors.Errorf("Host with ip '%s' was not created", ip)
	}

	log.Info("tasks/create_host:Validate() Create host setup task was successful.")
	return nil
}
