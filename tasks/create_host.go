/*
* Copyright (C) 2019 Intel Corporation
* SPDX-License-Identifier: BSD-3-Clause
 */
package tasks

import (
	"fmt"
	log "github.com/sirupsen/logrus"
	"intel/isecl/go-trust-agent/config"
	"intel/isecl/go-trust-agent/util"
	"intel/isecl/go-trust-agent/vsclient"
	"intel/isecl/lib/common/setup"
)

type CreateHost struct {
	ip          string
	hostsClient vsclient.HostsClient
	cfg         *config.TrustAgentConfiguration
}

//
// Registers (or updates) HVS with information about the currenct compute
// node (providing the connection string, hostname (ip addr) and tls policy).
//
// If the host already exists, create-host will return an error.
//
func (task *CreateHost) Run(c setup.Context) error {

	var err error

	task.ip, err = util.GetLocalIpAsString()
	if err != nil {
		return err
	}

	connectionString, err := util.GetConnectionString(task.cfg)
	if err != nil {
		return err
	}

	hostFilterCriteria := vsclient.HostFilterCriteria{NameEqualTo: task.ip}
	hostCollection, err := task.hostsClient.SearchHosts(&hostFilterCriteria)
	if err != nil {
		return err
	}

	if len(hostCollection.Hosts) == 0 {
		// no host present, create a new one
		hostCreateCriteria := vsclient.HostCreateCriteria{}
		hostCreateCriteria.HostName = task.ip
		hostCreateCriteria.ConnectionString = connectionString
		hostCreateCriteria.TlsPolicyId = vsclient.TRUST_POLICY_TRUST_FIRST_CERTIFICATE // tlsPolicy.Id

		host, err := task.hostsClient.CreateHost(&hostCreateCriteria)
		if err != nil {
			return err
		}

		log.Debugf("Successully create host id %s", host.Id)
	} else {
		return fmt.Errorf("Host with IP address %s already exists", task.ip)
	}

	return nil
}

// Using the ip address, query VS to verify if this host is registered
func (task *CreateHost) Validate(c setup.Context) error {

	hostFilterCriteria := vsclient.HostFilterCriteria{NameEqualTo: task.ip}
	hostCollection, err := task.hostsClient.SearchHosts(&hostFilterCriteria)
	if err != nil {
		return err
	}

	if len(hostCollection.Hosts) == 0 {
		return fmt.Errorf("Validation error: host with ip '%s' was not create", task.ip)
	}

	log.Info("Setup: Create host was successful.")
	return nil
}
