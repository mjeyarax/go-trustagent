/*
* Copyright (C) 2019 Intel Corporation
* SPDX-License-Identifier: BSD-3-Clause
 */
package tasks

import (
	"fmt"
	commLog "intel/isecl/lib/common/log"
	"intel/isecl/go-trust-agent/config"
	"intel/isecl/go-trust-agent/util"
	"intel/isecl/go-trust-agent/vsclient"
	"intel/isecl/lib/common/setup"
	"github.com/pkg/errors"
)

var log = commLog.GetDefaultLogger()
var secLog = commLog.GetSecurityLogger()

type CreateHost struct {
	clientFactory vsclient.VSClientFactory
	hostsClient   vsclient.HostsClient
	ip            string
	cfg           *config.TrustAgentConfiguration
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
	// initialize if nil
	if task.hostsClient == nil {
		task.hostsClient = task.clientFactory.HostsClient()
	}

	task.ip, err = util.GetLocalIpAsString()
	if err != nil {
		log.WithError(err).Error("tasks/create_host:Run() Error while getting Local IP address")
		return errors.New("Error while getting Local IP address")
	}

	connectionString, err := util.GetConnectionString(task.cfg)
	if err != nil {
		log.WithError(err).Error("tasks/create_host:Run() Error while getting Connection string")
		return errors.New("Error while getting Connection string")
	}

	hostFilterCriteria := vsclient.HostFilterCriteria{NameEqualTo: task.ip}
	hostCollection, err := task.hostsClient.SearchHosts(&hostFilterCriteria)
	if err != nil {
		log.WithError(err).Error("tasks/create_host:Run() Error while retrieving host collection")
		return errors.New("Error while retrieving host collection")
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

		log.Debugf("tasks/create_host:Run() Successfully created host, host id %s", host.Id)
	} else {
		log.WithError(err).Errorf("tasks/create_host:Run() Host with IP address %s already exists", task.ip)
		return errors.Errorf("Host with IP address %s already exists", task.ip)
	}

	return nil
}

// Using the ip address, query VS to verify if this host is registered
func (task *CreateHost) Validate(c setup.Context) error {
	log.Trace("tasks/create_host:Validate() Entering")
	defer log.Trace("tasks/create_host:Validate() Leaving")

	// Initialize the PrivacyCA client using the factory - this will be reused in Run
	task.hostsClient = task.clientFactory.HostsClient()

	hostFilterCriteria := vsclient.HostFilterCriteria{NameEqualTo: task.ip}
	hostCollection, err := task.hostsClient.SearchHosts(&hostFilterCriteria)
	if err != nil {
		return err
	}

	if len(hostCollection.Hosts) == 0 {
		log.WithError(err).Errorf("tasks/create_host:Run() host with ip '%s' was not create", task.ip)
		return errors.Errorf("Host with ip '%s' was not created", task.ip)
	}

	log.Info("tasks/create_host:Validate() Create host setup task was successful.")
	return nil
}
