/*
* Copyright (C) 2020 Intel Corporation
* SPDX-License-Identifier: BSD-3-Clause
 */
package tasks

import (
	"fmt"
	"github.com/intel-secl/intel-secl/v3/pkg/clients/hvsclient"
	"github.com/intel-secl/intel-secl/v3/pkg/hvs/domain/models"
	"github.com/intel-secl/intel-secl/v3/pkg/model/hvs"
	"github.com/pkg/errors"
	"intel/isecl/go-trust-agent/v2/util"
	"intel/isecl/lib/common/v2/setup"
)

type CreateHost struct {
	clientFactory    hvsclient.HVSClientFactory
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
		log.WithError(err).Error("tasks/create_host:Run() Could not create host client")
		return err
	}

	ip, err := util.GetLocalIpAsString()
	if err != nil {
		log.WithError(err).Error("tasks/create_host:Run() Error while getting Local IP address")
		return errors.New("Error while getting Local IP address")
	}

	hostCollection, err := hostsClient.SearchHosts(&models.HostFilterCriteria{NameEqualTo: ip})
	if err != nil {
		log.WithError(err).Error("tasks/create_host:Run() Error while retrieving host collection")
		return errors.New("Error while retrieving host collection")
	}

	if len(hostCollection.Hosts) == 0 {
		// no host present, create a new one
		hostCreateReq := hvs.HostCreateRequest{
			HostName :ip,
			ConnectionString: task.connectionString,
		}
		host, err := hostsClient.CreateHost(&hostCreateReq)
		if err != nil {
			return err
		}

		log.Debugf("tasks/create_host:Run() Successfully created host, host id %s", host.Id)
	} else {
		log.WithError(err).Errorf("tasks/create_host:Run() Host with IP address %s already exists", ip)
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
		log.WithError(err).Error("tasks/create_host:Validate() Could not create host client")
		return err
	}

	ip, err := util.GetLocalIpAsString()
	if err != nil {
		log.WithError(err).Error("tasks/create_host:Run() Error while getting Local IP address")
		return errors.New("Error while getting Local IP address")
	}

	hostCollection, err := hostsClient.SearchHosts(&models.HostFilterCriteria{NameEqualTo: ip})
	if err != nil {
		return err
	}

	if len(hostCollection.Hosts) == 0 {
		log.WithError(err).Errorf("tasks/create_host:Run() host with ip '%s' was not create", ip)
		return errors.Errorf("Host with ip '%s' was not created", ip)
	}

	log.Info("tasks/create_host:Validate() Create host setup task was successful.")
	return nil
}
