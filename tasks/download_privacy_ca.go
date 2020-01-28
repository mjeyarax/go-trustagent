/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package tasks

import (
	"fmt"
	"intel/isecl/go-trust-agent/config"
	"intel/isecl/go-trust-agent/constants"
	"intel/isecl/go-trust-agent/util"
	"intel/isecl/go-trust-agent/vsclient"
	"intel/isecl/lib/common/setup"
	"io/ioutil"

	"github.com/pkg/errors"
)

type DownloadPrivacyCA struct {
	clientFactory   vsclient.VSClientFactory
	privacyCAClient vsclient.PrivacyCAClient
	cfg             *config.TrustAgentConfiguration
}

// Download's the privacy CA from HVS.
func (task *DownloadPrivacyCA) Run(c setup.Context) error {
	log.Trace("tasks/download_privacy_ca:Run() Entering")
	defer log.Trace("tasks/download_privacy_ca:Run() Leaving")
	fmt.Println("Running setup task: download-privacy-ca")
	// initialize if nil
	if task.privacyCAClient == nil {
		task.privacyCAClient = task.clientFactory.PrivacyCAClient()
	}

	// initialize if nil
	if task.privacyCAClient == nil {
		task.privacyCAClient = task.clientFactory.PrivacyCAClient()
	}

	ca, err := task.privacyCAClient.DownloadPrivacyCa()
	if err != nil {
		log.WithError(err).Error("tasks/download_privacy_ca:Run() Error while downloading privacyCA file")
		return errors.New("Error while downloading privacyCA file")
	}

	err = ioutil.WriteFile(constants.PrivacyCA, ca, 0644)
	if err != nil {
		log.WithError(err).Errorf("tasks/download_privacy_ca:Run() Error while writing privacy ca file '%s'", constants.PrivacyCA)
		return errors.Errorf("Error while writing privacy ca file '%s'", constants.PrivacyCA)
	}

	return nil
}

func (task *DownloadPrivacyCA) Validate(c setup.Context) error {
	log.Trace("tasks/download_privacy_ca:Validate() Entering")
	defer log.Trace("tasks/download_privacy_ca:Validate() Leaving")
	_, err := util.GetPrivacyCA()
	if err != nil {
		return err
	}

	log.Info("tasks/download_privacy_ca:Validate() Download PrivacyCA was successful")

	return nil
}
