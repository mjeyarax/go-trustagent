/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package tasks

import (
	"fmt"
	log "github.com/sirupsen/logrus"
	"intel/isecl/go-trust-agent/config"
	"intel/isecl/go-trust-agent/constants"
	"intel/isecl/go-trust-agent/util"
	"intel/isecl/go-trust-agent/vsclient"
	"intel/isecl/lib/common/setup"
	"io/ioutil"
)

type DownloadPrivacyCA struct {
	cfg 			*config.TrustAgentConfiguration
	privacyCAClient vsclient.PrivacyCAClient
}

// Download's the privacy CA from HVS.
func (task *DownloadPrivacyCA) Run(c setup.Context) error {

	ca, err := task.privacyCAClient.DownloadPrivacyCa()
	if err != nil {
		return err
	}

	err = ioutil.WriteFile(constants.PrivacyCA, ca, 0644)
	if err != nil {
		return fmt.Errorf("Error saving privacy ca file '%s': %s", constants.PrivacyCA, err)
	}

	return nil
}

func (task *DownloadPrivacyCA) Validate(c setup.Context) error {
	_, err := util.GetPrivacyCA()
	if err != nil {
		return err
	}

	log.Info("Setup: Download PrivacyCA was successful")

	return nil
}
