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
	"net/http"
)

type DownloadPrivacyCA struct {
	cfg *config.TrustAgentConfiguration
}

// Download's the privacy CA from HVS.
func (task *DownloadPrivacyCA) Run(c setup.Context) error {

	// ISECL-7703:  Refactor setup tasks to use vsclient

	client, err := vsclient.NewVSClient(task.cfg)
	if err != nil {
		return err
	}

	url := fmt.Sprintf("%s/ca-certificates/privacy", task.cfg.HVS.Url)
	request, _ := http.NewRequest("GET", url, nil)
	request.SetBasicAuth(task.cfg.HVS.Username, task.cfg.HVS.Password)

	response, err := client.Do(request)
	if err != nil {
		return fmt.Errorf("%s request failed with error %s\n", url, err)
	} else {
		if response.StatusCode != http.StatusOK {
			return fmt.Errorf("%s returned status %d", url, response.StatusCode)
		}

		data, err := ioutil.ReadAll(response.Body)
		if err != nil {
			return fmt.Errorf("Error reading response: %s", err)
		}

		err = ioutil.WriteFile(constants.PrivacyCA, data, 0644)
		if err != nil {
			return fmt.Errorf("Error saving privacy ca file '%s': %s", constants.PrivacyCA, err)
		}
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
