/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package tasks

import (
	"fmt"
	"io/ioutil"
	"net/http"
	log "github.com/sirupsen/logrus"
	"intel/isecl/go-trust-agent/config"
	"intel/isecl/go-trust-agent/constants"
	"intel/isecl/go-trust-agent/util"
	"intel/isecl/go-trust-agent/vsclient"
	"intel/isecl/lib/common/setup"
)
 
type DownloadPrivacyCA struct {
	 Flags 	[]string
}


func (task *DownloadPrivacyCA) Run(c setup.Context) error {

	// move to vs_client

	client, err := vsclient.NewVSClient()
	if err != nil {
		return err
	}

	url := fmt.Sprintf("%s/ca-certificates/privacy", config.GetConfiguration().HVS.Url)
	request, _:= http.NewRequest("GET", url, nil)
	request.SetBasicAuth(config.GetConfiguration().HVS.Username, config.GetConfiguration().HVS.Password)

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

