/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package resource

import (
	"bytes"
	log "github.com/sirupsen/logrus"
	"intel/isecl/go-trust-agent/constants"
	"io/ioutil"
	"net/http"
	"os"
)

// Assuming that the /opt/trustagent/var/system-info/platform-info file has been create
// during startup, this function reads the contents of the json file and return it to the http
// writer.
//
// EX. curl --request GET --user tagentadmin:TAgentAdminPassword https://localhost:1443/v2/host -k --noproxy "*"
//
// {
// 	"errrCode":0,
// 	"os_name":"Fedora",
// 	"os_version":"29",
// 	"bios_version":"-1",
// 	"vmm_name":"",
// 	"VMMVersion":"",
// 	"processor_info":"-1",
// 	"host_name":"63a5dc91a4e4",
// 	"hardware_uuid":"-1",
// 	"process_flags":"",
// 	"tpm_version":"0",
// 	"pcr_banks":[
// 	   "SHA1",
// 	   "SHA256"
// 	],
// 	"no_of_sockets":"2",
// 	"tpm_enabled":"false",
// 	"txt_enabled":"false",
// 	"tboot_installed":"true",
// 	"is_docker_env":"false",
// 	"hardware_features":{
// 	   "TXT":{
// 		  "enabled":"false"
// 	   },
// 	   "TPM":{
// 		  "enabled":"false",
// 		  "Meta":{
// 			 "tpm_version":"0",
// 			 "pcr_banks":"SHA1_SHA256"
// 		  }
// 	   }
// 	},
// 	"installed_components":[
// 	   "trustagent"
// 	]
//  }
//
func getPlatformInfo(httpWriter http.ResponseWriter, httpRequest *http.Request) {

	log.Debugf("Request: %s", httpRequest.URL.Path)

	if _, err := os.Stat(constants.PlatformInfoFilePath); os.IsNotExist(err) {
		log.Errorf("%s: %s does not exist", httpRequest.URL.Path, constants.PlatformInfoFilePath)
		httpWriter.WriteHeader(http.StatusInternalServerError)
		return
	}

	b, err := ioutil.ReadFile(constants.PlatformInfoFilePath)
	if err != nil {
		log.Errorf("%s: There was an error reading %s", httpRequest.URL.Path, constants.PlatformInfoFilePath)
		httpWriter.WriteHeader(http.StatusInternalServerError)
		return
	}

	httpWriter.Header().Set("Content-Type", "application/json")
	httpWriter.WriteHeader(http.StatusOK)
	_, _ = bytes.NewBuffer(b).WriteTo(httpWriter)
	return
}
