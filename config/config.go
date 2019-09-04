/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package config

import (
// 	 "errors"
// 	 "intel/isecl/go-trust-agent/constants"
// 	 "os"
// 	 "path"
// 	 "path/filepath"
// 	 "sync"
 
 	 log "github.com/sirupsen/logrus"
// 	 "gopkg.in/yaml.v2"
)
  
 type TrustAgentConfiguration struct {
	configFile       		string
	Port             		int
	LogLevel         		log.Level
	HVS struct {
		Port				int
		Url					string
		UserName			string
		Password			string
	}
	Tpm struct {
		SecretKey			[]byte
	}
 }