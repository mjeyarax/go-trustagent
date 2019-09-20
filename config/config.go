/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package config

import (
	"errors"
	"intel/isecl/go-trust-agent/constants"
	"os"
	"sync"
	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"
)

//
//  Adapted from certificate-management-service/config/config.go
//

type TrustAgentConfiguration struct {
	configFile       		string
	LogLevel         		log.Level
	TrustAgentService struct {
		Port				int
		Username			string
		Password			string
	}
	HVS struct {
		Url					string
		Username			string
		Password			string
		TLS384				string
	}
	Tpm struct {
		SecretKey			string	// KWT:  Rname this to 'TPM' and 'TpmSecretKey'
		AikSecretKey		string
	}
}
var mu sync.Mutex

var instance *TrustAgentConfiguration

func GetConfiguration() *TrustAgentConfiguration {
	if instance == nil {
		instance = load(constants.ConfigFilePath)
	}
	return instance
}

var ErrNoConfigFile = errors.New("no config file")

func (c *TrustAgentConfiguration) Save() error {
	if c.configFile == "" {
		return ErrNoConfigFile
	}
	file, err := os.OpenFile(c.configFile, os.O_RDWR, 0)
	if err != nil {
		// we have an error
		if os.IsNotExist(err) {
			// error is that the config doesnt yet exist, create it
			file, err = os.Create(c.configFile)
			os.Chmod(c.configFile, 0660)
			if err != nil {
				return err
			}
		} else {
			// someother I/O related error
			return err
		}
	}
	defer file.Close()
	return yaml.NewEncoder(file).Encode(c)
}

func load(path string) *TrustAgentConfiguration {
	var c TrustAgentConfiguration
	file, err := os.Open(path)
	if err == nil {
		defer file.Close()
		yaml.NewDecoder(file).Decode(&c)
	} else {
		// file doesnt exist, create a new blank one
		c.LogLevel = log.InfoLevel
	}

	c.configFile = path
	return &c
}