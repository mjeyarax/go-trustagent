/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package config

import (
	commLog "intel/isecl/lib/common/log"
	"intel/isecl/lib/common/log/message"
	commLogInt "intel/isecl/lib/common/log/setup"
	"intel/isecl/lib/common/setup"
	"errors"
	"fmt"
	"github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"
	"intel/isecl/go-trust-agent/constants"
	"intel/isecl/lib/common/validation"
	"io"
	"os"
	"strings"
	"sync"
)

const (
	AIK_SECRET_KEY = "aik.secret"
)

//
//  Adapted from certificate-management-service/config/config.go
//

type TrustAgentConfiguration struct {
	configFile        string
	LogLevel          string
	LogEnableStdout   bool
	LogEntryMaxLength int
	TrustAgentService struct {
		Port     int
		Username string
		Password string
	}
	HVS struct {
		Url      string
	}
	Tpm struct {
		OwnerSecretKey string
		AikSecretKey   string
	}
	AAS struct{
		BaseURL string
	}
	CMS struct {
		BaseURL string
		TlsCertDigest string
	}
}

var mu sync.Mutex
var log = commLog.GetDefaultLogger()
var secLog = commLog.GetSecurityLogger()

func NewConfigFromYaml(pathToYaml string) (*TrustAgentConfiguration, error) {

	var c TrustAgentConfiguration
	file, err := os.Open(pathToYaml)
	if err == nil {
		defer file.Close()
		yaml.NewDecoder(file).Decode(&c)
	} else {
		// file doesnt exist, create a new blank one
		c.LogLevel = log.InfoLevel
	}

	c.configFile = pathToYaml
	return &c, nil
}

var ErrNoConfigFile = errors.New("no config file")

func (cfg *TrustAgentConfiguration) Save() error {
	if cfg.configFile == "" {
		return ErrNoConfigFile
	}

	file, err := os.OpenFile(cfg.configFile, os.O_RDWR, 0)
	if err != nil {
		// we have an error
		if os.IsNotExist(err) {
			// error is that the config doesnt yet exist, create it
			file, err = os.Create(cfg.configFile)
			os.Chmod(cfg.configFile, 0660)
			if err != nil {
				return err
			}
		} else {
			// someother I/O related error
			return err
		}
	}
	defer file.Close()
	return yaml.NewEncoder(file).Encode(cfg)
}

func (cfg *TrustAgentConfiguration) LoadEnvironmentVariables(c setup.Context) error {
	var err error
	dirty := false

	//---------------------------------------------------------------------------------------------
	// TPM_OWNER_SECRET
	//---------------------------------------------------------------------------------------------
	tpmOwnerSecret, err := c.GetenvString("TPM_OWNER_SECRET")
	if err == nil && tpmOwnerSecret != "" && cfg.Tpm.OwnerSecretKey != tpmOwnerSecret {
		cfg.Tpm.OwnerSecretKey = tpmOwnerSecret
		dirty = true
	} else if strings.TrimSpace(tpmOwnerSecret) == ""{
		return errors.Wrap(err, "TPM_OWNER_SECRET is not defined in environment or configuration file")
	}

	//---------------------------------------------------------------------------------------------
	// MTWILSON_API_URL
	//---------------------------------------------------------------------------------------------
	hvsApiUrl, err = c.GetenvString("MTWILSON_API_URL")
	if err == nil && hvsApiUrl != "" && cfg.HVS.Url != hvsApiUrl {
		cfg.HVS.Url = hvsApiUrl
		dirty = true
	} else if strings.TrimSpace(hvsApiUrl) == ""{
		return errors.Wrap(err, "MTWILSON_API_URL is not defined in environment or configuration file")
	}

	//---------------------------------------------------------------------------------------------
	// MTWILSON_API_USERNAME
	//---------------------------------------------------------------------------------------------
	hvsUsername, err = c.GetenvString("MTWILSON_API_USERNAME")
	if err != nil && hvsUsername != "" && cfg.HVS.Username != hvsUsername {
		cfg.HVS.Username = hvsUsername
		dirty = true
	} else if strings.TrimSpace(hvsUsername) == ""{
		return errors.Wrap(err, "MTWILSON_API_USERNAME is not defined in environment or configuration file")
	}

	//---------------------------------------------------------------------------------------------
	// MTWILSON_API_PASSWORD
	//---------------------------------------------------------------------------------------------
	environmentVariable, _ = c.GetenvString("MTWILSON_API_PASSWORD")
	if environmentVariable != "" && cfg.HVS.Password != environmentVariable {
		cfg.HVS.Password = environmentVariable
		dirty = true
	}

	//---------------------------------------------------------------------------------------------
	// MTWILSON_TLS_CERT_SHA384
	//---------------------------------------------------------------------------------------------
	environmentVariable, _ = c.GetenvString("MTWILSON_TLS_CERT_SHA384")
	if environmentVariable != "" {
		if len(environmentVariable) != 96 {
			return fmt.Errorf("Setup error:  Invalid length MTWILSON_TLS_CERT_SHA384: %d", len(environmentVariable))
		}

		if err = validation.ValidateHexString(environmentVariable); err != nil {
			return fmt.Errorf("Setup error:  MTWILSON_TLS_CERT_SHA384 is not a valid hex string: %s", environmentVariable)
		}

		if cfg.HVS.TLS384 != environmentVariable {
			cfg.HVS.TLS384 = environmentVariable
			dirty = true
		}
	}

	//---------------------------------------------------------------------------------------------
	// TRUSTAGENT_PORT
	//---------------------------------------------------------------------------------------------
	port := 0
	port, err = c.GetenvInt("TRUSTAGENT_PORT")
	if err != nil{
		return errors.Wrap(err, "MTWILSON_API_USERNAME is not defined in environment or configuration file")
	}

	// always apply the default port of 1443
	if port == 0 {
		port = constants.DefaultPort
	}

	if cfg.TrustAgentService.Port != port {
		cfg.TrustAgentService.Port = port
		dirty = true
	}

	//---------------------------------------------------------------------------------------------
	// TRUSTAGENT_ADMIN_USERNAME
	//---------------------------------------------------------------------------------------------
	environmentVariable = c.GetenvString("TRUSTAGENT_ADMIN_USERNAME")
	if environmentVariable != "" && cfg.TrustAgentService.Username != environmentVariable {
		cfg.TrustAgentService.Username = environmentVariable
		dirty = true
	}

	//---------------------------------------------------------------------------------------------
	// TRUSTAGENT_ADMIN_PASSWORD
	//---------------------------------------------------------------------------------------------
	environmentVariable = c.GetenvString("TRUSTAGENT_ADMIN_PASSWORD")
	if environmentVariable != "" && cfg.TrustAgentService.Password != environmentVariable {
		cfg.TrustAgentService.Password = environmentVariable
		dirty = true
	}

	logEntryMaxLength, err := c.GetenvString(constants.LogEntryMaxlengthEnv, "Maximum length of each entry in a log")
	if err == nil && logEntryMaxLength >= 300 {
		cfg.LogEntryMaxLength = logEntryMaxLength
	} else {
		log.Info("config/config:SaveConfiguration() Invalid Log Entry Max Length defined (should be >= ", constants.DefaultLogEntryMaxlength, "), using default value:", constants.DefaultLogEntryMaxlength)
		cfg.LogEntryMaxLength = constants.DefaultLogEntryMaxlength
	}

	ll, err := c.GetenvString("LOG_LEVEL", "Logging Level")
	if err != nil {
		if Configuration.LogLevel == "" {
			log.Infof("config/config:SaveConfiguration() LOG_LEVEL not defined, using default log level: Info")
			Configuration.LogLevel = logrus.InfoLevel.String()
		}
	} else {
		llp, err := logrus.ParseLevel(ll)
		if err != nil {
			log.Info("config/config:SaveConfiguration() Invalid log level specified in env, using default log level: Info")
			Configuration.LogLevel = logrus.InfoLevel.String()
		} else {
			Configuration.LogLevel = llp.String()
			log.Infof("config/config:SaveConfiguration() Log level set %s\n", ll)
		}
	}
	//---------------------------------------------------------------------------------------------
	// Save config if 'dirty'
	//---------------------------------------------------------------------------------------------
	if dirty {
		err = cfg.Save()
		if err != nil {
			return errors.Wrap(err, "Setup error:  Error saving configuration")
		}
	}

	return nil
}

func (cfg *TrustAgentConfiguration) Validate() error {

	if cfg.TrustAgentService.Port == 0 || cfg.TrustAgentService.Port > 65535 {
		return errors.Errorf("config/config:Validate() Invalid TrustAgent port value: '%d'", cfg.TrustAgentService.Port)
	}

	err := validation.ValidateAccount(cfg.TrustAgentService.Username, cfg.TrustAgentService.Password)
	if err != nil {
		return errors.Wrap(err, "config/config:Validate() Invalid TrustAgent username or password")
	}

	if cfg.HVS.Url == "" {
		return errors.New("config/config:Validate() Mtwilson api url is required")
	}

	if cfg.HVS.Username == "" {
		return errors.New("config/config:Validate() Mtwilson user is required")
	}

	if cfg.HVS.Password == "" {
		return errors.New("config/config:Validate() Mtwilson password is required")
	}

	if cfg.HVS.TLS384 == "" {
		return errors.New("config/config:Validate() Mtwilson tls 384 is required")
	}

	return nil
}

func (cfg *TrustAgentConfiguration) PrintConfigSetting(settingKey string) {

	switch settingKey {
	case AIK_SECRET_KEY:
		fmt.Printf("%s\n", cfg.Tpm.AikSecretKey)
	default:
		fmt.Printf("Unknown config parameter: %s\n", settingKey)
	}
}

func LogConfiguration(stdOut, logFile bool) {
	log.Trace("config/config:LogConfiguration() Entering")
	defer log.Trace("config/config:LogConfiguration() Leaving")

	// creating the log file if not preset
	var ioWriterDefault io.Writer
	defaultLogFile, _ := os.OpenFile(constants.DefautLogFilePath, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0660)
	secLogFile, _ := os.OpenFile(constants.SecurityLogFilePath, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0660)

	ioWriterDefault = defaultLogFile
	if stdOut && logFile {
		ioWriterDefault = io.MultiWriter(os.Stdout, defaultLogFile)
	}
	if stdOut && !logFile {
		ioWriterDefault = os.Stdout
	}
	ioWriterSecurity := io.MultiWriter(ioWriterDefault, secLogFile)

	if Configuration.LogLevel == "" {
		Configuration.LogLevel = logrus.InfoLevel.String()
	}

	llp, err := logrus.ParseLevel(Configuration.LogLevel)
	if err != nil {
		Configuration.LogLevel = logrus.InfoLevel.String()
		llp, _ = logrus.ParseLevel(Configuration.LogLevel)
	}
	commLogInt.SetLogger(commLog.DefaultLoggerName, llp, &commLog.LogFormatter{MaxLength: Configuration.LogEntryMaxLength}, ioWriterDefault, false)
	commLogInt.SetLogger(commLog.SecurityLoggerName, llp, &commLog.LogFormatter{MaxLength: Configuration.LogEntryMaxLength}, ioWriterSecurity, false)

	secLog.Infof("config/config:LogConfiguration() %s", message.LogInit)
	log.Infof("config/config:LogConfiguration() %s", message.LogInit)
}


// func load(path string) *TrustAgentConfiguration {
// 	var c TrustAgentConfiguration
// 	file, err := os.Open(path)
// 	if err == nil {
// 		defer file.Close()
// 		yaml.NewDecoder(file).Decode(&c)
// 	} else {
// 		// file doesnt exist, create a new blank one
// 		c.LogLevel = log.InfoLevel
// 	}

// 	c.configFile = path
// 	return &c
// }
