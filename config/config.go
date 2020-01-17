/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package config

import (
	commLog "intel/isecl/lib/common/log"
	"intel/isecl/lib/common/log/message"
	commLogInt "intel/isecl/lib/common/log/setup"
	"fmt"
	"intel/isecl/go-trust-agent/constants"
	"intel/isecl/lib/common/setup"
	"intel/isecl/lib/common/validation"
	"io"
	"os"
	"strconv"
	"strings"
	"sync"

	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"
	"github.com/pkg/errors"
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
	}
	HVS struct {
		Url string
	}
	Tpm struct {
		OwnerSecretKey string
		AikSecretKey   string
	}
	AAS struct {
		BaseURL string
	}
	CMS struct {
		BaseURL       string
		TLSCertDigest string
	}
	TLS struct {
		CertSAN  string
		CertCN string
	}
}

var mu sync.Mutex

func NewConfigFromYaml(pathToYaml string) (*TrustAgentConfiguration, error) {

	var c TrustAgentConfiguration
	file, err := os.Open(pathToYaml)
	if err == nil {
		defer file.Close()
		yaml.NewDecoder(file).Decode(&c)
	} else {
		// file doesnt exist, create a new blank one
		c.LogLevel = logrus.InfoLevel.String()
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
	secLog.Info(message.ConfigChanged)
	return yaml.NewEncoder(file).Encode(cfg)
}

func (cfg *TrustAgentConfiguration) LoadEnvironmentVariables() error {
	var err error
	dirty := false
	var context setup.Context

	//---------------------------------------------------------------------------------------------
	// TPM_OWNER_SECRET
	//---------------------------------------------------------------------------------------------
	environmentVariable, err := context.GetenvSecret(constants.EnvTPMOwnerSecret, "TPM Owner Secret")
	if environmentVariable != "" && cfg.Tpm.OwnerSecretKey != environmentVariable {
		cfg.Tpm.OwnerSecretKey = environmentVariable
		dirty = true
	} 

	//---------------------------------------------------------------------------------------------
	// MTWILSON_API_URL
	//---------------------------------------------------------------------------------------------
	environmentVariable, err = context.GetenvString(constants.EnvMtwilsonAPIURL, "Verification Service API URL")
	if environmentVariable != "" && cfg.HVS.Url != environmentVariable {
		cfg.HVS.Url = environmentVariable
		dirty = true
	}

	//---------------------------------------------------------------------------------------------
	// TRUSTAGENT_PORT
	//---------------------------------------------------------------------------------------------
	port := 0
	port, err = context.GetenvInt(constants.EnvTAPort, "Trust Agent Listener Port")
	if port > 0 {
		port, err = strconv.Atoi(environmentVariable)
		if err != nil {
			return errors.Wrapf(err, "Setup error: Invalid TRUSTAGENT_PORT value '%s'", environmentVariable)
		}
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
	// AAS_API_URL
	//---------------------------------------------------------------------------------------------
	environmentVariable, err = context.GetenvString(constants.EnvAASBaseURL, "AAS API Base URL")
	if environmentVariable != "" && cfg.AAS.BaseURL != environmentVariable {
		cfg.AAS.BaseURL = environmentVariable
		dirty = true
	}

	//---------------------------------------------------------------------------------------------
	// CMS_BASE_URL
	//---------------------------------------------------------------------------------------------
	environmentVariable, err = context.GetenvString(constants.EnvCMSBaseURL, "CMS Base URL")
	if environmentVariable != "" && cfg.CMS.BaseURL != environmentVariable {
		cfg.CMS.BaseURL = environmentVariable
		dirty = true
	}

	//---------------------------------------------------------------------------------------------
        // LOG_ENTRY_MAXLENGTH
        //---------------------------------------------------------------------------------------------
	logEntryMaxLength, err := context.GetenvInt(constants.LogEntryMaxlengthEnv, "Maximum length of each entry in a log")
	if err == nil && logEntryMaxLength >= 300 {
		cfg.LogEntryMaxLength = logEntryMaxLength
	} else {
		log.Info("config/config:LoadEnvironmentVariables() Invalid Log Entry Max Length defined (should be >= ", constants.DefaultLogEntryMaxlength, "), using default value:", constants.DefaultLogEntryMaxlength)
		cfg.LogEntryMaxLength = constants.DefaultLogEntryMaxlength
	}

	//---------------------------------------------------------------------------------------------
        // TRUSTAGENT_LOG_LEVEL
        //---------------------------------------------------------------------------------------------
	ll, err := context.GetenvString("TRUSTAGENT_LOG_LEVEL", "Logging Level")
	if err != nil {
		if cfg.LogLevel == "" {
			log.Infof("config/config:LoadEnvironmentVariables() LOG_LEVEL not defined, using default log level: Info")
			cfg.LogLevel = logrus.InfoLevel.String()
		}
	} else {
		llp, err := logrus.ParseLevel(ll)
		if err != nil {
			log.Info("config/config:LoadEnvironmentVariables() Invalid log level specified in env, using default log level: Info")
			cfg.LogLevel = logrus.InfoLevel.String()
		} else {
			cfg.LogLevel = llp.String()
			log.Infof("config/config:LoadEnvironmentVariables() Log level set %s\n", ll)
		}
	}

	//---------------------------------------------------------------------------------------------
	// CMS_TLS_CERT_SHA384
	//---------------------------------------------------------------------------------------------
	environmentVariable, err = context.GetenvString(constants.EnvCMSTLSCertDigest, "CMS TLS SHA384 Digest")
	if environmentVariable != "" {
		if len(environmentVariable) != 96 {
			return errors.Errorf("config/config:LoadEnvironmentVariables()  Invalid length %s: %d", constants.EnvCMSTLSCertDigest, len(environmentVariable))
		}

		if err = validation.ValidateHexString(environmentVariable); err != nil {
			return errors.Errorf("config/config:LoadEnvironmentVariables()  %s is not a valid hex string: %s", constants.EnvCMSTLSCertDigest, environmentVariable)
		}

		if cfg.CMS.TLSCertDigest != environmentVariable {
			cfg.CMS.TLSCertDigest = environmentVariable
			dirty = true
		}
	}

	//---------------------------------------------------------------------------------------------
        // TA_TLS_CERT_CN
        //---------------------------------------------------------------------------------------------
        environmentVariable, err = context.GetenvString(constants.EnvTLSCertCommonName, "Trustagent TLS Certificate Common Name")
	if err == nil && environmentVariable != "" {
		cfg.TLS.CertCN = environmentVariable
	} else if strings.TrimSpace(cfg.TLS.CertCN) == "" {
		log.Info("config/config:LoadEnvironmentVariables() TA_TLS_CERT_CN not defined, using default value")
		cfg.TLS.CertCN = constants.DefaultTaTlsCn
	}

	//---------------------------------------------------------------------------------------------
        // TA_CERT_SAN
        //---------------------------------------------------------------------------------------------
        environmentVariable, err = context.GetenvString(constants.EnvCertSanList, "Trustagent TLS Certificate SAN LIST")
        if err == nil && environmentVariable != "" {
                cfg.TLS.CertSAN = environmentVariable
        } else if strings.TrimSpace(cfg.TLS.CertSAN) == "" {
                log.Info("config/config:LoadEnvironmentVariables() TA_CERT_SAN not defined, using default value")
                cfg.TLS.CertSAN = constants.DefaultTaTlsSan
        }


	//---------------------------------------------------------------------------------------------
	// Save config if 'dirty'
	//---------------------------------------------------------------------------------------------
	if dirty {
		err = cfg.Save()
		if err != nil {
			return errors.Wrap(err, "config/config:LoadEnvironmentVariables:  Error saving configuration")
		}
	}

	return nil
}

func (cfg *TrustAgentConfiguration) Validate() error {

	if cfg.TrustAgentService.Port == 0 || cfg.TrustAgentService.Port > 65535 {
		return errors.Errorf("config/config:Validate() Invalid TrustAgent port value: '%d'", cfg.TrustAgentService.Port)
	}

	if cfg.HVS.Url == "" {
		return errors.New("Validation error: HVS API URL is required")
	}

	if cfg.AAS.BaseURL == "" {
		return errors.New("Validation error: AAS API URL is required")
	}

	if cfg.CMS.BaseURL == "" {
		return errors.New("Validation error: CMS Base URL is required")
	}

	if cfg.CMS.TLSCertDigest == "" {
		return errors.New("Validation error: CMS TLS Cert Digest is required")
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

func (cfg *TrustAgentConfiguration) LogConfiguration(stdOut bool) {
	log.Trace("config/config:LogConfiguration() Entering")
	defer log.Trace("config/config:LogConfiguration() Leaving")

	// creating the log file if not preset
	var ioWriterDefault io.Writer
	defaultLogFile, _ := os.OpenFile(constants.DefaultLogFilePath, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0660)
	secLogFile, _ := os.OpenFile(constants.SecurityLogFilePath, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0660)

	ioWriterDefault = defaultLogFile
	if stdOut {
		ioWriterDefault = io.MultiWriter(os.Stdout, defaultLogFile)
	}
	ioWriterSecurity := io.MultiWriter(ioWriterDefault, secLogFile)

	if cfg.LogLevel == "" {
		cfg.LogLevel = logrus.InfoLevel.String()
	}

	llp, err := logrus.ParseLevel(cfg.LogLevel)
	if err != nil {
		cfg.LogLevel = logrus.InfoLevel.String()
		llp, _ = logrus.ParseLevel(cfg.LogLevel)
	}
	commLogInt.SetLogger(commLog.DefaultLoggerName, llp, &commLog.LogFormatter{MaxLength: cfg.LogEntryMaxLength}, ioWriterDefault, false)
	commLogInt.SetLogger(commLog.SecurityLoggerName, llp, &commLog.LogFormatter{MaxLength: cfg.LogEntryMaxLength}, ioWriterSecurity, false)

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
