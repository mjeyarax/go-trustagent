/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package tasks

import (
	"crypto/x509/pkix"
	"errors"
	"fmt"
	log "github.com/sirupsen/logrus"
	"intel/isecl/go-trust-agent/config"
	"intel/isecl/go-trust-agent/constants"
	"intel/isecl/go-trust-agent/vsclient"
	"intel/isecl/lib/common/setup"
	"intel/isecl/lib/tpmprovider"
	"os"
)

// The TaskRegistry is used to aggregate commands into logical groups
// that can be invoked at once (in specific order).
type TaskRegistry struct {
	taskMap map[string][]setup.Task
}

const (
	DefaultSetupCommand                    = "all"
	DownloadRootCACertCommand              = "download-ca-cert"
	DownloadCertCommand                    = "download-cert"
	TakeOwnershipCommand                   = "take-ownership"
	CreateTLSKeyPairCommand                = "create-tls-keypair"
	ReplaceTLSKeyPairCommand               = "replace-tls-keypair"
	ProvisionEndorsementKeyCommand         = "provision-ek"
	ProvisionAttestationIdentityKeyCommand = "provision-aik"
	DownloadPrivacyCACommand               = "download-privacy-ca"
	DownloadAASJWTCertCommand              = "download-aas-jwt-cert"
	ProvisionPrimaryKeyCommand             = "provision-primary-key"
	CreateHostCommand                      = "create-host"
	CreateHostUniqueFlavorCommand          = "create-host-unique-flavor"
	GetConfiguredManifestCommand           = "get-configured-manifest"
)

// NewSetupTaskConfig sets up common configuration holder for all the setup tasks
func NewSetupTaskConfig(cfg *config.TrustAgentConfiguration) (*vsclient.VSClientConfig, error) {
	jwtToken := os.Getenv(constants.EnvBearerToken)
	if jwtToken == "" {
		fmt.Fprintln(os.Stderr, "BEARER_TOKEN is not defined in environment")
		return nil, errors.New("BEARER_TOKEN is not defined in environment")
	}

	vsClientConfig := vsclient.VSClientConfig{
		BaseURL:     cfg.HVS.Url,
		BearerToken: jwtToken,
	}

	return &vsClientConfig, nil
}

func CreateTaskRegistry(cfg *config.TrustAgentConfiguration, flags []string) (*TaskRegistry, error) {

	var registry TaskRegistry
	registry.taskMap = make(map[string][]setup.Task)

	vsClientConfig, err := NewSetupTaskConfig(cfg)
	if err != nil {
		log.Errorf("Could not create the vsclient config: %s", err)
		os.Exit(1)
	}

	vsClientFactory, err := vsclient.NewVSClientFactory(vsClientConfig)
	if err != nil {
		log.Errorf("Could not create the vsclient factory: %s", err)
		os.Exit(1)
	}

	tpmFactory, err := tpmprovider.NewTpmFactory()
	if err != nil {
		log.Errorf("Could not create the tpm factory: %s", err)
		os.Exit(1)
	}

	takeOwnership := TakeOwnership{tpmFactory: tpmFactory, cfg: cfg}

	downloadRootCACert := setup.Download_Ca_Cert{
		Flags:                flags,
		CmsBaseURL:           cfg.CMS.BaseURL,
		CaCertDirPath:        constants.TrustedCaCertsDir,
		TrustedTlsCertDigest: cfg.CMS.TLSCertDigest,
		ConsoleWriter:        os.Stdout,
	}

	downloadTLSCert := setup.Download_Cert{
		Flags:              flags,
		KeyFile:            constants.TLSKeyFilePath,
		CertFile:           constants.TLSCertFilePath,
		KeyAlgorithm:       constants.DefaultKeyAlgorithm,
		KeyAlgorithmLength: constants.DefaultKeyAlgorithmLength,
		CmsBaseURL:         cfg.CMS.BaseURL,
		Subject: pkix.Name{
			CommonName: cfg.TLS.CertDNS,
		},
		SanList:       cfg.TLS.CertIP,
		CertType:      "TLS",
		CaCertsDir:    constants.TrustedCaCertsDir,
		BearerToken:   "",
		ConsoleWriter: os.Stdout,
	}

	downloadAASJWTCert := DownloadAASJWTCert{
		Flags: flags,
	}

	provisionEndorsementKey := ProvisionEndorsementKey{
		clientFactory: vsClientFactory,
		tpmFactory:    tpmFactory,
		cfg:           cfg,
	}

	provisionAttestationIdentityKey := ProvisionAttestationIdentityKey{
		clientFactory: vsClientFactory,
		tpmFactory:    tpmFactory,
		cfg:           cfg,
	}

	downloadPrivacyCA := DownloadPrivacyCA{
		clientFactory: vsClientFactory,
		cfg:           cfg,
	}

	provisionPrimaryKey := ProvisionPrimaryKey{tpmFactory: tpmFactory, cfg: cfg}

	registry.taskMap[TakeOwnershipCommand] = []setup.Task{&takeOwnership}
	registry.taskMap[DownloadRootCACertCommand] = []setup.Task{&downloadRootCACert}
	registry.taskMap[DownloadAASJWTCertCommand] = []setup.Task{&downloadAASJWTCert}
	registry.taskMap[DownloadCertCommand] = []setup.Task{&downloadTLSCert}
	registry.taskMap[ProvisionEndorsementKeyCommand] = []setup.Task{&provisionEndorsementKey}
	registry.taskMap[ProvisionAttestationIdentityKeyCommand] = []setup.Task{&provisionAttestationIdentityKey}
	registry.taskMap[DownloadPrivacyCACommand] = []setup.Task{&downloadPrivacyCA}
	registry.taskMap[ProvisionPrimaryKeyCommand] = []setup.Task{&provisionPrimaryKey}

	registry.taskMap[DefaultSetupCommand] = []setup.Task{
		&downloadRootCACert,
		&downloadTLSCert,
		&downloadAASJWTCert,
		&downloadPrivacyCA,
		&takeOwnership,
		&provisionEndorsementKey,
		&provisionAttestationIdentityKey,
		&provisionPrimaryKey,
	}

	// these are individual commands that are not included in default setup tasks
	registry.taskMap[CreateHostCommand] = []setup.Task{
		&CreateHost{
			clientFactory: vsClientFactory,
			cfg:           cfg,
		},
	}

	registry.taskMap[CreateHostUniqueFlavorCommand] = []setup.Task{
		&CreateHostUniqueFlavor{
			clientFactory: vsClientFactory,
			cfg:           cfg,
		},
	}

	registry.taskMap[ReplaceTLSKeyPairCommand] = []setup.Task{
		&DeleteTlsKeypair{},
		&downloadTLSCert,
	}

	registry.taskMap[GetConfiguredManifestCommand] = []setup.Task{
		&GetConfiguredManifest{
			clientFactory: vsClientFactory,
		},
	}

	return &registry, nil
}

func (registry *TaskRegistry) RunCommand(command string) error {
	tasks, ok := registry.taskMap[command]
	if !ok {
		return errors.New("Command '" + command + "' is not a valid setup option")
	}

	setupRunner := &setup.Runner{
		Tasks:    tasks,
		AskInput: false,
	}

	err := setupRunner.RunTasks()
	if err != nil {
		return err
	}

	return nil
}
