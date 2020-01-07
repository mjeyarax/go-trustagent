/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package tasks

import (
	"crypto/x509/pkix"
	"errors"
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
	ProvisionPrimaryKeyCommand             = "provision-primary-key"
	CreateHostCommand                      = "create-host"
	CreateHostUniqueFlavorCommand          = "create-host-unique-flavor"
	GetConfiguredManifestCommand           = "get-configured-manifest"
)

func CreateTaskRegistry(vsClientFactory vsclient.VSClientFactory, tpmFactory tpmprovider.TpmFactory, cfg *config.TrustAgentConfiguration, flags []string) (*TaskRegistry, error) {

	var registry TaskRegistry
	registry.taskMap = make(map[string][]setup.Task)

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
		CertFile:           constants.TLSKeyFilePath,
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

	provisionEndorsementKey := ProvisionEndorsementKey{
		caCertificatesClient:  vsClientFactory.CACertificatesClient(),
		tpmEndorsementsClient: vsClientFactory.TpmEndorsementsClient(),
		tpmFactory:            tpmFactory,
		cfg:                   cfg,
	}

	provisionAttestationIdentityKey := ProvisionAttestationIdentityKey{
		privacyCAClient: vsClientFactory.PrivacyCAClient(),
		tpmFactory:      tpmFactory,
		cfg:             cfg,
	}

	downloadPrivacyCA := DownloadPrivacyCA{
		privacyCAClient: vsClientFactory.PrivacyCAClient(),
		cfg:             cfg,
	}

	provisionPrimaryKey := ProvisionPrimaryKey{tpmFactory: tpmFactory, cfg: cfg}

	registry.taskMap[TakeOwnershipCommand] = []setup.Task{&takeOwnership}
	registry.taskMap[DownloadRootCACertCommand] = []setup.Task{&downloadRootCACert}
	registry.taskMap[DownloadCertCommand] = []setup.Task{&downloadTLSCert}
	registry.taskMap[ProvisionEndorsementKeyCommand] = []setup.Task{&provisionEndorsementKey}
	registry.taskMap[ProvisionAttestationIdentityKeyCommand] = []setup.Task{&provisionAttestationIdentityKey}
	registry.taskMap[DownloadPrivacyCACommand] = []setup.Task{&downloadPrivacyCA}
	registry.taskMap[ProvisionPrimaryKeyCommand] = []setup.Task{&provisionPrimaryKey}

	registry.taskMap[DefaultSetupCommand] = []setup.Task{
		&downloadRootCACert,
		&downloadTLSCert,
		&downloadPrivacyCA,
		&takeOwnership,
		&provisionEndorsementKey,
		&provisionAttestationIdentityKey,
		&provisionPrimaryKey,
	}

	// these are individual commands that are not included of setup
	registry.taskMap[CreateHostCommand] = []setup.Task{
		&CreateHost{
			hostsClient: vsClientFactory.HostsClient(),
			cfg:         cfg,
		},
	}

	registry.taskMap[CreateHostUniqueFlavorCommand] = []setup.Task{
		&CreateHostUniqueFlavor{
			flavorsClient: vsClientFactory.FlavorsClient(),
			cfg:           cfg,
		},
	}

	registry.taskMap[ReplaceTLSKeyPairCommand] = []setup.Task{
		&DeleteTlsKeypair{},
		&downloadTLSCert,
	}

	registry.taskMap[GetConfiguredManifestCommand] = []setup.Task{
		&GetConfiguredManifest{
			manifestsClient: vsClientFactory.ManifestsClient(),
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
