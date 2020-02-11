/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package tasks

import (
	"crypto/x509/pkix"
	"github.com/pkg/errors"
	commLog "intel/isecl/lib/common/log"
	"intel/isecl/go-trust-agent/config"
	"intel/isecl/go-trust-agent/constants"
	"intel/isecl/go-trust-agent/util"
	"intel/isecl/go-trust-agent/vsclient"
	"intel/isecl/lib/common/setup"
	"intel/isecl/lib/tpmprovider"
	"os"
)

// The TaskRegistry is used to aggregate commands into logical groups
// that can be invoked at once (in specific order).
type TaskRegistry struct {
	taskMap map[string][]setup.Task
	cfg *config.TrustAgentConfiguration
}

const (
	DefaultSetupCommand                    = "all"
	DownloadRootCACertCommand              = "download-ca-cert"
	DownloadCertCommand                    = "download-cert"
	TakeOwnershipCommand                   = "take-ownership"
	ProvisionEndorsementKeyCommand         = "provision-ek"
	ProvisionAttestationIdentityKeyCommand = "provision-aik"
	DownloadPrivacyCACommand               = "download-privacy-ca"
	ProvisionPrimaryKeyCommand             = "provision-primary-key"
	CreateHostCommand                      = "create-host"
	CreateHostUniqueFlavorCommand          = "create-host-unique-flavor"
	GetConfiguredManifestCommand           = "get-configured-manifest"
	ProvisionAttestationCommand			   = "provision-attestation"
	UpdateCertificatesCommand			   = "update-certificates"
)

var log = commLog.GetDefaultLogger()
var secLog = commLog.GetSecurityLogger()

func CreateTaskRegistry(cfg *config.TrustAgentConfiguration, flags []string) (*TaskRegistry, error) {

	var registry TaskRegistry

	if cfg == nil {
		return nil, errors.New("The cfg paramater was not provided")
	}

	registry.cfg = cfg
	registry.taskMap = make(map[string][]setup.Task)

	vsClientFactory, err := vsclient.NewVSClientFactory(cfg.HVS.Url, util.GetBearerToken())
	if err != nil {
		return nil, errors.Wrap(err, "Could not create the vsclient factory")
	}

	tpmFactory, err := tpmprovider.NewTpmFactory()
	if err != nil {
		return nil, errors.Wrap(err, "Could not create tpm factory")
	}

	takeOwnership := TakeOwnership{
		tpmFactory: tpmFactory, 
		ownerSecretKey: &cfg.Tpm.OwnerSecretKey,
	}

	downloadRootCACert := setup.Download_Ca_Cert{
		Flags:                []string{"--force",},	 // to be consistent with other GTA tasks, always force update
		CmsBaseURL:           cfg.CMS.BaseURL,
		CaCertDirPath:        constants.TrustedCaCertsDir,
		TrustedTlsCertDigest: cfg.CMS.TLSCertDigest,
		ConsoleWriter:        os.Stdout,
	}

	downloadTLSCert := setup.Download_Cert{
		Flags:              []string{"--force",}, // to be consistent with other GTA tasks, always force update
		KeyFile:            constants.TLSKeyFilePath,
		CertFile:           constants.TLSCertFilePath,
		KeyAlgorithm:       constants.DefaultKeyAlgorithm,
		KeyAlgorithmLength: constants.DefaultKeyAlgorithmLength,
		CmsBaseURL:         cfg.CMS.BaseURL,
		Subject: pkix.Name{
			CommonName: cfg.TLS.CertCN,
		},
		SanList:       cfg.TLS.CertSAN,
		CertType:      "TLS",
		CaCertsDir:    constants.TrustedCaCertsDir,
		BearerToken:   "",
		ConsoleWriter: os.Stdout,
	}

	provisionEndorsementKey := ProvisionEndorsementKey{
		clientFactory: vsClientFactory,
		tpmFactory: tpmFactory,
		ownerSecretKey: &cfg.Tpm.OwnerSecretKey,
	}

	provisionAttestationIdentityKey := ProvisionAttestationIdentityKey{
		clientFactory: vsClientFactory,
		tpmFactory: tpmFactory,
		ownerSecretKey: &cfg.Tpm.OwnerSecretKey,
		aikSecretKey: &cfg.Tpm.AikSecretKey,
	}

	downloadPrivacyCA := DownloadPrivacyCA{
		clientFactory: vsClientFactory,
	}

	provisionPrimaryKey := ProvisionPrimaryKey{
		tpmFactory: tpmFactory,
		ownerSecretKey: &cfg.Tpm.OwnerSecretKey,
	}

	registry.taskMap[TakeOwnershipCommand] = []setup.Task{&takeOwnership}
	registry.taskMap[DownloadRootCACertCommand] = []setup.Task{&downloadRootCACert}
	registry.taskMap[DownloadCertCommand] = []setup.Task{&downloadTLSCert}
	registry.taskMap[ProvisionEndorsementKeyCommand] = []setup.Task{&provisionEndorsementKey}
	registry.taskMap[ProvisionAttestationIdentityKeyCommand] = []setup.Task{&provisionAttestationIdentityKey}
	registry.taskMap[DownloadPrivacyCACommand] = []setup.Task{&downloadPrivacyCA}
	registry.taskMap[ProvisionPrimaryKeyCommand] = []setup.Task{&provisionPrimaryKey}

	registry.taskMap[ProvisionAttestationCommand] = [] setup.Task{
		&downloadPrivacyCA,
		&takeOwnership,
		&provisionEndorsementKey,
		&provisionAttestationIdentityKey,
		&provisionPrimaryKey,
	}

	registry.taskMap[UpdateCertificatesCommand] = [] setup.Task{
		&downloadRootCACert,
		&downloadTLSCert,
	}

	registry.taskMap[DefaultSetupCommand] = []setup.Task{
		&downloadRootCACert,
		&downloadTLSCert,
		&downloadPrivacyCA,
		&takeOwnership,
		&provisionEndorsementKey,
		&provisionAttestationIdentityKey,
		&provisionPrimaryKey,
	}

	// these are individual commands that are not included in default setup tasks

	connectionString, err := util.GetConnectionString(cfg.WebService.Port)
	if err != nil {
		log.WithError(err).Error("tasks/TaskRegistry/CreateTaskRegistry() Error while getting connection string")
		return nil, errors.New("Error while getting connection string")
	}

	registry.taskMap[CreateHostCommand] = []setup.Task{
		&CreateHost{
			clientFactory: vsClientFactory,
			connectionString: connectionString,
		},
	}

	registry.taskMap[CreateHostUniqueFlavorCommand] = []setup.Task{
		&CreateHostUniqueFlavor{
			clientFactory: vsClientFactory,
			connectionString: connectionString,
		},
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
	registry.cfg.Save()	// always update the cofig.yaml regardless of error (so TPM owner/aik are persisted)
	if err != nil {
		return err
	}

	return nil
}
