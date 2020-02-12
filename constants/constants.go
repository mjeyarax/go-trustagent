/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package constants

import "time"

const (
	InstallationDir            = "/opt/trustagent/"
	ConfigDir                  = InstallationDir + "configuration/"
	ConfigFilePath             = ConfigDir + "config.yml"
	BinDir                     = InstallationDir + "bin/"
	TagentExe                  = BinDir + "tagent"
	ModuleAnalysis             = BinDir + "module_analysis.sh"
	LogDir                     = "/var/log/trustagent/"
	HttpLogFile                = LogDir + "http.log"
	DefaultLogFilePath         = LogDir + "trustagent.log"
	SecurityLogFilePath        = LogDir + "trustagent-security.log"
	TLSCertFilePath            = ConfigDir + "tls-cert.pem"
	TLSKeyFilePath             = ConfigDir + "tls-key.pem"
	EndorsementAuthoritiesFile = ConfigDir + "endorsement.pem"
	AikBlob                    = ConfigDir + "aik.blob"
	AikCert                    = ConfigDir + "aik.pem"
	PrivacyCA                  = ConfigDir + "privacy-ca.cer"
	VarDir                     = InstallationDir + "var/"
	RamfsDir                   = VarDir + "ramfs/"
	SystemInfoDir              = VarDir + "system-info/"
	PlatformInfoFilePath       = SystemInfoDir + "platform-info"
	MeasureLogFilePath         = VarDir + "measureLog.xml"
	BindingKeyCertificatePath  = "/etc/workload-agent/bindingkey.pem"
	TBootXmMeasurePath         = "/opt/tbootxm/bin/measure"
	RootUserName               = "root"
	TagentUserName             = "tagent"
	DefaultPort                = 1443
	FlavorUUIDs                = "FLAVOR_UUIDS"
	DefaultLogEntryMaxlength   = 300
	FlavorLabels               = "FLAVOR_LABELS"
	ServiceName                = "tagent.service"
	AASServiceName             = "TA"
	ServiceStatusCommand       = "systemctl status " + ServiceName
	ServiceStopCommand         = "systemctl stop " + ServiceName
	ServiceStartCommand        = "systemctl start " + ServiceName
	ServiceDisableCommand      = "systemctl disable " + ServiceName
	ServiceDisableInitCommand  = "systemctl disable tagent_init.service"
	UninstallTbootXmScript     = "/opt/tbootxm/bin/tboot-xm-uninstall.sh"
	LogEntryMaxlengthEnv       = "LOG_ENTRY_MAXLENGTH"
	TrustedJWTSigningCertsDir  = ConfigDir + "jwt/"
	TrustedCaCertsDir          = ConfigDir + "cacerts/"
	DefaultKeyAlgorithm        = "rsa"
	DefaultKeyAlgorithmLength  = 3072
	EnvBearerToken             = "BEARER_TOKEN"
	JWTCertsCacheTime          = "1m"
	AdministratorGroup         = "Administrator"
	EnvTPMOwnerSecret          = "TPM_OWNER_SECRET"
	EnvMtwilsonAPIURL          = "MTWILSON_API_URL"
	EnvTAPort                  = "TRUSTAGENT_PORT"
	EnvCMSBaseURL              = "CMS_BASE_URL"
	EnvCMSTLSCertDigest        = "CMS_TLS_CERT_SHA384"
	EnvAASBaseURL              = "AAS_API_URL"
	EnvTLSCertCommonName       = "TA_TLS_CERT_CN"
	EnvCertSanList             = "SAN_LIST"
	DefaultTaTlsCn             = "Trust Agent TLS Certificate"
	DefaultTaTlsSan            = "127.0.0.1,localhost"
	TrustAgentEnvMaxLength     = 10000
	FlavorUUIDMaxLength        = 500
	FlavorLabelsMaxLength      = 500
	DefaultReadTimeout         = 30 * time.Second
	DefaultReadHeaderTimeout   = 10 * time.Second
	DefaultWriteTimeout        = 10 * time.Second
	DefaultIdleTimeout         = 10 * time.Second
	DefaultMaxHeaderBytes      = 1 << 20
)
