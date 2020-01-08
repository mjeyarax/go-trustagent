/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package constants

const (
	InstallationDir            = "/opt/trustagent/"
	ConfigDir                  = InstallationDir + "configuration/"
	ConfigFilePath             = ConfigDir + "config.yml"
	BinDir                     = InstallationDir + "bin/"
	TagentExe                  = BinDir + "tagent"
	ModuleAnalysis             = BinDir + "module_analysis.sh"
	LogDir                     = "/var/log/trustagent/"
	DefaultLogFilePath         = LogDir + "trustagent.log"
	SecureLogFilePath          = LogDir + "trustagent-security.log"
	TLSCertFilePath            = ConfigDir + "tls-cert.pem"
	TLSKeyFilePath             = ConfigDir + "tls-key.pem"
	EndorsementAuthoritiesFile = ConfigDir + "endorsement.pem"
	AikBlob                    = ConfigDir + "aik.blob"
	AikCert                    = ConfigDir + "aik.cer"
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
	FlavorLabels               = "FLAVOR_LABELS"
	ServiceName                = "tagent.service"
	AASServiceName             = "TA"
	ServiceStatusCommand       = "systemctl status " + ServiceName
	ServiceStopCommand         = "systemctl stop " + ServiceName
	ServiceStartCommand        = "systemctl start " + ServiceName
	ServiceDisableCommand      = "systemctl disable " + ServiceName
	UninstallTbootXmScript     = "/opt/tbootxm/bin/tboot-xm-uninstall.sh"
	LogEntryMaxlengthEnv       = 300
	TrustedJWTSigningCertsDir  = ConfigDir + "jwt/"
	TrustedCaCertsDir          = ConfigDir + "cacerts/"
	DefaultKeyAlgorithm        = "rsa"
	DefaultKeyAlgorithmLength  = 3072
	DefaultTLSCertIP           = "127.0.0.1"
	DefaultTLSCertDNS          = "CN=trustagent"
	BearerTokenEnv             = "BEARER_TOKEN"
	JWTCertsCacheTime          = "1m"
	AdministratorGroup         = "Administrator"
	EnvTPMOwnerSecret          = "TPM_OWNER_SECRET"
	EnvMtwilsonAPIURL          = "MTWILSON_API_URL"
	EnvTAPort                  = "TRUSTAGENT_PORT"
	EnvCMSBaseURL              = "CMS_BASE_URL"
	EnvCMSTLSCertDigest        = "CMS_TLS_CERT_SHA384"
	EnvAASBaseURL              = "AAS_API_URL"
)
