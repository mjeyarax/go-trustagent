/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package constants

const (
	ServiceName					= "TrustAgent"
	HomeDir						= "/opt/trustagent/"
	ConfigDir					= HomeDir + "configuration/"
	ConfigFilePath				= ConfigDir + "config.yml"
	BinDir						= HomeDir + "bin/"
	TagentExe					= BinDir + "tagent"
	ModuleAnalysis				= BinDir + "module_analysis.sh"
	LogDir						= HomeDir + "logs/"
	LogFilePath					= LogDir + "trustagent.log"
	TLSCertFilePath				= ConfigDir + "tls-cert.pem"
	TLSKeyFilePath				= ConfigDir + "tls-key.pem"
	EndorsementAuthoritiesFile 	= ConfigDir + "endorsement.pem"
	AikBlob						= ConfigDir + "aik.blob"
	AikCert						= ConfigDir + "aik.cer"
	PrivacyCA					= ConfigDir + "privacy-ca.cer"
	VarDir						= HomeDir + "var/"
	RamfsDir					= VarDir + "ramfs/"
	SystemInfoDir				= VarDir + "system-info/"
	PlatformInfoFilePath		= SystemInfoDir + "platform-info"
	MeasureLogFilePath			= VarDir + "measureLog.xml"
	BindingKeyCertificatePath	= "/etc/workload-agent/bindingkey.pem"
	TBootXmMeasurePath			= "/opt/tbootxm/bin/measure"
	RootUserName				= "root"
	TagentUserName				= "tagent"
	DefaultPort					= 1443
	FlavorUUIDs					= "FLAVOR_UUIDS"
	FlavorLabels				= "FLAVOR_LABELS"
)