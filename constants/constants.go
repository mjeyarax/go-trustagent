/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package constants

const (
	ServiceName		= "TrustAgent"
	HomeDir			= "/opt/trustagent/"
	ConfigDir		= HomeDir + "conf/"
	ConfigFilePath	= ConfigDir + "config.yml"
	ExecutableDir	= HomeDir + "bin/"
	LogDir			= HomeDir + "logs/"
	LogFilePath		= LogDir + "trustagent.log"
	TLSCertPath		= ConfigDir + "tls-cert.pem"
	TLSKeyPath		= ConfigDir + "tls-key.pem" 
)