/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package util

import (
	"fmt"
	commLog "intel/isecl/lib/common/log"
	"intel/isecl/go-trust-agent/config"

	"github.com/pkg/errors"
)

var log = commLog.GetDefaultLogger()
var secLog = commLog.GetSecurityLogger()

func GetConnectionString(cfg *config.TrustAgentConfiguration) (string, error) {
	log.Trace("util/connection_string:GetConnectionString() Entering")
	defer log.Trace("util/connection_string:GetConnectionString() Leaving")

	ip, err := GetLocalIpAsString()
	if err != nil {
		return "", errors.Wrap(err, "util/connection_string:GetConnectionString() Error While retrieving local IP")
	}

	connectionString := fmt.Sprintf("intel:https://%s:%d;", ip, cfg.TrustAgentService.Port)
	return connectionString, nil
}
