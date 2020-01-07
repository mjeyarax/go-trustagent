/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package util

import (
	"fmt"
	"intel/isecl/go-trust-agent/config"
)

func GetConnectionString(cfg *config.TrustAgentConfiguration) (string, error) {

	ip, err := GetLocalIpAsString()
	if err != nil {
		return "", err
	}

	connectionString := fmt.Sprintf("intel:https://%s:%d;", ip, cfg.TrustAgentService.Port)
	return connectionString, nil
}
