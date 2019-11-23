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

	if len(cfg.TrustAgentService.Username) == 0 {
		return "", fmt.Errorf("The user name has not been set in the trust agent configuration")
	}

	if len(cfg.TrustAgentService.Password) == 0 {
		return "", fmt.Errorf("The password has not been set in the trust agent configuration")
	}

	connectionString := fmt.Sprintf("intel:https://%s:%d;u=%s;p=%s", ip, cfg.TrustAgentService.Port, cfg.TrustAgentService.Username, cfg.TrustAgentService.Password)
	return connectionString, nil
}
