/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package util

import (
	"fmt"
	"github.com/pkg/errors"
	"intel/isecl/go-trust-agent/v3/constants"
	commLog "intel/isecl/lib/common/v3/log"
	"net"
	"os"
)

var log = commLog.GetDefaultLogger()
var secLog = commLog.GetSecurityLogger()

func GetCurrentIP() (net.IP, error) {

	currentIP := os.Getenv(constants.EnvCurrentIP)
	if currentIP == "" {
		return nil, errors.New("CURRENT_IP is not define in the environment")
	}

	ip := net.ParseIP(currentIP)
	if ip == nil {
		return nil, errors.Errorf("Could not parse ip address '%s'", currentIP)
	}

	return ip, nil
}

func GetConnectionString(ip net.IP, port int) string {
	log.Trace("util/connection_string:GetConnectionString() Entering")
	defer log.Trace("util/connection_string:GetConnectionString() Leaving")

	return fmt.Sprintf("intel:https://%s:%d", ip.String(), port)
}
