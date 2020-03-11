/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package util

import (
	"net"
	"strings"

	"github.com/pkg/errors"
)

func GetLocalIpAsString() (string, error) {
	log.Trace("util/ip:GetLocalIpAsString() Entering")
	defer log.Trace("util/ip:GetLocalIpAsString() Leaving")

	addr, err := getLocalIpAddr()
	if err != nil {
		return "", err
	}

	// trim "/24" from addr if present
	ipString := addr.String()

	idx := strings.Index(ipString, "/")
	if idx > -1 {
		ipString = ipString[:idx]
	}

	return ipString, nil
}

//
// This function attempts to create a byte array from the host's ip address.  This
// is used to create a sha1 digest of the nonce that will make HVS happpy.
//
func GetLocalIpAsBytes() ([]byte, error) {
	log.Trace("util/ip:GetLocalIpAsBytes() Entering")
	defer log.Trace("util/ip:GetLocalIpAsBytes() Leaving")

	addr, err := getLocalIpAddr()
	if err != nil {
		return nil, errors.Wrap(err, "util/ip:GetLocalIpAsBytes() Error while trying to get local IP address")
	}

	if ipnet, ok := addr.(*net.IPNet); ok {
		return ipnet.IP[(len(ipnet.IP) - 4):len(ipnet.IP)], nil
	}

	return nil, errors.New("util/ip:GetLocalIpAsBytes() Could not collect local ip bytes")
}

func getLocalIpAddr() (net.Addr, error) {
	log.Trace("util/ip:getLocalIpAddr() Entering")
	defer log.Trace("util/ip:getLocalIpAddr() Leaving")

	var addr net.Addr

	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil, errors.Wrap(err, "util/ip:getLocalIpAddr() Error while retrieving the network interface addresses")
	}

	for _, address := range addrs {
		if ipnet, ok := address.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				if !strings.HasPrefix(ipnet.String(), "192.") {
					log.Debugf("util/ip:getLocalIpAddr() Found local ip address %s", ipnet.String())
					addr = ipnet
					break
				}
			}
		}
	}

	if addr == nil {
		return nil, errors.New("util/ip:getLocalIpAddr() Did not find the local ip address")
	}

	return addr, nil
}
