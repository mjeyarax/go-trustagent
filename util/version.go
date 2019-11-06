/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package util

import (
	"fmt"
	"strings"
	"strconv"
)

var Version = "unknown"
var GitHash = "unknown"
var CommitDate = "unknown"

func GetMajorVersion() (int, error) {
	endIdx := strings.Index(Version, ".")
	if endIdx <= 0 {
		return 0, fmt.Errorf("Could not parse version string %s", Version)
	}

	major, err := strconv.Atoi(strings.Replace(Version[0:endIdx], "v", "", -1))
	if err != nil {
		return 0, err
	}

	return major, nil
} 

func GetMinorVersion() (int, error) {
	startIdx := strings.Index(Version, ".")
	if startIdx <= 0 {
		return 0, fmt.Errorf("Could not parse version string %s", Version)
	}

	endIdx := strings.Index(Version[startIdx+1:], ".")
	if endIdx <= 0 {
		return 0, fmt.Errorf("Could not parse version string %s", Version)
	}

	endIdx += startIdx+1

	minor, err := strconv.Atoi(Version[startIdx+1:endIdx])
	if err != nil {
		return 0, err
	}

	return minor, nil
}

func GetPatchVersion() (int, error) {
	startIdx := strings.LastIndex(Version, ".")
	if startIdx <= 0 {
		return 0, fmt.Errorf("Could not parse version string %s", Version)
	}


	patch, err := strconv.Atoi(Version[startIdx+1:])
	if err != nil {
		return 0, err
	}

	return patch, nil
}
