/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package util

import (
	"github.com/pkg/errors"
	"strconv"
	"strings"
)

var Version = "0.0.0"
var GitHash = "fffffff"
var CommitDate = "1970-01-01T00:00:00-00:00"

func GetMajorVersion() (int, error) {
	log.Trace("util/version:GetMajorVersion() Entering")
	defer log.Trace("util/version:GetMajorVersion() Leaving")

	endIdx := strings.Index(Version, ".")
	if endIdx <= 0 {
		return 0, errors.Errorf("util/version:GetMinorVersion() Could not parse version string %s", Version)
	}

	major, err := strconv.Atoi(strings.Replace(Version[0:endIdx], "v", "", -1))
	if err != nil {
		return 0, err
	}

	return major, nil
}

func GetMinorVersion() (int, error) {
	log.Trace("util/version:GetMinorVersion() Entering")
	defer log.Trace("util/version:GetMinorVersion() Leaving")

	startIdx := strings.Index(Version, ".")
	if startIdx <= 0 {
		return 0, errors.Errorf("util/version:GetMinorVersion() Could not parse version string %s", Version)
	}

	endIdx := strings.Index(Version[startIdx+1:], ".")
	if endIdx <= 0 {
		return 0, errors.Errorf("util/version:GetMinorVersion() Could not parse version string %s", Version)
	}

	endIdx += startIdx + 1

	minor, err := strconv.Atoi(Version[startIdx+1 : endIdx])
	if err != nil {
		return 0, err
	}

	return minor, nil
}

func GetPatchVersion() (int, error) {
	log.Trace("util/version:GetPatchVersion() Entering")
	defer log.Trace("util/version:GetPatchVersion() Leaving")

	startIdx := strings.LastIndex(Version, ".")
	if startIdx <= 0 {
		return 0, errors.Errorf("util/version:GetPatchVersion() Could not parse version string %s", Version)
	}

	patch, err := strconv.Atoi(Version[startIdx+1:])
	if err != nil {
		return 0, err
	}

	return patch, nil
}
