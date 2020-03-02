/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package util

import (
	"os"
	"intel/isecl/go-trust-agent/constants"
)

func GetBearerToken() (string) {
	return os.Getenv(constants.EnvBearerToken)
}