/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package util

import (
	"intel/isecl/go-trust-agent/v3/constants"
	"os"
)

func GetBearerToken() string {
	return os.Getenv(constants.EnvBearerToken)
}
