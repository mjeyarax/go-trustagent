
// +build !integration

/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
 package tasks


import (
	"testing"
	"github.com/stretchr/testify/assert"
	"intel/isecl/go-trust-agent/config"
	"intel/isecl/lib/common/crypt"
)

// TODO
func TestTakeOwnership(t *testing.T) {
	assert := assert.New(t)

	cfg := config.TrustAgentConfiguration {}
	cfg.Tpm.SecretKey = "0123456789012345678901234567890123456789"

	registry, err := CreateTaskRegistry(nil)
	assert.NoError(err)

	registry.RunCommand(TakeOwnershipCommand)

}