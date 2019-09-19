// build !integration

/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
 package tasks

 import (
	"testing"
	"github.com/stretchr/testify/assert"
	"intel/isecl/go-trust-agent/config"
)

func TestRegisterDownloadEndorsementAuthorities(t *testing.T) {
	assert := assert.New(t)

	config.GetConfiguration().HVS.Url = "https://10.105.168.60:8443/mtwilson/v2"
	config.GetConfiguration().HVS.Username = "admin"
	config.GetConfiguration().HVS.Password = "password"
	config.GetConfiguration().HVS.TLS384 = "7ff464fdd47192d7218e9bc7a80043641196762b840c5c79b7fdaaae471cbffb0ee893c23bca63197b8a863f516a7d8b"

	provisionEndorsementKey := ProvisionEndorsementKey { Flags: nil }

	err := provisionEndorsementKey.downloadEndorsementAuthorities()
	assert.NoError(err)
}