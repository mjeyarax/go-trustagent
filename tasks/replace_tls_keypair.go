/*
* Copyright (C) 2019 Intel Corporation
* SPDX-License-Identifier: BSD-3-Clause
*/
package tasks

import (
	"errors"
	log "github.com/sirupsen/logrus"
//	"intel/isecl/go-trust-agent/config"
//	"intel/isecl/go-trust-agent/constants"
	"intel/isecl/lib/common/setup"
)

type ReplaceTlsKeypair struct {
	Flags 	[]string
}

func (task* ReplaceTlsKeypair) Run(c setup.Context) error {
	return errors.New("ReplaceTlsKeypair.Run is not implemented")
}

func (task* ReplaceTlsKeypair) Validate(c setup.Context) error {
	log.Info("Setup: Replace tls keypair was successful.")
	return errors.New("ReplaceTlsKeypair.Validate is not implemented")
}