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

type GetConfiguredManifest struct {
	Flags 	[]string
}

func (task* GetConfiguredManifest) Run(c setup.Context) error {
	return errors.New("GetConfiguredManifest.Run is not implemented")
}

func (task* GetConfiguredManifest) Validate(c setup.Context) error {
	log.Info("Setup: Get configured manifest was successful.")
	return errors.New("GetConfiguredManifest.Validate is not implemented")
}