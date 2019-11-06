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

type CreateHostUniqueFlavor struct {
	Flags 	[]string
}

func (task* CreateHostUniqueFlavor) Run(c setup.Context) error {
	return errors.New("CreateHostUniqueFlavor.Run is not implemented")
}

func (task* CreateHostUniqueFlavor) Validate(c setup.Context) error {
	log.Info("Setup: Create host unique flavor was successful.")
	return errors.New("CreateHostUniqueFlavor.Validate is not implemented")
}