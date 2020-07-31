/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package util

import (
	"github.com/pkg/errors"
	"intel/isecl/lib/tpmprovider/v2"
)

func GetEndorsementKeyBytes(ownerSecretKey string) ([]byte, error) {
	log.Trace("util/endorsement_certificate:GetEndorsementKeyBytes() Entering")
	defer log.Trace("util/endorsement_certificate:GetEndorsementKeyBytes() Leaving")

	tpmFactory, err := tpmprovider.NewTpmFactory()
	if err != nil {
		return nil, errors.Wrap(err, "util/endorsement_certificate:GetEndorsementKeyBytes() Could not create tpm factory")
	}

	//---------------------------------------------------------------------------------------------
	// Get the endorsement key certificate from the tpm
	//---------------------------------------------------------------------------------------------
	tpm, err := tpmFactory.NewTpmProvider()
	if err != nil {
		return nil, errors.Wrap(err, "util/endorsement_certificate:GetEndorsementKeyBytes() Error while creating NewTpmProvider")
	}

	defer tpm.Close()

	ekCertBytes, err := tpm.NvRead(ownerSecretKey, tpmprovider.NV_IDX_RSA_ENDORSEMENT_CERTIFICATE)
	if err != nil {
		return nil, errors.Wrap(err, "util/endorsement_certificate:GetEndorsementKeyBytes() Error while performing tpm Nv read operation for getting endorsement certificate in bytes")
	}

	return ekCertBytes, nil
}