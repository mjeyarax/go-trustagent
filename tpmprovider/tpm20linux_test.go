/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
 package tpmprovider

import (
	"testing"
	"github.com/stretchr/testify/assert"
)

func TestTpmVersion(t *testing.T) {
	tpm, _ := NewTpm()
	defer tpm.Close()
	version := tpm.Version()
	t.Logf("Version %d\n", version)
	assert.NotEqual(t, version, 0)
}

func TestTpmTakeOwnership(t *testing.T) {
	tpm, _ := NewTpm()
	defer tpm.Close()

	var b[] byte
	b = make([]byte, 20, 20)

	rc := tpm.TakeOwnership(b)
	assert.Equal(t, rc, nil)
}