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
	tpmProvider, _ := NewTpmProvider()
	defer tpmProvider.Close()
	version := tpmProvider.Version()
	t.Logf("Version %d\n", version)
	assert.NotEqual(t, version, 0)
}

func TestTpmTakeOwnership(t *testing.T) {
	tpmProvider, _ := NewTpmProvider()
	defer tpmProvider.Close()

	var b[] byte
	b = make([]byte, 20, 20)

	rc := tpmProvider.TakeOwnership(b)
	assert.Equal(t, rc, nil)
}