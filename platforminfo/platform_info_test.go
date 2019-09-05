/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
 package platforminfo

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"github.com/stretchr/testify/assert"
)

func TestBiosName(t *testing.T) {
	assert := assert.New(t)
	biosName, err := BiosName()
	assert.NoError(err)
	fmt.Printf("Bios Name: '%s'\n", biosName)
}

func TestBiosVersion(t *testing.T) {
	assert := assert.New(t)
	biosVersion, err := BiosVersion()
	assert.NoError(err)
	fmt.Printf("Bios Version: '%s'\n", biosVersion)
}

func TestHardwareUUID(t *testing.T) {
	assert := assert.New(t)
	hardwareUUID, err := HardwareUUID()
	assert.NoError(err)
	fmt.Printf("Hardware UUID: '%s'\n", hardwareUUID)
}

func TestOSName(t *testing.T) {
	assert := assert.New(t)
	osName, err := OSName()
	assert.NoError(err)
	fmt.Printf("OS Name: '%s'\n", osName)
}

func TestOSVersion(t *testing.T) {
	assert := assert.New(t)
	osVersion, err := OSVersion()
	assert.NoError(err)
	fmt.Printf("OS Version: '%s'\n", osVersion)
}

func TestProcessorFlags(t *testing.T) {
	assert := assert.New(t)
	processorFlags, err := ProcessorFlags()
	assert.NoError(err)
	fmt.Printf("Flags for processor 0: '%s'\n", strings.Join(processorFlags, ", "))
}

func TestProcessorID(t *testing.T) {
	assert := assert.New(t)
	processorID, err := ProcessorID()
	assert.NoError(err)
	fmt.Printf("ID for processor 0: '%s'\n", processorID)
}

func TestVMMName(t *testing.T) {
	assert := assert.New(t)
	vmmName, err := VMMName()
	assert.NoError(err)
	fmt.Printf("Hypervisor name: '%s'\n", vmmName)
}

func TestVMMVersion(t *testing.T) {
	assert := assert.New(t)
	vmmVersion, err := VMMVersion()
	assert.NoError(err)
	fmt.Printf("Hypervisor version: '%s'\n", vmmVersion)
}

func TestTPMVersion(t *testing.T) {
	assert := assert.New(t)
	tpmVersion, err := TPMVersion()
	assert.NoError(err)
	fmt.Printf("TPM version: '%s'\n", tpmVersion)
}

func TestHostName(t *testing.T) {
	assert := assert.New(t)
	hostName, err := HostName()
	assert.NoError(err)
	fmt.Printf("Host name: '%s'\n", hostName)
}

func TestNoOfSockets(t *testing.T) {
	assert := assert.New(t)
	numSockets, err := NoOfSockets()
	assert.NoError(err)
	fmt.Printf("Number of sockets: '%d'\n", numSockets)
}

func TestTPMEnabled(t *testing.T) {
	assert := assert.New(t)
	tpmStatus, err := TPMEnabled()
	assert.NoError(err)
	fmt.Printf("TPM Enabled: '%t'\n", tpmStatus)
}

func TestTXTEnabled(t *testing.T) {
	assert := assert.New(t)
	txtStatus, err := TXTEnabled()
	assert.NoError(err)
	fmt.Printf("TXT Enabled: '%t'\n", txtStatus)
}

func TestPlatformInfoStruct(t *testing.T) {
	assert := assert.New(t)
	platformInfo, err := GetPlatformInfo()
	assert.NoError(err)
	b, err := json.Marshal(platformInfo)
	assert.NoError(err)
	fmt.Printf("PlatformInfo JSON:\n%s\n", string(b))
}