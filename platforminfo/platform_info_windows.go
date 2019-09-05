// +build windows

/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package platforminfo

import (
	"errors"
	"regexp"
	"strings"
)

var (
	ErrTXTNotSupportedError = errors.New("TXT is not supported on the host")
)

var (
	biosNameCmd                    = []string{"wmic", "bios", "get", "manufacturer"}
	biosVersionCmd                 = []string{"wmic", "bios", "get", "smbiosbiosversion"}
	hardwareUUIDCmd                = []string{"wmic", "path", "Win32_ComputerSystemProduct", "get", "uuid"}
	osNameCmd                      = []string{"wmic", "os", "get", "caption"}
	osVersionCmd                   = []string{"wmic", "os", "get", "version"}
	processorIDCmd                 = []string{"wmic", "cpu", "get", "ProcessorId"}
	vmmNameCmd                     = []string{"reg", "query", `HKLM\SOFTWARE\Microsoft\virtual machine\guest\parameters`, "/v", "Hostname"}
	vmmVersionCmd                  = []string{"wmic", "datafile", "where", `name='c:\\windows\\system32\\vmms.exe'`, "get", "version"}
	tpmInfoCmd                     = []string{"wmic", "/namespace:\\\\root\\CIMV2\\Security\\MicrosoftTpm", "path", "Win32_Tpm", "get", "/value"}
	hostNameCmd                    = []string{"wmic", "computersystem", "get", "Name"}
	noSocketsCmd                   = []string{"wmic", "cpu", "get", "SocketDesignation"}
	txtEnabledCmd                  = []string{"systeminfo"}
	processorFlagsAndTXTSupportCmd = []string{"coreinfo", "-f"}
)

// BiosName retrieves the host BIOS name.
// An example of the host bios name is LENOVO
func BiosName() (string, error) {
	/*
		Sample output of 'wmic bios get manufacturer'

		Manufacturer
		LENOVO
	*/
	result, err := readAndParseFromCommandLine(biosNameCmd)
	if err != nil {
		return "-1", err
	}

	biosName := ""
	if len(result) > 1 {
		biosName = result[1]
	}
	return biosName, err
}

// BiosVersion retrieves the host BIOS version.
// An example of the host bios version is N24ET48W (1.23 )
func BiosVersion() (string, error) {
	/*
		Sample output of 'wmic bios get manufacturer'

		SMBIOSBIOSVERSION
		N24ET48W (1.23 )
	*/
	result, err := readAndParseFromCommandLine(biosVersionCmd)
	if err != nil {
		return "-1", err
	}

	biosVersion := ""
	if len(result) > 1 {
		biosVersion = result[1]
	}
	return biosVersion, err
}

// HardwareUUID retireves the host hardware UUID.
// An example of the host hardware UUID is 4219B2F5-C25F-6AF2-573C-35B0DF557236
func HardwareUUID() (string, error) {
	/*
		Sample output of 'wmic path Win32_ComputerSystemProduct get uuid'

		UUID
		4219B2F5-C25F-6AF2-573C-35B0DF557236
	*/
	result, err := readAndParseFromCommandLine(hardwareUUIDCmd)
	if err != nil {
		return "-1", err
	}
	hardwareUUID := ""
	if len(result) > 1 {
		// remove all spaces from the second line as that line consists hardware uuid
		re := regexp.MustCompile("\\s|\\r")
		hardwareUUID = re.ReplaceAllString(result[1], "")
	}
	return hardwareUUID, nil
}

// OSName retrieves the host OS name.
// An example of the host OS name is Windows 10 Home
func OSName() (string, error) {
	/*
		Sample output of 'wmic os get caption'

		Caption
		Microsoft Windows 10 Home
	*/
	result, err := readAndParseFromCommandLine(osNameCmd)
	if err != nil {
		return "-1", err
	}
	osName := ""
	if len(result) > 1 {
		osName = result[1]
	}
	return osName, err
}

// OSVersion retrieves the host OS version.
// An example of the Host OS version is 12.3.4567
func OSVersion() (string, error) {
	/*
		Sample output of 'wmic os get caption'

		Version
		12.3.4567
	*/
	result, err := readAndParseFromCommandLine(osVersionCmd)
	if err != nil {
		return "-1", err
	}
	osVersion := ""
	if len(result) > 1 {
		osVersion = strings.TrimSpace(result[1])
	}
	return osVersion, err
}

// ProcessorFlags retrieves the processor flags.
// Some examples of host processor flags are FPU, VME
func ProcessorFlags() ([]string, error) {
	flags, _, err := processorFlagsAndTXTSupport()
	return flags, err
}

// ProcessorID retrieves the processor ID.
// An example of the processor ID is ABCDFGHI012345JK
func ProcessorID() (string, error) {
	/*
		Sample output of 'wmic os get caption'

		ProcessorID
		ABCDFGHI012345JK
	*/
	result, err := readAndParseFromCommandLine(processorIDCmd)
	if err != nil {
		return "-1", err
	}
	processorID := ""
	if len(result) > 1 {
		processorID = result[1]
	}
	return processorID, err
}

// VMMName retrives the name of the hypervisor running on the host.
// An example of the hypervisor name is hello.world.foo.bar.com
func VMMName() (string, error) {
	//Output of command:
	//hello.world.foo.bar.com
	result, err := readAndParseFromCommandLine(vmmNameCmd)
	if err != nil {
		return "-1", err
	}
	vmmName := strings.Fields(result[1])[2]
	return vmmName, err
}

// VMMVersion retrieves the version of the hypervisor running on the host.
// An example of the hypervisor version is 98.7.65432.100
func VMMVersion() (string, error) {
	/*
		Sample output of 'wmic datafile where name="C:\\Windows\\System32\\vmms.exe" get version'

		Version
		98.7.65432.100
	*/
	result, err := readAndParseFromCommandLine(vmmVersionCmd)
	if err != nil {
		return "-1", err
	}
	vmmVersion := ""
	if len(result) > 1 {
		vmmVersion = strings.TrimSpace(result[1])
	}
	return vmmVersion, err
}

// TPMEnabled indicates whether the Trusted Platform Module is enabled or not.
func TPMEnabled() (bool, error) {
	tpmEnabled, _, err := tpmEnabledAndVersion()
	return tpmEnabled, err
}

// TPMVersion retrieves the version of the installed Trusted Platform Module (TPM).
// An example of the TPM version is 1.2
func TPMVersion() (string, error) {
	_, tpmVersion, err := tpmEnabledAndVersion()
	return tpmVersion, err
}

func tpmEnabledAndVersion() (bool, string, error) {
	/*
		Sample output of 'wmic /namespace:\\root\CIMV2\Security\MicrosoftTpm path Win32_tpm get /value':

		IsActivated_InitialValue=TRUE
		IsEnabled_InitialValue=TRUE
		IsOwned_InitialValue=TRUE
		ManufacturerId=1398033696
		ManufacturerVersion=8.28
		ManufacturerVersionInfo=Not Supported
		PhysicalPresenceVersionInfo=1.2
		SpecVersion=1.2, 2, 3
	*/
	result, err := readAndParseFromCommandLine(tpmInfoCmd)
	tpmEnabled, tpmVersion := false, "0.0"
	if err != nil {
		return tpmEnabled, tpmVersion, err
	}
	for i := range result {
		if strings.HasPrefix("IsEnabled_InitialValue", result[i]) {
			checkStatus := result[i][strings.Index(result[i], "="):]
			if strings.EqualFold(checkStatus, "true") {
				tpmEnabled = true
			}
		} else if strings.HasPrefix(result[i], "SpecVersion") {
			versionInfo := strings.TrimPrefix(result[i], "SpecVersion=")
			tpmVersion = strings.Split(versionInfo, ",")[0]
			break
		}
	}
	return tpmEnabled, tpmVersion, err
}

// HostName retireves the network hostname.
// An example of the host name is WIN-GLU9NEPGT1L
func HostName() (string, error) {
	/*
		Sample output of 'wmic computersystem get Name'

		Name
		WIN-GLU9NEPGT1L
	*/
	result, err := readAndParseFromCommandLine(hostNameCmd)
	if err != nil {
		return "-1", err
	}
	hostName := ""
	if len(result) > 1 {
		hostName = result[1]
	}
	return hostName, err
}

// NoOfSockets retrieves the number of CPU sockets on the host platform.
func NoOfSockets() (int, error) {
	/*
	 Sample output of 'wmic cpu get SocketDesignation'

	 SocketDesignation
	 CPU0
	 CPU1
	*/
	result, err := readAndParseFromCommandLine(noSocketsCmd)
	if err != nil {
		return -1, err
	}
	numSockets := len(result) - 1
	return numSockets, err
}

// TXTEnabled indicates whether Intel TXT is enabled or not.
func TXTEnabled() (bool, error) {
	_, txtSupported, err := processorFlagsAndTXTSupport()
	if err != nil {
		return false, err
	}
	if !txtSupported {
		return false, ErrTXTNotSupportedError
	}

	result, err := readAndParseFromCommandLine(txtEnabledCmd)
	if err != nil {
		return false, err
	}
	txtEnabled := false
	for i := range result {
		if strings.Contains(result[i], "Virtualization Enabled In Firmware: Yes") {
			txtEnabled = true
			break
		}
	}
	return txtEnabled, err
}

func processorFlagsAndTXTSupport() ([]string, bool, error) {
	result, err := readAndParseFromCommandLine(processorFlagsAndTXTSupportCmd)
	if err != nil {
		return make([]string, 0), false, err
	}

	flags := make([]string, 0)
	recordFlags := false
	txtSupported := false
	vmxCheck, smxCheck := false, false
	for i := range result {
		if strings.Contains(result[i], "Microcode signature") {
			recordFlags = true
			continue
		} else if strings.Contains(result[i], "Maximum implemented CPUID leaves") {
			break
		}

		if recordFlags {
			flags = append(flags, strings.Fields(result[i])[0])
		}

		if strings.Contains(result[i], "Supports Intel hardware-assisted virtualization") {
			vmxCheck = true
		} else if strings.Contains(result[i], "Supports Intel trusted execution") {
			smxCheck = true
		}
		if vmxCheck == true && smxCheck == true {
			txtSupported = true
		}
	}
	return flags, txtSupported, err
}
