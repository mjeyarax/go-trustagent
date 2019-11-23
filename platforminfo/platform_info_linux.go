// +build linux

/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package platforminfo

import (
	"errors"
	"os"
	"regexp"
	"strconv"
	"strings"
)

var (
	ErrNoVMMError                   = errors.New("VMM is not installed")
	ErrMissingVirshVersionFileError = errors.New("Empty virsh version file, assuming no VMM installed")
	ErrNoTPMError                   = errors.New("No TPM chip present on host")
	ErrTPMStatusError               = errors.New("Error in getting the TPM status")
)

var (
	tpm12File  = "/sys/class/tpm/tpm0/device/enabled"
	tpm20File0 = "/sys/class/tpm/tpm0/device/description"
	tpm20File1 = "/sys/class/tpm/tpm0/device/firmware_node/description"
)

var (
	biosNameCmd      = []string{"dmidecode", "-s", "bios-vendor"}
	biosVersionCmd   = []string{"dmidecode", "-s", "bios-version"}
	hardwareUUIDCmd  = []string{"dmidecode", "-s", "system-uuid"}
	osInfoCmd        = []string{"lsb_release", "-a"}
	processorInfoCmd = []string{"dmidecode", "--type", "processor"}
	dockerVersionCmd = []string{"docker", "-v"}
	virshVersionCmd  = []string{"virsh", "-v"}
	hostNameCmd      = []string{"hostname"}
	noSocketsCmd     = []string{"lscpu"}
	txtEnabledCmd    = []string{"txt-stat"}
)

// BiosName retrieves the host BIOS name.
// An example of the host bios name is Intel Corporation
func BiosName() (string, error) {
	//Output of command:
	//Intel Corporation
	result, err := readAndParseFromCommandLine(biosNameCmd)
	if err != nil {
		return "", err
	}
	biosName := ""
	// Split the output separated by new line into list
	for i := range result {
		biosName = strings.TrimSpace(result[i])
		break
	}
	return biosName, err
}

// BiosVersion retrieves the host BIOS version.
// An example of the host bios version is S5500.86B.01.00.0060.090920111354
func BiosVersion() (string, error) {
	//Output of command:
	//S5500.86B.01.00.0060.090920111354
	result, err := readAndParseFromCommandLine(biosVersionCmd)
	if err != nil {
		return "-1", err
	}

	biosVersion := ""
	for i := range result {
		biosVersion = strings.TrimSpace(result[i])
		break
	}

	return biosVersion, err
}

// HardwareUUID retireves the host hardware UUID.
// An example of the host hardware UUID is 4219B2F5-C25F-6AF2-573C-35B0DF557236
func HardwareUUID() (string, error) {
	//Output of command:
	//4219B2F5-C25F-6AF2-573C-35B0DF557236
	result, err := readAndParseFromCommandLine(hardwareUUIDCmd)
	if err != nil {
		return "-1", err
	}

	hardwareUUID := ""
	for i := range result {
		hardwareUUID = strings.TrimSpace(result[i])
		break
	}
	return hardwareUUID, err
}

// OSName retrieves the host OS name.
// An example of the host OS name is Ubuntu
func OSName() (string, error) {

	osName, _, err := osNameAndVersion()

	// ISECL-7227:  This is a hack to get flavors to work in hvs.  HVS is expecting "RedHatEnterpriseServer",
	// but on RHEL8 'lsb_release -a' is returning "RedHatEnterprise".  This needs to be
	// fixed in HVS.
	if osName == "RedHatEnterprise" {
		osName = "RedHatEnterpriseServer"
	}

	return osName, err
}

// OSVersion retrieves the host OS version.
// An example of the host OS version is 11.10
func OSVersion() (string, error) {
	_, osVersion, err := osNameAndVersion()
	return osVersion, err
}

// osNameandVersion retrieves the host OS name and version
func osNameAndVersion() (string, string, error) {
	/*
		Sample response of 'lsb_release -a'

		No LSB modules are available.
		Distributor ID: Ubuntu
		Description:    Ubuntu 11.10
		Release:        11.10
		Codename:       oneiric
	*/
	result, err := readAndParseFromCommandLine(osInfoCmd)
	if err != nil {
		return "", "-1", err
	}

	osName, osVersion := "", ""
	for i := range result {
		if strings.HasPrefix(result[i], "Distributor ID:") {
			osName = strings.TrimSpace(strings.TrimPrefix(result[i], "Distributor ID:"))
		} else if strings.HasPrefix(result[i], "Release:") {
			osVersion = strings.TrimSpace(strings.TrimPrefix(result[i], "Release:"))
		}
	}
	return osName, osVersion, err
}

// NoOfSockets retrieves the number of CPU sockets on the host platform.
func NoOfSockets() (int, error) {
	result, err := readAndParseFromCommandLine(noSocketsCmd)
	if err != nil {
		return -1, err
	}

	noOfSockets := 0
	for i := range result {
		if strings.HasPrefix(result[i], "Socket(s):") {
			noOfSockets, _ = strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(result[i], "Socket(s):")))
			break
		}
	}
	return noOfSockets, err
}

// ProcessorFlags retrieves the processor flags.
// Some examples of host processor flags are FPU, VME
func ProcessorFlags() ([]string, error) {
	_, flags, err := processorInfo()
	return flags, err
}

// ProcessorID retrieves the processor ID.
// An example of the processor ID is ABCDFGHI012345JK
func ProcessorID() (string, error) {
	id, _, err := processorInfo()
	return id, err
}

func processorInfo() (string, []string, error) {
	/*
		Sample output of 'dmidecode --type processor'

		Processor Information
				Socket Designation: CPU1
				Type: Central Processor
				Family: Xeon
				Manufacturer: Intel(R) Corporation
				ID: C2 06 02 00 FF FB EB BF
				Signature: Type 0, Family 6, Model 44, Stepping 2
				Flags:
						FPU (Floating-point unit on-chip)
						VME (Virtual mode extension)
						DE (Debugging extension)
						PSE (Page size extension)
						TSC (Time stamp counter)
						...
				Version: Intel(R) Xeon(R) Gold 6140 CPU @ 2.30GHz
				Voltage: 1.6 V
				External Clock: 100 MHz
				Max Speed: 4000 MHz
				Current Speed: 2300 MHz
				Status: Populated, Enabled
				Upgrade: Socket LGA3647-1
				L1 Cache Handle: 0x000E
				L2 Cache Handle: 0x000F
				L3 Cache Handle: 0x0010
				Serial Number: Not Specified
				Asset Tag: UNKNOWN
				Part Number: Not Specified
				Core Count: 18
				Core Enabled: 18
				Thread Count: 36
				Characteristics:
						64-bit capable
				        Multi-Core
				        Hardware Thread
				        Execute Protection
				        Enhanced Virtualization
				        Power/Performance Control
	*/
	result, err := readAndParseFromCommandLine(processorInfoCmd)
	if err != nil {
		return "-1", make([]string, 0), err
	}

	id := ""
	flags := make([]string, 0)
	flagRegExp, _ := regexp.Compile(`^\t*[A-Z0-9\-]+ \([A-Za-z0-9\- ]+\)$`)
	for i := range result {
		line := result[i]
		if strings.HasPrefix(line, "ID:") {
			id = strings.Join(strings.Fields(line)[1:], " ")
		} else if flagRegExp.MatchString(line) {
			flags = append(flags, strings.Fields(line)[0])
		} else if strings.HasPrefix(line, "Version:") {
			break
		}
	}
	return id, flags, err
}

// VMMName retrives the name of the hypervisor running on the host.
// An example of the hypervisor name is Docker.
func VMMName() (string, error) {
	vmmName, _, err := vmmInfo()
	return vmmName, err
}

// VMMVersion retrieves the version of the hypervisor running on the host.
// An example of the hypervisor version is 1.13.1
func VMMVersion() (string, error) {
	_, vmmVersion, err := vmmInfo()
	return vmmVersion, err
}

// vmmNameAndVersion retrieves the name and version of the hypervisor running on the host.
func vmmInfo() (string, string, error) {
	// Check if docker is installed
	/*
		Sample response of 'docker -v'

		Docker version 1.13.1, build 07f3374/1.13.1
	*/
	result, err := readAndParseFromCommandLine(dockerVersionCmd)

	// if no error occurs, assume docker is installed, return name and version...
	if err == nil && len(result) != 0 {
		response := result[0]
		parts := strings.Split(response, " ")
		return parts[0], strings.TrimSuffix(parts[2], ","), nil
	}

	// Check if virsh is installed...
	result, err = readAndParseFromCommandLine(virshVersionCmd)
	if err == nil && len(result) != 0 {
		response := result[0]
		parts := strings.Split(response, " ")
		return "Virsh", parts[0], nil
	}

	// if neither is installed, just return empty strings to satisfy platforminfo json
	return "", "", nil
}

// HostName retireves the network hostname.
// An example of the hostname is Redhat
func HostName() (string, error) {
	result, err := readAndParseFromCommandLine(hostNameCmd)
	if err != nil {
		return "", err
	}

	hostName := strings.TrimSpace(result[0])
	return hostName, err
}

// TPMVersion retrieves the version of the installed Trusted Platform Module (TPM).
// An example of the host TPM version is 1.2
func TPMVersion() (string, error) {
	_, err := os.Stat("/dev/tpm0")
	if os.IsNotExist(err) {
		return "0", nil
	}
	_, err = os.Stat("/sys/class/misc/tpm0/device/caps")
	if !os.IsNotExist(err) {
		return "1.2", nil
	}
	_, err = os.Stat("/sys/class/tpm/tpm0/device/caps")
	if !os.IsNotExist(err) {
		return "1.2", nil
	}
	return "2.0", nil
}

// TPMEnabled indicates whether the Trusted Platform Module is enabled or not.
func TPMEnabled() (bool, error) {
	version, err := TPMVersion()
	if version == "0" {
		return false, nil
	}

	tpmEnabled := false
	if version == "1.2" {
		_, err := readAndParseFromCommandLine([]string{"cat", tpm12File})
		tpmEnabled = err == nil
	} else if version == "2.0" {
		_, err = os.Stat(tpm20File0)
		tpmEnabled = !os.IsNotExist(err)
		if !tpmEnabled {
			_, err = os.Stat(tpm20File1)
			if !os.IsNotExist(err) {
				tpmEnabled = true
			} else {
				err = ErrTPMStatusError
			}
		}
	}
	return tpmEnabled, err
}

// TXTEnabled indicates whether Intel TXT is enabled or not.
func TXTEnabled() (bool, error) {
	result, err := readAndParseFromCommandLine(txtEnabledCmd)
	if err != nil {
		return false, nil
	}

	txtStatus := false
	for i := range result {
		trimmed := strings.TrimSpace(result[i])
		if strings.HasPrefix(trimmed, "TXT measured launch:") {
			txtStatus = strings.Contains(trimmed, "TRUE")
			break
		}
	}
	return txtStatus, err
}
