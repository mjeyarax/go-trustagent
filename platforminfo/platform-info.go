/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
 package platforminfo

// Struct used to hold the current host's platform information that can be encoded/decoded to 
// json (see example below).
//
// {
//     "errorCode": 0,
//     "os_name": "RedHatEnterpriseServer",
//     "os_version": "7.6",
//     "bios_version": "SE5C620.86B.00.01.0014.070920180847",
//     "vmm_name": "",
//     "vmm_version": "",
//     "processor_info": "54 06 05 00 FF FB EB BF",
//     "host_name": "Purley32",
//     "bios_name": "Intel Corporation",
//     "hardware_uuid": "809797df-6d2d-e711-906e-0017a4403562",
//     "processor_flags": "fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 clflush dts acpi mmx fxsr sse sse2 ss ht tm pbe syscall nx pdpe1gb rdtscp lm constant_tsc art arch_perfmon pebs bts rep_good nopl xtopology nonstop_tsc aperfmperf eagerfpu pni pclmulqdq dtes64 monitor ds_cpl vmx smx est tm2 ssse3 sdbg fma cx16 xtpr pdcm pcid dca sse4_1 sse4_2 x2apic movbe popcnt tsc_deadline_timer aes xsave avx f16c rdrand lahf_lm abm 3dnowprefetch epb cat_l3 cdp_l3 intel_ppin intel_pt ssbd mba ibrs ibpb stibp tpr_shadow vnmi flexpriority ept vpid fsgsbase tsc_adjust bmi1 hle avx2 smep bmi2 erms invpcid rtm cqm mpx rdt_a avx512f avx512dq rdseed adx smap clflushopt clwb avx512cd avx512bw avx512vl xsaveopt xsavec xgetbv1 cqm_llc cqm_occup_llc cqm_mbm_total cqm_mbm_local dtherm ida arat pln pts hwp hwp_act_window hwp_epp hwp_pkg_req pku ospke spec_ctrl intel_stibp flush_l1d",
//     "tpm_version": "2.0",
//     "pcr_banks": [
//         "SHA1",
//         "SHA256"
//     ],
//     "no_of_sockets": "2",
//     "tpm_enabled": "true",
//     "txt_enabled": "true",
//     "tboot_installed": "true",
//     "is_docker_env": "false",
//     "hardware_features": {
//         "TXT": {
//             "enabled": true
//         },
//         "TPM": {
//             "enabled": true,
//             "meta": {
//                 "tpm_version": "2.0",
//                 "pcr_banks": "SHA1_SHA256"
//             }
//         }
//     },
//     "installed_components": [
//         "tagent"
//     ]
// }
type PlatformInfo struct {
	ErrorCode int   				`json:"errrCode"`
	OSName string 					`json:"os_name"`
	OSVersion string				`json:"os_version"`
	BiosVersion string				`json:"bios_version"`
	VMMName string					`json:"vmm_name"`
	VMMVersion string				`json:vmm_version"`
	ProcessorInfo string			`json:"processor_info"`
	HostName string					`json:"host_name"`
	HardwareUUID string				`json:"hardware_uuid"`
	ProcessorFlags string			`json:"process_flags"`
	TPMVersion string				`json:"tpm_version"`
	PCRBanks []string				`json:"pcr_banks"`
	NumberOfSockets string			`json:"no_of_sockets"`
	TPMEnabled bool					`json:"tpm_enabled"`
	TXTEnabled bool					`json:"txt_enabled"`
	TbootInstalled bool				`json:"tboot_installed"`
	IsDockerEnvironment bool		`json:"is_docker_env"`
	HardwareFeatures struct {
		TXT struct {
			Enabled bool			`json:"enabled"`
		}							`json:"TXT"`
		TPM struct {
			Enabled bool			`json:"enabled"`
			Meta struct {
				TPMVersion string	`json:"tpm_version"`
				PCRBanks string 	`json:"pcr_banks"`
			}
		}							`json:"TPM"`
	}								`json:"hardware_features"`
	InstalledComponents []string	`json:"installed_components"`
}

func GetPlatformInfo() (PlatformInfo, error) {
    platformInfo := PlatformInfo {}
    
    // TODO:  Handle error conditions...
    platformInfo.ErrorCode = 0
    platformInfo.OSName, _ = OSName()
    platformInfo.OSVersion, _ = OSVersion()
    platformInfo.BiosVersion, _ = BiosVersion()
    platformInfo.VMMName, _ = VMMName()
    platformInfo.VMMVersion, _ = VMMVersion()
    platformInfo.ProcessorInfo, _  = ProcessorID()
    platformInfo.HostName, _ = HostName()
    platformInfo.HardwareUUID, _ = HardwareUUID()
    //KWT: platformInfo.ProcessorFlags, _ = ProcessorFlags() --> array to single string
    platformInfo.TPMVersion, _ = TPMVersion()               // TODO:  delegate to tpm
    platformInfo.PCRBanks = []string { "SHA1", "SHA256",}   // TODO:  delegate to tpm
    //KWT: platformInfo.NumberOfSockets, _ = NoOfSockets()
    platformInfo.TPMEnabled, _ = TPMEnabled()               // TODO:  delegate to tpm
    platformInfo.TXTEnabled, _ = TXTEnabled()               // TODO:  delegate to tpm
    platformInfo.TbootInstalled = true                   // TODO: ???
    //KWT: platformInfo.IsDockerEnvironment --> VMMName contains docker
    platformInfo.HardwareFeatures.TXT.Enabled = platformInfo.TXTEnabled
    platformInfo.HardwareFeatures.TPM.Enabled = platformInfo.TPMEnabled
    platformInfo.HardwareFeatures.TPM.Meta.TPMVersion = platformInfo.TPMVersion
    //KWT: platformInfo.HardwareFeatures.TPM.Meta.PCRBanks = platformInfo.PCRBanks


	return platformInfo, nil
}