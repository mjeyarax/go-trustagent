/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package resource

import (
	"bufio"
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"intel/isecl/go-trust-agent/v3/constants"
	"io"
	"os"
	"strconv"
	"strings"
	"syscall"

	"github.com/pkg/errors"
)

const (
	Uint8Size            = 1
	Uint16Size           = 2
	Uint32Size           = 4
	Uint64Size           = 8
	ExtDataElementOffset = 92

	//Uefi Event Info
	UefiBaseOffset = 68
	UefiSizeOffset = 64

	//TXT Heap Base Address and size
	TxtHeapBaseOffset = 0xFED30300
	TxtHeapSizeOffset = 0xFED30308

	//501 Events Info
	Event501 = "0x501"
	TBPolicy = "tb_policy"
	VMLinuz  = "vmlinuz"
	Initrd   = "initrd"
	AssetTag = "asset-tag"

	//Application Events Info
	AppEventTypeID = "0x90000001"
	AppEventName   = "APPLICATION_AGENT_MEASUREMENT"

	//Event types
	Event80000001 = 0x80000001
	Event80000002 = 0x80000002
	Event80000007 = 0x80000007
	Event8000000A = 0x8000000A
	Event8000000B = 0x8000000B
	Event8000000C = 0x8000000C
	Event80000010 = 0x80000010
	Event800000E0 = 0x800000E0
	Event00000007 = 0x00000007
	Event00000001 = 0x00000001
	Event00000005 = 0x00000005
	Event0000000A = 0x0000000A
	Event0000000C = 0x0000000C
	Event00000012 = 0x00000012
	Event00000010 = 0x00000010
	Event00000011 = 0x00000011

	//SHA Types
	SHA1    = "SHA1"
	SHA256  = "SHA256"
	SHA384  = "SHA384"
	SHA512  = "SHA512"
	SM3_256 = "SM3_256"

	//Algorithm Types
	AlgSHA1    = 0x4
	AlgSHA256  = 0xb
	AlgSHA384  = 0xc
	AlgSHA512  = 0xd
	AlgSM3_256 = 0x12

	EventLogFilePath = "/dev/mem"
	Tpm2FilePath     = "/sys/firmware/acpi/tables/TPM2"
	AppEventFilePath = "/opt/trustagent/var/ramfs/pcr_event_log"
)

//EventLogInfo structure is used as receiver object
type EventLogInfo struct {
	UefiEventSize    uint32
	UefiEventAddr    uint64
	TxtHeapSize      uint64
	TxtHeapBaseAddr  uint64
	FinalPcrEventLog []PcrEventLogs
	TxtEnabled       bool
}

//PcrEventLogs structure is used to hold complete events log info
type PcrEventLogs struct {
	Pcr       PcrData    `json:"pcr"`
	TpmEvents []TpmEvent `json:"tpm_events"`
}

//PcrData structure is used to hold pcr info
type PcrData struct {
	Index uint32 `json:"index"`
	Bank  string `json:"bank"`
}

//TpmEvent structure is used to hold Tpm Event Info
type TpmEvent struct {
	TypeID      string   `json:"type_id"`
	TypeName    string   `json:"type_name,omitempty"`
	Tags        []string `json:"tags,omitempty"`
	Measurement string   `json:"measurement"`
}

//TcgPcrEvent2 structure represents TCG_PCR_EVENT2 of Intel TXT spec rev16.2
type TcgPcrEvent2 struct {
	PcrIndex  uint32
	EventType uint32
	Digest    TpmlDigestValues
	EventSize uint32
	Event     []uint8
}

//TpmlDigestValues structure represents TPML_DIGEST_VALUES of Intel TXT spec rev16.2
type TpmlDigestValues struct {
	count   uint32
	digests []TpmtHA
}

//TpmtHA structure represents TPMT_HA of Intel TXT spec rev16.2
type TpmtHA struct {
	hashAlg uint16
	digest  []byte
}

//TcgPcrEvent structure represents TCG_PCR_EVENT of Intel TXT spec rev16.2
type TcgPcrEvent struct {
	PcrIndex  uint32
	EventType uint32
	Digest    [20]byte
	EventSize uint32
	Event     []uint8
}

//UefiGUID structure represents UEFI_GUID of TCG PC Client Platform Firmware Profile spec rev22
type UefiGUID struct {
	Data1 uint32
	Data2 uint16
	Data3 uint16
	Data4 [8]uint8
}

//UefiVariableData structure represents UEFI_GUID of TCG PC Client Platform Firmware Profile spec rev22
type UefiVariableData struct {
	VariableName       UefiGUID
	UnicodeNameLength  uint64
	VariableDataLength uint64
	UnicodeName        []uint16
	VariableData       []int8 // Driver or platform-specific data
}

//PfrEventDataHeader structure represents PFR_EVENT_DATA_HEADER
type PfrEventDataHeader struct { // Description
	Version    uint8  // Version# of PFR_EVENT_DATA structure
	Cpld       uint8  // CPLD# (0-based)
	EventID    uint8  // Event Identifier
	Attribute  uint8  // Extend and String Type information
	Reserved   uint32 // Reserved for future use (set to 0)
	InfoSize   uint32 // P, Size of event information in bytes
	StringSize uint32 // S, Size of event string in bytes
}

//EventNameList - define map for event name
var eventNameList = map[uint32]string{
	0x00000000: "EV_PREBOOT_CERT",
	0x00000001: "EV_POST_CODE",
	0x00000002: "EV_UNUSED",
	0x00000003: "EV_NO_ACTION",
	0x00000004: "EV_SEPARATOR",
	0x00000005: "EV_ACTION",
	0x00000006: "EV_EVENT_TAG",
	0x00000007: "EV_S_CRTM_CONTENTS",
	0x00000008: "EV_S_CRTM_VERSION",
	0x00000009: "EV_CPU_MICROCODE",
	0x0000000A: "EV_PLATFORM_CONFIG_FLAGS",
	0x0000000B: "EV_TABLE_OF_DEVICES",
	0x0000000C: "EV_COMPACT_HASH",
	0x0000000D: "EV_IPL",
	0x0000000E: "EV_IPL_PARTITION_DATA",
	0x0000000F: "EV_NONHOST_CODE",
	0x00000010: "EV_NONHOST_CONFIG",
	0x00000011: "EV_NONHOST_INFO",
	0x00000012: "EV_OMIT_BOOT_DEVICE_EVENTS",
	0x80000000: "EV_EFI_EVENT_BASE",
	0x80000001: "EV_EFI_VARIABLE_DRIVER_CONFIG",
	0x80000002: "EV_EFI_VARIABLE_BOOT",
	0x80000003: "EV_EFI_BOOT_SERVICES_APPLICATION",
	0x80000004: "EV_EFI_BOOT_SERVICES_DRIVER",
	0x80000005: "EV_EFI_RUNTIME_SERVICES_DRIVER",
	0x80000006: "EV_EFI_GPT_EVENT",
	0x80000007: "EV_EFI_ACTION",
	0x80000008: "EV_EFI_PLATFORM_FIRMWARE_BLOB",
	0x80000009: "EV_EFI_HANDOFF_TABLES",
	0x8000000A: "EV_EFI_PLATFORM_FIRMWARE_BLOB2",
	0x8000000B: "EV_EFI_HANDOFF_TABLES2",
	0x8000000C: "EV_EFI_VARIABLE_BOOT2",
	0x80000010: "EV_EFI_HCRTM_EVENT",
	0x800000E0: "EV_EFI_VARIABLE_AUTHORITY",
	0x800000E1: "EV_EFI_SPDM_FIRMWARE_BLOB",
	0x800000E2: "EV_EFI_SPDM_FIRMWARE_CONFIG",
	0x401:      "PCR_MAPPING",
	0x402:      "HASH_START",
	0x403:      "COMBINED_HASH",
	0x404:      "MLE_HASH",
	0x40a:      "BIOSAC_REG_DATA",
	0x40b:      "CPU_SCRTM_STAT",
	0x40c:      "LCP_CONTROL_HASH",
	0x40d:      "ELEMENTS_HASH",
	0x40e:      "STM_HASH",
	0x40f:      "OSSINITDATA_CAP_HASH",
	0x410:      "SINIT_PUBKEY_HASH",
	0x411:      "LCP_HASH",
	0x412:      "LCP_DETAILS_HASH",
	0x413:      "LCP_AUTHORITIES_HASH",
	0x414:      "NV_INFO_HASH",
	0x416:      "EVTYPE_KM_HASH",
	0x417:      "EVTYPE_BPM_HASH",
	0x418:      "EVTYPE_KM_INFO_HASH",
	0x419:      "EVTYPE_BPM_INFO_HASH",
	0x41a:      "EVTYPE_BOOT_POL_HASH",
	0x4ff:      "CAP_VALUE",
}

var eventLogInfo *EventLogInfo

//InitializeEventLogInfo - Function to create and intialize eventLogInfo variable
func InitializeEventLogInfo() *EventLogInfo {
	log.Trace("resource/event_log:InitializeEventLogInfo() Entering")
	defer log.Trace("resource/event_log:InitializeEventLogInfo() Leaving")
	eventLogInfo := new(EventLogInfo)
	eventLogInfo.TxtHeapBaseAddr = 0
	eventLogInfo.TxtHeapSize = 0
	eventLogInfo.UefiEventAddr = 0
	eventLogInfo.UefiEventSize = 0
	eventLogInfo.TxtEnabled = false
	return eventLogInfo
}

//GetEventLogInfo - Getter function for eventLogInfo variable
func GetEventLogInfo() *EventLogInfo {
	log.Trace("resource/event_log:GetEventLogInfo() Entering")
	defer log.Trace("resource/event_log:GetEventLogInfo() Leaving")
	if eventLogInfo == nil {
		eventLogInfo = InitializeEventLogInfo()
	}
	return eventLogInfo
}

//FetchUefiEventInfo - Function to get Uefi Events Info
func (eventLogInfo *EventLogInfo) FetchUefiEventInfo() error {

	log.Trace("resource/event_log:FetchUefiEventInfo() Entering")
	defer log.Trace("resource/event_log:FetchUefiEventInfo() Leaving")

	uefiBaseAddress := make([]byte, Uint64Size)
	uefiSize := make([]byte, Uint32Size)
	file, err := os.Open(Tpm2FilePath)
	if err != nil {
		return errors.Wrapf(err, "resource/event_log:FetchUefiEventInfo() There was an error opening %s", Tpm2FilePath)
	}
	defer file.Close()

	fileInfo, err := file.Stat()
	if err != nil {
		return errors.Wrapf(err, "resource/event_log:FetchUefiEventInfo() There was an error getting FileInfo of %s", Tpm2FilePath)
	}

	// As TPM2 file contains uefi_event_log size from offset 64-67 and uefi_event_log address from offset 68-75, so below check is for uefi_event_log Info in TPM2 file
	if fileInfo.Size() < 76 {
		secLog.Errorf("resource/event_log:FetchUefiEventInfo() UefiEventInfo missing in %s", Tpm2FilePath)
		return errors.Errorf("UefiEventInfo missing in %s", Tpm2FilePath)
	}

	_, err = file.Seek(UefiBaseOffset, io.SeekStart)
	if err != nil {
		return errors.Wrapf(err, "resource/event_log:FetchUefiEventInfo() There was an error traversing %s", Tpm2FilePath)
	}
	_, err = io.ReadFull(file, uefiBaseAddress)
	if err != nil {
		return errors.Wrapf(err, "resource/event_log:FetchUefiEventInfo() There was an error reading %s", Tpm2FilePath)
	}
	_, err = file.Seek(UefiSizeOffset, io.SeekStart)
	if err != nil {
		return errors.Wrapf(err, "resource/event_log:FetchUefiEventInfo() There was an error traversing %s", Tpm2FilePath)
	}
	_, err = io.ReadFull(file, uefiSize)
	if err != nil {
		return errors.Wrapf(err, "resource/event_log:FetchUefiEventInfo() There was an error reading %s", Tpm2FilePath)
	}

	eventLogInfo.UefiEventSize = binary.LittleEndian.Uint32(uefiSize)
	eventLogInfo.UefiEventAddr = binary.LittleEndian.Uint64(uefiBaseAddress)
	return nil
}

//FetchTxtHeapInfo - Function to fetch txt events info
func (eventLogInfo *EventLogInfo) FetchTxtHeapInfo() error {
	log.Trace("resource/event_log:FetchTxtHeapInfo() Entering")
	defer log.Trace("resource/event_log:FetchTxtHeapInfo() Leaving")

	txtHeapBaseAddr := make([]byte, Uint64Size)
	txtHeapSize := make([]byte, Uint64Size)
	file, err := os.Open(EventLogFilePath)
	if err != nil {
		return errors.Wrapf(err, "resource/event_log:FetchTxtHeapInfo() There was an error opening %s", EventLogFilePath)
	}
	defer file.Close()

	_, err = file.Seek(TxtHeapBaseOffset, io.SeekStart)
	if err != nil {
		return errors.Wrapf(err, "resource/event_log:FetchTxtHeapInfo() There was an error traversing %s", EventLogFilePath)
	}
	_, err = io.ReadFull(file, txtHeapBaseAddr)
	if err != nil {
		return errors.Wrapf(err, "resource/event_log:FetchTxtHeapInfo() There was an error reading %s", EventLogFilePath)
	}
	_, err = file.Seek(TxtHeapSizeOffset, io.SeekStart)
	if err != nil {
		return errors.Wrapf(err, "resource/event_log:FetchTxtHeapInfo() There was an error traversing %s", EventLogFilePath)
	}
	_, err = io.ReadFull(file, txtHeapSize)
	if err != nil {
		return errors.Wrapf(err, "resource/event_log:FetchTxtHeapInfo() There was an error reading %s", EventLogFilePath)
	}

	eventLogInfo.TxtHeapSize = binary.LittleEndian.Uint64(txtHeapSize)
	eventLogInfo.TxtHeapBaseAddr = binary.LittleEndian.Uint64(txtHeapBaseAddr)
	return nil
}

//UpdateTxtEventLog - Function to read txt event log address and fetch txt event data
func (eventLogInfo *EventLogInfo) UpdateTxtEventLog() error {

	log.Trace("resource/event_log:UpdateTxtEventLog() Entering")
	defer log.Trace("resource/event_log:UpdateTxtEventLog() Leaving")

	file, err := os.Open(EventLogFilePath)
	if err != nil {
		return errors.Wrapf(err, "resource/event_log:UpdateTxtEventLog() There was an error opening %s", EventLogFilePath)
	}
	defer file.Close()

	mmap, err := syscall.Mmap(int(file.Fd()), int64(eventLogInfo.TxtHeapBaseAddr), int(eventLogInfo.TxtHeapSize), syscall.PROT_READ, syscall.MAP_SHARED)
	if err != nil {
		return errors.Wrapf(err, "resource/event_log:UpdateTxtEventLog() There was an error reading TXT heap data %s", EventLogFilePath)
	}

	//Parse the txt-event log data
	biosDataSize := binary.LittleEndian.Uint64(mmap[0:])
	osMleDataSize := binary.LittleEndian.Uint64(mmap[biosDataSize:])
	if osMleDataSize <= 0 {
		secLog.Error("resource/event_log:UpdateTxtEventLog() Invalid osMleDataSize")
		return errors.New("resource/event_log:UpdateTxtEventLog() Invalid osMleDataSize")
	}

	//Read OsSinitData (Table 22. OS to SINIT Data Table) at HeapBase+BiosDataSize+OsMleDataSize+8
	osSinitVersion := binary.LittleEndian.Uint32(mmap[biosDataSize+osMleDataSize+Uint64Size:])
	if osSinitVersion >= 6 {
		log.Info("resource/event_log:UpdateTxtEventLog() OSInitData.Version = %d", osSinitVersion)
	} else {
		secLog.Error("resource/event_log:UpdateTxtEventLog() OSInitData.Version was less than 6")
		return errors.New("resource/event_log:UpdateTxtEventLog() OSInitData.Version was less than 6")
	}

	//ExtDataElement that is HEAP_EVENT_LOG_POINTER_ELEMENT2_1. ie OsSinitData.ExtDataElements[0].Type must be 0x8.
	osSinitExtType := binary.LittleEndian.Uint32(mmap[biosDataSize+osMleDataSize+Uint64Size+ExtDataElementOffset:])
	if osSinitExtType != 0x8 {
		secLog.Error("resource/event_log:UpdateTxtEventLog() OsSinitData.ExtDataElements[0].Type was not 0x8")
		return errors.New("resource/event_log:UpdateTxtEventLog() OsSinitData.ExtDataElements[0].Type was not 0x8")
	}

	//Data is parsed based on HEAP_EVENT_LOG_POINTER_ELEMENT2_1 of Intel TXT spec 16.2. Reading EventLogPointer (20 bytes)
	physicalAddress := binary.LittleEndian.Uint64(mmap[biosDataSize+osMleDataSize+Uint64Size+ExtDataElementOffset+Uint64Size:])
	allocatedEventContainerSize := binary.LittleEndian.Uint32(mmap[biosDataSize+osMleDataSize+Uint64Size+ExtDataElementOffset+Uint64Size+Uint64Size:])
	firstRecordOffset := binary.LittleEndian.Uint32(mmap[biosDataSize+osMleDataSize+Uint64Size+ExtDataElementOffset+Uint64Size+Uint64Size+Uint32Size:])
	nextRecordOffset := binary.LittleEndian.Uint32(mmap[biosDataSize+osMleDataSize+Uint64Size+ExtDataElementOffset+Uint64Size+Uint64Size+Uint32Size+Uint32Size:])

	firstEventLogOffset := (physicalAddress - eventLogInfo.TxtHeapBaseAddr) + uint64(firstRecordOffset)
	firstEventLogBuffer := bytes.NewBuffer(mmap[firstEventLogOffset:])

	//Skip TCG_PCR_EVENT(Intel TXT spec. ver. 16.2) log data and put the remaining eventlog in measureLog.json
	err = parseEventLog(firstEventLogBuffer, allocatedEventContainerSize)
	if err != nil {
		return errors.Wrap(err, "resource/event_log:UpdateTxtEventLog() Error while parsing EventLog data")
	}

	//Parse eventlog from nextRecordOffset and put in measurelog.json
	if nextRecordOffset != 0 {
		nextEventLogOffset := (physicalAddress - eventLogInfo.TxtHeapBaseAddr) + uint64(nextRecordOffset)
		nextEventLogBuffer := bytes.NewBuffer(mmap[nextEventLogOffset:])
		err = createMeasureLog(nextEventLogBuffer, allocatedEventContainerSize-uint32(nextEventLogOffset))
		if err != nil {
			return errors.Wrap(err, "resource/event_log:UpdateTxtEventLog() Error while parsing nextEventLogOffset data")
		}
	}

	//Unmap the /dev/mem buffer
	err = syscall.Munmap(mmap)
	if err != nil {
		return errors.Wrapf(err, "resource/event_log:UpdateTxtEventLog() Error while unmapping TXT heap data")
	}

	return nil
}

//ParseEventLog - Function to parse event log data from buffer
func parseEventLog(buf *bytes.Buffer, size uint32) error {

	log.Trace("resource/event_log:parseEventLog() Entering")
	defer log.Trace("resource/event_log:parseEventLog() Leaving")

	//Skip TCG_PCR_EVENT(Intel TXT spec. ver. 16.2) log data
	tcgPcrEvent := TcgPcrEvent{}
	binary.Read(buf, binary.LittleEndian, &tcgPcrEvent.PcrIndex)
	binary.Read(buf, binary.LittleEndian, &tcgPcrEvent.EventType)
	binary.Read(buf, binary.LittleEndian, &tcgPcrEvent.Digest)
	binary.Read(buf, binary.LittleEndian, &tcgPcrEvent.EventSize)
	tcgPcrEvent.Event = buf.Next(int(tcgPcrEvent.EventSize))
	err := createMeasureLog(buf, size-(tcgPcrEvent.EventSize+32))
	if err != nil {
		return errors.Wrapf(err, "resource/event_log:parseEventLog() There is an error parsing event log after skipping first one")
	}

	return nil
}

//CreateMeasureLog - Function to create PCR Measure log data for measureLog.json
func createMeasureLog(buf *bytes.Buffer, size uint32) error {

	log.Trace("resource/event_log:createMeasureLog() Entering")
	defer log.Trace("resource/event_log:createMeasureLog() Leaving")

	tcgPcrEvent2 := TcgPcrEvent2{}
	tpmlDigestValues := TpmlDigestValues{}
	var digest []byte
	var offset int64
	event501Index := 0

	for offset = 0; offset < int64(size); {

		binary.Read(buf, binary.LittleEndian, &tcgPcrEvent2.PcrIndex)
		offset = offset + Uint32Size

		if tcgPcrEvent2.PcrIndex > 23 || tcgPcrEvent2.PcrIndex < 0 {
			break
		}

		binary.Read(buf, binary.LittleEndian, &tcgPcrEvent2.EventType)
		offset = offset + Uint32Size
		eventTypeStr := fmt.Sprintf("0x%x", tcgPcrEvent2.EventType)

		binary.Read(buf, binary.LittleEndian, &tpmlDigestValues.count)
		offset = offset + Uint32Size

		//From Tpm2.0 spec: https://dox.ipxe.org/Tpm20_8h_source.html#l01081
		//It supports only 5 types of digest algorithm
		if tpmlDigestValues.count <= 0 || tpmlDigestValues.count > 5 {
			break
		}

		var hashIndex int
		eventData := make([]TpmEvent, tpmlDigestValues.count)
		pcr := make([]PcrData, tpmlDigestValues.count)

		for hashIndex = 0; hashIndex < int(tpmlDigestValues.count); hashIndex++ {

			var digestSize int
			var algID uint16
			binary.Read(buf, binary.LittleEndian, &algID)
			offset = offset + Uint16Size

			if algID == AlgSHA1 {

				digest = buf.Next(sha1.Size)
				offset = offset + int64(sha1.Size)
				digestStr := hex.EncodeToString(digest)
				eventData[hashIndex].Measurement = digestStr
				pcr[hashIndex].Bank = SHA1

			} else if algID == AlgSHA256 {

				digest = buf.Next(sha256.Size)
				offset = offset + int64(sha256.Size)
				digestStr := hex.EncodeToString(digest)
				eventData[hashIndex].Measurement = digestStr
				pcr[hashIndex].Bank = SHA256

			} else if algID == AlgSHA384 {

				digestSize = 48
				digest = buf.Next(digestSize)
				offset = offset + int64(digestSize)
				digestStr := hex.EncodeToString(digest)
				eventData[hashIndex].Measurement = digestStr
				pcr[hashIndex].Bank = SHA384

			} else if algID == AlgSHA512 {

				digest = buf.Next(sha512.Size)
				offset = offset + int64(sha512.Size)
				digestStr := hex.EncodeToString(digest)
				eventData[hashIndex].Measurement = digestStr
				pcr[hashIndex].Bank = SHA512

			} else if algID == AlgSM3_256 {

				digestSize = 32
				digest = buf.Next(digestSize)
				offset = offset + int64(digestSize)
				digestStr := hex.EncodeToString(digest)
				eventData[hashIndex].Measurement = digestStr
				pcr[hashIndex].Bank = SM3_256

			}

			eventData[hashIndex].TypeID = eventTypeStr
			pcr[hashIndex].Index = tcgPcrEvent2.PcrIndex

			//Map Event name against the specified types from the TCG PC Client Platform Firmware Profile Specification v1.5
			eventName, ok := eventNameList[tcgPcrEvent2.EventType]
			if ok {
				eventData[hashIndex].TypeName = eventName
				if eventLogInfo.TxtEnabled == true {
					eventData[hashIndex].Tags = append(eventData[hashIndex].Tags, eventName)
				}
			} else {
				//Handling of 501 Events according to spec.
				//The first and second  occurrence of 501 events is tb_policy
				//The third occurrence results in “vmlinuz”.
				//The fouth occurrence results in “initrd”.
				//The fifth occurrence results in “asset-tag”.
				//All other occurrences will be blank.

				if eventTypeStr == Event501 {
					if event501Index < 2 {
						eventData[hashIndex].TypeName = TBPolicy
						eventData[hashIndex].Tags = append(eventData[hashIndex].Tags, TBPolicy)
					} else if event501Index == 2 {
						eventData[hashIndex].TypeName = VMLinuz
						eventData[hashIndex].Tags = append(eventData[hashIndex].Tags, VMLinuz)
					} else if event501Index == 3 {
						eventData[hashIndex].TypeName = Initrd
						eventData[hashIndex].Tags = append(eventData[hashIndex].Tags, Initrd)
					} else if event501Index == 4 {
						eventData[hashIndex].TypeName = AssetTag
						eventData[hashIndex].Tags = append(eventData[hashIndex].Tags, AssetTag)
					}
				}
			}

			//After parsing of TPML_DIGEST_VALUES form (Intel TXT spec. ver. 16.2) increment the offset to read the next TCG_PCR_EVENT2
			if hashIndex+1 == int(tpmlDigestValues.count) {
				binary.Read(buf, binary.LittleEndian, &tcgPcrEvent2.EventSize)
				offset = offset + Uint32Size
				tcgPcrEvent2.Event = buf.Next(int(tcgPcrEvent2.EventSize))
				offset = offset + int64(tcgPcrEvent2.EventSize)
				if eventTypeStr == Event501 {
					event501Index++
				}

				//Adding eventlog data according to PcrEventLogs
				for index := 0; index < int(tpmlDigestValues.count); index++ {

					var tempPcrEventLog PcrEventLogs
					//Handling of Uefi Event Tag according to TCG PC Client Platform Firmware Profile Specification v1.5
					if eventLogInfo.TxtEnabled == false {
						eventData[index].Tags = getEventTag(tcgPcrEvent2.EventType, tcgPcrEvent2.Event, tcgPcrEvent2.EventSize, tcgPcrEvent2.PcrIndex)
					}

					tempPcrEventLog.Pcr = pcr[index]
					tempPcrEventLog.TpmEvents = append(tempPcrEventLog.TpmEvents, eventData[index])

					if len(eventLogInfo.FinalPcrEventLog) == 0 {
						eventLogInfo.FinalPcrEventLog = append(eventLogInfo.FinalPcrEventLog, tempPcrEventLog)
					} else {

						var flag int = 0
						for i := range eventLogInfo.FinalPcrEventLog {
							//Check pcr index and bank if already existing in database and then add eventlog data in database
							if (eventLogInfo.FinalPcrEventLog[i].Pcr.Index == pcr[index].Index) && (eventLogInfo.FinalPcrEventLog[i].Pcr.Bank == pcr[index].Bank) {
								eventLogInfo.FinalPcrEventLog[i].TpmEvents = append(eventLogInfo.FinalPcrEventLog[i].TpmEvents, eventData[index])
								flag = 1
								break
							}
						}

						if flag == 0 {
							eventLogInfo.FinalPcrEventLog = append(eventLogInfo.FinalPcrEventLog, tempPcrEventLog)
						}
					}
				}
			}
		}
	}
	return nil
}

//WriteMeasureLogFile - Write the Measure log data in measurelog.json file
func (eventLogInfo *EventLogInfo) WriteMeasureLogFile() error {

	log.Trace("resource/event_log:WriteMeasureLogFile() Entering")
	defer log.Trace("resource/event_log:WriteMeasureLogFile() Leaving")

	jsonData, err := json.Marshal(eventLogInfo.FinalPcrEventLog)
	if err != nil {
		secLog.Errorf("resource/event_log:WriteMeasureLogFile() Error while marshalling measureLog json data: %s", err.Error())
		return errors.New("resource/event_log:WriteMeasureLogFile() Error while marshalling measureLog json data")
	}

	jsonReport, err := os.OpenFile(constants.MeasureLogFilePath, os.O_WRONLY|os.O_CREATE, 0644)
	if err != nil {
		return errors.Wrapf(err, "resource/event_log:WriteMeasureLogFile() Error while opening %s", constants.MeasureLogFilePath)
	}

	jsonReport.Write(jsonData)
	jsonReport.Close()
	return nil
}

//UpdateUefiEventLog - Function to update uefi event log data
func (eventLogInfo *EventLogInfo) UpdateUefiEventLog() error {

	log.Trace("resource/event_log:UpdateUefiEventLog() Entering")
	defer log.Trace("resource/event_log:UpdateUefiEventLog() Leaving")

	eventLogBuffer := make([]byte, eventLogInfo.UefiEventSize)
	_, err := os.Stat(EventLogFilePath)
	if err != nil {
		return errors.Wrapf(err, "resource/event_log:UpdateUefiEventLog() Error while checking the existence of %s", EventLogFilePath)
	}

	file, err := os.Open(EventLogFilePath)
	if err != nil {
		return errors.Wrapf(err, "resource/event_log:UpdateUefiEventLog() There was an error opening %s", EventLogFilePath)
	}
	defer file.Close()

	//Go to Uefi Event Log Address in /dev/mem
	_, err = file.Seek(int64(eventLogInfo.UefiEventAddr), io.SeekStart)
	if err != nil {
		return errors.Wrapf(err, "resource/event_log:UpdateUefiEventLog() There was an error traversing %s", EventLogFilePath)
	}
	_, err = io.ReadFull(file, eventLogBuffer)
	if err != nil {
		return errors.Wrapf(err, "resource/event_log:UpdateUefiEventLog() There was an error reading %s", EventLogFilePath)
	}

	buf := bytes.NewBuffer(eventLogBuffer)
	err = parseEventLog(buf, eventLogInfo.UefiEventSize)
	if err != nil {
		return errors.Wrap(err, "resource/event_log:UpdateUefiEventLog() Error while parsing EventLog data")
	}

	return nil
}

//GetEventTag - Function to get tag for uefi events
func getEventTag(eventType uint32, eventData []byte, eventSize uint32, pcrIndex uint32) []string {

	log.Trace("resource/event_log:getEventTag() Entering")
	defer log.Trace("resource/event_log:getEventTag() Leaving")
	//Handling EV_EFI_VARIABLE_DRIVER_CONFIG, EV_EFI_VARIABLE_BOOT, EV_EFI_VARIABLE_BOOT2 and EV_EFI_VARIABLE_AUTHORITY as all
	//These events are associated with UEFI_VARIABLE_DATA
	if eventType == Event80000001 || eventType == Event80000002 || eventType == Event8000000C || eventType == Event800000E0 {

		var uefiVariableData UefiVariableData
		var unicodeName []byte
		var index, index1 int
		buf := bytes.NewBuffer(eventData)
		binary.Read(buf, binary.LittleEndian, &uefiVariableData.VariableName)
		binary.Read(buf, binary.LittleEndian, &uefiVariableData.UnicodeNameLength)
		binary.Read(buf, binary.LittleEndian, &uefiVariableData.VariableDataLength)
		unicodeName = buf.Next(int(uefiVariableData.UnicodeNameLength * 2))

		runeChar1 := make([]rune, uefiVariableData.UnicodeNameLength)
		for index = 0; index1 < int((uefiVariableData.UnicodeNameLength * 2)); index++ {
			runeChar1[index] = rune(unicodeName[index1])
			index1 = index1 + 2
		}

		return []string{string(runeChar1)}
	}
	//Handling EV_EFI_PLATFORM_FIRMWARE_BLOB2 and EV_S_CRTM_CONTENTS as both are associated with UEFI_PLATFORM_FIRMWARE_BLOB2
	//0x8000000B is EV_EFI_HANDOFF_TABLES2 but the description starts from second byte similar to UEFI_PLATFORM_FIRMWARE_BLOB2 so handling here.
	if eventType == Event8000000A || eventType == Event00000007 || eventType == Event8000000B {
		var blobDescriptionSize uint8
		buf := bytes.NewBuffer(eventData)
		binary.Read(buf, binary.LittleEndian, &blobDescriptionSize)
		blobDesc := buf.Next(int(blobDescriptionSize))
		tagName := fmt.Sprintf("%s", blobDesc)
		return []string{tagName}
	}
	//Handling EV_POST_CODE, EV_ACTION, EV_EFI_ACTION, EV_PLATFORM_CONFIG_FLAGS, EV_COMPACT_HASH(Only when PCR6),
	//EV_OMIT_BOOT_DEVICE_EVENTS and EV_EFI_HCRTM_EVENT all these events as the event data is a String.
	if eventType == Event00000001 || eventType == Event00000005 || eventType == Event80000007 || eventType == Event0000000A || (eventType == Event0000000C && pcrIndex == 0x6) || eventType == Event00000012 || eventType == Event80000010 {
		buf := bytes.NewBuffer(eventData)
		postCode := buf.Next(int(eventSize))
		tagName := fmt.Sprintf("%s", postCode)
		return []string{tagName}
	}
	//Handling EV_NONHOST_CONFIG and EV_NONHOST_INFO as PFR events as per the design
	if eventType == Event00000010 || eventType == Event00000011 {
		var pfrEventSize uint32
		var pfrHeader PfrEventDataHeader

		//As per PFR TPM Event log Design, following are the information about the valid attribute value.
		//Bit1-0 Extend information
		//	00 Extend whole PFR_EVENT_DATA
		//	01 Extend only PFR_EVENT_DATA.Info
		//	02 Extend only PFR_EVENT_DATA.String
		//	03 Reserved for future use
		//Bit6-2 Reserved for future use (set to 0)
		//Bit-7 String Type: 0/1, ASCII/Unicode String

		//Binary representation of valid PFR attribute values are mentioned below
		//00000000 - 0x0, 00000001 - 0x1, 00000010 - 0x2, 10000000 - 0x80, 10000001 - 0x81, 10000010 - 0x82
		validPFRAttribute := [6]uint8{0x0, 0x1, 0x2, 0x80, 0x81, 0x82}

		buf := bytes.NewBuffer(eventData)
		binary.Read(buf, binary.LittleEndian, &pfrHeader)
		//PFR_EVENT_DATA_HEADER includes four UINT8 and three UINT32 variables. PFR_EVENT_DATA includes PFR_EVENT_DATA_HEADER and InfoSize + StringSize
		pfrEventSize = (Uint8Size * 4) + (Uint32Size * 3) + uint32(pfrHeader.InfoSize) + uint32(pfrHeader.StringSize)
		//Checking the event size from event log structure and pfr event size is same or not
		if eventSize != pfrEventSize {
			return []string{}
		}

		//Checking the PCR index, version and event id are valid as mentioned in HLD
		if (pcrIndex != 0 && pcrIndex != 1 && pcrIndex != 7) || pfrHeader.Version != 0x01 || (pfrHeader.EventID <= 1 || pfrHeader.EventID >= 6) {
			return []string{}
		}

		//Checking the PFR attribute is valid or not as mentioned in the PFR design
		for index, pfrAttr := range validPFRAttribute {
			if pfrHeader.Attribute == pfrAttr {
				break
			}
			if index == 5 {
				return []string{}
			}
		}

		if pfrHeader.InfoSize != 0 {
			_ = buf.Next(int(pfrHeader.InfoSize))
		}

		if pfrHeader.StringSize != 0 {
			var tagName string
			pfrString := buf.Next(int(pfrHeader.StringSize))
			if len(pfrString) > 0 {
				tagName = fmt.Sprintf("%s", pfrString)
			}
			//Checking the string is starts with PFR/pfr as mentioned in HLD
			if (pfrString[0] == 'P' && pfrString[1] == 'F' && pfrString[2] == 'R') || (pfrString[0] == 'p' && pfrString[1] == 'f' && pfrString[2] == 'r') {
				return []string{string(tagName)}
			}
		}
	}

	return []string{}
}

//UpdateAppEventLog - Function to parse and update  Application Event Log
func (eventLogInfo *EventLogInfo) UpdateAppEventLog() error {
	log.Trace("resource/event_log:UpdateAppEventLog() Entering")
	defer log.Trace("resource/event_log:UpdateAppEventLog() Leaving")

	_, err := os.Stat(AppEventFilePath)
	if err != nil {
		return errors.Wrapf(err, "resource/event_log:UpdateAppEventLog() Error while checking the existence of %s", AppEventFilePath)
	}

	file, err := os.Open(AppEventFilePath)
	if err != nil {
		return errors.Wrapf(err, "resource/event_log:UpdateAppEventLog() There was an error opening %s", AppEventFilePath)
	}
	defer file.Close()

	var tempAppEventLogs []PcrEventLogs

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		//Read each line of data from pcr_event_log file and update in measureLog.json
		line := scanner.Text()
		Array := strings.Split(line, "	")

		var tempEventData TpmEvent
		var tempAppEventLog PcrEventLogs

		//Parse the event log data according to sha bank, pcr index, event name, hash value
		tempAppEventLog.Pcr.Bank = Array[0]
		index, _ := strconv.Atoi(Array[1])
		tempAppEventLog.Pcr.Index = uint32(index)

		tempEventData.TypeID = AppEventTypeID
		tempEventData.TypeName = AppEventName
		tempEventData.Tags = append(tempEventData.Tags, Array[2])
		tempEventData.Measurement = Array[3]

		tempAppEventLog.TpmEvents = append(tempAppEventLog.TpmEvents, tempEventData)

		flag := 0

		if tempAppEventLogs != nil {
			for i := range tempAppEventLogs {
				if (tempAppEventLogs[i].Pcr.Index == tempAppEventLog.Pcr.Index) && (tempAppEventLogs[i].Pcr.Bank == tempAppEventLog.Pcr.Bank) {
					tempAppEventLogs[i].TpmEvents = append(tempAppEventLogs[i].TpmEvents, tempEventData)
					flag = 1
					break
				}
			}
		}

		if flag == 0 {
			tempAppEventLogs = append(tempAppEventLogs, tempAppEventLog)
		}
	}

	//Add all Application event log data in finalEventLog Array
	for i := range tempAppEventLogs {
		eventLogInfo.FinalPcrEventLog = append(eventLogInfo.FinalPcrEventLog, tempAppEventLogs[i])
	}

	return nil
}
