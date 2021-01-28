/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package eventlog

import (
	"bytes"
	"encoding/binary"
	"io"
	"os"
	"syscall"

	"github.com/pkg/errors"
)

// GetTxtEventLog - Function to get TXT Events Log
func getTxtEventLog(devMemFilePath string, txtHeapBaseOffset int64, txtHeapSizeOffset int64) ([]PcrEventLog, error) {
	log.Trace("eventlog/collect_txt_event:getTxtEventLog() Entering")
	defer log.Trace("eventlog/collect_txt_event:getTxtEventLog() Leaving")

	txtHeapBaseAddr := make([]byte, Uint64Size)
	txtHeapSize := make([]byte, Uint64Size)
	if _, err := os.Stat(devMemFilePath); os.IsNotExist(err) {
		return nil, errors.Wrapf(err, "eventlog/collect_txt_event:getTxtEventLog() %s file does not exist", devMemFilePath)
	}

	file, err := os.Open(devMemFilePath)
	if err != nil {
		return nil, errors.Wrapf(err, "eventlog/collect_txt_event:getTxtEventLog() There was an error opening %s", devMemFilePath)
	}
	defer func() {
		derr := file.Close()
		if derr != nil {
			log.WithError(derr).Errorf("eventlog/collect_txt_event:getTxtEventLog() There was an error closing %s", devMemFilePath)
		}
	}()

	_, err = file.Seek(txtHeapBaseOffset, io.SeekStart)
	if err != nil {
		return nil, errors.Wrapf(err, "eventlog/collect_txt_event:getTxtEventLog() There was an error traversing %s for TXT Heap Base Offset", devMemFilePath)
	}

	_, err = io.ReadFull(file, txtHeapBaseAddr)
	if err != nil {
		return nil, errors.Wrapf(err, "eventlog/collect_txt_event:getTxtEventLog() There was an error reading TXT Heap Base Address from %s", devMemFilePath)
	}

	_, err = file.Seek(txtHeapSizeOffset, io.SeekStart)
	if err != nil {
		return nil, errors.Wrapf(err, "eventlog/collect_txt_event:getTxtEventLog() There was an error traversing %s for TXT Heap Size Offset", devMemFilePath)
	}

	_, err = io.ReadFull(file, txtHeapSize)
	if err != nil {
		return nil, errors.Wrapf(err, "eventlog/collect_txt_event:getTxtEventLog() There was an error reading TXT Heap Size from %s", devMemFilePath)
	}

	txtHeapSizeLE := binary.LittleEndian.Uint64(txtHeapSize)
	txtHeapBaseAddrLE := binary.LittleEndian.Uint64(txtHeapBaseAddr)
	mmap, err := syscall.Mmap(int(file.Fd()), int64(txtHeapBaseAddrLE), int(txtHeapSizeLE), syscall.PROT_READ, syscall.MAP_SHARED)
	if err != nil {
		return nil, errors.Wrapf(err, "eventlog/collect_txt_event:getTxtEventLog() There was an error reading TXT Heap Data from %s", devMemFilePath)
	}
	defer func() {
		// Unmap the /dev/mem buffer
		if mmap != nil {
			derr := syscall.Munmap(mmap)
			if derr != nil {
				log.WithError(derr).Error(derr, "eventlog/collect_txt_event:getTxtEventLog() There was an error while unmapping TXT Heap Data")
			}
		}
	}()

	// Traverse upto the txt-event log starting Point
	biosDataSize := binary.LittleEndian.Uint64(mmap[0:])
	osMleDataSize := binary.LittleEndian.Uint64(mmap[biosDataSize:])
	if osMleDataSize <= 0 {
		return nil, errors.New("eventlog/collect_txt_event:getTxtEventLog() Invalid osMleDataSize")
	}

	// Read OsSinitData (Table 22. OS to SINIT Data Table) at HeapBase+BiosDataSize+OsMleDataSize+8
	osSinitVersion := binary.LittleEndian.Uint32(mmap[biosDataSize+osMleDataSize+Uint64Size:])
	if osSinitVersion >= 6 {
		log.Infof("eventlog/collect_txt_event:getTxtEventLog() OSInitData.Version = %d", osSinitVersion)
	} else {
		return nil, errors.New("eventlog/collect_txt_event:getTxtEventLog() OSInitData.Version was less than 6")
	}

	// ExtDataElement that is HEAP_EVENT_LOG_POINTER_ELEMENT2_1. ie OsSinitData.ExtDataElements[0].Type must be 0x8.
	osSinitExtType := binary.LittleEndian.Uint32(mmap[biosDataSize+osMleDataSize+Uint64Size+ExtDataElementOffset:])
	if osSinitExtType != 0x8 {
		return nil, errors.New("eventlog/collect_txt_event:getTxtEventLog() OsSinitData.ExtDataElements[0].Type was not 0x8")
	}

	// Data is parsed based on HEAP_EVENT_LOG_POINTER_ELEMENT2_1 of Intel TXT spec 16.2. Reading EventLogPointer (20 bytes)
	physicalAddress := binary.LittleEndian.Uint64(mmap[biosDataSize+osMleDataSize+Uint64Size+ExtDataElementOffset+Uint64Size:])
	allocatedEventContainerSize := binary.LittleEndian.Uint32(mmap[biosDataSize+osMleDataSize+Uint64Size+ExtDataElementOffset+Uint64Size+Uint64Size:])
	firstRecordOffset := binary.LittleEndian.Uint32(mmap[biosDataSize+osMleDataSize+Uint64Size+ExtDataElementOffset+Uint64Size+Uint64Size+Uint32Size:])
	nextRecordOffset := binary.LittleEndian.Uint32(mmap[biosDataSize+osMleDataSize+Uint64Size+ExtDataElementOffset+Uint64Size+Uint64Size+Uint32Size+Uint32Size:])
	firstEventLogOffset := (physicalAddress - txtHeapBaseAddrLE) + uint64(firstRecordOffset)
	firstEventLogBuffer := bytes.NewBuffer(mmap[firstEventLogOffset:])

	// Parse and skip TCG_PCR_EVENT(Intel TXT spec. ver. 16.2) from event-log buffer
	txtEventBuf, txtEventSize, err := parseTcgSpecEvent(firstEventLogBuffer, allocatedEventContainerSize)
	if err != nil {
		return nil, errors.Wrap(err, "eventlog/collect_txt_event:getTxtEventLog() There was an error while parsing TXT Event Log Data")
	}

	var txtEventLogs []PcrEventLog
	txtEventLogs, err = createMeasureLog(txtEventBuf, txtEventSize, txtEventLogs, true)
	if err != nil {
		return nil, errors.Wrap(err, "eventlog/collect_uefi_event:getTxtEventLog() There was an error while creating measure-log data for first set of TXT Events")
	}

	// Parse eventlog from nextRecordOffset and put in measure-log.json
	if nextRecordOffset != 0 {
		nextEventLogOffset := (physicalAddress - txtHeapBaseAddrLE) + uint64(nextRecordOffset)
		nextEventLogBuffer := bytes.NewBuffer(mmap[nextEventLogOffset:])
		txtEventLogs, err = createMeasureLog(nextEventLogBuffer, allocatedEventContainerSize-uint32(nextEventLogOffset), txtEventLogs, true)
		if err != nil {
			return nil, errors.Wrap(err, "eventlog/collect_txt_event:getTxtEventLog() There was an error while creating measure-log for next set of TXT Events")
		}
	}

	return txtEventLogs, nil
}
