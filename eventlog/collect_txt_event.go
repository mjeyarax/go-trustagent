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

// FetchTxtHeapInfo - Function to fetch txt events info
func (eventLog *eventLogInfo) fetchTxtHeapInfo(eventLogFilePath string) error {
	log.Trace("eventlog/collect_txt_event:fetchTxtHeapInfo() Entering")
	defer log.Trace("eventlog/collect_txt_event:fetchTxtHeapInfo() Leaving")

	txtHeapBaseAddr := make([]byte, Uint64Size)
	txtHeapSize := make([]byte, Uint64Size)
	if _, err := os.Stat(eventLogFilePath); os.IsNotExist(err) {
		return errors.Wrapf(err, "eventlog/collect_txt_event:fetchTxtHeapInfo() %s file does not exist", eventLogFilePath)
	}

	file, err := os.Open(eventLogFilePath)
	if err != nil {
		return errors.Wrapf(err, "eventlog/collect_txt_event:fetchTxtHeapInfo() There was an error opening %s", eventLogFilePath)
	}
	defer func() {
		derr := file.Close()
		if derr != nil {
			log.WithError(derr).Error("eventlog/collect_txt_event:fetchTxtHeapInfo() Error closing file")
		}
	}()

	_, err = file.Seek(TxtHeapBaseOffset, io.SeekStart)
	if err != nil {
		return errors.Wrapf(err, "eventlog/collect_txt_event:fetchTxtHeapInfo() There was an error traversing %s", eventLogFilePath)
	}

	_, err = io.ReadFull(file, txtHeapBaseAddr)
	if err != nil {
		return errors.Wrapf(err, "eventlog/collect_txt_event:fetchTxtHeapInfo() There was an error reading %s", eventLogFilePath)
	}

	_, err = file.Seek(TxtHeapSizeOffset, io.SeekStart)
	if err != nil {
		return errors.Wrapf(err, "eventlog/collect_txt_event:fetchTxtHeapInfo() There was an error traversing %s", eventLogFilePath)
	}

	_, err = io.ReadFull(file, txtHeapSize)
	if err != nil {
		return errors.Wrapf(err, "eventlog/collect_txt_event:fetchTxtHeapInfo() There was an error reading %s", eventLogFilePath)
	}

	eventLog.TxtHeapSize = binary.LittleEndian.Uint64(txtHeapSize)
	eventLog.TxtHeapBaseAddr = binary.LittleEndian.Uint64(txtHeapBaseAddr)
	return nil
}

// UpdateTxtEventLog - Function to read txt event log address and fetch txt event data
func (eventLog *eventLogInfo) updateTxtEventLog(eventLogFilePath string) error {
	log.Trace("eventlog/collect_txt_event:updateTxtEventLog() Entering")
	defer log.Trace("eventlog/collect_txt_event:updateTxtEventLog() Leaving")

	if _, err := os.Stat(eventLogFilePath); os.IsNotExist(err) {
		return errors.Wrapf(err, "eventlog/collect_txt_event:updateTxtEventLog() %s file does not exist", eventLogFilePath)
	}

	file, err := os.Open(eventLogFilePath)
	if err != nil {
		return errors.Wrapf(err, "eventlog/collect_txt_event:updateTxtEventLog() There was an error opening %s", eventLogFilePath)
	}
	defer func() {
		derr := file.Close()
		if derr != nil {
			log.WithError(derr).Error("eventlog/collect_txt_event:updateTxtEventLog() Error closing file")
		}
	}()

	mmap, err := syscall.Mmap(int(file.Fd()), int64(eventLog.TxtHeapBaseAddr), int(eventLog.TxtHeapSize), syscall.PROT_READ, syscall.MAP_SHARED)
	if err != nil {
		return errors.Wrapf(err, "eventlog/collect_txt_event:updateTxtEventLog() There was an error reading TXT heap data %s", eventLogFilePath)
	}

	// Parse the txt-event log data
	biosDataSize := binary.LittleEndian.Uint64(mmap[0:])
	osMleDataSize := binary.LittleEndian.Uint64(mmap[biosDataSize:])
	if osMleDataSize <= 0 {
		return errors.New("eventlog/collect_txt_event:updateTxtEventLog() Invalid osMleDataSize")
	}

	// Read OsSinitData (Table 22. OS to SINIT Data Table) at HeapBase+BiosDataSize+OsMleDataSize+8
	osSinitVersion := binary.LittleEndian.Uint32(mmap[biosDataSize+osMleDataSize+Uint64Size:])
	if osSinitVersion >= 6 {
		log.Infof("eventlog/collect_txt_event:updateTxtEventLog() OSInitData.Version = %d", osSinitVersion)
	} else {
		return errors.New("eventlog/collect_txt_event:updateTxtEventLog() OSInitData.Version was less than 6")
	}

	// ExtDataElement that is HEAP_EVENT_LOG_POINTER_ELEMENT2_1. ie OsSinitData.ExtDataElements[0].Type must be 0x8.
	osSinitExtType := binary.LittleEndian.Uint32(mmap[biosDataSize+osMleDataSize+Uint64Size+ExtDataElementOffset:])
	if osSinitExtType != 0x8 {
		return errors.New("eventlog/collect_txt_event:updateTxtEventLog() OsSinitData.ExtDataElements[0].Type was not 0x8")
	}

	// Data is parsed based on HEAP_EVENT_LOG_POINTER_ELEMENT2_1 of Intel TXT spec 16.2. Reading EventLogPointer (20 bytes)
	physicalAddress := binary.LittleEndian.Uint64(mmap[biosDataSize+osMleDataSize+Uint64Size+ExtDataElementOffset+Uint64Size:])
	allocatedEventContainerSize := binary.LittleEndian.Uint32(mmap[biosDataSize+osMleDataSize+Uint64Size+ExtDataElementOffset+Uint64Size+Uint64Size:])
	firstRecordOffset := binary.LittleEndian.Uint32(mmap[biosDataSize+osMleDataSize+Uint64Size+ExtDataElementOffset+Uint64Size+Uint64Size+Uint32Size:])
	nextRecordOffset := binary.LittleEndian.Uint32(mmap[biosDataSize+osMleDataSize+Uint64Size+ExtDataElementOffset+Uint64Size+Uint64Size+Uint32Size+Uint32Size:])
	firstEventLogOffset := (physicalAddress - eventLog.TxtHeapBaseAddr) + uint64(firstRecordOffset)
	firstEventLogBuffer := bytes.NewBuffer(mmap[firstEventLogOffset:])

	// Skip TCG_PCR_EVENT(Intel TXT spec. ver. 16.2) log data and put the remaining eventlog in measure-log.json
	err = parseEventLog(firstEventLogBuffer, allocatedEventContainerSize)
	if err != nil {
		return errors.Wrap(err, "eventlog/collect_txt_event:updateTxtEventLog() Error while parsing EventLog data")
	}

	// Parse eventlog from nextRecordOffset and put in measure-log.json
	if nextRecordOffset != 0 {
		nextEventLogOffset := (physicalAddress - eventLog.TxtHeapBaseAddr) + uint64(nextRecordOffset)
		nextEventLogBuffer := bytes.NewBuffer(mmap[nextEventLogOffset:])
		err = createMeasureLog(nextEventLogBuffer, allocatedEventContainerSize-uint32(nextEventLogOffset))
		if err != nil {
			return errors.Wrap(err, "eventlog/collect_txt_event:updateTxtEventLog() Error while parsing nextEventLogOffset data")
		}
	}

	// Unmap the /dev/mem buffer
	err = syscall.Munmap(mmap)
	if err != nil {
		return errors.Wrap(err, "eventlog/collect_txt_event:updateTxtEventLog() Error while unmapping TXT heap data")
	}

	return nil
}
