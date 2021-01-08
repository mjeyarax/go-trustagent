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

	"github.com/pkg/errors"
)

// FetchUefiEventInfo - Function to get Uefi Events Info
func (eventLog *eventLogInfo) fetchUefiEventInfo(tpm2FilePath string) error {
	log.Trace("eventlog/collect_uefi_event:fetchUefiEventInfo() Entering")
	defer log.Trace("eventlog/collect_uefi_event:fetchUefiEventInfo() Leaving")

	tpm2Sig := make([]byte, Uint32Size)
	tpm2len := make([]byte, Uint32Size)
	uefiEventAddr := make([]byte, Uint64Size)
	uefiEventSize := make([]byte, Uint32Size)
	if _, err := os.Stat(tpm2FilePath); os.IsNotExist(err) {
		return errors.Wrapf(err, "eventlog/collect_uefi_event:fetchUefiEventInfo() %s file does not exist", tpm2FilePath)
	}

	file, err := os.Open(tpm2FilePath)
	if err != nil {
		return errors.Wrapf(err, "eventlog/collect_uefi_event:fetchUefiEventInfo() There was an error opening %s", tpm2FilePath)
	}
	defer func() {
		derr := file.Close()
		if derr != nil {
			log.WithError(derr).Errorf("eventlog/collect_uefi_event:fetchUefiEventInfo() There was an error closing %s", tpm2FilePath)
		}
	}()

	// Validate TPM2 file signature
	_, err = io.ReadFull(file, tpm2Sig)
	if err != nil {
		return errors.Wrapf(err, "eventlog/collect_uefi_event:fetchUefiEventInfo() There was an error reading TPM2 Signature from %s", tpm2FilePath)
	}

	tpm2Signature := string(tpm2Sig)
	if Tpm2Signature != tpm2Signature {
		return errors.Errorf("eventlog/collect_uefi_event:fetchUefiEventInfo() Invalid TPM2 Signature in %s", tpm2FilePath)
	}

	// Validate TPM2 file length
	_, err = io.ReadFull(file, tpm2len)
	if err != nil {
		return errors.Wrapf(err, "eventlog/collect_uefi_event:fetchUefiEventInfo() There was an error reading TPM2 File Length from %s", tpm2FilePath)
	}

	tpm2FileLength := binary.LittleEndian.Uint32(tpm2len)
	if tpm2FileLength < Tpm2FileLength {
		return errors.Errorf("eventlog/collect_uefi_event:fetchUefiEventInfo() UEFI Event Info missing in %s", tpm2FilePath)
	}

	_, err = file.Seek(UefiBaseOffset, io.SeekStart)
	if err != nil {
		return errors.Wrapf(err, "eventlog/collect_uefi_event:fetchUefiEventInfo() There was an error traversing %s for UEFI Base Offset", tpm2FilePath)
	}

	_, err = io.ReadFull(file, uefiEventAddr)
	if err != nil {
		return errors.Wrapf(err, "eventlog/collect_uefi_event:fetchUefiEventInfo() There was an error reading UEFI Event Address from %s", tpm2FilePath)
	}

	_, err = file.Seek(UefiSizeOffset, io.SeekStart)
	if err != nil {
		return errors.Wrapf(err, "eventlog/collect_uefi_event:fetchUefiEventInfo() There was an error traversing %s for UEFI Size Offset", tpm2FilePath)
	}

	_, err = io.ReadFull(file, uefiEventSize)
	if err != nil {
		return errors.Wrapf(err, "eventlog/collect_uefi_event:fetchUefiEventInfo() There was an error reading UEFI Event Size from %s", tpm2FilePath)
	}

	eventLog.UefiEventSize = binary.LittleEndian.Uint32(uefiEventSize)
	eventLog.UefiEventAddr = binary.LittleEndian.Uint64(uefiEventAddr)
	return nil
}

// UpdateUefiEventLog - Function to update uefi event log data
func (eventLog *eventLogInfo) updateUefiEventLog(eventLogFilePath string) error {
	log.Trace("eventlog/collect_uefi_event:updateUefiEventLog() Entering")
	defer log.Trace("eventlog/collect_uefi_event:updateUefiEventLog() Leaving")

	eventLogBuffer := make([]byte, eventLog.UefiEventSize)
	if _, err := os.Stat(eventLogFilePath); os.IsNotExist(err) {
		return errors.Wrapf(err, "eventlog/collect_uefi_event:updateUefiEventLog() %s file does not exist", eventLogFilePath)
	}

	file, err := os.Open(eventLogFilePath)
	if err != nil {
		return errors.Wrapf(err, "eventlog/collect_uefi_event:updateUefiEventLog() There was an error opening %s", eventLogFilePath)
	}
	defer func() {
		derr := file.Close()
		if derr != nil {
			log.WithError(derr).Errorf("eventlog/collect_uefi_event:updateUefiEventLog() There was an error closing %s", eventLogFilePath)
		}
	}()

	// Go to Uefi Event Log Address in /dev/mem
	_, err = file.Seek(int64(eventLog.UefiEventAddr), io.SeekStart)
	if err != nil {
		return errors.Wrapf(err, "eventlog/collect_uefi_event:updateUefiEventLog() There was an error traversing %s for UEFI Event Address", eventLogFilePath)
	}

	_, err = io.ReadFull(file, eventLogBuffer)
	if err != nil {
		return errors.Wrapf(err, "eventlog/collect_uefi_event:updateUefiEventLog() There was an error reading UEFI Event Log from %s", eventLogFilePath)
	}

	buf := bytes.NewBuffer(eventLogBuffer)
	err = eventLog.parseEventLog(buf, eventLog.UefiEventSize)
	if err != nil {
		return errors.Wrap(err, "eventlog/collect_uefi_event:updateUefiEventLog() There was an error while parsing UEFI Event Log Data")
	}

	return nil
}
