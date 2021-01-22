/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package eventlog

import (
	commLog "intel/isecl/lib/common/v3/log"
)

// PcrEventLog structure is used to hold complete events log info
type PcrEventLog struct {
	Pcr       PcrData    `json:"pcr"`
	TpmEvents []TpmEvent `json:"tpm_events"`
}

// PcrData structure is used to hold pcr info
type PcrData struct {
	Index uint32 `json:"index"`
	Bank  string `json:"bank"`
}

// TpmEvent structure is used to hold Tpm Event Info
type TpmEvent struct {
	TypeID      string   `json:"type_id"`
	TypeName    string   `json:"type_name,omitempty"`
	Tags        []string `json:"tags,omitempty"`
	Measurement string   `json:"measurement"`
}

// EventLogFiles structure is used to hold the eventlog files Path
type EventLogFiles struct {
	DevMemFilePath   string
	Tpm2FilePath     string
	AppEventFilePath string
}

// EventLogParser - Public interface for collecting eventlog data
type EventLogParser interface {
	GetEventLogs() ([]PcrEventLog, error)
}

var log = commLog.GetDefaultLogger()
var secLog = commLog.GetSecurityLogger()

// NewEventLogParser returns an instance of EventLogFiles
func NewEventLogParser(devMemFilePath string, tpm2FilePath string, appEventFilePath string) EventLogParser {
	log.Trace("eventlog/event_log:NewEventLogParser() Entering")
	defer log.Trace("eventlog/event_log:NewEventLogParser() Leaving")

	return &EventLogFiles{
		DevMemFilePath:   devMemFilePath,
		Tpm2FilePath:     tpm2FilePath,
		AppEventFilePath: appEventFilePath,
	}
}

// GetEventLogs extracts the eventlogs data and returns these for serialization of array to constants.MeasureLogFilePath
func (evtLogFile *EventLogFiles) GetEventLogs() ([]PcrEventLog, error) {
	log.Trace("eventlog/event_log:GetEventLogs() Entering")
	defer log.Trace("eventlog/event_log:GetEventLogs() Leaving")

	var finalPcrEventLog []PcrEventLog
	uefiEventLogs, err := getUefiEventLog(evtLogFile.Tpm2FilePath, evtLogFile.DevMemFilePath)
	if err != nil {
		log.WithError(err).Error("eventlog/event_log:GetEventLogs() There was an error while getting UEFI Event Log")
	} else {
		// Add all Uefi event log data in final Event Log Array
		finalPcrEventLog = append(finalPcrEventLog, uefiEventLogs...)
	}

	txtEventLogs, err := getTxtEventLog(evtLogFile.DevMemFilePath, TxtHeapBaseOffset, TxtHeapSizeOffset)
	if err != nil {
		log.WithError(err).Error("eventlog/event_log:GetEventLogs() There was an error while getting TXT Event Log")
	} else {
		// Add all TXT event log data in final Event Log Array
		finalPcrEventLog = append(finalPcrEventLog, txtEventLogs...)
	}

	appEventLogs, err := getAppEventLog(evtLogFile.AppEventFilePath)
	if err != nil {
		log.WithError(err).Error("eventlog/event_log:GetEventLogs() There was an error while getting Application Event Log")
	} else {
		// Add all Application event log data in final Event Log Array
		finalPcrEventLog = append(finalPcrEventLog, appEventLogs...)
	}

	return finalPcrEventLog, nil
}
