/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package eventlog

import (
	"bufio"
	"os"
	"strconv"
	"strings"

	"github.com/pkg/errors"
)

// UpdateAppEventLog - Function to parse and update Application Event Log
func (eventLog *eventLogInfo) updateAppEventLog(appEventFilePath string) error {
	log.Trace("eventlog/collect_application_event:updateAppEventLog() Entering")
	defer log.Trace("eventlog/collect_application_event:updateAppEventLog() Leaving")

	if _, err := os.Stat(appEventFilePath); os.IsNotExist(err) {
		return errors.Wrapf(err, "eventlog/collect_application_event:updateAppEventLog() %s file does not exist", appEventFilePath)
	}

	file, err := os.Open(appEventFilePath)
	if err != nil {
		return errors.Wrapf(err, "eventlog/collect_application_event:updateAppEventLog() There was an error opening %s", appEventFilePath)
	}
	defer func() {
		derr := file.Close()
		if derr != nil {
			log.WithError(derr).Errorf("eventlog/collect_application_event:updateAppEventLog() There was an error closing %s", appEventFilePath)
		}
	}()

	var tempAppEventLogs []PcrEventLog
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		var tempEventData TpmEvent
		var tempAppEventLog PcrEventLog
		// Read each line of data from pcr_event_log file, parse it in array by splitting with spaces
		line := scanner.Text()
		array := strings.Split(line, "	")
		// Parse the event log data according to sha bank, pcr index, event name, hash value
		tempAppEventLog.Pcr.Bank = array[0]
		index, err := strconv.Atoi(array[1])
		if err != nil {
			return errors.Wrap(err, "eventlog/collect_application_event:updateAppEventLog() There was an error while converting string to integer")
		}

		tempAppEventLog.Pcr.Index = uint32(index)
		tempEventData.TypeID = AppEventTypeID
		tempEventData.TypeName = AppEventName
		tempEventData.Tags = append(tempEventData.Tags, array[2])
		tempEventData.Measurement = array[3]
		tempAppEventLog.TpmEvents = append(tempAppEventLog.TpmEvents, tempEventData)

		// Flag is used to check if same pcr index and pcr bank is available in existing array
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

	// Add all Application event log data in final EventLog Array
	for i := range tempAppEventLogs {
		eventLog.FinalPcrEventLog = append(eventLog.FinalPcrEventLog, tempAppEventLogs[i])
	}

	return nil
}
