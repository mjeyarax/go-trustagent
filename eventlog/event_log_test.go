/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package eventlog

import (
	"reflect"
	"testing"
)

func TestEventLogFiles_GetEventLogs(t *testing.T) {
	type fields struct {
		DevMemFilePath   string
		Tpm2FilePath     string
		AppEventFilePath string
	}
	tests := []struct {
		name    string
		fields  fields
		want    []PcrEventLog
		wantErr bool
	}{
		{
			name: "Test Case",
			fields: fields{
				DevMemFilePath:   "../test/eventlog/uefi_event_log.bin",
				Tpm2FilePath:     "../test/eventlog/tpm2_valid",
				AppEventFilePath: "../test/eventlog/pcr_event_log",
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			evtLogFile := &EventLogFiles{
				DevMemFilePath:   tt.fields.DevMemFilePath,
				Tpm2FilePath:     tt.fields.Tpm2FilePath,
				AppEventFilePath: tt.fields.AppEventFilePath,
			}
			_, err := evtLogFile.GetEventLogs()
			if (err != nil) != tt.wantErr {
				t.Errorf("EventLogFiles.GetEventLogs() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

func TestNewEventLogParser(t *testing.T) {
	type args struct {
		devMemFilePath   string
		tpm2FilePath     string
		appEventFilePath string
	}
	tests := []struct {
		name string
		args args
		want EventLogParser
	}{
		{
			name: "Test Case",
			args: args{
				devMemFilePath:   "../test/eventlog/uefi_event_log.bin",
				tpm2FilePath:     "../test/eventlog/tpm2_valid",
				appEventFilePath: "../test/eventlog/pcr_event_log",
			},
			want: &EventLogFiles{
				DevMemFilePath:   "../test/eventlog/uefi_event_log.bin",
				Tpm2FilePath:     "../test/eventlog/tpm2_valid",
				AppEventFilePath: "../test/eventlog/pcr_event_log",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := NewEventLogParser(tt.args.devMemFilePath, tt.args.tpm2FilePath, tt.args.appEventFilePath); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewEventLogParser() = %v, want %v", got, tt.want)
			}
		})
	}
}
