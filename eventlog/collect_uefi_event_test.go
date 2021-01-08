/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package eventlog

import (
	"testing"
)

func Test_eventLogInfo_fetchUefiEventInfo(t *testing.T) {
	type fields struct {
		UefiEventSize     uint32
		UefiEventAddr     uint64
		TxtHeapSize       uint64
		TxtHeapBaseAddr   uint64
		FinalPcrEventLog  []PcrEventLog
		TxtEnabled        bool
		TxtHeapBaseOffset int64
		TxtHeapSizeOffset int64
	}
	type args struct {
		tpm2FilePath string
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		// TODO: Add test cases.
		{
			name:   "Positive test case",
			fields: fields{},
			args: args{
				tpm2FilePath: "../test/eventlog/tpm2_valid",
			},
			wantErr: false,
		},
		{
			name:   "Negative test: TPM2 file has invalid file length",
			fields: fields{},
			args: args{
				tpm2FilePath: "../test/eventlog/tpm2_invalid_file_length",
			},
			wantErr: true,
		},
		{
			name:   "Negative test: TPM2 file has invalid signature",
			fields: fields{},
			args: args{
				tpm2FilePath: "../test/eventlog/tpm2_invalid_signature",
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			eventLog := &eventLogInfo{
				UefiEventSize:     tt.fields.UefiEventSize,
				UefiEventAddr:     tt.fields.UefiEventAddr,
				TxtHeapSize:       tt.fields.TxtHeapSize,
				TxtHeapBaseAddr:   tt.fields.TxtHeapBaseAddr,
				FinalPcrEventLog:  tt.fields.FinalPcrEventLog,
				TxtEnabled:        tt.fields.TxtEnabled,
				TxtHeapBaseOffset: tt.fields.TxtHeapBaseOffset,
				TxtHeapSizeOffset: tt.fields.TxtHeapSizeOffset,
			}
			if err := eventLog.fetchUefiEventInfo(tt.args.tpm2FilePath); (err != nil) != tt.wantErr {
				t.Errorf("eventLogInfo.fetchUefiEventInfo() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func Test_eventLogInfo_updateUefiEventLog(t *testing.T) {
	type fields struct {
		UefiEventSize     uint32
		UefiEventAddr     uint64
		TxtHeapSize       uint64
		TxtHeapBaseAddr   uint64
		FinalPcrEventLog  []PcrEventLog
		TxtEnabled        bool
		TxtHeapBaseOffset int64
		TxtHeapSizeOffset int64
	}
	type args struct {
		eventLogFilePath string
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		// TODO: Add test cases.
		{
			name: "Positive test case",
			fields: fields{
				UefiEventSize: 65536,
				UefiEventAddr: 0,
			},
			args: args{
				eventLogFilePath: "../test/eventlog/uefi_event_log.bin",
			},
			wantErr: false,
		},
		{
			name: "Negative test: Uefi event log file does not exist",
			fields: fields{
				UefiEventSize: 65536,
				UefiEventAddr: 0,
			},
			args: args{
				eventLogFilePath: "../test/eventlog/uefi_event.bin",
			},
			wantErr: true,
		},
		{
			name: "Negative test: Invalid uefi event log address",
			fields: fields{
				UefiEventSize: 65536,
				UefiEventAddr: 1048576,
			},
			args: args{
				eventLogFilePath: "../test/eventlog/uefi_event_log.bin",
			},
			wantErr: true,
		},
		{
			name: "Negative test: Invalid uefi event log size",
			fields: fields{
				UefiEventSize: 0,
				UefiEventAddr: 0,
			},
			args: args{
				eventLogFilePath: "../test/eventlog/uefi_event_log.bin",
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			eventLog := &eventLogInfo{
				UefiEventSize:     tt.fields.UefiEventSize,
				UefiEventAddr:     tt.fields.UefiEventAddr,
				TxtHeapSize:       tt.fields.TxtHeapSize,
				TxtHeapBaseAddr:   tt.fields.TxtHeapBaseAddr,
				FinalPcrEventLog:  tt.fields.FinalPcrEventLog,
				TxtEnabled:        tt.fields.TxtEnabled,
				TxtHeapBaseOffset: tt.fields.TxtHeapBaseOffset,
				TxtHeapSizeOffset: tt.fields.TxtHeapSizeOffset,
			}
			if err := eventLog.updateUefiEventLog(tt.args.eventLogFilePath); (err != nil) != tt.wantErr {
				t.Errorf("eventLogInfo.updateUefiEventLog() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
