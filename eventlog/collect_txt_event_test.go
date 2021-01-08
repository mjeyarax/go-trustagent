/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package eventlog

import (
	"testing"
)

func Test_eventLogInfo_fetchTxtHeapInfo(t *testing.T) {
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
				TxtHeapBaseOffset: 0,
				TxtHeapSizeOffset: 8,
			},
			args: args{
				eventLogFilePath: "../test/eventlog/txt_heap_info.bin",
			},
			wantErr: false,
		},
		{
			name: "Negative test: Txt event log file does not exist",
			fields: fields{
				TxtHeapBaseOffset: 0,
				TxtHeapSizeOffset: 8,
			},
			args: args{
				eventLogFilePath: "../test/eventlog/txt_heap.bin",
			},
			wantErr: true,
		},
		{
			name: "Negative test: Invalid txt heap base offset",
			fields: fields{
				TxtHeapBaseOffset: 36,
				TxtHeapSizeOffset: 8,
			},
			args: args{
				eventLogFilePath: "../test/eventlog/txt_heap_info.bin",
			},
			wantErr: true,
		},
		{
			name: "Negative test: Invalid txt heap size offset",
			fields: fields{
				TxtHeapBaseOffset: 0,
				TxtHeapSizeOffset: 36,
			},
			args: args{
				eventLogFilePath: "../test/eventlog/txt_heap_info.bin",
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
			if err := eventLog.fetchTxtHeapInfo(tt.args.eventLogFilePath); (err != nil) != tt.wantErr {
				t.Errorf("eventLogInfo.fetchTxtHeapInfo() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func Test_eventLogInfo_updateTxtEventLog(t *testing.T) {
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
				TxtHeapSize:     1048576,
				TxtHeapBaseAddr: 0,
				TxtEnabled:      true,
			},
			args: args{
				eventLogFilePath: "../test/eventlog/txt_event_log.bin",
			},
			wantErr: false,
		},
		{
			name: "Negative test: Txt event log file does not exist",
			fields: fields{
				TxtHeapSize:     1048576,
				TxtHeapBaseAddr: 0,
				TxtEnabled:      true,
			},
			args: args{
				eventLogFilePath: "../test/eventlog/txt_event.bin",
			},
			wantErr: true,
		},
		{
			name: "Negative test: Invalid txt heap size",
			fields: fields{
				TxtHeapSize:     0,
				TxtHeapBaseAddr: 0,
				TxtEnabled:      true,
			},
			args: args{
				eventLogFilePath: "../test/eventlog/txt_event_log.bin",
			},
			wantErr: true,
		},
		{
			name: "Negative test: Invalid txt heap base address",
			fields: fields{
				TxtHeapSize:     1048576,
				TxtHeapBaseAddr: 1048,
				TxtEnabled:      true,
			},
			args: args{
				eventLogFilePath: "../test/eventlog/txt_event_log.bin",
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
			if err := eventLog.updateTxtEventLog(tt.args.eventLogFilePath); (err != nil) != tt.wantErr {
				t.Errorf("eventLogInfo.updateTxtEventLog() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
