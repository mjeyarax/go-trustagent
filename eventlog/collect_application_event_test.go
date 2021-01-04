/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package eventlog

import "testing"

func Test_eventLogInfo_updateAppEventLog(t *testing.T) {
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
		appEventFilePath string
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
				appEventFilePath: "../test/eventlog/pcr_event_log",
			},
			wantErr: false,
		},
		{
			name:   "Negative test: Pcr event log file does not exist",
			fields: fields{},
			args: args{
				appEventFilePath: "../test/eventlog/pcr_event",
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
			if err := eventLog.updateAppEventLog(tt.args.appEventFilePath); (err != nil) != tt.wantErr {
				t.Errorf("eventLogInfo.updateAppEventLog() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
