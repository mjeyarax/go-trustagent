/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package eventlog

import (
	"reflect"
	"testing"
)

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
		// TODO: Add test cases.
		{
			name: "Test Case",
			args: args{
				devMemFilePath:   "../test/eventlog/uefi_event_log.bin",
				tpm2FilePath:     "../test/eventlog/tpm2_valid",
				appEventFilePath: "../test/eventlog/pcr_event",
			},
			want: &EventLogFiles{
				DevMemFilePath:   "../test/eventlog/uefi_event_log.bin",
				Tpm2FilePath:     "../test/eventlog/tpm2_valid",
				AppEventFilePath: "../test/eventlog/pcr_event",
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
