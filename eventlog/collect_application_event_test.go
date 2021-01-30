/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package eventlog

import (
	"testing"
)

func Test_getAppEventLog(t *testing.T) {
	type args struct {
		appEventFilePath string
	}
	tests := []struct {
		name    string
		args    args
		want    []PcrEventLog
		wantErr bool
	}{
		// TODO: Add test cases.
		{
			name: "Positive test case",
			args: args{
				appEventFilePath: "../test/eventlog/pcr_event_log",
			},
			wantErr: false,
		},
		{
			name: "Negative test: Pcr event log file does not exist",
			args: args{
				appEventFilePath: "../test/eventlog/pcr_event",
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := getAppEventLog(tt.args.appEventFilePath)
			if (err != nil) != tt.wantErr {
				t.Errorf("getAppEventLog() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}
