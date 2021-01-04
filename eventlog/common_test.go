/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package eventlog

import (
	"reflect"
	"testing"
)

func Test_initializeEventLogInfo(t *testing.T) {
	tests := []struct {
		name string
		want *eventLogInfo
	}{
		// TODO: Add test cases.
		{
			name: "Test Case",
			want: &eventLogInfo{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := initializeEventLogInfo(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("initializeEventLogInfo() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_getEventLogInfo(t *testing.T) {
	tests := []struct {
		name string
		want *eventLogInfo
	}{
		// TODO: Add test cases.
		{
			name: "Test Case",
			want: &eventLogInfo{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := getEventLogInfo(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("getEventLogInfo() = %v, want %v", got, tt.want)
			}
		})
	}
}
