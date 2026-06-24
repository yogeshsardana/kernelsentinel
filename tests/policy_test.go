// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Yogesh Sardana <yogesh.sardana1@gmail.com>
// Author: Yogesh Sardana

package tests

import (
	"testing"

	ks "github.com/kernelsentinel/kernelsentinel/pkg/ks"
)

func TestVersion(t *testing.T) {
	v := ks.Version()
	if v != "0.1.0" {
		t.Fatalf("expected 0.1.0, got %s", v)
	}
}

func TestDefaultConfig(t *testing.T) {
	cfg := ks.DefaultConfig()
	if cfg == nil {
		t.Fatal("expected non-nil config")
	}
	if cfg.BPFProgDir != "/sys/fs/bpf" {
		t.Fatalf("unexpected BPFProgDir: %s", cfg.BPFProgDir)
	}
	if cfg.QuorumRequired != 2 {
		t.Fatalf("unexpected QuorumRequired: %d", cfg.QuorumRequired)
	}
}

func TestNewKernelSentinel(t *testing.T) {
	ks, err := ks.New(nil)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}
	ks.Close()
}

func TestEvaluateEvent(t *testing.T) {
	app, _ := ks.New(nil)
	defer app.Close()

	ev := &ks.Event{
		EventType: ks.EventFileOpen,
		PID:       100,
	}
	action := app.EvaluateEvent(ev)
	if action != ks.ActionAllow {
		t.Fatalf("expected allow, got %d", action)
	}
}

func TestStats(t *testing.T) {
	app, _ := ks.New(nil)
	defer app.Close()

	ev := &ks.Event{EventType: ks.EventSocketConnect}
	app.EvaluateEvent(ev)
	app.EvaluateEvent(ev)

	stats := app.Stats()
	if stats.EventsProcessed != 2 {
		t.Fatalf("expected 2 events, got %d", stats.EventsProcessed)
	}
}

func TestConfigOverride(t *testing.T) {
	cfg := &ks.Config{
		BPFProgDir:     "/custom/bpf",
		PolicyDir:      "/custom/policies",
		QuorumRequired: 3,
		QuorumTotal:    5,
	}
	ks, _ := ks.New(cfg)
	defer ks.Close()

	got := ks.Config()
	if got.BPFProgDir != "/custom/bpf" {
		t.Fatalf("unexpected BPFProgDir: %s", got.BPFProgDir)
	}
	if got.QuorumRequired != 3 {
		t.Fatalf("unexpected QuorumRequired: %d", got.QuorumRequired)
	}
}

func TestEventTypes(t *testing.T) {
	tests := []struct {
		et  ks.EventType
		str string
	}{
		{ks.EventFileOpen, "EventFileOpen"},
		{ks.EventExecve, "EventExecve"},
		{ks.EventSocketConnect, "EventSocketConnect"},
		{ks.EventMMap, "EventMMap"},
		{ks.EventMax, "EventMax"},
	}
	for _, tc := range tests {
		if tc.et < ks.EventMax {
			_ = tc.str // type is valid
		} else {
			t.Fatalf("invalid event type: %d", tc.et)
		}
	}
}
