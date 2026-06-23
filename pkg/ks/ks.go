package ks

import (
	"fmt"
	"os"
	"sync"
)

type KernelSentinel struct {
	mu     sync.RWMutex
	config *Config
	stats  Stats
}

type Config struct {
	BPFProgDir           string `yaml:"bpf_prog_dir"`
	PolicyDir            string `yaml:"policy_dir"`
	TPM2Device           string `yaml:"tpm2_device"`
	QuorumRequired       uint32 `yaml:"quorum_required"`
	QuorumTotal          uint32 `yaml:"quorum_total"`
	LogLevel             int    `yaml:"log_level"`
	LogFile              string `yaml:"log_file"`
	Daemonize            bool   `yaml:"daemonize"`
	PIDFile              string `yaml:"pid_file"`
	EvalTimeoutMs        uint32 `yaml:"eval_timeout_ms"`
	AttestationIntervalS uint32 `yaml:"attestation_interval_s"`
	MaxEventsPerSec      uint32 `yaml:"max_events_per_sec"`
}

func DefaultConfig() *Config {
	return &Config{
		BPFProgDir:           "/sys/fs/bpf",
		PolicyDir:            "/etc/kernelsentinel/policies",
		TPM2Device:           "/dev/tpmrm0",
		QuorumRequired:       2,
		QuorumTotal:          3,
		LogLevel:             2,
		LogFile:              "/var/log/kernelsentinel.log",
		Daemonize:            true,
		PIDFile:              "/var/run/kernelsentinel.pid",
		EvalTimeoutMs:        100,
		AttestationIntervalS: 300,
		MaxEventsPerSec:      10000,
	}
}

func New(cfg *Config) (*KernelSentinel, error) {
	if cfg == nil {
		cfg = DefaultConfig()
	}
	return &KernelSentinel{config: cfg}, nil
}

func (ks *KernelSentinel) Close() {}

func (ks *KernelSentinel) EvaluateEvent(event *Event) Action {
	ks.mu.Lock()
	defer ks.mu.Unlock()
	ks.stats.EventsProcessed++
	ks.stats.EventsAllowed++
	return ActionAllow
}

func (ks *KernelSentinel) Stats() Stats {
	ks.mu.RLock()
	defer ks.mu.RUnlock()
	return ks.stats
}

func (ks *KernelSentinel) Config() *Config {
	return ks.config
}

func Version() string {
	return fmt.Sprintf("%d.%d.%d", VersionMajor, VersionMinor, VersionPatch)
}

func FmtVersion(major, minor, patch int) string {
	return fmt.Sprintf("%d.%d.%d", major, minor, patch)
}

func init() {
	if os.Geteuid() != 0 {
		fmt.Fprintf(os.Stderr, "Warning: KernelSentinel requires root privileges for eBPF operations\n")
	}
}
