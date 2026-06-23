package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
	ks "github.com/kernelsentinel/kernelsentinel/pkg/ks"
)

func Load(path string) (*ks.Config, error) {
	cfg := ks.DefaultConfig()

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ks.ErrNotFound, err)
	}

	raw := struct {
		KernelSentinel *ks.Config `yaml:"kernelsentinel"`
	}{}
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("%w: %w", ks.ErrConfig, err)
	}

	if raw.KernelSentinel != nil {
		if raw.KernelSentinel.BPFProgDir != "" {
			cfg.BPFProgDir = raw.KernelSentinel.BPFProgDir
		}
		if raw.KernelSentinel.PolicyDir != "" {
			cfg.PolicyDir = raw.KernelSentinel.PolicyDir
		}
		if raw.KernelSentinel.TPM2Device != "" {
			cfg.TPM2Device = raw.KernelSentinel.TPM2Device
		}
		if raw.KernelSentinel.QuorumRequired > 0 {
			cfg.QuorumRequired = raw.KernelSentinel.QuorumRequired
		}
		if raw.KernelSentinel.QuorumTotal > 0 {
			cfg.QuorumTotal = raw.KernelSentinel.QuorumTotal
		}
		if raw.KernelSentinel.LogFile != "" {
			cfg.LogFile = raw.KernelSentinel.LogFile
		}
		if raw.KernelSentinel.PIDFile != "" {
			cfg.PIDFile = raw.KernelSentinel.PIDFile
		}
		cfg.LogLevel = raw.KernelSentinel.LogLevel
		cfg.Daemonize = raw.KernelSentinel.Daemonize
		if raw.KernelSentinel.EvalTimeoutMs > 0 {
			cfg.EvalTimeoutMs = raw.KernelSentinel.EvalTimeoutMs
		}
		if raw.KernelSentinel.AttestationIntervalS > 0 {
			cfg.AttestationIntervalS = raw.KernelSentinel.AttestationIntervalS
		}
		if raw.KernelSentinel.MaxEventsPerSec > 0 {
			cfg.MaxEventsPerSec = raw.KernelSentinel.MaxEventsPerSec
		}
	}

	return cfg, nil
}

func Dump(cfg *ks.Config) {
	fmt.Println("KernelSentinel Configuration:")
	fmt.Printf("  bpf_prog_dir: %s\n", cfg.BPFProgDir)
	fmt.Printf("  policy_dir: %s\n", cfg.PolicyDir)
	fmt.Printf("  tpm2_device: %s\n", cfg.TPM2Device)
	fmt.Printf("  quorum_required: %d\n", cfg.QuorumRequired)
	fmt.Printf("  quorum_total: %d\n", cfg.QuorumTotal)
	fmt.Printf("  log_level: %d\n", cfg.LogLevel)
	fmt.Printf("  daemonize: %v\n", cfg.Daemonize)
	fmt.Printf("  eval_timeout_ms: %d\n", cfg.EvalTimeoutMs)
	fmt.Printf("  attestation_interval_s: %d\n", cfg.AttestationIntervalS)
	fmt.Printf("  max_events_per_sec: %d\n", cfg.MaxEventsPerSec)
}
