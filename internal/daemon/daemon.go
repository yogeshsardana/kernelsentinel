// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Yogesh Sardana <yogesh.sardana1@gmail.com>
// Author: Yogesh Sardana

package daemon

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	ks "github.com/kernelsentinel/kernelsentinel/pkg/ks"
	"github.com/kernelsentinel/kernelsentinel/internal/config"
	"github.com/kernelsentinel/kernelsentinel/internal/hsm"
	"github.com/kernelsentinel/kernelsentinel/internal/policy"
	"github.com/kernelsentinel/kernelsentinel/internal/ringbuf"
	"github.com/kernelsentinel/kernelsentinel/internal/tpm2"
)

type Daemon struct {
	mu       sync.Mutex
	cfg      *ks.Config
	pm       *policy.Manager
	tpm2     *tpm2.Attestation
	quorum   *hsm.Quorum
	reader   *ringbuf.Reader
	links    []link.Link
	started  time.Time
	logFile  *os.File
}

func New(cfgPath string) (*Daemon, error) {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		log.Printf("Warning: using default config (%v)", err)
		cfg = ks.DefaultConfig()
	}

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Printf("Warning: failed to remove memlock rlimit: %v", err)
	}

	d := &Daemon{
		cfg:     cfg,
		pm:      policy.New(cfg.PolicyDir),
		started: time.Now(),
	}

	if cfg.Daemonize {
		if err := d.daemonize(); err != nil {
			return nil, fmt.Errorf("daemonize: %w", err)
		}
	}

	if err := d.setupLogging(); err != nil {
		return nil, fmt.Errorf("logging: %w", err)
	}

	log.Printf("KernelSentinel v%s starting...", ks.Version())
	config.Dump(cfg)

	return d, nil
}

func (d *Daemon) Start() error {
	d.mu.Lock()
	defer d.mu.Unlock()

	// Load policies
	if err := d.pm.LoadAll(); err != nil {
		log.Printf("Warning: no policies loaded (%v)", err)
	}
	log.Printf("Loaded %d policies (%d rules)", d.pm.NumPolicies(), d.pm.NumRules())

	// Initialize TPM2
	tpm2Dev, err := tpm2.Open(d.cfg.TPM2Device)
	if err != nil {
		log.Printf("Warning: TPM2 init failed (%v) — continuing without hardware attestation", err)
	} else {
		d.tpm2 = tpm2Dev
		log.Printf("TPM2 initialized: %s", d.cfg.TPM2Device)
	}

	// Initialize HSM quorum
	quorum, err := hsm.New(d.cfg.QuorumRequired, d.cfg.QuorumTotal)
	if err != nil {
		log.Printf("Warning: HSM quorum init failed (%v)", err)
	} else {
		d.quorum = quorum
		// Add default tokens for the prototype
		for i := uint32(0); i < d.cfg.QuorumTotal; i++ {
			_ = quorum.AddToken(i, []byte{byte(i), 0xAB, 0xCD, 0xEF})
		}
		log.Printf("HSM quorum initialized: %d/%d required", d.cfg.QuorumRequired, d.cfg.QuorumTotal)
	}

	// Commit policy to TPM2
	if d.tpm2 != nil {
		if err := d.tpm2.PCRPolicyChain(15, []byte(fmt.Sprintf("ks-policy-v%d", time.Now().Unix()))); err != nil {
			log.Printf("Warning: TPM2 policy commit failed (%v)", err)
		} else {
			log.Printf("TPM2 policy committed to PCR 15")
		}
	}

	// Load eBPF programs
	if err := d.loadBPFPrograms(); err != nil {
		log.Printf("Warning: eBPF load failed (%v) — continuing in policy-only mode", err)
	}

	log.Printf("KernelSentinel running. PID: %d", os.Getpid())

	return nil
}

func (d *Daemon) loadBPFPrograms() error {
	// Discover .bpf.o files
	matches, err := filepath.Glob(filepath.Join(d.cfg.BPFProgDir, "*.bpf.o"))
	if err != nil {
		return err
	}

	if len(matches) == 0 {
		matches, err = filepath.Glob("build/*.bpf.o")
		if err != nil {
			return fmt.Errorf("no BPF programs found: %w", err)
		}
		if len(matches) == 0 {
			return fmt.Errorf("no .bpf.o files found in %s or build/", d.cfg.BPFProgDir)
		}
	}

	for _, path := range matches {
		spec, err := ebpf.LoadCollectionSpec(path)
		if err != nil {
			log.Printf("  Skipping %s: %v", path, err)
			continue
		}

		coll, err := ebpf.NewCollection(spec)
		if err != nil {
			log.Printf("  Skipping %s: %v", path, err)
			continue
		}

		for progName, prog := range coll.Programs {
			if prog == nil {
				continue
			}
			lk, err := link.AttachLSM(link.LSMOptions{
				Program: prog,
			})
			if err != nil {
				log.Printf("  Attach %s: %v", progName, err)
				continue
			}
			d.links = append(d.links, lk)
			log.Printf("  Loaded & attached: %s (%s)", progName, path)
		}

		// Set up ring buffer reader for ks_events map
		if m := coll.Maps["ks_events"]; m != nil {
			rd, err := ringbuf.NewReader(m, d.onEvent)
			if err != nil {
				log.Printf("  RingBuf reader failed: %v", err)
			} else {
				d.reader = rd
				rd.Start()
				log.Printf("  Ring buffer reader started")
			}
		}
	}

	return nil
}

func (d *Daemon) onEvent(event *ks.Event) {
	action := d.pm.Evaluate(event)

	if action == ks.ActionDeny {
		log.Printf("DENIED event type=%d pid=%d", event.EventType, event.PID)
	}
}

func (d *Daemon) daemonize() error {
	_, err := os.StartProcess(os.Args[0], os.Args, &os.ProcAttr{
		Files: []*os.File{os.Stdin, os.Stdout, os.Stderr},
	})
	if err != nil {
		return err
	}
	os.Exit(0)
	return nil
}

func (d *Daemon) setupLogging() error {
	if d.cfg.LogFile == "" {
		return nil
	}

	f, err := os.OpenFile(d.cfg.LogFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return err
	}
	d.logFile = f
	log.SetOutput(f)
	return nil
}

func (d *Daemon) Stats() ks.Stats {
	s := d.pm.Stats()
	s.UptimeNS = uint64(time.Since(d.started))
	return s
}

func (d *Daemon) Wait() {
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	log.Printf("Shutting down...")
	d.Shutdown()
}

func (d *Daemon) Shutdown() {
	d.mu.Lock()
	defer d.mu.Unlock()

	for _, lk := range d.links {
		lk.Close()
	}
	d.links = nil

	if d.reader != nil {
		d.reader.Close()
	}
	if d.tpm2 != nil {
		d.tpm2.Close()
	}
	if d.logFile != nil {
		d.logFile.Close()
	}

	os.Remove(d.cfg.PIDFile)
	log.Printf("KernelSentinel stopped.")
}
