package policy

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"
	ks "github.com/kernelsentinel/kernelsentinel/pkg/ks"
)

type Manager struct {
	mu       sync.RWMutex
	policies []ks.PolicyHeader
	rules    []ks.PolicyRule
	stats    ks.Stats
	dir      string
}

type policyFile struct {
	Policy struct {
		Name        string          `yaml:"name"`
		Version     uint64          `yaml:"version"`
		Scope       string          `yaml:"scope"`
		Description string          `yaml:"description"`
		Attestation policyAttest    `yaml:"attestation"`
		Rules       []ks.PolicyRule `yaml:"rules"`
	} `yaml:"policy"`
}

type policyAttest struct {
	PCRIndex       uint32 `yaml:"pcr_index"`
	QuorumRequired uint32 `yaml:"quorum_required"`
	QuorumTotal    uint32 `yaml:"quorum_total"`
}

func New(dir string) *Manager {
	return &Manager{dir: dir}
}

func (m *Manager) LoadAll() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.policies = nil
	m.rules = nil

	entries, err := os.ReadDir(m.dir)
	if err != nil {
		return fmt.Errorf("%w: reading %s: %w", ks.ErrNotFound, m.dir, err)
	}

	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".yaml") {
			continue
		}
		path := filepath.Join(m.dir, e.Name())
		if err := m.loadFile(path); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: skipping %s: %v\n", path, err)
		}
	}

	return nil
}

func (m *Manager) loadFile(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	var pf policyFile
	if err := yaml.Unmarshal(data, &pf); err != nil {
		return fmt.Errorf("%w: %w", ks.ErrPolicyParse, err)
	}

	hdr := ks.PolicyHeader{
		Name:          pf.Policy.Name,
		PolicyVersion: pf.Policy.Version,
		QuorumRequired: pf.Policy.Attestation.QuorumRequired,
		QuorumTotal:    pf.Policy.Attestation.QuorumTotal,
	}

	switch pf.Policy.Scope {
	case "system":
		hdr.Scope = ks.ScopeSystem
	case "process":
		hdr.Scope = ks.ScopeProcess
	case "container":
		hdr.Scope = ks.ScopeContainer
	case "user":
		hdr.Scope = ks.ScopeUser
	}

	hdr.Attestation.PCRIndex = pf.Policy.Attestation.PCRIndex

	m.policies = append(m.policies, hdr)
	m.rules = append(m.rules, pf.Policy.Rules...)

	return nil
}

func (m *Manager) Evaluate(event *ks.Event) ks.Action {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.stats.EventsProcessed++

	if len(m.rules) == 0 {
		m.stats.EventsAllowed++
		return ks.ActionAllow
	}

	for _, rule := range m.rules {
		if rule.Event != event.EventType && rule.Event != ks.EventMax {
			continue
		}
		switch rule.Action {
		case ks.ActionDeny:
			m.stats.EventsDenied++
			return ks.ActionDeny
		case ks.ActionLog:
			m.stats.EventsLogged++
			return ks.ActionLog
		}
	}

	m.stats.EventsAllowed++
	return ks.ActionAllow
}

func (m *Manager) Stats() ks.Stats {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.stats
}

func (m *Manager) NumPolicies() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.policies)
}

func (m *Manager) NumRules() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.rules)
}
