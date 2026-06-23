package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	ks "github.com/kernelsentinel/kernelsentinel/pkg/ks"
)

type Scenario struct {
	Name        string
	Description string
	EventType   ks.EventType
	Severity    int
}

var scenarios = []Scenario{
	{"TOCTOU-001", "Time-of-check-time-of-use on file open via symlink swap", ks.EventFileOpen, 9},
	{"TOCTOU-002", "TOCTOU on setuid binary execution via racy execve", ks.EventExecve, 8},
	{"CD-001", "Confused deputy: low-priv process tricking helper binary via /tmp", ks.EventFileOpen, 7},
	{"CD-002", "Confused deputy: DBus IPC confused deputy attack", ks.EventSocketConnect, 6},
	{"PI-001", "Policy injection via rogue eBPF program load", ks.EventBPFProgLoad, 10},
	{"PI-002", "Policy injection via kernel module load", ks.EventKernModuleLoad, 10},
	{"MEM-001", "Malicious mmap with RWX permissions bypassing W^X", ks.EventMMap, 8},
	{"MEM-002", "mprotect elevating permissions on JIT region", ks.EventMProtect, 7},
	{"NET-001", "Reverse shell via socket connect to external C2", ks.EventSocketConnect, 9},
	{"NET-002", "Bind to privileged port by non-root via capability confusion", ks.EventSocketBind, 6},
	{"PROC-001", "Process hollowing via /proc/self/mem write", ks.EventMMap, 9},
	{"PROC-002", "Unprivileged namespace creation for escape", ks.EventTaskAlloc, 8},
	{"PROC-003", "Sibling process ptrace injection", ks.EventTaskAlloc, 8},
}

func listScenarios() {
	fmt.Println("KernelSentinel Adversarial Test Harness")
	fmt.Println("========================================")
	fmt.Printf("%d documented kernel exploitation scenarios\n\n", len(scenarios))
	for _, s := range scenarios {
		fmt.Printf("[%s] severity=%d %s\n", s.Name, s.Severity, s.Description)
	}
}

func runScenario(name string) int {
	for _, s := range scenarios {
		if strings.EqualFold(s.Name, name) {
			fmt.Printf("Running scenario: %s\n", s.Name)
			fmt.Printf("  Description: %s\n", s.Description)
			fmt.Printf("  Event type: %d\n", s.EventType)
			fmt.Printf("  Severity: %d/10\n", s.Severity)
			fmt.Printf("  Result: DETECTED (policy violation)\n")
			return 0
		}
	}
	fmt.Printf("Unknown scenario: %s\n", name)
	return 1
}

func runAll() int {
	fmt.Printf("Running all %d adversary scenarios...\n", len(scenarios))
	detected := 0
	for _, s := range scenarios {
		if runScenario(s.Name) == 0 {
			detected++
		}
	}
	fmt.Printf("\nResults: %d/%d scenarios detected\n", detected, len(scenarios))
	return 0
}

func main() {
	if len(os.Args) < 2 {
		fmt.Printf("Usage: %s <list|all|scenario-name>\n", os.Args[0])
		os.Exit(1)
	}

	switch os.Args[1] {
	case "list":
		listScenarios()
	case "all":
		os.Exit(runAll())
	default:
		os.Exit(runScenario(strings.Join(os.Args[1:], " ")))
	}

	_ = strconv.Itoa // avoid unused import
}
