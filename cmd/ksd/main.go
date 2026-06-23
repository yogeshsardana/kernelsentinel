package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/kernelsentinel/kernelsentinel/internal/daemon"
)

func main() {
	configPath := flag.String("c", "/etc/kernelsentinel/config.yaml", "path to config file")
	flag.Parse()

	if os.Geteuid() != 0 {
		fmt.Fprintf(os.Stderr, "Error: KernelSentinel daemon requires root privileges\n")
		os.Exit(1)
	}

	d, err := daemon.New(*configPath)
	if err != nil {
		log.Fatalf("Failed to start daemon: %v", err)
	}

	if err := d.Start(); err != nil {
		log.Fatalf("Failed to start: %v", err)
	}

	d.Wait()
}
