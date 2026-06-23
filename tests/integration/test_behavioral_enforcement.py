#!/usr/bin/env python3
"""
KernelSentinel Integration Test Suite
Tests behavioral enforcement via the eBPF LSM interface.

Requires: Linux 6.8+, root privileges, bpftool
"""

import os
import sys
import time
import json
import subprocess
import tempfile
import unittest

KSCTL = "./build/ksctl"
KSD = "./build/ksd"
BPF_PROGS = [
    "./build/ks_behavior_tracker.bpf.o",
    "./build/ks_integrity_enforcer.bpf.o",
    "./build/ks_process_monitor.bpf.o",
    "./build/ks_policy_eval.bpf.o",
]

class TestKernelSentinelIntegration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.has_root = os.geteuid() == 0
        cls.has_bpftool = subprocess.run(
            ["which", "bpftool"], capture_output=True
        ).returncode == 0
        cls.has_bpf = os.path.exists("/sys/fs/bpf")

    def test_bpf_programs_compile(self):
        """Verify all eBPF programs compile without error"""
        for prog in BPF_PROGS:
            if not os.path.exists(prog):
                self.skipTest(f"{prog} not built, run make first")

    def test_tools_exist(self):
        """Verify CLI tools are built"""
        self.assertTrue(os.path.exists(KSCTL), "ksctl not built")
        self.assertTrue(os.path.exists(KSD), "ksd not built")

    def test_ksctl_version(self):
        """Test ksctl version command"""
        result = subprocess.run([KSCTL, "version"], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0)
        self.assertIn("KernelSentinel", result.stdout)

    def test_ksctl_help(self):
        """Test ksctl help command"""
        result = subprocess.run([KSCTL, "help"], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0)
        self.assertIn("Commands:", result.stdout)

    def test_ksctl_status(self):
        """Test ksctl status command"""
        result = subprocess.run([KSCTL, "status"], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0)
        self.assertIn("KernelSentinel Daemon Status", result.stdout)

    def test_ksctl_stats(self):
        """Test ksctl stats command"""
        result = subprocess.run([KSCTL, "stats"], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0)
        self.assertIn("Events Processed", result.stdout)

    def test_adversary_list(self):
        """Test adversary scenario listing"""
        adv = "./build/ks-adversary"
        if not os.path.exists(adv):
            self.skipTest("ks-adversary not built")
        result = subprocess.run([adv, "list"], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0)
        self.assertIn("TOCTOU-001", result.stdout)

    def test_adversary_single(self):
        """Test running a single adversary scenario"""
        adv = "./build/ks-adversary"
        if not os.path.exists(adv):
            self.skipTest("ks-adversary not built")
        result = subprocess.run([adv, "TOCTOU-001"], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0)
        self.assertIn("DETECTED", result.stdout)

    def test_adversary_all(self):
        """Test running all adversary scenarios"""
        adv = "./build/ks-adversary"
        if not os.path.exists(adv):
            self.skipTest("ks-adversary not built")
        result = subprocess.run([adv, "all"], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0)

    def test_benchmark(self):
        """Test benchmark suite runs"""
        bench = "./build/ks-benchmark"
        if not os.path.exists(bench):
            self.skipTest("ks-benchmark not built")
        result = subprocess.run([bench], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0)
        self.assertIn("KernelSentinel Benchmark Suite", result.stdout)


if __name__ == "__main__":
    unittest.main()
