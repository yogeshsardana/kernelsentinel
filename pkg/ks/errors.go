// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Yogesh Sardana <yogesh.sardana1@gmail.com>
// Author: Yogesh Sardana

package ks

import "errors"

var (
	ErrGeneric       = errors.New("kernelsentinel: generic error")
	ErrNoMem         = errors.New("kernelsentinel: out of memory")
	ErrInval         = errors.New("kernelsentinel: invalid parameter")
	ErrNotFound      = errors.New("kernelsentinel: resource not found")
	ErrPerm          = errors.New("kernelsentinel: permission denied")
	ErrBPFLoad       = errors.New("kernelsentinel: eBPF program load failed")
	ErrBPFAttach     = errors.New("kernelsentinel: eBPF program attach failed")
	ErrTPM2Init      = errors.New("kernelsentinel: TPM2 initialization failed")
	ErrTPM2Quote     = errors.New("kernelsentinel: TPM2 quote failed")
	ErrTPM2PCRExtend = errors.New("kernelsentinel: TPM2 PCR extend failed")
	ErrHSMQuorum     = errors.New("kernelsentinel: HSM quorum not met")
	ErrHSMSign       = errors.New("kernelsentinel: HSM signing failed")
	ErrPolicyParse   = errors.New("kernelsentinel: policy parse error")
	ErrPolicyEval    = errors.New("kernelsentinel: policy evaluation error")
	ErrPolicyVersion = errors.New("kernelsentinel: policy version mismatch")
	ErrRingBuf       = errors.New("kernelsentinel: ring buffer error")
	ErrConfig        = errors.New("kernelsentinel: configuration error")
	ErrIO            = errors.New("kernelsentinel: I/O error")
	ErrNotSupported  = errors.New("kernelsentinel: not supported")
)
