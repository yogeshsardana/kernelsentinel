// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Yogesh Sardana <yogesh.sardana1@gmail.com>
// Author: Yogesh Sardana

package tpm2

import (
	"crypto/sha256"
	"fmt"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	ks "github.com/kernelsentinel/kernelsentinel/pkg/ks"
)

type Attestation struct {
	device string
	rwc    transport.TPMCloser
	closed bool
}

func Open(device string) (*Attestation, error) {
	rwc, err := transport.OpenTPM()
	if err != nil {
		return nil, fmt.Errorf("%w: open %s: %w", ks.ErrTPM2Init, device, err)
	}
	return &Attestation{device: device, rwc: rwc}, nil
}

func (a *Attestation) Close() error {
	if a.closed {
		return nil
	}
	a.closed = true
	return a.rwc.Close()
}

func (a *Attestation) PCRRead(pcrIndex uint32) ([]byte, error) {
	pcrSel := tpm2.TPMLPCRSelection{
		PCRSelections: []tpm2.TPMSPCRSelection{
			{
				Hash:      tpm2.TPMAlgSHA256,
				PCRSelect: tpm2.PCClientCompatible.PCRs(uint(pcrIndex)),
			},
		},
	}

	pcrRead := tpm2.PCRRead{
		PCRSelectionIn: pcrSel,
	}

	rsp, err := pcrRead.Execute(a.rwc)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ks.ErrTPM2Quote, err)
	}

	if len(rsp.PCRValues.Digests) == 0 {
		return nil, fmt.Errorf("%w: no PCR values returned", ks.ErrTPM2Quote)
	}

	return rsp.PCRValues.Digests[0].Buffer, nil
}

func (a *Attestation) PCRExtend(pcrIndex uint32, hash []byte) error {
	pcrExtend := tpm2.PCRExtend{
		PCRHandle: tpm2.TPMHandle(pcrIndex),
		Digests: tpm2.TPMLDigestValues{
			Digests: []tpm2.TPMTHA{
				{
					HashAlg: tpm2.TPMAlgSHA256,
					Digest:  hash,
				},
			},
		},
	}
	_, err := pcrExtend.Execute(a.rwc)
	if err != nil {
		return fmt.Errorf("%w: %w", ks.ErrTPM2PCRExtend, err)
	}
	return nil
}

func (a *Attestation) PCRPolicyChain(pcrIndex uint32, policyHash []byte) error {
	current, err := a.PCRRead(pcrIndex)
	if err != nil {
		return err
	}

	h := sha256.New()
	h.Write(current)
	h.Write(policyHash)
	extendVal := h.Sum(nil)

	return a.PCRExtend(pcrIndex, extendVal)
}

func (a *Attestation) GetRandom(size int) ([]byte, error) {
	getRand := tpm2.GetRandom{
		BytesRequested: uint16(size),
	}
	rsp, err := getRand.Execute(a.rwc)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ks.ErrTPM2Quote, err)
	}
	return rsp.RandomBytes.Buffer, nil
}

func (a *Attestation) Device() string { return a.device }
