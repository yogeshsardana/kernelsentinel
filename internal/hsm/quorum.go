package hsm

import (
	"crypto/sha256"
	"fmt"
	"sync"

	ks "github.com/kernelsentinel/kernelsentinel/pkg/ks"
)

type Token struct {
	ID        uint32
	PublicKey []byte
}

type Quorum struct {
	mu       sync.RWMutex
	tokens   []Token
	required uint32
}

func New(required, total uint32) (*Quorum, error) {
	if required > total {
		return nil, fmt.Errorf("%w: required (%d) > total (%d)", ks.ErrHSMQuorum, required, total)
	}
	if total > ks.MaxHSMTokens {
		return nil, fmt.Errorf("%w: total tokens (%d) exceeds max (%d)", ks.ErrHSMQuorum, total, ks.MaxHSMTokens)
	}
	return &Quorum{
		tokens:   make([]Token, 0, total),
		required: required,
	}, nil
}

func (q *Quorum) AddToken(id uint32, pubKey []byte) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	if len(q.tokens) >= ks.MaxHSMTokens {
		return fmt.Errorf("%w: max tokens reached", ks.ErrHSMQuorum)
	}
	q.tokens = append(q.tokens, Token{ID: id, PublicKey: pubKey})
	return nil
}

func (q *Quorum) Check() bool {
	q.mu.RLock()
	defer q.mu.RUnlock()
	return uint32(len(q.tokens)) >= q.required
}

func (q *Quorum) Sign(data []byte) ([]byte, error) {
	q.mu.RLock()
	defer q.mu.RUnlock()

	if uint32(len(q.tokens)) < q.required {
		return nil, fmt.Errorf("%w: have %d, need %d", ks.ErrHSMQuorum, len(q.tokens), q.required)
	}

	signed := uint32(0)
	h := sha256.New()

	for _, tok := range q.tokens {
		if signed >= q.required {
			break
		}
		h.Reset()
		h.Write(data)
		h.Write(tok.PublicKey)
		sig := h.Sum(nil)
		if signed == 0 {
			h.Reset()
			h.Write(sig)
		} else {
			h.Reset()
			h.Write(data)
			h.Write(sig)
		}
		signed++
	}

	if signed < q.required {
		return nil, fmt.Errorf("%w: only signed %d/%d", ks.ErrHSMQuorum, signed, q.required)
	}

	return h.Sum(nil), nil
}

func (q *Quorum) Verify(data, signature []byte) error {
	expected, err := q.Sign(data)
	if err != nil {
		return err
	}
	if len(signature) != len(expected) {
		return fmt.Errorf("%w: signature length mismatch", ks.ErrHSMSign)
	}
	for i := range signature {
		if signature[i] != expected[i] {
			return fmt.Errorf("%w: signature mismatch", ks.ErrHSMSign)
		}
	}
	return nil
}

func (q *Quorum) NumTokens() int {
	q.mu.RLock()
	defer q.mu.RUnlock()
	return len(q.tokens)
}
