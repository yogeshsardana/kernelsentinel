package ringbuf

import (
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
	ks "github.com/kernelsentinel/kernelsentinel/pkg/ks"
)

type EventCallback func(*ks.Event)

type Reader struct {
	mu       sync.Mutex
	rb       *ringbuf.Reader
	callback EventCallback
	done     chan struct{}
}

func NewReader(bpfMap *ebpf.Map, cb EventCallback) (*Reader, error) {
	if bpfMap == nil {
		return nil, fmt.Errorf("%w: nil map", ks.ErrRingBuf)
	}

	rb, err := ringbuf.NewReader(bpfMap)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ks.ErrRingBuf, err)
	}

	return &Reader{
		rb:       rb,
		callback: cb,
		done:     make(chan struct{}),
	}, nil
}

func (r *Reader) Start() {
	go r.loop()
}

func (r *Reader) loop() {
	for {
		select {
		case <-r.done:
			return
		default:
		}

		record, err := r.rb.Read()
		if err != nil {
			if err == ringbuf.ErrClosed {
				return
			}
			if os.IsTimeout(err) {
				continue
			}
			fmt.Fprintf(os.Stderr, "RingBuf read error: %v\n", err)
			continue
		}

		event, err := parseEvent(record.RawSample)
		if err != nil {
			fmt.Fprintf(os.Stderr, "RingBuf parse error: %v\n", err)
			continue
		}

		r.mu.Lock()
		cb := r.callback
		r.mu.Unlock()

		if cb != nil {
			cb(event)
		}
	}
}

func (r *Reader) SetCallback(cb EventCallback) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.callback = cb
}

func (r *Reader) Close() error {
	close(r.done)
	return r.rb.Close()
}

func parseEvent(data []byte) (*ks.Event, error) {
	if len(data) < 64 {
		return nil, io.ErrUnexpectedEOF
	}

	e := &ks.Event{}
	e.Sequence = binary.LittleEndian.Uint64(data[0:8])
	e.EventType = ks.EventType(binary.LittleEndian.Uint32(data[8:12]))
	e.PID = binary.LittleEndian.Uint32(data[12:16])
	e.TID = binary.LittleEndian.Uint32(data[16:20])
	e.UID = binary.LittleEndian.Uint32(data[20:24])
	e.GID = binary.LittleEndian.Uint32(data[24:28])
	e.TimestampNS = binary.LittleEndian.Uint64(data[28:36])
	e.Retval = int64(binary.LittleEndian.Uint64(data[36:44]))

	return e, nil
}
