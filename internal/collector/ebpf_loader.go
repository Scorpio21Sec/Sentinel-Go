// Package collector handles eBPF program loading, tracepoint attachment,
// and reading kernel events from the ring buffer into a Go channel.
package collector

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

// sentinelObjects holds eBPF maps and programs loaded from the compiled object.
// We use a plain struct rather than bpf2go-generated code so the binary can
// be built without the clang/libbpf toolchain installed.
type sentinelObjects struct {
	Programs struct {
		TraceExecve  *ebpf.Program `ebpf:"trace_execve"`
		TraceOpenat  *ebpf.Program `ebpf:"trace_openat"`
		TraceConnect *ebpf.Program `ebpf:"trace_connect"`
		TraceClone   *ebpf.Program `ebpf:"trace_clone"`
	}
	Maps struct {
		Events        *ebpf.Map `ebpf:"events"`
		SyscallCounts *ebpf.Map `ebpf:"syscall_counts"`
	}
}

// Collector reads BPF events from the kernel and pushes them to EventCh.
type Collector struct {
	EventCh chan BpfEvent
	stopCh  chan struct{}
}

// NewCollector creates a Collector with a buffered event channel.
// bufSize controls how many events can queue before the ring-buffer
// reader has to drop; 512 is a reasonable default for most workloads.
func NewCollector(bufSize int) *Collector {
	return &Collector{
		EventCh: make(chan BpfEvent, bufSize),
		stopCh:  make(chan struct{}),
	}
}

// Run loads the eBPF object file, attaches the four tracepoints, and
// streams events to EventCh until c.stopCh is closed or an unrecoverable
// error occurs.  Must be called with CAP_BPF (or as root) on Linux 5.8+.
func (c *Collector) Run(objPath string) error {
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("remove memlock: %w", err)
	}

	spec, err := ebpf.LoadCollectionSpec(objPath)
	if err != nil {
		return fmt.Errorf("load collection spec %q: %w", objPath, err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return fmt.Errorf("create eBPF collection: %w", err)
	}
	defer coll.Close()

	hooks := []struct {
		group   string
		name    string
		progKey string
	}{
		{"syscalls", "sys_enter_execve", "trace_execve"},
		{"syscalls", "sys_enter_openat", "trace_openat"},
		{"syscalls", "sys_enter_connect", "trace_connect"},
		{"syscalls", "sys_enter_clone", "trace_clone"},
	}

	var links []link.Link
	for _, h := range hooks {
		prog, ok := coll.Programs[h.progKey]
		if !ok {
			return fmt.Errorf("eBPF program %q missing from object file", h.progKey)
		}
		l, err := link.Tracepoint(h.group, h.name, prog, nil)
		if err != nil {
			return fmt.Errorf("attach tracepoint %s/%s: %w", h.group, h.name, err)
		}
		links = append(links, l)
		log.Printf("attached tracepoint: %s/%s", h.group, h.name)
	}
	defer func() {
		for _, l := range links {
			l.Close()
		}
	}()

	eventsMap, ok := coll.Maps["events"]
	if !ok {
		return fmt.Errorf("ring buffer map %q not found in eBPF object", "events")
	}

	rd, err := ringbuf.NewReader(eventsMap)
	if err != nil {
		return fmt.Errorf("open ring buffer reader: %w", err)
	}
	defer rd.Close()

	// Close the ring buffer reader when the pipeline shuts down so that
	// rd.Read() below unblocks and returns ringbuf.ErrClosed.
	// We do this here instead of re-subscribing to OS signals to avoid
	// conflicting with the signal handler in main().
	go func() {
		<-c.stopCh
		rd.Close()
	}()

	log.Println("SentinelGo: listening for kernel events")

	for {
		record, err := rd.Read()
		if err != nil {
			if err == ringbuf.ErrClosed {
				return nil
			}
			log.Printf("[collector] ring buffer read error: %v", err)
			continue
		}

		var event BpfEvent
		if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &event); err != nil {
			log.Printf("[collector] decode event: %v", err)
			continue
		}

		select {
		case c.EventCh <- event:
		default:
			// Channel full — drop the event rather than blocking the ring buffer reader.
		}
	}
}
