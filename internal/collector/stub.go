// ============================================================
// internal/collector/stub.go
// Stub event generator — replaces RunStub inline to avoid
// import cycle and keep ebpf_loader.go clean of "time" import
// when building for real kernel targets.
// ============================================================
package collector

import (
	"log"
	"time"
)

// RunStub emits synthetic BpfEvents so the full pipeline can be
// tested on any machine that doesn't have eBPF support.
func (c *Collector) RunStubEvents() {
	log.Println("🧪 Running STUB collector — synthetic events, no real eBPF")

	syscalls := []SyscallID{SyscallExecve, SyscallOpenat, SyscallConnect, SyscallClone}
	procs := []string{"bash", "curl", "python3", "sshd", "cat", "wget", "nmap"}
	files := []string{
		"/bin/bash", "/etc/passwd", "/tmp/data",
		"/home/user/.ssh/id_rsa", "/dev/null", "/etc/shadow",
	}

	ticker := time.NewTicker(150 * time.Millisecond)
	defer ticker.Stop()

	i := 0
	for {
		select {
		case <-c.stopCh:
			log.Println("[stub] stopped")
			return
		case <-ticker.C:
			proc := procs[i%len(procs)]
			sc := syscalls[i%len(syscalls)]
			file := files[i%len(files)]

			var comm [16]byte
			var fname [64]byte
			copy(comm[:], proc)
			copy(fname[:], file)

			evt := BpfEvent{
				PID:         uint32(1000 + i%500),
				PPID:        1000,
				Comm:        comm,
				Filename:    fname,
				SyscallID:   sc,
				TimestampNS: uint64(time.Now().UnixNano()),
			}

			select {
			case c.EventCh <- evt:
			default:
				// pipeline channel full — drop
			}
			i++
		}
	}
}

// Stop signals the stub (or real) collector to halt.
func (c *Collector) Stop() {
	select {
	case <-c.stopCh: // already closed
	default:
		close(c.stopCh)
	}
}
