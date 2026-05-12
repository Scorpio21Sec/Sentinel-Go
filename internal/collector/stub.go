// Package collector — stub event generator for testing without a real kernel.
package collector

import (
	"log"
	"time"
)

// RunStubEvents emits synthetic BpfEvents so the full pipeline can be
// exercised on any machine without eBPF support (CI, macOS, VMs).
func (c *Collector) RunStubEvents() {
	log.Println("[stub] starting synthetic event stream")

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
				// pipeline full — drop rather than blocking
			}
			i++
		}
	}
}

// Stop signals the collector to halt.  Safe to call multiple times.
func (c *Collector) Stop() {
	select {
	case <-c.stopCh: // already closed
	default:
		close(c.stopCh)
	}
}
