// ============================================================
// internal/collector/types.go
// Shared event and feature types.
// The BpfEvent struct MUST mirror the C struct in sentinel.bpf.c
// ============================================================
package collector

// SyscallID maps integer IDs (from eBPF) to human-readable names.
type SyscallID uint32

const (
	SyscallExecve  SyscallID = 0
	SyscallOpenat  SyscallID = 1
	SyscallConnect SyscallID = 2
	SyscallClone   SyscallID = 3
)

var SyscallNames = map[SyscallID]string{
	SyscallExecve:  "execve",
	SyscallOpenat:  "openat",
	SyscallConnect: "connect",
	SyscallClone:   "clone",
}

// BpfEvent is the raw event received from the eBPF ring buffer.
// Field layout MUST match struct event in sentinel.bpf.c (byte-for-byte).
type BpfEvent struct {
	PID         uint32
	PPID        uint32
	Comm        [16]byte // process name
	Filename    [64]byte // file or path argument
	SyscallID   SyscallID
	TimestampNS uint64
}

// ProcessName returns the null-terminated comm field as a Go string.
func (e *BpfEvent) ProcessName() string {
	for i, b := range e.Comm {
		if b == 0 {
			return string(e.Comm[:i])
		}
	}
	return string(e.Comm[:])
}

// FilePath returns the null-terminated filename field as a Go string.
func (e *BpfEvent) FilePath() string {
	for i, b := range e.Filename {
		if b == 0 {
			return string(e.Filename[:i])
		}
	}
	return string(e.Filename[:])
}

// SyscallName returns the human-readable syscall name.
func (e *BpfEvent) SyscallName() string {
	if name, ok := SyscallNames[e.SyscallID]; ok {
		return name
	}
	return "unknown"
}

// Sensitive file prefixes — hits on these are flagged.
var SensitivePrefixes = []string{
	"/etc/passwd",
	"/etc/shadow",
	"/etc/sudoers",
	"/root/",
	"/home/",
	"/.ssh/",
	"/proc/",
	"/sys/",
}
