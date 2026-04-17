// ============================================================
// TOPIC 4 — eBPF C Program (sentinel.bpf.c)
// Hooks into execve, openat, and connect syscalls.
// Compiles to eBPF bytecode loaded by the Go userspace program.
//
// Build: clang -O2 -g -Wall -target bpf \
//          -D__TARGET_ARCH_x86 \
//          -I/usr/include/bpf \
//          -c sentinel.bpf.c -o sentinel.bpf.o
// ============================================================

//go:build ignore
// ^ This comment tells `go generate` to skip this file (it's C, not Go).

#include "vmlinux.h"           // kernel type definitions (generated via bpftool)
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

// ── Event struct shared between kernel and userspace ─────────
// MUST match the Go struct in internal/collector/types.go
struct event {
    __u32 pid;
    __u32 ppid;
    __u8  comm[16];       // process name (task_comm_len = 16)
    __u8  filename[64];   // file/path argument (truncated)
    __u32 syscall_id;     // 0=execve, 1=openat, 2=connect
    __u64 timestamp_ns;
};

// ── Ring buffer map — kernel writes, Go reads ────────────────
// Ring buffer is preferred over perf buffer for modern kernels (5.8+).
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24); // 16 MB ring buffer
} events SEC(".maps");

// ── Statistics map — counters per syscall type ───────────────
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 8);
    __type(key, __u32);
    __type(value, __u64);
} syscall_counts SEC(".maps");

// Helper: increment a counter in syscall_counts
static __always_inline void inc_counter(__u32 key) {
    __u64 *val = bpf_map_lookup_elem(&syscall_counts, &key);
    if (val) {
        __sync_fetch_and_add(val, 1);
    }
}

// ── Hook 1: execve (process execution) ───────────────────────
SEC("tracepoint/syscalls/sys_enter_execve")
int trace_execve(struct trace_event_raw_sys_enter *ctx) {
    struct event *e;
    struct task_struct *task;

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;

    task = (struct task_struct *)bpf_get_current_task();

    e->pid          = bpf_get_current_pid_tgid() >> 32;
    e->ppid         = BPF_CORE_READ(task, real_parent, tgid);
    e->syscall_id   = 0; // execve
    e->timestamp_ns = bpf_ktime_get_ns();

    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    // Read the filename argument (first arg to execve)
    const char *fname = (const char *)ctx->args[0];
    bpf_probe_read_user_str(e->filename, sizeof(e->filename), fname);

    bpf_ringbuf_submit(e, 0);
    inc_counter(0);
    return 0;
}

// ── Hook 2: openat (file access) ─────────────────────────────
SEC("tracepoint/syscalls/sys_enter_openat")
int trace_openat(struct trace_event_raw_sys_enter *ctx) {
    struct event *e;

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;

    e->pid          = bpf_get_current_pid_tgid() >> 32;
    e->syscall_id   = 1; // openat
    e->timestamp_ns = bpf_ktime_get_ns();

    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    // args[1] is the pathname for openat(dirfd, pathname, flags)
    const char *fname = (const char *)ctx->args[1];
    bpf_probe_read_user_str(e->filename, sizeof(e->filename), fname);

    bpf_ringbuf_submit(e, 0);
    inc_counter(1);
    return 0;
}

// ── Hook 3: connect (network connections) ────────────────────
SEC("tracepoint/syscalls/sys_enter_connect")
int trace_connect(struct trace_event_raw_sys_enter *ctx) {
    struct event *e;

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;

    e->pid          = bpf_get_current_pid_tgid() >> 32;
    e->syscall_id   = 2; // connect
    e->timestamp_ns = bpf_ktime_get_ns();

    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    bpf_ringbuf_submit(e, 0);
    inc_counter(2);
    return 0;
}

// ── Hook 4: clone/fork (process creation) ────────────────────
SEC("tracepoint/syscalls/sys_enter_clone")
int trace_clone(struct trace_event_raw_sys_enter *ctx) {
    struct event *e;

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;

    e->pid          = bpf_get_current_pid_tgid() >> 32;
    e->syscall_id   = 3; // clone/fork
    e->timestamp_ns = bpf_ktime_get_ns();

    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    bpf_ringbuf_submit(e, 0);
    inc_counter(3);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
