//go:build ignore

#include "headers/vmlinux.h"
#include "headers/bpf_helpers.h"
#include "headers/bpf_tracing.h"
#include "headers/bpf_core_read.h"

char __license[] SEC("license") = "GPL";

#define TASK_COMM_LEN 16
#define MAX_STACK_DEPTH 50

// Event types
#define EVENT_GET_SIGNAL_ENTRY   1
#define EVENT_GET_SIGNAL_RETURN  2
#define EVENT_VFS_COREDUMP       3
#define EVENT_DO_GROUP_EXIT      4
#define EVENT_FORCE_SIGSEGV      5
#define EVENT_SIGNAL_SETUP_FAILED 6
#define EVENT_FORCE_FATAL_SIG    7
#define EVENT_FORCE_SIG          8
#define EVENT_X64_RT_FRAME_FAILED 9

// Userspace registers structure (architecture-independent subset)
struct user_regs {
    __u64 ip;      // Instruction pointer (rip on x86_64, pc on arm64)
    __u64 sp;      // Stack pointer
    __u64 flags;   // Flags register (eflags on x86_64, pstate on arm64)
    // General purpose registers (named for x86_64, mapped from arm64)
    __u64 ax;      // rax / x0
    __u64 bx;      // rbx / x1
    __u64 cx;      // rcx / x2
    __u64 dx;      // rdx / x3
    __u64 si;      // rsi / x4
    __u64 di;      // rdi / x5
    __u64 bp;      // rbp / x29 (frame pointer)
    __u64 r8;      // r8 / x6
    __u64 r9;      // r9 / x7
    __u64 r10;     // r10 / x8
    __u64 r11;     // r11 / x9
    __u64 r12;     // r12 / x10
    __u64 r13;     // r13 / x11
    __u64 r14;     // r14 / x12
    __u64 r15;     // r15 / x13
};

// Stack probe offsets (negative = above stack pointer)
#define STACK_PROBE_OFF_0   0
#define STACK_PROBE_OFF_1   (-128)
#define STACK_PROBE_OFF_2   (-568)

// Error code for bad address (not in vmlinux.h)
#define EFAULT 14

// Probed stack values
struct stack_probe {
    __u64 val_0;       // value at sp+0
    __u64 val_m128;    // value at sp-128
    __u64 val_m568;    // value at sp-568
    __s32 err_0;       // 0 on success, negative errno on failure
    __s32 err_m128;
    __s32 err_m568;
};

// Event structure sent to userspace
struct event {
    __u32 pid;
    __u32 tid;
    __u64 timestamp;
    char comm[TASK_COMM_LEN];
    __u8 event_type;
    __s64 retval;
    __s32 stack_depth;
    __u64 stack[MAX_STACK_DEPTH];
    struct user_regs regs;
    __u8 regs_valid;
    struct stack_probe stack_probe;
};

// Ring buffer for events
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024); // 256 KB
} events SEC(".maps");

// Hash map to pass signal number from kprobe to kretprobe for x64_setup_rt_frame
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32);    // tid
    __type(value, __s32);  // sig
} x64_setup_rt_frame__signals SEC(".maps");

// Force BTF type export for bpf2go type generation
const struct event *unused_event __attribute__((unused));
const struct user_regs *unused_user_regs __attribute__((unused));
const struct stack_probe *unused_stack_probe __attribute__((unused));

// Helper to fill common event fields
static __always_inline void fill_event(struct event *e, __u8 event_type) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    e->pid = pid_tgid >> 32;
    e->tid = (__u32)pid_tgid;
    e->timestamp = bpf_ktime_get_ns();
    e->event_type = event_type;
    e->retval = 0;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
}

// Helper to capture kernel stack
static __always_inline void capture_stack(struct pt_regs *ctx, struct event *e) {
    long ret = bpf_get_stack(ctx, e->stack, sizeof(e->stack), 0);
    if (ret < 0) {
        e->stack_depth = 0;
    } else {
        e->stack_depth = ret / sizeof(__u64);
    }
}

// Helper to capture userspace registers
static __always_inline void capture_user_regs(struct event *e) {
    struct task_struct *task = bpf_get_current_task_btf();
    if (!task) {
        e->regs_valid = 0;
        return;
    }

    struct pt_regs *regs = (struct pt_regs *)bpf_task_pt_regs(task);
    if (!regs) {
        e->regs_valid = 0;
        return;
    }

#if defined(__TARGET_ARCH_x86)
    e->regs.ip = BPF_CORE_READ(regs, ip);
    e->regs.sp = BPF_CORE_READ(regs, sp);
    e->regs.flags = BPF_CORE_READ(regs, flags);
    e->regs.ax = BPF_CORE_READ(regs, ax);
    e->regs.bx = BPF_CORE_READ(regs, bx);
    e->regs.cx = BPF_CORE_READ(regs, cx);
    e->regs.dx = BPF_CORE_READ(regs, dx);
    e->regs.si = BPF_CORE_READ(regs, si);
    e->regs.di = BPF_CORE_READ(regs, di);
    e->regs.bp = BPF_CORE_READ(regs, bp);
    e->regs.r8 = BPF_CORE_READ(regs, r8);
    e->regs.r9 = BPF_CORE_READ(regs, r9);
    e->regs.r10 = BPF_CORE_READ(regs, r10);
    e->regs.r11 = BPF_CORE_READ(regs, r11);
    e->regs.r12 = BPF_CORE_READ(regs, r12);
    e->regs.r13 = BPF_CORE_READ(regs, r13);
    e->regs.r14 = BPF_CORE_READ(regs, r14);
    e->regs.r15 = BPF_CORE_READ(regs, r15);
#elif defined(__TARGET_ARCH_arm64)
    e->regs.ip = BPF_CORE_READ(regs, pc);
    e->regs.sp = BPF_CORE_READ(regs, sp);
    e->regs.flags = BPF_CORE_READ(regs, pstate);
    e->regs.ax = BPF_CORE_READ(regs, regs[0]);
    e->regs.bx = BPF_CORE_READ(regs, regs[1]);
    e->regs.cx = BPF_CORE_READ(regs, regs[2]);
    e->regs.dx = BPF_CORE_READ(regs, regs[3]);
    e->regs.si = BPF_CORE_READ(regs, regs[4]);
    e->regs.di = BPF_CORE_READ(regs, regs[5]);
    e->regs.r8 = BPF_CORE_READ(regs, regs[6]);
    e->regs.r9 = BPF_CORE_READ(regs, regs[7]);
    e->regs.r10 = BPF_CORE_READ(regs, regs[8]);
    e->regs.r11 = BPF_CORE_READ(regs, regs[9]);
    e->regs.r12 = BPF_CORE_READ(regs, regs[10]);
    e->regs.r13 = BPF_CORE_READ(regs, regs[11]);
    e->regs.r14 = BPF_CORE_READ(regs, regs[12]);
    e->regs.r15 = BPF_CORE_READ(regs, regs[13]);
    e->regs.bp = BPF_CORE_READ(regs, regs[29]); // frame pointer
#endif
    e->regs_valid = 1;
}

// Helper to probe userspace stack at specific offsets
static __always_inline void probe_user_stack(struct event *e) {
    if (!e->regs_valid) {
        e->stack_probe.err_0 = -EFAULT;
        e->stack_probe.err_m128 = -EFAULT;
        e->stack_probe.err_m568 = -EFAULT;
        return;
    }

    __u64 sp = e->regs.sp;

    // Probe at sp+0
    e->stack_probe.err_0 = bpf_probe_read_user(&e->stack_probe.val_0,
                                                sizeof(e->stack_probe.val_0),
                                                (void *)(sp + STACK_PROBE_OFF_0));

    // Probe at sp-128
    e->stack_probe.err_m128 = bpf_probe_read_user(&e->stack_probe.val_m128,
                                                   sizeof(e->stack_probe.val_m128),
                                                   (void *)(sp + STACK_PROBE_OFF_1));

    // Probe at sp-568
    e->stack_probe.err_m568 = bpf_probe_read_user(&e->stack_probe.val_m568,
                                                   sizeof(e->stack_probe.val_m568),
                                                   (void *)(sp + STACK_PROBE_OFF_2));
}

// Helper to emit a full event with stack, regs, and stack probe
static __always_inline void emit_event(struct pt_regs *ctx, __u8 event_type, __s64 retval) {
    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        return;
    }

    fill_event(e, event_type);
    e->retval = retval;
    capture_stack(ctx, e);
    capture_user_regs(e);
    probe_user_stack(e);

    bpf_ringbuf_submit(e, 0);
}

SEC("kprobe/get_signal")
int BPF_KPROBE(kprobe_get_signal) {
    emit_event(ctx, EVENT_GET_SIGNAL_ENTRY, 0);
    return 0;
}

SEC("kretprobe/get_signal")
int BPF_KRETPROBE(kretprobe_get_signal, long ret) {
    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        return 0;
    }

    fill_event(e, EVENT_GET_SIGNAL_RETURN);
    e->retval = ret;
    e->stack_depth = 0;
    e->regs_valid = 0;

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("kprobe/vfs_coredump")
int BPF_KPROBE(kprobe_vfs_coredump) {
    emit_event(ctx, EVENT_VFS_COREDUMP, 0);
    return 0;
}

SEC("kprobe/do_coredump")
int BPF_KPROBE(kprobe_do_coredump) {
    emit_event(ctx, EVENT_VFS_COREDUMP, 0);
    return 0;
}

SEC("kprobe/do_group_exit")
int BPF_KPROBE(kprobe_do_group_exit) {
    emit_event(ctx, EVENT_DO_GROUP_EXIT, 0);
    return 0;
}

SEC("kprobe/force_sigsegv")
int BPF_KPROBE(kprobe_force_sigsegv) {
    emit_event(ctx, EVENT_FORCE_SIGSEGV, 0);
    return 0;
}

// void signal_setup_done(int failed, struct ksignal *ksig, int stepping)
SEC("kprobe/signal_setup_done")
int BPF_KPROBE(kprobe_signal_setup_done, int failed, struct ksignal *ksig, int stepping) {
    if (failed == 0) {
        return 0;
    }
    emit_event(ctx, EVENT_SIGNAL_SETUP_FAILED, BPF_CORE_READ(ksig, sig));
    return 0;
}

SEC("kprobe/force_fatal_sig")
int BPF_KPROBE(kprobe_force_fatal_sig, int sig) {
    emit_event(ctx, EVENT_FORCE_FATAL_SIG, sig);
    return 0;
}

SEC("kprobe/force_sig")
int BPF_KPROBE(kprobe_force_sig, int sig) {
    emit_event(ctx, EVENT_FORCE_SIG, sig);
    return 0;
}

// int x64_setup_rt_frame(struct ksignal *ksig, struct pt_regs *regs)
// Store signal number in hash map for retrieval in kretprobe
SEC("kprobe/x64_setup_rt_frame")
int BPF_KPROBE(kprobe_x64_setup_rt_frame, struct ksignal *ksig) {
    __u32 tid = (__u32)bpf_get_current_pid_tgid();
    __s32 sig = BPF_CORE_READ(ksig, sig);
    bpf_map_update_elem(&x64_setup_rt_frame__signals, &tid, &sig, BPF_ANY);
    return 0;
}

// x64_setup_rt_frame returns 0 on success, negative on failure
SEC("kretprobe/x64_setup_rt_frame")
int BPF_KRETPROBE(kretprobe_x64_setup_rt_frame, int ret) {
    __u32 tid = (__u32)bpf_get_current_pid_tgid();
    __s32 *sig = bpf_map_lookup_elem(&x64_setup_rt_frame__signals, &tid);
    __s32 signal = sig ? *sig : 0;
    bpf_map_delete_elem(&x64_setup_rt_frame__signals, &tid);

    if (ret == 0) {
        return 0;
    }
    emit_event(ctx, EVENT_X64_RT_FRAME_FAILED, signal);
    return 0;
}

// Raw tracepoint with BTF - receives task_struct pointer directly
SEC("tp_btf/sched_process_free")
int BPF_PROG(tracepoint__sched_process_free, struct task_struct *task) {
    // __s32 pid = BPF_CORE_READ(task, pid);
    // bpf_printk("sched_process_free: pid=%d", pid);
    return 0;
}
