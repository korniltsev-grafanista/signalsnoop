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
#define EVENT_RT_SIGRETURN       9
#define EVENT_X64_RT_FRAME_FAILED 10

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

// Maximum number of stack probes
#define MAX_STACK_PROBES 4

// Error code for bad address (not in vmlinux.h)
#define EFAULT 14

// Single stack probe entry
struct stack_probe_entry {
    __s64 off;  // offset from sp (configured from userspace)
    __u64 val;  // value read at offset
    __s32 err;  // 0 on success, negative errno on failure
    __s32 _pad; // padding for alignment
};

// Probed stack values
struct stack_probe {
    struct stack_probe_entry entries[MAX_STACK_PROBES];
};

// Mirror of x86_64 sigcontext_64 for rt_sigframe capture
struct sigcontext_64_capture {
    __u64 r8, r9, r10, r11, r12, r13, r14, r15;
    __u64 di, si, bp, bx, dx, ax, cx, sp, ip, flags;
    __u16 cs, gs, fs, ss;
    __u64 err, trapno, oldmask, cr2;
    __u64 fpstate;
    __u64 reserved1[8];
};

// Mirror of stack_t
struct stack_t_capture {
    __u64 ss_sp;
    __s32 ss_flags;
    __s32 _pad;
    __u64 ss_size;
};

// Mirror of ucontext for rt_sigframe capture
struct ucontext_capture {
    __u64 uc_flags;
    __u64 uc_link;
    struct stack_t_capture uc_stack;
    struct sigcontext_64_capture uc_mcontext;
    __u64 uc_sigmask;
};

// Mirror of siginfo for rt_sigframe capture
struct siginfo_capture {
    __s32 si_signo;
    __s32 si_errno;
    __s32 si_code;
    __s32 _pad;
    // _sifields union - we capture the _sigfault variant
    __u64 si_addr;       // _sigfault._addr
    __u64 _reserved[14]; // rest of the 128-byte siginfo
};

// Full rt_sigframe capture (x86_64 only)
struct rt_sigframe_capture {
    __u64 pretcode;
    struct ucontext_capture uc;
    struct siginfo_capture info;
};

// Event-specific data for rt_sigreturn
struct rt_sigreturn_data {
    __u64 frame_addr;                    // Address of rt_sigframe on user stack
    __u8 read_success;                   // 1 if frame was successfully read
    __u8 _pad[7];
    struct rt_sigframe_capture frame;    // The captured frame data
};

// Stack probe offsets as constants (rewritten from userspace before loading)
volatile const __s64 stack_probe_off_0 = 0;
volatile const __s64 stack_probe_off_1 = -128;
volatile const __s64 stack_probe_off_2 = -568;
volatile const __s64 stack_probe_off_3 = -700;

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
    struct rt_sigreturn_data sigreturn_data;  // Valid for EVENT_RT_SIGRETURN
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
const struct rt_sigframe_capture *unused_rt_sigframe_capture __attribute__((unused));
const struct rt_sigreturn_data *unused_rt_sigreturn_data __attribute__((unused));
const struct sigcontext_64_capture *unused_sigcontext_64_capture __attribute__((unused));
const struct ucontext_capture *unused_ucontext_capture __attribute__((unused));
const struct siginfo_capture *unused_siginfo_capture __attribute__((unused));
const struct stack_t_capture *unused_stack_t_capture __attribute__((unused));

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

// Helper to probe userspace stack at a single offset
static __always_inline void probe_stack_offset(struct event *e, __u64 sp, int idx, __s64 off) {
    struct stack_probe_entry *entry = &e->stack_probe.entries[idx];
    entry->off = off;
    if (!e->regs_valid) {
        entry->err = -EFAULT;
        return;
    }
    entry->err = bpf_probe_read_user(&entry->val, sizeof(entry->val), (void *)(sp + off));
}

// Helper to probe userspace stack at specific offsets
static __always_inline void probe_user_stack(struct event *e) {
    __u64 sp = e->regs_valid ? e->regs.sp : 0;

    probe_stack_offset(e, sp, 0, stack_probe_off_0);
    probe_stack_offset(e, sp, 1, stack_probe_off_1);
    probe_stack_offset(e, sp, 2, stack_probe_off_2);
    probe_stack_offset(e, sp, 3, stack_probe_off_3);
}

// Read entire rt_sigframe from user stack (x86_64 only)
// The frame starts at sp - 8 because the signal handler's 'ret' instruction
// already popped the pretcode (return address) off the stack.
static __always_inline void read_rt_sigframe(struct event *e) {
    e->sigreturn_data.read_success = 0;

    if (!e->regs_valid) {
        return;
    }

    // Adjust for the popped return address (same as kernel: sp - sizeof(long))
    __u64 frame_addr = e->regs.sp - sizeof(__u64);
    e->sigreturn_data.frame_addr = frame_addr;

    // Read the entire rt_sigframe structure in one call
    int err = bpf_probe_read_user(&e->sigreturn_data.frame,
                                   sizeof(e->sigreturn_data.frame),
                                   (void *)frame_addr);
    if (err == 0) {
        e->sigreturn_data.read_success = 1;
    }
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

SEC("kprobe/__x64_sys_rt_sigreturn")
int BPF_KPROBE(kprobe_rt_sigreturn) {
    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        return 0;
    }
    fill_event(e, EVENT_RT_SIGRETURN);
    capture_stack(ctx, e);
    capture_user_regs(e);
    read_rt_sigframe(e);
    bpf_ringbuf_submit(e, 0);
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
