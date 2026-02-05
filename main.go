package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/kallsyms"
)

const maxStackProbes = 4

var (
	flagAll             = flag.Bool("all", false, "Enable all probes")
	flagGetSignal       = flag.Bool("get-signal", false, "Enable get_signal kprobe/kretprobe")
	flagVfsCoredump     = flag.Bool("vfs-coredump", true, "Enable vfs_coredump kprobe")
	flagDoGroupExit     = flag.Bool("do-group-exit", false, "Enable do_group_exit kprobe")
	flagForceSigsegv    = flag.Bool("force-sigsegv", true, "Enable force_sigsegv kprobe")
	flagSignalSetupDone = flag.Bool("signal-setup-done", true, "Enable signal_setup_done kprobe (fires on failed signal setup)")
	flagForceFatalSig   = flag.Bool("force-fatal-sig", true, "Enable force_fatal_sig kprobe")
	flagForceSig        = flag.Bool("force-sig", true, "Enable force_sig kprobe")
	flagRtSigreturn     = flag.Bool("rt-sigreturn", false, "Enable rt_sigreturn kprobe")
	flagX64SetupRtFrame         = flag.Bool("x64-setup-rt-frame", true, "Enable x64_setup_rt_frame kretprobe (fires on failure)")
	flagCopySiginfoToUser       = flag.Bool("copy-siginfo-to-user", true, "Enable copy_siginfo_to_user kretprobe (fires on failure)")
	flagSetupSignalShadowStack  = flag.Bool("setup-signal-shadow-stack", true, "Enable setup_signal_shadow_stack kretprobe (fires on failure)")
	flagGetSigframe             = flag.Bool("get-sigframe", true, "Enable get_sigframe kretprobe (fires on failure)")
	flagStackProbes             = flag.String("stack-probes", "0,-128,-568,-700", "Comma-separated list of stack probe offsets from sp (max 4)")
	flagMapsPattern     = flag.String("maps-pattern", "", "Regex pattern to match process cmdline or exe for maps monitoring (empty = disabled)")
	flagMapsTTLSec      = flag.Int("maps-ttl", 5, "Seconds to keep maps cached after process death")
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -no-strip -cflags "-O2 -g -Wall -Werror" -target amd64 -type event -type user_regs -type stack_probe -type stack_probe_entry -type rt_sigframe_capture -type rt_sigreturn_data -type sigcontext_64_capture -type ucontext_capture -type siginfo_capture -type stack_t_capture signalsnoop ./bpf/signalsnoop.c
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -no-strip -cflags "-O2 -g -Wall -Werror" -target arm64 -type event -type user_regs -type stack_probe -type stack_probe_entry -type rt_sigframe_capture -type rt_sigreturn_data -type sigcontext_64_capture -type ucontext_capture -type siginfo_capture -type stack_t_capture signalsnoop ./bpf/signalsnoop.c

const maxStackDepth = 50

// SA_RESTORER - x86_64 signal flag indicating sa_restorer is set
const SA_RESTORER = 0x04000000

// Event types matching the eBPF code
const (
	EventGetSignalEntry    = 1
	EventGetSignalReturn   = 2
	EventVfsCoredump       = 3
	EventDoGroupExit       = 4
	EventForceSigsegv      = 5
	EventSignalSetupFailed = 6
	EventForceFatalSig     = 7
	EventForceSig          = 8
	EventRtSigreturn                   = 9
	EventX64RtFrameFailed              = 10
	EventCopySiginfoToUserFailed       = 11
	EventSetupSignalShadowStackFailed  = 12
	EventGetSigframeFailed             = 13
)

var resolver *kallsyms.KAllSyms
var mapsCache *ProcessMapsCache
var mapsPattern *regexp.Regexp

// eventInfo maps event types to their display format
var eventInfo = map[uint8]struct {
	name    string
	showSig bool
}{
	EventGetSignalEntry:    {"get_signal", false},
	EventVfsCoredump:       {"vfs_coredump", false},
	EventDoGroupExit:       {"do_group_exit", false},
	EventForceSigsegv:      {"force_sigsegv", false},
	EventSignalSetupFailed: {"signal_setup_done failed", true},
	EventForceFatalSig:     {"force_fatal_sig", true},
	EventForceSig:          {"force_sig", true},
	EventRtSigreturn:                  {"rt_sigreturn", false},
	EventX64RtFrameFailed:             {"x64_setup_rt_frame failed", true},
	EventCopySiginfoToUserFailed:      {"copy_siginfo_to_user", true},
	EventSetupSignalShadowStackFailed: {"setup_signal_shadow_stack failed", true},
	EventGetSigframeFailed:            {"get_sigframe", true},
}

func parseStackProbes(s string) ([]int64, error) {
	parts := strings.Split(s, ",")
	if len(parts) > maxStackProbes {
		return nil, fmt.Errorf("too many stack probes (max %d)", maxStackProbes)
	}
	offsets := make([]int64, maxStackProbes)
	for i := 0; i < maxStackProbes; i++ {
		if i < len(parts) {
			v, err := strconv.ParseInt(strings.TrimSpace(parts[i]), 10, 64)
			if err != nil {
				return nil, fmt.Errorf("invalid stack probe offset %q: %v", parts[i], err)
			}
			offsets[i] = v
		}
	}
	return offsets, nil
}

func main() {
	flag.Parse()

	if *flagAll {
		*flagGetSignal = true
		*flagVfsCoredump = true
		*flagDoGroupExit = true
		*flagForceSigsegv = true
		*flagSignalSetupDone = true
		*flagForceFatalSig = true
		*flagForceSig = true
		*flagRtSigreturn = true
		*flagX64SetupRtFrame = true
		*flagCopySiginfoToUser = true
		*flagSetupSignalShadowStack = true
		*flagGetSigframe = true
	}

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("Failed to remove memlock limit: %v", err)
	}

	var err error
	resolver, err = kallsyms.NewKAllSyms()
	if err != nil {
		log.Printf("Warning: Failed to initialize kallsyms resolver: %v", err)
		log.Printf("Stack traces will show raw addresses only")
	}

	stackProbeOffsets, err := parseStackProbes(*flagStackProbes)
	if err != nil {
		log.Fatalf("Failed to parse stack probes: %v", err)
	}

	// Load the BPF spec and rewrite constants
	spec, err := loadSignalsnoop()
	if err != nil {
		log.Fatalf("Failed to load eBPF spec: %v", err)
	}

	// Rewrite stack probe offset constants
	if err := spec.RewriteConstants(map[string]interface{}{
		"stack_probe_off_0": stackProbeOffsets[0],
		"stack_probe_off_1": stackProbeOffsets[1],
		"stack_probe_off_2": stackProbeOffsets[2],
		"stack_probe_off_3": stackProbeOffsets[3],
	}); err != nil {
		log.Fatalf("Failed to rewrite stack probe constants: %v", err)
	}

	objs := signalsnoopObjects{}
	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			log.Fatalf("Failed to load eBPF objects: %v\n%+v", err, ve)
		}
		log.Fatalf("Failed to load eBPF objects: %v", err)
	}
	defer objs.Close()

	var links []link.Link

	attachKprobe := func(enabled *bool, name string, prog *ebpf.Program) bool {
		if !*enabled {
			return false
		}
		l, err := link.Kprobe(name, prog, nil)
		if err != nil {
			log.Printf("[FAIL] kprobe/%s: %v", name, err)
			return false
		}
		links = append(links, l)
		log.Printf("[OK] kprobe/%s", name)
		return true
	}

	attachKretprobe := func(enabled *bool, name string, prog *ebpf.Program) bool {
		if !*enabled {
			return false
		}
		l, err := link.Kretprobe(name, prog, nil)
		if err != nil {
			log.Printf("[FAIL] kretprobe/%s: %v", name, err)
			return false
		}
		links = append(links, l)
		log.Printf("[OK] kretprobe/%s", name)
		return true
	}

	attachKprobe(flagGetSignal, "get_signal", objs.KprobeGetSignal)
	attachKretprobe(flagGetSignal, "get_signal", objs.KretprobeGetSignal)

	// Try vfs_coredump first, fall back to do_coredump if not available
	if *flagVfsCoredump {
		if !attachKprobe(flagVfsCoredump, "vfs_coredump", objs.KprobeVfsCoredump) {
			log.Printf("Trying fallback do_coredump...")
			attachKprobe(flagVfsCoredump, "do_coredump", objs.KprobeDoCoredump)
		}
	}

	attachKprobe(flagDoGroupExit, "do_group_exit", objs.KprobeDoGroupExit)
	attachKprobe(flagForceSigsegv, "force_sigsegv", objs.KprobeForceSigsegv)
	attachKprobe(flagSignalSetupDone, "signal_setup_done", objs.KprobeSignalSetupDone)
	attachKprobe(flagForceFatalSig, "force_fatal_sig", objs.KprobeForceFatalSig)
	attachKprobe(flagForceSig, "force_sig", objs.KprobeForceSig)
	attachKprobe(flagRtSigreturn, "__x64_sys_rt_sigreturn", objs.KprobeRtSigreturn)
	attachKprobe(flagX64SetupRtFrame, "x64_setup_rt_frame", objs.KprobeX64SetupRtFrame)
	attachKretprobe(flagX64SetupRtFrame, "x64_setup_rt_frame", objs.KretprobeX64SetupRtFrame)
	attachKretprobe(flagCopySiginfoToUser, "copy_siginfo_to_user", objs.KretprobeCopySiginfoToUser)
	attachKretprobe(flagSetupSignalShadowStack, "setup_signal_shadow_stack", objs.KretprobeSetupSignalShadowStack)
	attachKretprobe(flagGetSigframe, "get_sigframe", objs.KretprobeGetSigframe)

	// Attach sched_process_free raw tracepoint
	if tp, err := link.AttachTracing(link.TracingOptions{Program: objs.TracepointSchedProcessFree}); err != nil {
		log.Printf("[FAIL] tp_btf/sched_process_free: %v", err)
	} else {
		links = append(links, tp)
		log.Printf("[OK] tp_btf/sched_process_free")
	}

	if len(links) == 0 {
		log.Fatal("No probes enabled. Use -h to see available options.")
	}

	defer func() {
		for _, l := range links {
			l.Close()
		}
	}()

	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		log.Fatalf("Failed to create ring buffer reader: %v", err)
	}
	defer rd.Close()

	// Initialize process maps monitoring
	var cancelMapsScanner context.CancelFunc
	if *flagMapsPattern != "" {
		var err error
		mapsPattern, err = regexp.Compile(*flagMapsPattern)
		if err != nil {
			log.Fatalf("Invalid maps-pattern regex: %v", err)
		}
		mapsCache = NewProcessMapsCache()
		var ctx context.Context
		ctx, cancelMapsScanner = context.WithCancel(context.Background())
		go RunProcessScanner(ctx, mapsPattern, time.Duration(*flagMapsTTLSec)*time.Second, mapsCache)
		log.Printf("Process maps monitoring enabled for pattern: %s", *flagMapsPattern)
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	fmt.Println("Tracing signal events... Press Ctrl+C to stop.")
	fmt.Println()

	// Buffered channel for passing raw event bytes from reader to handler
	// Large buffer to avoid dropping events during bursts
	eventChan := make(chan []byte, 100000)

	// Multiple event handler goroutines for parallel parsing
	const numHandlers = 4
	for i := 0; i < numHandlers; i++ {
		go func() {
			for rawEvent := range eventChan {
				// Use unsafe pointer cast instead of slow binary.Read
				if len(rawEvent) < int(unsafe.Sizeof(signalsnoopEvent{})) {
					log.Printf("Event too small: %d bytes", len(rawEvent))
					continue
				}
				event := *(*signalsnoopEvent)(unsafe.Pointer(&rawEvent[0]))
				printEvent(&event)
			}
		}()
	}

	// Event reader goroutine - minimal work, just copy bytes
	go func() {
		for {
			record, err := rd.Read()
			if err != nil {
				if errors.Is(err, ringbuf.ErrClosed) {
					close(eventChan)
					return
				}
				log.Printf("Error reading from ring buffer: %v", err)
				continue
			}

			// Copy raw bytes to avoid holding reference to ring buffer memory
			rawCopy := make([]byte, len(record.RawSample))
			copy(rawCopy, record.RawSample)

			// Non-blocking send to channel
			select {
			case eventChan <- rawCopy:
			default:
				log.Printf("Event channel full, dropping event")
			}
		}
	}()

	<-sig
	if cancelMapsScanner != nil {
		cancelMapsScanner()
	}
	fmt.Println("\nExiting...")
}

func printEvent(e *signalsnoopEvent) {
	comm := commToString(e.Comm[:])

	if e.EventType == EventGetSignalReturn {
		fmt.Printf("get_signal returned: %d\n\n", e.Retval)
		return
	}

	if e.EventType == EventRtSigreturn {
		// Skip events from self
		if e.Pid == uint32(os.Getpid()) {
			return
		}
		// If maps-pattern is set, only print for matching processes (match exe only, not cmdline args)
		if mapsPattern != nil {
			exe := ReadProcExe(e.Pid)
			if !mapsPattern.MatchString(exe) {
				return
			}
		}
		fmt.Printf("rt_sigreturn for tgid=%d tid=%d (%s)\n", e.Pid, e.Tid, comm)
		printStack(e)
		printRegs(e)
		printRtSigreturn(e)
		fmt.Println()
		return
	}

	if e.EventType == EventGetSigframeFailed {
		// Skip events from self
		if e.Pid == uint32(os.Getpid()) {
			return
		}
		// If maps-pattern is set, only print for matching processes (match exe only, not cmdline args)
		if mapsPattern != nil {
			exe := ReadProcExe(e.Pid)
			if !mapsPattern.MatchString(exe) {
				return
			}
		}
		fmt.Printf("get_sigframe for tgid=%d tid=%d (%s), ret=0x%x\n", e.Pid, e.Tid, comm, e.Retval)
		printStack(e)
		printRegs(e)
		fmt.Println()
		return
	}

	if e.EventType == EventCopySiginfoToUserFailed {
		// Skip events from self
		if e.Pid == uint32(os.Getpid()) {
			return
		}
		// If maps-pattern is set, only print for matching processes (match exe only, not cmdline args)
		if mapsPattern != nil {
			exe := ReadProcExe(e.Pid)
			if !mapsPattern.MatchString(exe) {
				return
			}
		}
		fmt.Printf("copy_siginfo_to_user for tgid=%d tid=%d (%s), ret=%d\n", e.Pid, e.Tid, comm, e.Retval)
		printStack(e)
		printRegs(e)
		fmt.Println()
		return
	}

	info, ok := eventInfo[e.EventType]
	if !ok {
		fmt.Printf("unknown event type %d for tgid=%d tid=%d (%s)\n", e.EventType, e.Pid, e.Tid, comm)
		return
	}

	if info.showSig {
		fmt.Printf("%s for tgid=%d tid=%d (%s), sig=%d\n", info.name, e.Pid, e.Tid, comm, e.Retval)
	} else {
		fmt.Printf("%s for tgid=%d tid=%d (%s)\n", info.name, e.Pid, e.Tid, comm)
	}

	// Print sa_flags for x64_setup_rt_frame failures
	if e.EventType == EventX64RtFrameFailed {
		hasRestorer := e.SaFlags&SA_RESTORER != 0
		fmt.Printf("    sa_flags: 0x%x (SA_RESTORER=%v)\n", e.SaFlags, hasRestorer)
	}
	printStack(e)
	printRegs(e)
	printStackProbe(e)
	if e.EventType == EventVfsCoredump {
		printCachedMaps(e.Pid, e)
	}
	fmt.Println()
}

func printStack(e *signalsnoopEvent) {
	if e.StackDepth <= 0 {
		return
	}

	depth := int(e.StackDepth)
	if depth > maxStackDepth {
		depth = maxStackDepth
	}

	for i := 0; i < depth; i++ {
		addr := e.Stack[i]
		if addr == 0 {
			break
		}

		sym := resolveSymbol(addr)
		if sym != "" {
			fmt.Printf("        %s\n", sym)
		} else {
			fmt.Printf("        0x%x\n", addr)
		}
	}
}

func printRegs(e *signalsnoopEvent) {
	if e.RegsValid == 0 {
		return
	}

	r := &e.Regs
	fmt.Println("    Userspace registers:")
	fmt.Printf("        rip: 0x%016x  rsp: 0x%016x  flags: 0x%016x\n", r.Ip, r.Sp, r.Flags)
	fmt.Printf("        rax: 0x%016x  rbx: 0x%016x  rcx:   0x%016x\n", r.Ax, r.Bx, r.Cx)
	fmt.Printf("        rdx: 0x%016x  rsi: 0x%016x  rdi:   0x%016x\n", r.Dx, r.Si, r.Di)
	fmt.Printf("        rbp: 0x%016x  r8:  0x%016x  r9:    0x%016x\n", r.Bp, r.R8, r.R9)
	fmt.Printf("        r10: 0x%016x  r11: 0x%016x  r12:   0x%016x\n", r.R10, r.R11, r.R12)
	fmt.Printf("        r13: 0x%016x  r14: 0x%016x  r15:   0x%016x\n", r.R13, r.R14, r.R15)
}

func printStackProbe(e *signalsnoopEvent) {
	if e.RegsValid == 0 {
		return
	}

	sp := e.Regs.Sp
	fmt.Println("    Stack probe:")

	for i := 0; i < maxStackProbes; i++ {
		entry := &e.StackProbe.Entries[i]
		addr := uint64(int64(sp) + entry.Off)
		if entry.Err == 0 {
			fmt.Printf("        [sp%+d] 0x%016x: 0x%016x\n", entry.Off, addr, entry.Val)
		} else {
			fmt.Printf("        [sp%+d] 0x%016x: <failed: %d>\n", entry.Off, addr, entry.Err)
		}
	}
}

func printCachedMaps(pid uint32, e *signalsnoopEvent) {
	if mapsCache == nil {
		return
	}
	if maps, ok := mapsCache.Get(pid); ok {
		fmt.Println("    Process maps:")
		for _, line := range strings.Split(maps, "\n") {
			if line != "" {
				regInfo := findRegistersInMapLine(line, e)
				if regInfo != "" {
					fmt.Printf("        %s  <-- %s\n", line, regInfo)
				} else {
					fmt.Printf("        %s\n", line)
				}
			}
		}
	} else {
		fmt.Println("    no mappings found")
	}
}

// parseMapRange extracts the start and end addresses from a /proc/pid/maps line
// Line format: "55e8f4600000-55e8f4628000 r--p ..."
func parseMapRange(line string) (start, end uint64, ok bool) {
	parts := strings.Fields(line)
	if len(parts) < 1 {
		return 0, 0, false
	}
	addrRange := parts[0]
	idx := strings.Index(addrRange, "-")
	if idx < 0 {
		return 0, 0, false
	}
	start, err1 := strconv.ParseUint(addrRange[:idx], 16, 64)
	end, err2 := strconv.ParseUint(addrRange[idx+1:], 16, 64)
	if err1 != nil || err2 != nil {
		return 0, 0, false
	}
	return start, end, true
}

// findRegistersInMapLine returns a string listing which registers point into this map range
func findRegistersInMapLine(line string, e *signalsnoopEvent) string {
	if e.RegsValid == 0 {
		return ""
	}
	start, end, ok := parseMapRange(line)
	if !ok {
		return ""
	}

	r := &e.Regs
	regs := []struct {
		name string
		val  uint64
	}{
		{"rip", r.Ip},
		{"rsp", r.Sp},
		{"rbp", r.Bp},
		{"rax", r.Ax},
		{"rbx", r.Bx},
		{"rcx", r.Cx},
		{"rdx", r.Dx},
		{"rsi", r.Si},
		{"rdi", r.Di},
		{"r8", r.R8},
		{"r9", r.R9},
		{"r10", r.R10},
		{"r11", r.R11},
		{"r12", r.R12},
		{"r13", r.R13},
		{"r14", r.R14},
		{"r15", r.R15},
	}

	var matched []string
	for _, reg := range regs {
		if reg.val >= start && reg.val < end {
			matched = append(matched, fmt.Sprintf("%s=0x%x", reg.name, reg.val))
		}
	}

	return strings.Join(matched, ", ")
}

func signalName(signo int32) string {
	names := map[int32]string{
		1: "SIGHUP", 2: "SIGINT", 3: "SIGQUIT", 4: "SIGILL",
		5: "SIGTRAP", 6: "SIGABRT", 7: "SIGBUS", 8: "SIGFPE",
		9: "SIGKILL", 10: "SIGUSR1", 11: "SIGSEGV", 12: "SIGUSR2",
		13: "SIGPIPE", 14: "SIGALRM", 15: "SIGTERM", 16: "SIGSTKFLT",
		17: "SIGCHLD", 18: "SIGCONT", 19: "SIGSTOP", 20: "SIGTSTP",
		21: "SIGTTIN", 22: "SIGTTOU", 23: "SIGURG", 24: "SIGXCPU",
		25: "SIGXFSZ", 26: "SIGVTALRM", 27: "SIGPROF", 28: "SIGWINCH",
		29: "SIGIO", 30: "SIGPWR", 31: "SIGSYS",
	}
	if name, ok := names[signo]; ok {
		return fmt.Sprintf("%s(%d)", name, signo)
	}
	return fmt.Sprintf("SIG(%d)", signo)
}

func printRtSigreturn(e *signalsnoopEvent) {
	data := &e.SigreturnData
	if data.ReadSuccess == 0 {
		fmt.Println("    rt_sigframe: <failed to read>")
		return
	}

	frame := &data.Frame
	uc := &frame.Uc
	sc := &uc.UcMcontext
	info := &frame.Info

	fmt.Printf("    rt_sigframe at 0x%x:\n", data.FrameAddr)
	fmt.Printf("        pretcode: 0x%x\n", frame.Pretcode)

	// Signal info
	fmt.Printf("    siginfo:\n")
	fmt.Printf("        si_signo: %d (%s)\n", info.SiSigno, signalName(info.SiSigno))
	fmt.Printf("        si_errno: %d\n", info.SiErrno)
	fmt.Printf("        si_code:  %d\n", info.SiCode)
	if info.SiSigno == 11 || info.SiSigno == 7 { // SIGSEGV or SIGBUS
		fmt.Printf("        si_addr:  0x%x\n", info.SiAddr)
	}

	// ucontext
	fmt.Printf("    ucontext:\n")
	fmt.Printf("        uc_flags: 0x%x\n", uc.UcFlags)
	fmt.Printf("        uc_link:  0x%x\n", uc.UcLink)
	fmt.Printf("        uc_stack: ss_sp=0x%x ss_flags=%d ss_size=%d\n",
		uc.UcStack.SsSp, uc.UcStack.SsFlags, uc.UcStack.SsSize)
	fmt.Printf("        uc_sigmask: 0x%x\n", uc.UcSigmask)

	// Saved registers (sigcontext_64)
	fmt.Printf("    uc_mcontext (saved registers to restore):\n")
	fmt.Printf("        rip: 0x%016x  rsp: 0x%016x  flags: 0x%016x\n", sc.Ip, sc.Sp, sc.Flags)
	fmt.Printf("        rax: 0x%016x  rbx: 0x%016x  rcx:   0x%016x\n", sc.Ax, sc.Bx, sc.Cx)
	fmt.Printf("        rdx: 0x%016x  rsi: 0x%016x  rdi:   0x%016x\n", sc.Dx, sc.Si, sc.Di)
	fmt.Printf("        rbp: 0x%016x  r8:  0x%016x  r9:    0x%016x\n", sc.Bp, sc.R8, sc.R9)
	fmt.Printf("        r10: 0x%016x  r11: 0x%016x  r12:   0x%016x\n", sc.R10, sc.R11, sc.R12)
	fmt.Printf("        r13: 0x%016x  r14: 0x%016x  r15:   0x%016x\n", sc.R13, sc.R14, sc.R15)
	fmt.Printf("        cs: 0x%x  gs: 0x%x  fs: 0x%x  ss: 0x%x\n", sc.Cs, sc.Gs, sc.Fs, sc.Ss)
	fmt.Printf("        err: 0x%x  trapno: %d  oldmask: 0x%x  cr2: 0x%x\n",
		sc.Err, sc.Trapno, sc.Oldmask, sc.Cr2)
}

func resolveSymbol(addr uint64) string {
	if resolver == nil {
		return ""
	}
	return resolver.LookupByInstructionPointer(addr)
}

func commToString(comm []int8) string {
	b := unsafe.Slice((*byte)(unsafe.Pointer(unsafe.SliceData(comm))), len(comm))
	n := bytes.IndexByte(b, 0)
	if n < 0 {
		n = len(b)
	}
	return unsafe.String(unsafe.SliceData(b), n)
}
