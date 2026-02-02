package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/kallsyms"
)

var (
	flagAll             = flag.Bool("all", false, "Enable all probes")
	flagGetSignal       = flag.Bool("get-signal", false, "Enable get_signal kprobe/kretprobe")
	flagVfsCoredump     = flag.Bool("vfs-coredump", true, "Enable vfs_coredump kprobe")
	flagDoGroupExit     = flag.Bool("do-group-exit", false, "Enable do_group_exit kprobe")
	flagForceSigsegv    = flag.Bool("force-sigsegv", true, "Enable force_sigsegv kprobe")
	flagSignalSetupDone = flag.Bool("signal-setup-done", true, "Enable signal_setup_done kprobe (fires on failed signal setup)")
	flagForceFatalSig   = flag.Bool("force-fatal-sig", true, "Enable force_fatal_sig kprobe")
	flagForceSig        = flag.Bool("force-sig", true, "Enable force_sig kprobe")
	flagX64SetupRtFrame = flag.Bool("x64-setup-rt-frame", true, "Enable x64_setup_rt_frame kretprobe (fires on failure)")
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -no-strip -cflags "-O2 -g -Wall -Werror" -target amd64 -type event -type user_regs -type stack_probe signalsnoop ./bpf/signalsnoop.c
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -no-strip -cflags "-O2 -g -Wall -Werror" -target arm64 -type event -type user_regs -type stack_probe signalsnoop ./bpf/signalsnoop.c

const maxStackDepth = 50

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
	EventX64RtFrameFailed  = 9
)

var resolver *kallsyms.KAllSyms

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
	EventX64RtFrameFailed:  {"x64_setup_rt_frame failed", true},
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
		*flagX64SetupRtFrame = true
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

	objs := signalsnoopObjects{}
	if err := loadSignalsnoopObjects(&objs, nil); err != nil {
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
	attachKprobe(flagX64SetupRtFrame, "x64_setup_rt_frame", objs.KprobeX64SetupRtFrame)
	attachKretprobe(flagX64SetupRtFrame, "x64_setup_rt_frame", objs.KretprobeX64SetupRtFrame)

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

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	fmt.Println("Tracing signal events... Press Ctrl+C to stop.")
	fmt.Println()

	go func() {
		for {
			record, err := rd.Read()
			if err != nil {
				if errors.Is(err, ringbuf.ErrClosed) {
					return
				}
				log.Printf("Error reading from ring buffer: %v", err)
				continue
			}

			var event signalsnoopEvent
			if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &event); err != nil {
				log.Printf("Error parsing event: %v", err)
				continue
			}

			printEvent(&event)
		}
	}()

	<-sig
	fmt.Println("\nExiting...")
}

func printEvent(e *signalsnoopEvent) {
	comm := commToString(e.Comm[:])

	if e.EventType == EventGetSignalReturn {
		fmt.Printf("get_signal returned: %d\n\n", e.Retval)
		return
	}

	info, ok := eventInfo[e.EventType]
	if !ok {
		fmt.Printf("unknown event type %d for pid %d (%s)\n", e.EventType, e.Pid, comm)
		return
	}

	if info.showSig {
		fmt.Printf("%s for pid %d (%s), sig=%d\n", info.name, e.Pid, comm, e.Retval)
	} else {
		fmt.Printf("%s for pid %d (%s)\n", info.name, e.Pid, comm)
	}
	printStack(e)
	printRegs(e)
	printStackProbe(e)
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
	p := &e.StackProbe
	fmt.Println("    Stack probe:")

	printProbeVal := func(offset int64, val uint64, err int32) {
		addr := uint64(int64(sp) + offset)
		if err == 0 {
			fmt.Printf("        [sp%+d] 0x%016x: 0x%016x\n", offset, addr, val)
		} else {
			fmt.Printf("        [sp%+d] 0x%016x: <failed: %d>\n", offset, addr, err)
		}
	}

	printProbeVal(0, p.Val0, p.Err0)
	printProbeVal(-128, p.ValM128, p.ErrM128)
	printProbeVal(-568, p.ValM568, p.ErrM568)
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
