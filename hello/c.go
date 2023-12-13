package hello

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf"
)

func main() {
	bpfModule, err := ebpf.LoadCollection("hello.bpf.o")
	defer bpfModule.Close()

	// Attach the eBPF program to the network interface (replace "eth0" with your network interface)
	prog := bpfModule.GetProgram("hello")
	if prog == nil {
		fmt.Fprintln(os.Stderr, "Error finding eBPF program")
		os.Exit(1)
	}

	link, err := ebpf.AttachXDP("eth0", prog)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error attaching eBPF program: %v\n", err)
		os.Exit(1)
	}

	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()

	kp, err := link.Kprobe("sys_execve", objs.KprobeExecve, nil)
	if err != nil {
		log.Fatalf("opening kprobe: %s", err)
	}
	defer kp.Close()

	fmt.Println("Hello, eBPF!")

	// Setup signal handling for graceful exit
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	// Sleep indefinitely to keep the program running
	<-sig

	// Detach the eBPF program on exit
	link.Detach()
}
