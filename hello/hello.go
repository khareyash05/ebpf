package hello

import (
	"fmt"
	"os"
	"os/signal"

	bpf "github.com/aquasecurity/tracee/libbpfgo"
)

const (
	port = 4040
)

func main() {
	// // Load the eBPF program
	// module, err := ebpf.LoadModule("hello.c")
	// if err != nil {
	// 	fmt.Fprintf(os.Stderr, "Error loading eBPF program: %v\n", err)
	// 	os.Exit(1)
	// }

	// // Attach the eBPF program to the network interface (replace "eth0" with your network interface)
	// prog := module.GetProgram("drop_tcp_port")
	// if prog == nil {
	// 	fmt.Fprintln(os.Stderr, "Error finding eBPF program")
	// 	module.Close()
	// 	os.Exit(1)
	// }

	// link, err := ebpf.AttachXDP("eth0", prog)
	// if err != nil {
	// 	fmt.Fprintf(os.Stderr, "Error attaching eBPF program: %v\n", err)
	// 	module.Close()
	// 	os.Exit(1)
	// }

	// fmt.Printf("eBPF program attached. Dropping TCP packets on port %d\n", port)

	// // Setup signal handling for graceful exit
	// sig := make(chan os.Signal, 1)
	// signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	// // Sleep indefinitely to keep the program running
	// <-sig

	// // Detach the eBPF program on exit
	// link.Detach()
	// module.Close()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)

	b, err := bpf.NewModuleFromFile("new.c")
	must(err)
	defer b.Close()

	must(b.BPFLoadObject())

	p, err := b.GetProgram("hello")
	must(err)

	_, err = p.AttachKprobe("__X64_sys_execve")
	must(err)

	go bpf.TracePrint() // goroutine

	<-sig // wait until interrupt
	fmt.Println("Cleaning")
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}
