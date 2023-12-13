package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"
)

const (
	port = 4040
)

func main() {
	// Load the eBPF program
	module, err := ebpf.LoadModule("hello.c")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading eBPF program: %v\n", err)
		os.Exit(1)
	}

	// Attach the eBPF program to the network interface (replace "eth0" with your network interface)
	prog := module.GetProgram("drop_tcp_port")
	if prog == nil {
		fmt.Fprintln(os.Stderr, "Error finding eBPF program")
		module.Close()
		os.Exit(1)
	}

	link, err := ebpf.AttachXDP("eth0", prog)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error attaching eBPF program: %v\n", err)
		module.Close()
		os.Exit(1)
	}

	fmt.Printf("eBPF program attached. Dropping TCP packets on port %d\n", port)

	// Setup signal handling for graceful exit
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	// Sleep indefinitely to keep the program running
	<-sig

	// Detach the eBPF program on exit
	link.Detach()
	module.Close()
}
