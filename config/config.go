package config

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"strconv"

	"github.com/dropbox/goebpf"
)

func main() {

	if len(os.Args) != 2 {
		log.Fatal("Usage: go run main.go <port>")
	}

	// Specify Interface Name
	interfaceName := "lo"

	// Parse the port from the command line arguments
	port, err := strconv.Atoi(os.Args[1])
	if err != nil {
		log.Fatalf("Invalid port: %s", err)
	}

	// Load XDP Into App
	bpf := goebpf.NewDefaultEbpfSystem()
	err = bpf.LoadElf("bpf/xdp.elf")
	if err != nil {
		log.Fatalf("LoadELF() failed: %s", err)
	}
	port_map := bpf.GetMapByName("port_map")
	if port_map == nil {
		log.Fatalf("eBPF map 'port_map' not found\n")
	}

	// Update the configurable port in the eBPF map
	err = port_map.Update(uint32(0), uint32(port))
	if err != nil {
		log.Fatalf("Error updating port_map: %v", err)
	}

	xdp := bpf.GetProgramByName("drop_tcp_port")
	if xdp == nil {
		log.Fatalln("Program 'drop_tcp_port' not found in Program")
	}
	err = xdp.Load()
	if err != nil {
		fmt.Printf("xdp.Attach(): %v", err)
	}
	err = xdp.Attach(interfaceName)
	if err != nil {
		log.Fatalf("Error attaching to Interface: %s", err)
	}

	defer xdp.Detach()
	ctrlC := make(chan os.Signal, 1)
	signal.Notify(ctrlC, os.Interrupt)
	log.Println("XDP Program Loaded successfuly into the Kernel.")
	log.Println("Press CTRL+C to stop.")
	<-ctrlC
}
