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

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)

	b, err := bpf.NewModuleFromFile("hello.bpf.c")
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
