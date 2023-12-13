package config

import (
	"fmt"

	ebpf "github.com/aquasecurity/tracee/libbpfgo"
)

var objs struct {
	XCProg *ebpf.BPFProg `ebpf:"xdp_xconnect"`
	XCMap  *ebpf.BPFMap  `ebpf:"xconnect_map"`
}

func config() {

	ans, err := objs.XCMap.GetValue(uint32(0), 10)
	if err != nil {
		panic(err)
	}
	fmt.Println(ans)
}
