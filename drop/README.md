This is the README file for an EBPF Program to drop TCP packets with user configurable port number<br>

Code BreakDown- <br>
<ol>
<li>Main.go - Userspace code in Go using Cilium/EBPF</li><br>
<li>Drop.c - EBPF code </li><br>
<li>Bpf_bpfel.go/Bpf_bpfeb.go - Auto Generated Go file using Cilium/EBPF which support objects and maps to be used in EBPF code as well as handle access to the userspace code</li><br>
<li>Object files to foster conversion of EBPF code to object files </li><br>


<h3>EBPF Code Breakdown</h3><br>
//go:build ignore <br>

#include "bpf_endian.h" // standard libraries to access ebpf code<br>
#include "common.h"<br>

char __license[] SEC("license") = "Dual MIT/GPL";<br>

struct bpf_map_def SEC("maps") port_map = {<br>
	.type        = BPF_MAP_TYPE_HASH, // a hashmap to store port number<br>
	.key_size    = sizeof(u32),<br>
	.value_size  = sizeof(u64),<br>
	.max_entries = 2,<br>
};<br>

struct tcphdr {<br>
	__u16	source;<br>
	__u16	dest;<br>
	__u32	seq;<br>
	__u32	ack_seq;<br>
}__attribute__((packed)); // seems not to be defined<br>


SEC("xdp")<br>
int drop_tcp_port(struct xdp_md *ctx) {<br>

    void *data_end = (void*)(long)ctx->data_end;<br>
    void*data = (void*)(long)ctx->data;<br>
    struct ethhdr *eth = data;<br>

    struct iphdr *ip = data + sizeof(struct ethhdr);<br>
    struct tcphdr *tcph = data + sizeof(struct ethhdr) + sizeof(struct iphdr);<br>
    if (ip->protocol == 6) { // needed to use IPPROTO_TCP https://elixir.bootlin.com/linux/latest/source/include/uapi/linux/in.h#L39<br>
        int *port_ptr = bpf_map_lookup_elem(&port_map, 1); // match 1 with mentioned in the args.<br>
        if(port_ptr == NULL) return XDP_ABORTED;<br>
        if (tcph->source == bpf_htons(*port_ptr)) { // host byte order to network byte order<br>
            return XDP_DROP; // drop packets with corresponding port number matched<br>
        }<br>
    }<br>
    return XDP_PASS; // pass other<br>
}<br>
