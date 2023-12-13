#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>

// Ethernet header
struct ethhdr {
  __u8 h_dest[6];
  __u8 h_source[6];
  __u16 h_proto;
} __attribute__((packed));

// IPv4 header
struct iphdr {
  __u8 ihl : 4;
  __u8 version : 4;
  __u8 tos;
  __u16 tot_len;
  __u16 id;
  __u16 frag_off;
  __u8 ttl;
  __u8 protocol;
  __u16 check;
  __u32 saddr;
  __u32 daddr;
} __attribute__((packed));


#define Total_size (sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr))

SEC("xdp")
int drop_packet(struct xdp_md *ctx){

    void *data_end = (void*)(long)ctx->data_end;
    void*data = (void*)(long)ctx->data;
    struct ethhdr *eth = data;

    struct iphdr *ip = data + sizeof(struct ethhdr);
    struct tcphdr *tcp = data + sizeof(struct ethhdr) + sizeof(struct iphdr);

    if (data + Total_size > data_end) { // if size of data is bigger than that of a TCP format pass it
        return XDP_PASS;
    }

    // Check if the packet is a TCP packet
    if (ip->protocol == IPPROTO_TCP) {
        // Check if the destination port is the configured port
        if (tcp->dest == htons(4040)) {
            // Drop the packet by returning XDP_DROP
            return XDP_DROP;
        }
    }
    // Allow all other packets
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";



// compile using following commands
// clang -O2 -target bpf -c main.c -o main.o

// Load program into kernel using following commands
// bpftool prog load main.o /sys/fs/bpf/main 

// You can use bpftool prog list to see that it is loaded into the kernel.
/*
    But at this point the program is not associated with any events that will trigger it. The next command attaches it to the loopback network interface on this virtual machine.
    bpftool net attach xdp name hello dev lo    

    You can see all the network-related eBPF programs by running the following command:
    bpftool net list
*/
// Read trace output by bpftool prog trace log and ping localhost to check if packets are available or not
