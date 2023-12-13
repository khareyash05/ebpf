#include <uapi/linux/bpf.h>
#include <uapi/linux/in.h>
#include <uapi/linux/if_ether.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/tcp.h>
#define Total_size (sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr))

SEC("filter")
int drop_packet(struct xdp_md *ctx){

    void *data_end = (void*)(long)ctx->data_end;
    void*data = (void*)(long)ctx->data;
    struct ethhdr *eth = data;

    struct iphdr *ip = data + sizeof(struct ethhdr);
    struct tcphdr *tcph = data + sizeof(struct ethhdr) + sizeof(struct iphdr);

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
// clang -O2 -target bpf -c packet_count.c -o packet_count.o

// Load into kernel using following commands
// bpftool prog load packet_count.o /sys/fs/bpf/packet_count 
