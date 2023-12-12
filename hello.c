#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>

// User-configurable port number
#define PORT 4040

// BPF program to drop TCP packets on a specific port
SEC("filter")
int drop_tcp_port(struct __sk_buff *skb) {
    struct ethhdr *eth = bpf_hdr_pointer(skb, 0);

    // Check if the packet is an IPv4 packet
    if (eth->h_proto == htons(ETH_P_IP)) {
        struct iphdr *ip = (struct iphdr *)(eth + 1);

        // Check if the packet is a TCP packet
        if (ip->protocol == IPPROTO_TCP) {
            struct tcphdr *tcp = (struct tcphdr *)(ip + 1);

            // Check if the destination port is the configured port
            if (tcp->dest == htons(PORT)) {
                // Drop the packet by returning XDP_DROP
                return XDP_DROP;
            }
        }
    }

    // Allow all other packets
    return XDP_PASS;
}
