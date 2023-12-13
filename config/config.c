#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>

// Define a map to store the configurable port number
BPF_MAP_DEF(port_map) = {
    .map_type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(int),
    .value_size = sizeof(int),
    .max_entries = 1,
};
BPF_MAP_ADD(port_map);

// BPF program to drop TCP packets on a configurable port
SEC("filter")
int drop_tcp_port(struct __sk_buff *skb) {
    struct ethhdr *eth = bpf_hdr_pointer(skb, 0);

    // Check if the packet is an IPv4 packet
    if (eth->h_proto == htons(ETH_P_IP)) {
        struct iphdr *ip = (struct iphdr *)(eth + 1);

        // Check if the packet is a TCP packet
        if (ip->protocol == IPPROTO_TCP) {
            struct tcphdr *tcp = (struct tcphdr *)(ip + 1);

            // Load the configurable port from the map
            int *port_ptr = bpf_map_lookup_elem(&port_map, 0);
            if (port_ptr == NULL) {
                // Use a default port if not configured
                return XDP_PASS;
            }

            // Check if the destination port is the configured port
            if (tcp->dest == htons(*port_ptr)) {
                // Drop the packet by returning XDP_DROP
                return XDP_DROP;
            }
        }
    }

    // Allow all other packets
    return XDP_PASS;
}
