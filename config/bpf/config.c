#include "bpf_helpers.h"

struct ethhdr {
  __u8 h_dest[6];
  __u8 h_source[6];
  __u16 h_proto;
} __attribute__((packed));

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

struct tcphdr {
	__u16	source;
	__u16	dest;
	__u32	seq;
	__u32	ack_seq;
}__attribute__((packed));

BPF_MAP_DEF(port_map) = {
    .map_type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(int),
    .value_size = sizeof(int),
    .max_entries = 1,
};
BPF_MAP_ADD(port_map);
SEC("filter")
int drop_tcp_port(struct xdp_md *ctx) {

    void *data_end = (void*)(long)ctx->data_end;
    void*data = (void*)(long)ctx->data;
    struct ethhdr *eth = data;

    struct iphdr *ip = data + sizeof(struct ethhdr);
    struct tcphdr *tcp = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
    if (ip->protocol == 6) {
        int *port_ptr = bpf_map_lookup_elem(&port_map, 0);
        if (tcp->dest == htons(*port_ptr)) {
            return XDP_DROP;
        }
    }
    return XDP_PASS;
}
