
#include <linux/in.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

/*
 * Port filtering key.
 *
 * protocol:
 *   TCP = 6
 *   UDP = 17
 *
 * pad ensures a predictable 4-byte structure
 * compatible with the Go control plane.
 */
struct port_rule {
    __u8 protocol;
    __u8 pad;
    __u16 destination_port;
};

/* Map 1: Blocked TCP/UDP destination ports */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct port_rule);
    __type(value, __u8);
} blocked_ports SEC(".maps");

/* Map 2: Blocked source IPv4 addresses */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, __u8);
} blocked_ips SEC(".maps");

/* Map 3: Packet statistics */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 2);
    __type(key, __u32);
    __type(value, __u64);
} packet_stats SEC(".maps");

/*
 * Increment dropped packet counter.
 * Counter index 1 = dropped packets.
 */
static __always_inline int drop_packet(void)
{
    __u32 key = 1;

    __u64 *dropped =
        bpf_map_lookup_elem(&packet_stats, &key);

    if (dropped)
        __sync_fetch_and_add(dropped, 1);

    return XDP_DROP;
}

/* Main XDP firewall program */
SEC("xdp")
int netguard_xdp(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    /* Ethernet header validation */
    struct ethhdr *eth = data;

    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    /* Process IPv4 packets only */
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    /* IPv4 header validation */
    struct iphdr *ip = (void *)(eth + 1);

    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    if (ip->version != 4 || ip->ihl < 5)
        return XDP_PASS;

    /* Validate complete IPv4 header, including options */
    __u32 ip_header_len = ip->ihl * 4;

    if ((void *)ip + ip_header_len > data_end)
        return XDP_PASS;

    /* Count processed IPv4 packets: counter index 0 */
    __u32 key = 0;

    __u64 *processed =
        bpf_map_lookup_elem(&packet_stats, &key);

    if (processed)
        __sync_fetch_and_add(processed, 1);

    /*
     * FEATURE 1: SOURCE IP BLOCKING
     */
    __u32 src_ip = ip->saddr;

    __u8 *ip_blocked =
        bpf_map_lookup_elem(&blocked_ips, &src_ip);

    if (ip_blocked)
        return drop_packet();

    /*
     * FEATURE 2: TCP/UDP DESTINATION PORT BLOCKING
     *
     * Non-initial IPv4 fragments do not contain
     * the transport header, so skip port filtering.
     */
    if (bpf_ntohs(ip->frag_off) & 0x1FFF)
        return XDP_PASS;

    void *transport = (void *)ip + ip_header_len;

    struct port_rule rule = {};

    /* TCP packet */
    if (ip->protocol == IPPROTO_TCP) {

        struct tcphdr *tcp = transport;

        if ((void *)(tcp + 1) > data_end)
            return XDP_PASS;

        rule.protocol = IPPROTO_TCP;
        rule.destination_port = bpf_ntohs(tcp->dest);

    }

    /* UDP packet */
    else if (ip->protocol == IPPROTO_UDP) {

        struct udphdr *udp = transport;

        if ((void *)(udp + 1) > data_end)
            return XDP_PASS;

        rule.protocol = IPPROTO_UDP;
        rule.destination_port = bpf_ntohs(udp->dest);

    }

    /* Other IPv4 protocols are allowed */
    else {
        return XDP_PASS;
    }

    /* Look up the TCP/UDP destination port */
    __u8 *port_blocked =
        bpf_map_lookup_elem(&blocked_ports, &rule);

    if (port_blocked)
        return drop_packet();

    /* Packet passed all firewall rules */
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
