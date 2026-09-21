#ifndef __COMMON_KERN_H
#define __COMMON_KERN_H

#include "common_defines.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

extern struct bpf_elf_map control_map;

static __always_inline int oncache_control_allows(void) {
    __u32 key = 0;
    struct oncache_control_v1 *control = bpf_map_lookup_elem(&control_map, &key);
    if (!control || control->abi_version != ONCACHE_ABI_VERSION) return 0;
    if (control->enabled != 1) return 0;
    if (control->flags & ONCACHE_CONTROL_FLAG_FORCE_PASS) return 0;
    if (control->heartbeat_timeout_ns == 0) return 0;

    __u64 now = bpf_ktime_get_ns();
    if (now < control->heartbeat_ns) return 0;
    if (now - control->heartbeat_ns > control->heartbeat_timeout_ns) return 0;
    return 1;
}

static __always_inline
int check_l4_bound(int hdr_type, void* l4hdr, void* data_end) {
    if (hdr_type == IPPROTO_UDP) {
        if (data_end < l4hdr + UDPLEN) return 1;
    } else if (hdr_type == IPPROTO_TCP) {
        if (data_end < l4hdr + TCPLEN) return 1;
    }
    return 0;
}

static __always_inline
int parse_5tuple_in(struct iphdr * iph, void *data_end, struct oncache_flow_v1* tuple) {
    int proto = iph->protocol;

    if (check_l4_bound(proto, iph + 1, data_end)) return 1;

    tuple->remote_addr = iph->saddr;
    tuple->local_addr = iph->daddr;
    tuple->protocol = iph->protocol;
    if (proto == IPPROTO_TCP) {
        struct tcphdr *tcphdr = (struct tcphdr *)(iph + 1);
        tuple->remote_port = tcphdr->source;
        tuple->local_port = tcphdr->dest;
    } else if (proto == IPPROTO_UDP) {
        struct udphdr *udphdr = (struct udphdr *)(iph + 1);
        tuple->remote_port = udphdr->source;
        tuple->local_port = udphdr->dest;
    } else {
        tuple->remote_port = 0;
        tuple->local_port = 0;
    }
    return 0;
}

static __always_inline
int parse_5tuple_e(struct iphdr * iph, void *data_end, struct oncache_flow_v1* tuple) {
    int proto = iph->protocol;

    if (check_l4_bound(proto, iph + 1, data_end)) return 1;

    tuple->local_addr = iph->saddr;
    tuple->remote_addr = iph->daddr;
    tuple->protocol = iph->protocol;
    if (proto == IPPROTO_TCP) {
        struct tcphdr *tcphdr = (struct tcphdr *)(iph + 1);
        tuple->local_port = tcphdr->source;
        tuple->remote_port = tcphdr->dest;
    } else if (proto == IPPROTO_UDP) {
        struct udphdr *udphdr = (struct udphdr *)(iph + 1);
        tuple->local_port = udphdr->source;
        tuple->remote_port = udphdr->dest;
    } else {
        tuple->local_port = 0;
        tuple->remote_port = 0;
    }
    return 0;
}

static __always_inline void initegressinfo(struct oncache_egress_v1* ci, const void * data, int ifindex) {
    __builtin_memcpy(&(ci->outer_header), data, 64);
    ci->ifindex = ifindex;
}

unsigned long long load_byte(void *skb,
        unsigned long long off) asm("llvm.bpf.load.byte");
unsigned long long load_half(void *skb,
        unsigned long long off) asm("llvm.bpf.load.half");
unsigned long long load_word(void *skb,
        unsigned long long off) asm("llvm.bpf.load.word");

#define IP_CSUM_OFF (ETH_HLEN + offsetof(struct iphdr, check))
#define IP_DST_OFF (ETH_HLEN + offsetof(struct iphdr, daddr))
#define IP_SRC_OFF (ETH_HLEN + offsetof(struct iphdr, saddr))
#define IP_TOS_OFF (ETH_HLEN + offsetof(struct iphdr, tos))
#define IP_ID_OFF (ETH_HLEN + offsetof(struct iphdr, id))
#define IP_LEN_OFF (ETH_HLEN + offsetof(struct iphdr, tot_len))
#define TCP_PORT_OFF (ETH_HLEN + sizeof(struct iphdr) + offsetof(struct tcphdr, source))
#define UDP_PORT_OFF (ETH_HLEN + sizeof(struct iphdr) + offsetof(struct udphdr, source))
#define TCP_CSUM_OFF (ETH_HLEN + sizeof(struct iphdr) + offsetof(struct tcphdr, check))
#define UDP_CSUM_OFF (ETH_HLEN + sizeof(struct iphdr) + offsetof(struct udphdr, check))
#define UDP_LEN_OFF (ETH_HLEN + sizeof(struct iphdr) + offsetof(struct udphdr, len))
#define IS_PSEUDO 0x10
#define IS_SRC 1
#define IS_DST 2

static inline void set_ip_tos(struct __sk_buff *skb, unsigned int off, __u8 tos)
{
    __u8 old_tos = load_byte(skb, off + IP_TOS_OFF);
    __u8 new_tos;
    if (tos){
        new_tos = old_tos | tos;
    } else {
        new_tos = old_tos & 0xf3;
    }
    bpf_l3_csum_replace(
        skb, off + IP_CSUM_OFF, bpf_htons(old_tos), bpf_htons(new_tos), 2);
    bpf_skb_store_bytes(
        skb, off + IP_TOS_OFF, &new_tos, sizeof(new_tos), 0);
}

static inline void set_new_ip(
    struct __sk_buff *skb, unsigned int off,  __be32 new_ip, int is_src, unsigned char proto, bool do_l4csum) {
    unsigned int field;
    if (is_src == IS_SRC) field = off + IP_SRC_OFF;
    else field = off + IP_DST_OFF;
    __be32 old_ip = bpf_htonl(load_word(skb, field));

    if (do_l4csum) {
        if (proto == IPPROTO_TCP) {
            bpf_l4_csum_replace(skb, off + TCP_CSUM_OFF, old_ip, new_ip, IS_PSEUDO | sizeof(new_ip));
        } else if (proto == IPPROTO_UDP) {
            bpf_l4_csum_replace(skb, off + UDP_CSUM_OFF, old_ip, new_ip, IS_PSEUDO | sizeof(new_ip));
        }
    }
    bpf_l3_csum_replace(skb, off + IP_CSUM_OFF, old_ip, new_ip, sizeof(new_ip));
    bpf_skb_store_bytes(skb, field, &new_ip, sizeof(new_ip), 0);
}

static inline void set_new_ipid(struct __sk_buff *skb, unsigned int off,  __be16 new_id) {
    __be16 old_id = bpf_htons(load_half(skb, off + IP_ID_OFF));
    bpf_l3_csum_replace(skb, off + IP_CSUM_OFF, old_id, new_id, sizeof(new_id));
    bpf_skb_store_bytes(skb, off + IP_ID_OFF, &new_id, sizeof(new_id), 0);
}

// The function is used to set the IP length and UDP length according to the orignal length.
static inline void set_new_length_outerhdr(struct __sk_buff *skb, unsigned int ori_len) {
    if ((void *)(long)skb->data_end < (void *)(long)skb->data + MACLEN + IPLEN + UDPLEN) return;
    __u16 udp_len = bpf_htons(ori_len - MACLEN - IPLEN);
    bpf_skb_store_bytes(skb, UDP_LEN_OFF, &udp_len, sizeof(udp_len), 0);

    if ((void *)(long)skb->data_end < (void *)(long)skb->data + MACLEN + IPLEN) return;
    __u16 old_len = bpf_htons(load_half(skb, IP_LEN_OFF));
    __u16 ip_len = bpf_htons(ori_len - MACLEN);
    bpf_l3_csum_replace(skb, IP_CSUM_OFF, old_len, ip_len, sizeof(ip_len));
    bpf_skb_store_bytes(skb, IP_LEN_OFF, &ip_len, sizeof(ip_len), 0);
}

// Check if UDP packet is VXLAN/Geneve and set VXLAN/Geneve hdr ptr
static inline bool is_encap(struct udphdr* udph) {
    return (udph->dest == bpf_htons(6081) ||
            udph->dest == bpf_htons(4789) ||
            udph->dest == bpf_htons(8472));
}

static __always_inline int maccmp(char* mac1, char* mac2, int len) {
    int i;
    for (i = 0; i < len; i++) {
        if (mac1[i] != mac2[i]) return 1;
    }
    return 0;
}

#endif  // COMMON_KERN_H_
