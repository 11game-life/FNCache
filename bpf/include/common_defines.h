#ifndef __COMMON_DEFINES_H
#define __COMMON_DEFINES_H

#include <stdbool.h>
#include <stddef.h>

#include <linux/if_ether.h>
#include <linux/types.h>
#include <linux/pkt_cls.h>
#include <linux/pkt_sched.h> /* TC_H_MAJ + TC_H_MIN */
#include <linux/if_packet.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/types.h>
#include "linux/bpf.h"
#include "oncache_abi.h"

#define MACLEN 14
#define IPLEN 20
#define UDPLEN 8
#define TCPLEN 20
#define VXLANLEN 8
#define ONCACHE_IPV4_FRAGMENT_MASK 0x3fff
#define ONCACHE_IPV4_RESERVED_FLAG 0x8000
#define ONCACHE_VXLAN_I_FLAG 0x08
#define ONCACHE_MISS_MASK 0x04
#define ONCACHE_ESTABLISHED_MASK 0x08
#define ONCACHE_TOS_MASK (ONCACHE_MISS_MASK | ONCACHE_ESTABLISHED_MASK)
#define ONCACHE_INGRESS_READY_MASK ((__u32)1)
#define ONCACHE_EGRESS_READY_MASK ((__u32)1 << 16)

enum oncache_stat_id {
    ONCACHE_STAT_INIT_E_POLICY_LOOKUP_MISS,
    ONCACHE_STAT_MASQ_POLICY_MISS,
    ONCACHE_STAT_MASQ_EGRESSIP_MISS,
    ONCACHE_STAT_MASQ_EGRESS_CACHE_MISS,
    ONCACHE_STAT_MASQ_INGRESS_NOT_READY,
    ONCACHE_STAT_MASQ_ADJUST_ROOM_FAIL,
    ONCACHE_STAT_RESTORE_POLICY_MISS,
    ONCACHE_STAT_RESTORE_DEVINFO_MISMATCH,
    ONCACHE_STAT_RESTORE_OUTER_IP_MISMATCH,
    ONCACHE_STAT_RESTORE_POD_NOT_READY,
    ONCACHE_STAT_RESTORE_EGRESSIP_MISS,
    ONCACHE_STAT_RESTORE_ADJUST_ROOM_FAIL,
    ONCACHE_STAT_INIT_IN_ENDPOINT_MISS,
    ONCACHE_STAT_INIT_IN_POLICY_LOOKUP_MISS,
    ONCACHE_STAT_COUNT,
};

#define MAX_IFINDEX 4096

struct bpf_elf_map {
        __u32 type;
        __u32 size_key;
        __u32 size_value;
        __u32 max_elem;
        __u32 flags;
        __u32 id;
        __u32 pinning;
    __u32 inner_id;
    __u32 inner_idx;
};

struct oncache_policy_lock_v1 {
    struct bpf_spin_lock lock;
};

struct rule {
    struct oncache_flow_v1 flow;
    int isIngress;
};

#define PORT_AVAILABLE 1024

int verbose;

#define EXIT_OK   0 /* == EXIT_SUCCESS (stdlib.h) man exit(3) */
#define EXIT_FAIL  1 /* == EXIT_FAILURE (stdlib.h) man exit(3) */
#define EXIT_FAIL_OPTION 2
#define EXIT_FAIL_XDP  3
#define EXIT_FAIL_MAP  20
#define EXIT_FAIL_MAP_KEY 21
#define EXIT_FAIL_MAP_FILE 22
#define EXIT_FAIL_MAP_FS 23
#define EXIT_FAIL_IP  30
#define EXIT_FAIL_CPU  31
#define EXIT_FAIL_BPF  40
#define EXIT_FAIL_BPF_ELF 41
#define EXIT_FAIL_BPF_RELOCATE 42

#endif
