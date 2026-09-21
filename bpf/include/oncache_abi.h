#ifndef ONCACHE_ABI_H
#define ONCACHE_ABI_H

#include <linux/types.h>

#define ONCACHE_ABI_VERSION 1U
#define ONCACHE_PIN_ROOT "/sys/fs/bpf/oncache/v1"
#define ONCACHE_MAP_PIN_ROOT ONCACHE_PIN_ROOT "/maps"
#define ONCACHE_PROGRAM_PIN_ROOT ONCACHE_PIN_ROOT "/programs"
#define ONCACHE_CONTROL_FLAG_FORCE_PASS (1U << 0)
#define ONCACHE_CONTROL_FLAG_DEBUG_COUNTERS (1U << 1)

struct oncache_flow_v1 {
    __be32 local_addr;
    __be32 remote_addr;
    __be16 local_port;
    __be16 remote_port;
    __u32 protocol;
};

struct oncache_egress_v1 {
    __u8 outer_header[64];
    __u32 ifindex;
};

struct oncache_action_v1 {
    __u16 ingress_ready;
    __u16 egress_ready;
};

struct oncache_device_v1 {
    __be32 ipv4;
    __u8 mac[6];
    __u8 pad[2];
};

struct oncache_ingress_v1 {
    __u32 ifindex;
    __u8 dst_mac[6];
    __u8 src_mac[6];
};

struct oncache_control_v1 {
    __u32 abi_version;
    __u32 enabled;
    __u64 generation;
    __u64 heartbeat_ns;
    __u64 heartbeat_timeout_ns;
    __u32 flags;
    __u32 reserved;
};

#endif
