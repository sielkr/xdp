#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/in.h>

#define MAX_ENTRIES 1024

struct ip_key {
    __u32 ip;
};

struct hash_entry {
    __u64 count;
};

struct bpf_map_def SEC("maps") hash_table = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(struct ip_key),
    .value_size = sizeof(struct hash_entry),
    .max_entries = MAX_ENTRIES,
    .map_flags = BPF_F_NO_PREALLOC,
};

SEC("xdp")
int xdp_prog(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    if (data + sizeof(*eth) > data_end) {
        return XDP_DROP;
    }
    if (eth->h_proto != htons(ETH_P_IP)) {
        return XDP_PASS;
    }
    struct iphdr *ip = data + sizeof(*eth);
    if (ip + 1 > data_end) {
        return XDP_DROP;
    }
    struct ip_key key = {
        .ip = ip->saddr,
    };
    struct hash_entry *entry = bpf_map_lookup_elem(&hash_table, &key);
    if (!entry) {
        struct hash_entry new_entry = {
            .count = 1,
        };
        bpf_map_update_elem(&hash_table, &key, &new_entry, BPF_NOEXIST);
        return XDP_PASS;
    }
    if (entry->count >= 10) {
        return XDP_DROP;
    }
    entry->count++;
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
