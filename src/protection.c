#include <linux/bpf.h>
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <linux/tcp.h>
#include <linux/in.h>

#define SECRET_KEY 0x12345678

struct bpf_map_def SEC("maps") cookie_map = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u32),
    .max_entries = 1024,
};

SEC("main")
int protection(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    if ((void *)eth + sizeof(*eth) <= data_end) {
        struct iphdr *ip = data + sizeof(*eth);
        if ((void *)ip + sizeof(*ip) <= data_end) {
            if (ip->protocol == IPPROTO_TCP) {
                // SYN Cookie
                struct tcphdr *tcp = data + sizeof(*eth) + sizeof(*ip);
                __u32 saddr = ip->saddr;
                __u32 daddr = ip->daddr;
                __be16 sport = tcp->source;
                __be16 dport = tcp->dest;

                if (tcp->syn && !tcp->ack) {
                    __u32 cookie = jhash_3words(saddr, daddr, sport ^ dport ^ SECRET_KEY, 0) & 0xffffffff;

                    __u32 index = 0;
                    bpf_map_update_elem(&cookie_map, &index, &cookie, BPF_ANY);

                    tcp->seq = cookie;
                    tcp->urg_ptr = 1;
                    ip->ttl = 1;
                    return XDP_TX;
                }

                return XDP_PASS;
            } else if (ip->protocol == IPPROTO_UDP) {
                struct udphdr *udp = (void *)ip + sizeof(*ip);
                if ((void *)udp + sizeof(*udp) <= data_end) {
                    // Drop UDP packets with incorrect source and destination port
                    if (ntohs(1) <= udp->source <= ntohs(65535) && ntohs(1) <= udp->dest <= ntohs(65535)) {
                        // Drop unused udp ports
                        if (udp->dest == ntohs(22) || udp->dest == ntohs(80) || udp->dest == ntohs(443) || udp->dest == ntohs(3389) || udp->dest == ntohs(25565)) {
                            return XDP_DROP;
                        }
                        unsigned int payload_size = ntohs(udp->len) - sizeof(*udp);

                        // Block invalid SNMP Length
                        if (udp->source == ntohs(161) && (payload_size == 2536 || payload_size == 1244)) {
                            return XDP_DROP;
                        }
                        // Drop zero-length UDP packets
                        // Helps fight off UDP-NULL attacks
                        if (payload_size == 0) {
                            return XDP_DROP;
                        }

                        unsigned char *payload = (unsigned char *)udp + sizeof(*udp);
                        if ((void *)payload + payload_size > data_end) {
                            return XDP_PASS;
                        }
                        
                        // Drop some packets that contains not allowed string
                        unsigned char vse[] = "\xff\xff\xff\xff\x54\x53\x6f\x75\x72\x63\x65\x20\x45\x6e\x67\x69\x6e\x65\x20\x51\x75\x65\x72\x79\x00"
                        unsigned char fivem[] = "\xff\xff\xff\xffgetinfo xxx\x00\x00\x00";
                        unsigned char ts3 [] = "\x05\xca\x7f\x16\x9c\x11\xf9\x89\x00\x00\x00\x00\x02";
                        unsigned char mcpe[] = "\x61\x74\x6f\x6d\x20\x64\x61\x74\x61\x20\x6f\x6e\x74\x6f\x70\x20\x6d\x79\x20\x6f\x77\x6e\x20\x61\x73\x73\x20\x61\x6d\x70\x2f\x74\x72\x69\x70\x68\x65\x6e\x74\x20\x69\x73\x20\x6d\x79\x20\x64\x69\x63\x6b\x20\x61\x6e\x64\x20\x62\x61\x6c\x6c\x73";
                        unsigned char amp[] = "\x00\x00\x00\x00\x00\x00\x00\xff\x00\x00\x00\x00\x00\x00\x00\x00";
                        unsigned char cldap[] = "\x30\x25\x02\x01\x01\x63\x20\x04\x00\x0a\x01\x00\x0a\x01\x00\x02\x01\x00\x02\x01\x00\x01\x01\x00\x87\x0b\x6f\x62\x6a\x65\x63\x74\x63\x6c\x61\x73\x73\x30\x00";
                        unsigned char mem[] = "\x00\x01\x00\x00\x00\x01\x00\x00gets p h e\n";
                        unsigned char chargen[] = "\x01";
                        unsigned char ard[] = "\x00\x14\x00\x00";
                        unsigned char ntp[] "\x17\x00\x03\x2a\x00\x00\x00\x00";
                        unsigned char dns = "\x45\x67\x01\x00\x00\x01\x00\x00\x00\x00\x00\x01\x02\x73\x6c\x00\x00\xff\x00\x01\x00\x00\x29\xff\xff\x00\x00\x00\x00\x00\x00";
                        if (payload_size != sizeof(vse) - 1 && payload_size != sizeof(fivem) - 1 && payload_size != sizeof(ts3) - 1 && payload_size != sizeof(mcpe) - 1 && payload_size != sizeof(amp) - 1 && payload_size != sizeof(cldap) - 1 && payload_size != sizeof(mem) - 1 && payload_size != sizeof(chargen) - 1 && payload_size != sizeof(ard) - 1 && payload_size != sizeof(ntp) - 1 && payload_size != sizeof(dns) - 1) {
                           return XDP_PASS;
                        }

                        for (unsigned int i = 0; i < payload_size; i++) {
                            if (payload[i] != vse[i] && payload[i] != fivem[i] && payload[i] != ts3[i] && payload[i] != mcpe[i] && payload[i] != amp[i] && payload[i] != cldap[i] && payload[i] != mem[i] && payload[i] != chargen[i] && payload[i] != ard[i] && payload[i] != ntp[i] && payload[i] != dns[i]) {
                                return XDP_PASS;
                            }
                        }
                        return XDP_DROP;
                    } else {
                        return XDP_DROP;
                    }
                }
            } else if (ip->protocol == IPPROTO_ICMP) {
                return XDP_DROP;
            // Drop some Layer3 Protocols
            // Helps fight off ESP/GRE/AH floods
            // If you need these protocols - uncomment these rules,
            // or set PBA variable to PASS}
            } else if (ip->protocol == IPPROTO_ESP) {
                return XDP_DROP;
            } else if (ip->protocol == IPPROTO_GRE) {
                return XDP_DROP;
            } else if (ip->protocol == IPPROTO_AH) {
                return XDP_DROP;
            }
        }
    }
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
