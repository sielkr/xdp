#include <linux/bpf.h>
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>

SEC("main")
int protection(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    if ((void *)eth + sizeof(*eth) <= data_end) {
        struct iphdr *ip = data + sizeof(*eth);
        if ((void *)ip + sizeof(*ip) <= data_end) {
            if (ip->protocol == IPPROTO_UDP) {
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
                        
                        unsigned char http[] = "\xff\xff\xff\xff\x54\x53\x6f\x75\x72\x63\x65\x20\x45\x6e\x67\x69\x6e\x65\x20\x51\x75\x65\x72\x79\x00";
                        unsigned char http2[] = "\xff\xff\xff\xffgetinfo xxx\x00\x00\x00";
                        if (payload_size != sizeof(http) - 1 && payload_size != sizeof(http2) - 1) {
                           return XDP_PASS;
                        }

                        for (unsigned int i = 0; i < payload_size; i++) {
                            if (payload[i] != http[i] && payload[i] != http2[i]) {
                                return XDP_PASS;
                            }
                        }
                        /*
                        for (unsigned int i = 0; i < payload_size; i++) {
                            if (payload[i] != http2[i]) {
                                return XDP_PASS;
                            }
                        }*/

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