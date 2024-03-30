/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/bpf.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/icmp.h>
#include <linux/pkt_cls.h>

struct my_timestamp {
    __u16 magic;
    __u64 time;
} __attribute__((packed)); 
//pack the members of the struct my_timestamp structure as tightly as possible in memory. This means the compiler will minimize any padding bytes that might be inserted between members for alignment purposes.

/* Header cursor to keep track of current parsing position */
struct hdr_cursor {
    void *pos;
};

static __always_inline int parse_ethhdr(struct hdr_cursor *nh, void *data_end, struct ethhdr **ethhdr)
{
    struct ethhdr *eth = nh->pos;
    int hdrsize = sizeof(*eth);
    __u16 h_proto;

    /* Byte-count bounds check for Ethernet header */
    if (nh->pos + hdrsize > data_end)
        return -1;

    nh->pos += hdrsize;
    *ethhdr = eth;
    h_proto = eth->h_proto;

    return h_proto; /* Network-byte-order next protocol type */
}

static __always_inline int parse_iphdr(struct hdr_cursor *nh, void *data_end, struct iphdr **iphdr){
    struct iphdr *iph = nh->pos;
    int hdrsize;

    if (iph + 1 > data_end)
        return -1;

    hdrsize = iph->ihl * 4;
    /* Sanity check packet field is valid */
    if(hdrsize < sizeof(*iph))
        return -1;

    /* Variable-length IPv4 header, need to use byte-based arithmetic */
    if (nh->pos + hdrsize > data_end)
        return -1;

    nh->pos += hdrsize;
    *iphdr = iph;

    return iph->protocol;
}

SEC("tc")
int  tc_attachTimestamp(struct __sk_buff *skb){

    void *data_end;
    void *data;
    int eth_type, ip_type;
    struct hdr_cursor nh;
    struct iphdr *iphdr;
    struct ethhdr *eth;
    struct icmphdr *icmp_header;
    __u16 ip_tot_len;
    
    struct my_timestamp *ts;
    __u8 offset = sizeof(*ts);
    data_end = (void *)(long)skb->data_end;
    data = (void *)(long)skb->data;

    /* These keep track of the next header type and iterator pointer */
    nh.pos = data;

    eth_type = parse_ethhdr(&nh, data_end, &eth);
    if (eth_type < 0) {
        bpf_printk("Eth_type<0");
        return TC_ACT_SHOT;
    }

    if (eth_type == bpf_htons(ETH_P_IP)) {
        ip_type = parse_iphdr(&nh, data_end, &iphdr);
    } else {
        return TC_ACT_OK;
    }

    if (ip_type == IPPROTO_ICMP) {
        /* Packet size in bytes, including IP header and data */
        ip_tot_len = bpf_ntohs(iphdr->tot_len);

        if (ip_tot_len < 2) {
            return TC_ACT_OK;
        }
        ip_tot_len &= 0xFFF; /* Max 4095 */

        /* Finding end of packet + offset, and bound access */
        if ((void *)iphdr + (ip_tot_len) > data_end) {
            bpf_printk(">data_end");
            return TC_ACT_SHOT;
        }

        ts = (void *)iphdr + ip_tot_len - offset;
        ts->magic = 0x5354; /* String "TS" in network-byte-order */
        ts->time  = bpf_ktime_get_ns();
        bpf_printk("Time : %llu",ts->time);

        __u16 ip_header_offset = iphdr->ihl * 4;  // ihl is in units of 4 bytes

        if ((void *)iphdr + ip_header_offset + sizeof(struct icmphdr) > data_end) {
            // Packet too small, cannot access ICMP header
            return TC_ACT_OK;
        }

        icmp_header = (void *)iphdr + ip_header_offset;
        bpf_printk("Old Checksum : %llu",icmp_header->checksum);
        // __u32 size = sizeof(struct icmphdr);
        // __u32 new_csum = bpf_csum_diff(NULL,0,(__be32 *)icmp_header,size,0);
        // icmp_header->checksum = ~new_csum;

        
        icmp_header->checksum = 0;
        __u32 csum = 0;
        __u8 *next_icmp_u8 = (__u8 *)icmp_header;

        for (int i = 0; i < sizeof(struct icmphdr); i++) {
            // bpf_printk("Content : %llu",*next_icmp_u8);
            csum += *next_icmp_u8++;
        }
        // Check if there's data payload after the ICMP header
        int icmp_data_len = ip_tot_len - ip_header_offset - sizeof(struct icmphdr);
        if (icmp_data_len > 0) {
            next_icmp_u8 = (__u8 *)icmp_header + sizeof(struct icmphdr);
            // Include data payload in checksum calculation
            for (int i = 0; i < icmp_data_len; i++) {
                csum += *next_icmp_u8++;
            }
            // bpf_printk("Content Size: %llu",data_end - (void *)next_icmp_u8);
        }
        icmp_header->checksum = ~((csum & 0xffff) + (csum >> 16));
        bpf_printk("New Checksum : %llu",icmp_header->checksum);
    }
    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
