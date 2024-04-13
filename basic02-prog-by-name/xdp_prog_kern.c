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
#include <stdio.h>
#define ICMP_CSUM_OFF (ETH_HLEN + sizeof(struct iphdr) + offsetof(struct icmphdr, checksum))
#define ICMP_PING 8
#define ICMP_CSUM_SIZE sizeof(__u16)

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
/*
static __always_inline int parse_icmphdr(struct hdr_cursor *nh, void *data_end, struct icmphdr **icmp_header){

    struct icmphdr *icmphdr = nh->pos;
    int hdrsize;

    if (icmphdr + 1 > data_end)
        return -1;

    hdrsize = sizeof(*icmphdr);
    if (nh->pos + hdrsize > data_end)
        return -1;

    bpf_printk("icmp type : %llu", icmphdr->type);
    bpf_printk("icmp code : %llu", icmphdr->code);
    bpf_printk("icmp checksum : %llu", icmphdr->checksum);
    bpf_printk("icmp id : %llu", icmphdr->un.echo.id);
    bpf_printk("icmp seq : %llu", icmphdr->un.echo.sequence);
    bpf_printk("icmp gateway : %llu", icmphdr->un.gateway);
    bpf_printk("icmp mtu : %llu", icmphdr->un.frag.mtu);
    bpf_printk("icmp unused : %llu", icmphdr->un.frag.__unused);
    for (int i =0; i < 4; i++)
    {
        bpf_printk("icmp reserved : %llu", icmphdr->un.reserved[i]);
    }
    
    icmphdr->checksum = 0;
    __u16 csum = 0;
    for(int i=0;i<(hdrsize >> 1);i++){
        csum += *((__u16 *)nh->pos);
        nh->pos += sizeof(__u16);
    }
    bpf_printk("new hedaer checksum: %llu", csum);

    if(((void *)nh->pos + 1) > data_end){
        return -1;
    }

    int data_size = (void *)data_end - (void *)(nh->pos);
    for(int i=0;i < (data_size >> 2);i++){
        csum += *((__u16 *)nh->pos);
        if(i == ((data_size >> 1)-1))break;
        nh->pos += sizeof(__u16);
    }
    if((data_size % 2) != 0){
        csum += ((*((__u8*)nh->pos))<<8);
        nh->pos += sizeof(__u8);
        // return -1;
    }
    
    bpf_printk("new Body checksum: %llu", csum);

    // if( nh->pos >= data_end || (nh->pos + sizeof(__u8)) >= data_end){
    //     return -1;
    // }
    // while(1)  
    // {
    //     __u16* cur_16bit_val = nh->pos;
    //     csum += *cur_16bit_val;
    //     if((nh->pos + sizeof(__u8)) >= data_end){
    //         __u8* cur_16bit_val = nh->pos;
    //         csum += ((*cur_16bit_val)<<1);
    //         break;
    //     }
    //     if(nh->pos + sizeof(__u16) >= data_end){
    //         nh->pos += sizeof(__u16);
    //         break;
    //     }
    //     nh->pos += sizeof(__u16);
    // }

    // bpf_printk(" checksum  full New: %llu", csum);
    
    *icmp_header = icmphdr;
    return icmphdr->checksum;
}
*/
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

        // int oldChecksum = parse_icmphdr(&nh,data_end,&icmp_header);
        // if(oldChecksum<0){
        //     return TC_ACT_SHOT;
        // }
        // bpf_printk("Old Checksum : %llu",oldChecksum);


        if((void *)iphdr + ip_tot_len > data_end){
            return TC_ACT_SHOT;
        }

        ts = (void *)iphdr + ip_tot_len - offset;
        ts->magic = 0x5354; /* String "TS" in network-byte-order */
        ts->time  = bpf_ktime_get_ns();
        bpf_printk("Time : %llu",ts->time);

        __u8 ip_header_offset = (iphdr->ihl) * 4;  // ihl is in units of 4 bytes

        if ((void *)iphdr + ip_header_offset + (__u8)(sizeof(struct icmphdr)) > data_end) {
            // Packet too small, cannot access ICMP header
            return TC_ACT_OK;
        }
        
        icmp_header = (void *)iphdr + ip_header_offset;

        // bpf_l4_csum_replace(skb, ICMP_CSUM_OFF, 0, 0, ICMP_CSUM_SIZE);

        icmp_header->checksum = 0;
        __u32 csum = 0;
        int count= ip_tot_len - ip_header_offset;
        __u16 * addr = (__u16*)icmp_header;
        if((void *)addr + count >= data_end){
            return TC_ACT_OK;
        }
        // while (count > 1) {
        //     count -= 2;
        //     if(count!=0)csum += *addr++;
        // }

        // if (count > 0) {
        //     csum +=   (*(__u8*) addr)<<8;
        // }
        

        csum = (csum & 0xffff) + (csum >> 16);
        // csum = icmp_header->type + icmp_header->code + icmp_header->un.echo.id + icmp_header->un.echo.sequence;

        // __u8 *next_icmp_u8 = (__u8 *)(icmp_header);
        // __u16 icmp_offset = sizeof(struct icmphdr);
        // int iterations = icmp_offset;
        // for(int i=0;i<iterations;i++)csum += next_icmp_u8[i];
        // if((void *)icmp_header + (icmp_offset) > data_end){
        //     return TC_ACT_SHOT;
        // }
        // next_icmp_u8 = (__u8*)((void *)(icmp_header) + icmp_offset + 1);
        // if((void *)next_icmp_u8 > data_end) return TC_ACT_SHOT;
        // else{
        //     int iterations = ip_tot_len - (ip_header_offset + icmp_offset);
        //     if(iterations<=0)return TC_ACT_SHOT;
        //     else{
        //         for (int i = 0; i < iterations; i++) {
        //             csum += next_icmp_u8[i];
        //         }
        //     }
        // }   
        // icmp_header->checksum = ~((csum & 0xffff) + (csum >> 16));
        icmp_header->checksum = ~csum;
        bpf_printk("New Checksum : %llu",icmp_header->checksum);
    }
    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
