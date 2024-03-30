/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/bpf.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <string.h>

struct my_timestamp {
	__u16 magic;
	__u64 time;
} __attribute__((packed)); 
//pack the members of the struct my_timestamp structure as tightly as possible in memory. This means the compiler will minimize any padding bytes that might be inserted between members for alignment purposes.

/* Header cursor to keep track of current parsing position */
struct hdr_cursor {
	void *pos;
};

__u16 count = 0; //Increamenting the Packet Number

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

#define XDP_ACTION_MAX (XDP_REDIRECT + 1)
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, struct datarec);
	__uint(max_entries, XDP_ACTION_MAX);
} xdp_delay_map SEC(".maps");

struct datarec {
	__u16 packNo;
	__u64 delay;
};

//Function to Insert Records into Map
int xdp_delay_update(struct xdp_md *ctx, __u32 action, __u16 packNo, __u64 delay) {
  struct datarec stats = {packNo, delay};
  return bpf_map_update_elem(&xdp_delay_map, &action, &stats, BPF_ANY);
}

SEC("xdp")
int  xdp_calcDelay(struct xdp_md *ctx){

    void *data_end;
	void *data;
	int action = XDP_PASS;
	int eth_type, ip_type;
	struct hdr_cursor nh;
	struct iphdr *iphdr; //standard structure representing the IP header in the Linux kernel.
	struct ethhdr *eth; //standard structure representing the Ethernet header in the Linux kernel.
	__u16 ip_tot_len;

	__u64 current_time;
	__u64 delta;

	struct my_timestamp *ts = NULL;
	__u8 offset = sizeof(*ts);
	
	data_end = (void *)(long)ctx->data_end;
	data = (void *)(long)ctx->data;

    /* These keep track of the next header type and iterator pointer */
	nh.pos = data;

    eth_type = parse_ethhdr(&nh, data_end, &eth);
	if (eth_type < 0) {
		action = XDP_ABORTED;
		goto out;
	}

    if (eth_type == bpf_htons(ETH_P_IP)) {
		ip_type = parse_iphdr(&nh, data_end, &iphdr);
	} else {
		action = XDP_PASS;
		goto out;
	}

    if (ip_type == IPPROTO_ICMP) {
		/* Packet size in bytes, including IP header and data */
		ip_tot_len = bpf_ntohs(iphdr->tot_len);
		bpf_printk("IP Length : %llu",ip_tot_len);
		if (ip_tot_len < 2) {
			goto out;
		}
		ip_tot_len &= 0xFFF; /* Max 4095 */

		if ((void *)iphdr + ip_tot_len > data_end) {
			action = XDP_ABORTED;
			goto out;
		}

		void *potential_ts_start = (void *)iphdr + ip_tot_len - offset;
		// bpf_printk("Offset : %llu",data_end - potential_ts_start); //10

		if ((potential_ts_start <= data_end)) {
			unsigned char byte1 = *((unsigned char *)potential_ts_start);
			bpf_printk("T : %u",byte1); 
			unsigned char byte2 = *(((unsigned char *)potential_ts_start) + 1);
			bpf_printk("S : %u",byte2);

			int magicLen = sizeof(ts->magic);
			// bpf_printk("Magic Len : %d",magicLen); //2
			void *timestamp_start = potential_ts_start + magicLen ;

			if (timestamp_start + sizeof(ts->time) <= data_end) {
				unsigned char *current_byte = (unsigned char *)timestamp_start;
				__u64 timestamp = ((__u64)(*current_byte) << 56) | ((__u64)(*(current_byte + 1)) << 48) | ((__u64)(*(current_byte + 2)) << 40) | ((__u64)(*(current_byte + 3)) << 32) | ((__u64)(*(current_byte + 4)) << 24) | ((__u64)(*(current_byte + 5)) << 16)| ((__u64)(*(current_byte + 6)) << 8)| ((__u64)(*(current_byte + 7))) ;

				current_time = bpf_ktime_get_ns();
				delta = current_time - timestamp;

				// bpf_printk("Current Time : %llu , Timestamp: %llu",current_time,timestamp);
				
				__u32 act = XDP_PASS;  
				__u16 packNo = count;
				__u64 delay = delta;
				count+=1;
				xdp_delay_update(ctx, act, packNo, delay);
			} else {
				goto out;
			}
		} else {
			action=XDP_DROP;
			goto out; 
		}
	}
out:
	// action=XDP_DROP;
	return action;
}

char _license[] SEC("license") = "GPL";

/* Hint the avail XDP action return codes are:

enum xdp_action {
        XDP_ABORTED = 0,
        XDP_DROP,
        XDP_PASS,
        XDP_TX,
        XDP_REDIRECT,
};
*/


/*

__u64 timestamp =  
				((__u64)(*((unsigned char *)timestamp_start + 7)) << 56) |
				((__u64)(*((unsigned char *)timestamp_start + 6)) << 48) |
				 ((__u64)(*((unsigned char *)timestamp_start + 5)) << 40) |
				 ((__u64)(*((unsigned char *)timestamp_start + 4)) << 32) |
				((__u64)(*((unsigned char *)timestamp_start + 3)) << 24) |
								((__u64)(*((unsigned char *)timestamp_start + 2)) << 16) |
								((__u64)(*((unsigned char *)timestamp_start + 1)) << 8) |
								(*((unsigned char *)timestamp_start));

*/