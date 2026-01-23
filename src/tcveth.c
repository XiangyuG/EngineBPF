#include <uapi/linux/bpf.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/pkt_cls.h>

#include <linux/udp.h>
#include <linux/tcp.h> // --> struct tcphdr tcp;

#ifndef SRC_IP
#define SRC_IP 0x0A0001D2  // 10.0.1.210 (hex representation)
#endif

#ifndef SRCIF
#define SRCIF 13          // source interface ifindex
#endif

#ifndef SVCIP
#define SVCIP 0x0A686FCF  // 10.104.111.207 (hex representation)
#endif

#ifndef NEW_DST_IP
#define NEW_DST_IP 0x0A00017A  // 10.0.1.122 (hex representation)
#endif

#ifndef DSTIFINDEX
#define DSTIFINDEX 12          // destination #1 interface ifindex
#endif

#ifndef NEW_DST_IP2
#define NEW_DST_IP2 0x0A000154  // 10.0.1.84 (hex representation)
#endif

#ifndef DSTIFINDEX2
#define DSTIFINDEX2 15          // destination #2 interface ifindex
#endif

#ifndef SRCVPEER
#define SRCVPEER 0 // 0 is no vpeer on the way back
#endif

#define IS_PSEUDO 0x10

struct ct_key {
    u32 src_ip;
    u16 src_port;
    u8  proto;
};

struct ct_val {
    u32 backend_ip;
    u16 backend_port;
    u32 backend_idx;
    u32 client_ip;
    u16 client_port;
};

struct backend_pair {
    u32 size;
    u32 ips[4];
};

// map service -> backends. size: 32 services, key is the svc ip
BPF_HASH(svc_backends, u32, struct backend_pair, 32);
BPF_HASH(podIfIdx, u32, u32, 32);
BPF_TABLE("lru_hash", struct ct_key, struct ct_val, ct_map, 65536);

//BPF_HASH(backend_set, u32, u8);

static inline int l4_checksum_update(struct __sk_buff *skb, int ip_offset, int l4_offset, u8 protocol, u32 old_ip, u32 new_ip) {
    if (protocol == IPPROTO_TCP) {
        int csum_offset = 16;
        // TODO: check how to set the value of flags
        int flags = 0 | 4;
        int ret = bpf_l4_csum_replace(skb, l4_offset + csum_offset, old_ip, new_ip, IS_PSEUDO | flags);
        if (ret < 0) {
            return ret;
        }
    } else if (protocol == IPPROTO_UDP) {
        int csum_offset = 6;
        int flags = BPF_F_PSEUDO_HDR | BPF_F_MARK_MANGLED_0 | 4;
        int ret = bpf_l4_csum_replace(skb, l4_offset + csum_offset, old_ip, new_ip, IS_PSEUDO | flags);
        if (ret < 0) {
            return ret;
        }
    }
    return 0;
}

int redirect_service(struct __sk_buff *skb) {
    int ifindex = skb->ifindex;
    // bpf_trace_printk("redirect_service tc_ingress on ifindex=%d\\n", ifindex);
   void *data = (void *)(long)skb->data;
   void *data_end = (void *)(long)skb->data_end;
   struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return TC_ACT_OK;
    struct iphdr *ip = data + sizeof(struct ethhdr);
    if ((void *)(ip + 1) > data_end)
        return TC_ACT_OK;
    if (ip->ihl < 5) {
        bpf_trace_printk("Invalid IP header length: %d\\n", ip->ihl);
        return TC_ACT_SHOT;
    }
    void *l4 = data + sizeof(struct ethhdr) + ip->ihl * 4;
    if (l4 + sizeof(struct tcphdr) > data_end)
        return TC_ACT_OK;

   u32 dst_ip = ip->daddr;
   u32 src_ip = ip->saddr;

    // Check reply first
   struct ct_key key = { .src_ip = 0, .src_port = 0, .proto = 0};
   key.proto = ip->protocol;
   int l4_offset = sizeof(struct ethhdr) + (ip->ihl * 4);

   if (ip->protocol == IPPROTO_TCP) {
    struct tcphdr *tcp = l4;
    key.src_port = tcp->dest;
   } else if (ip->protocol == IPPROTO_UDP) {
    struct udphdr *udp = l4;
    key.src_port = udp->dest;
   }

   //u8 *is_backend = backend_set.lookup(&src_ip);
   int ip_offset = 14;
   u32 dst_ip_host = bpf_ntohl(dst_ip);
   struct backend_pair *bk_pair = svc_backends.lookup(&dst_ip_host);
   if (bk_pair) {
        // bpf_trace_printk("Service IP matched, processing packet\\n");
	u32 ifidx = 0;
        key.src_ip = src_ip;
        u32 new_dst_ip = 0; // Initialization
	if (key.proto == IPPROTO_TCP) {
            struct tcphdr *tcp = l4;
            key.src_port = tcp->source;
            struct ct_val *ct = ct_map.lookup(&key);
	    if (ct == NULL) {
		struct ct_val new_ct = {
                    .backend_ip = 0,
                    .backend_port = 0,
		    .backend_idx = 0,
                    .client_ip = 0,
                    .client_port = 0,
                };
		u32 backend_size = bk_pair->size;
		if (backend_size == 0 || backend_size > 4)
                    return TC_ACT_OK;
		u32 choiceId = bpf_get_prandom_u32() % backend_size;
		if (choiceId >= 4) {
		    return TC_ACT_OK;
		}
		// Do mod
		u32 chosenIp = 0;
		switch (choiceId) {
		    case 0: chosenIp = bk_pair->ips[0]; break;
		    case 1: chosenIp = bk_pair->ips[1]; break;
		    case 2: chosenIp = bk_pair->ips[2]; break;
		    case 3: chosenIp = bk_pair->ips[3]; break;
		    default: return TC_ACT_OK;
		}
		new_ct.backend_ip = bpf_htonl(chosenIp);
		// Get ifidx
                new_ct.backend_port = tcp->dest;
                new_ct.client_ip = dst_ip;
                new_ct.client_port = tcp->source;
		u32 *idxptr = podIfIdx.lookup(&chosenIp);
	        if (idxptr) {
		    new_ct.backend_idx = (*idxptr);
		} else {
		    return TC_ACT_OK;
		}
                ct_map.update(&key, &new_ct);
                new_dst_ip = new_ct.backend_ip;
		ifidx = new_ct.backend_idx;
	    } else {
		new_dst_ip = ct->backend_ip;
		ifidx = ct->backend_idx;
	    }
        } else if (key.proto == IPPROTO_UDP) {
            struct udphdr *udp = l4;
	    key.src_port = udp->source;
	    struct ct_val *ct = ct_map.lookup(&key);
	    if (ct == NULL) {
		struct ct_val new_ct = {
                    .backend_ip = 0,
                    .backend_port = 0,
		    .backend_idx = 0,
                    .client_ip = 0,
                    .client_port = 0,
                };
		u32 backend_size = bk_pair->size;
		if (backend_size == 0 || backend_size > 4)
                    return TC_ACT_OK;
		u32 choiceId = bpf_get_prandom_u32() % backend_size;
		if (choiceId >= 4) {
		    return TC_ACT_OK;
		}
                u32 chosenIp = 0;
		switch (choiceId) {
		    case 0: chosenIp = bk_pair->ips[0]; break;
		    case 1: chosenIp = bk_pair->ips[1]; break;
		    case 2: chosenIp = bk_pair->ips[2]; break;
		    case 3: chosenIp = bk_pair->ips[3]; break;
		    default: return TC_ACT_OK;
		}
		new_ct.backend_ip = bpf_htonl(chosenIp);
                new_ct.backend_port = udp->dest;
                new_ct.client_ip = dst_ip;
                new_ct.client_port = udp->source;
		u32 *idxptr = podIfIdx.lookup(&chosenIp);
	        if (idxptr) {
		    new_ct.backend_idx = (*idxptr);
		} else {
		    return TC_ACT_OK;
		}
                ct_map.update(&key, &new_ct);
                new_dst_ip = new_ct.backend_ip;
		ifidx = new_ct.backend_idx;
            } else {
                new_dst_ip = ct->backend_ip;
		ifidx = ct->backend_idx;
            }
	}
        ip->daddr = new_dst_ip;
        if (bpf_l3_csum_replace(skb, ip_offset + offsetof(struct iphdr, check), dst_ip, new_dst_ip, sizeof(new_dst_ip)) < 0) {
            bpf_trace_printk("Failed to update IP checksum\\n");
            return TC_ACT_SHOT;
        }

        u16 protocol = key.proto;
        int ret = l4_checksum_update(skb, ip_offset, l4_offset, protocol, dst_ip, new_dst_ip);
        if (ret < 0) {
            bpf_trace_printk("l4 csum replace ret=%d\\n", ret);
            return TC_ACT_SHOT;
        }

    bpf_skb_change_type(skb,PACKET_HOST);
    return bpf_redirect_peer(ifidx, 0);

    }
    key.src_ip = dst_ip;

    struct ct_val *ct = ct_map.lookup(&key);
   if (ct) {
        // bpf_trace_printk("Found CT entry for reply packet\\n");
        u32 new_src_ip = ct->client_ip; // From pod IP to svc IP
        // Store the updated destination IP in the packet
        ip->saddr = new_src_ip;
        if (bpf_l3_csum_replace(skb, ip_offset + offsetof(struct iphdr, check), src_ip, new_src_ip, sizeof(new_src_ip)) < 0) {
            bpf_trace_printk("Failed to update IP l3 checksum\\n");
            return TC_ACT_SHOT;
        }
        u16 protocol = key.proto;

        int ret = l4_checksum_update(skb, ip_offset, l4_offset, protocol, src_ip, new_src_ip);
        if (ret < 0) {
            bpf_trace_printk("l4 csum replace ret=%d\\n", ret);
            return TC_ACT_SHOT;
        }
	u32 ifidx = 0;
	u32 *ifidxptr = podIfIdx.lookup(&dst_ip_host);
	if (ifidxptr) {
	    ifidx = (*ifidxptr);
	} else {
	    return TC_ACT_OK;
	}
        if (SRCVPEER == 1) {
            return bpf_redirect_peer(ifidx, 0);
        }
        return bpf_redirect(ifidx, 0);
   }

   return TC_ACT_OK;
}

