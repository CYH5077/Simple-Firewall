#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>

#include <linux/kernel.h>

#include "packet.h"

unsigned int packet_filter(void * priv,
			   struct sk_buff * sk_buff,
			   const struct nf_hook_state * state){
	struct iphdr * ip_header;
	if(sk_buff == NULL)
		return NF_ACCEPT;
	ip_header = (struct iphdr *)skb_network_header(sk_buff);
	
	if(ip_header->protocol == IPPROTO_TCP){
		struct tcphdr * tcp_header;
		tcp_header = (struct tcphdr *)((__u32 *)ip_header + ip_header->ihl);
		if(htons((unsigned short int)tcp_header->dest) == 80)
			return NF_DROP;
	} else if(ip_header->protocol == IPPROTO_UDP){
		struct udphdr * udp_header;
					
	}
	return NF_ACCEPT;
}
