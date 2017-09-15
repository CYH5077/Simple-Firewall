#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>

#include <linux/kernel.h>

#include "packet.h"

struct nf_hook_ops net_hook;

int network_hook_register(void){
	net_hook.hook = packet_hook;
	net_hook.hooknum = 1; // 호출 순서 번호
	net_hook.pf = PF_INET; // ipv4
	net_hook.priority = NF_IP_PRI_FIRST; // 후킹된 함수들을 제일 먼저 실행

	return nf_register_hook(&net_hook);
}

void network_hook_unregister(void){
	nf_unregister_hook(&net_hook);
}


unsigned int packet_hook(void * priv,
			 struct sk_buff * sk_buff,
			 const struct nf_hook_state * state){
	if(sk_buff == NULL)
		return NF_ACCEPT;
	if(packet_filter(sk_buff) == PACKET_DROP)
		return NF_DROP;
	/*	if(htons((unsigned short int)tcp_header->dest) == 80){
			char source_ip[16] = {0,};
			snprintf(source_ip, 16, "%pI4", &ip_header->saddr);
			printk("DROP ip address : %s\n", source_ip);
			return NF_DROP;
		}
	}*/
	return NF_ACCEPT;
}

//Filter 함수
enum PACKET_CHECK packet_filter(struct sk_buff * sk_buff){
	struct packet_info info;
	struct iphdr * ip_header = (struct iphdr *)skb_network_header(sk_buff);
	struct tcphdr * tcp_header = NULL;
	struct udphdr * udp_header = NULL;

	info.flag = IP_PROTOCOL;
	info.saddr = ip_header->saddr;
	info.daddr = ip_header->daddr;
	
	switch(ip_header->protocol){
	case IPPROTO_TCP: //TCP protocol
		tcp_header = 
			(struct tcphdr *)((__u32 *)ip_header + ip_header->ihl);
		info.flag |= TCP_PROTOCOL;
		info.sport = htons(tcp_header->source);
		info.dport = htons(tcp_header->dest);
		break;
	case IPPROTO_UDP: //UDP protocol
		udp_header = 
			(struct udphdr *)((__u32 *)ip_header + ip_header->ihl);
		info.flag |= UDP_PROTOCOL;
		info.sport = htons(udp_header->source);
		info.dport = htons(udp_header->dest);
		break;
	default:
		break;	
	}
	return packet_check_rule(&info);
}

enum PACKET_CHECK packet_check_rule(const struct packet_info * info){
	return list_match(&rule_list, info);
}
