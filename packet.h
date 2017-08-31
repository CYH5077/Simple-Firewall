#ifndef __FIREWALL_PACKET_HEADER__
#define __FIREWALL_PACKET_HEADER__
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>

/*
 * Packet을 처리할 함수.
 */
unsigned int packet_filter(void * priv,
			   struct sk_buff * sk_buff,
			   const struct nf_hook_state * state);

#endif
