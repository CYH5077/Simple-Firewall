#ifndef __FIREWALL_PACKET_HEADER__
#define __FIREWALL_PACKET_HEADER__
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>

#include "list.h"
#include "firewall_const.h"

extern struct nf_hook_ops net_hook;


/////////////////////////////////////////////////////// Function

/*
 * 패킷 훅을 등록한다.
 * @return
 * 성공시 0  실패시 에러 코드 반환.
 */
int network_hook_register(void);

/*
 * 패킷 훅 제거.
 */
void network_hook_unregister(void);

/*
 * Packet을 처리할 함수.
 */
unsigned int packet_hook(void * priv,
			   struct sk_buff * sk_buff,
			   const struct nf_hook_state * state);

/*
 * 문자열 IP 를 정수로 변환.
 */
unsigned int inet_addr(char * str);

//Filter 함수.
//허용될경우 0
//제한될경우 -1 반환
enum PACKET_CHECK packet_filter(struct sk_buff * sk_buff);
enum PACKET_CHECK packet_check_rule(const struct packet_info * info);
#endif
