#ifndef __FIREWALL_LINKED_LIST_HEADER__
#define __FIREWALL_LINKED_LIST_HEADER__
#include <linux/slab.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>

#include "firewall_const.h"

// 패킷 정보 저장 구조체
struct packet_info {
	enum RULE flag;
	enum PROTOCOL_VALUE protocol;
	unsigned int saddr, daddr;
	unsigned short sport, dport;
	unsigned int temp_address;
};

struct link_node {
	unsigned char rule_num;	//룰 번호
	struct packet_info data; // 패킷 정보

	struct link_node * next;
};

// 연결리스트.
struct link_list {
	int rule_count; //룰 개수

	struct link_node * start;
	struct link_node * end;
};

extern struct link_list rule_list;

//////////////////////////////////////////////////////////// Function

/*
 * link_node 를 생성.
 * @param
 * info - packet_info 구조체
 * @return
 * 성공시 link_node 구조체를 반환하고
 * 실패시 NULL 반환
 */
struct link_node * link_node_create(const struct packet_info * info);
/*
 * link_list 초기화
 * @param
 * list - 초기화할 link_list 구조체
 */
void link_list_init(struct link_list * list);

/*
 * link_list 구조체에 노드를 추가한다.
 * @param
 * node - 추가할 노드 
 * @return
 * 성공시 0을 반환
 * 실패시 -1을 반환
 */
int link_list_add(struct link_list * list, struct link_node * node);

/*
 * link_list 에서 해당 값을 가진 노드를 제거한다.
 * @param
 * list - link_list 구조체
 * rule_num  - 룰 번호.
 * @return
 * 성공시 0
 * 실패시 -1을 반환.
 */
int link_list_del(struct link_list * list, int rule_num);

/*
 * 위와 같다. ipaddr값에 해당하는 모든 노드를 제거한다.
 * @param
 * ipaddr - 제거할 ip 
 * @return
 * 성공시 0
 * 실패시 -1을 반환.
 */
int link_list_del_ip(struct link_list * list, unsigned int ipaddr);

/*
 * 위와 같다. portaddr값에 해당하는 모든 노드를 제거한다.
 * @param
 * portaddr - 제거할 port 
 * @return
 * 성공시 0
 * 실패시 -1을 반환
 */
int link_list_del_port(struct link_list * list, unsigned short portaddr);

/*
 * list 노드를 초기화한다 (모든 노드 제거)
 * @param 
 * list - 초기화할 link_list
 */
void link_list_clear(struct link_list * list);

/*
 * packet_info 구조체의 데이터를 link_list 구조체의 룰과 매칭한다.
 * @param
 * list - link_list 구조체
 * packet_info - info 구조체
 * @return 
 * PACKET_ACCEPT 또는 PACKET_DROP 반환
 */
enum PACKET_CHECK list_match(struct link_list * list, const struct packet_info * info);

/*
 * 리스트에 저장된 룰 정보를 가져온다.
 */
int get_rule_data(struct link_list * list, char * buf, int buf_size);

// @TODO 디버깅용 출력함수.
void link_list_print_all(struct link_list * list);
#endif
