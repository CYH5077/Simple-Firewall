#ifndef __FIREWALL_LINKED_LIST_HEADER__
#define __FIREWALL_LINKED_LIST_HEADER__
#include <linux/slab.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>

#include "firewall_const.h"

// ��Ŷ ���� ���� ����ü
struct packet_info {
	enum RULE flag;
	enum PROTOCOL_VALUE protocol;
	unsigned int saddr, daddr;
	unsigned short sport, dport;
	unsigned int temp_address;
};

struct link_node {
	unsigned char rule_num;	//�� ��ȣ
	struct packet_info data; // ��Ŷ ����

	struct link_node * next;
};

// ���Ḯ��Ʈ.
struct link_list {
	int rule_count; //�� ����

	struct link_node * start;
	struct link_node * end;
};

extern struct link_list rule_list;

//////////////////////////////////////////////////////////// Function

/*
 * link_node �� ����.
 * @param
 * info - packet_info ����ü
 * @return
 * ������ link_node ����ü�� ��ȯ�ϰ�
 * ���н� NULL ��ȯ
 */
struct link_node * link_node_create(const struct packet_info * info);
/*
 * link_list �ʱ�ȭ
 * @param
 * list - �ʱ�ȭ�� link_list ����ü
 */
void link_list_init(struct link_list * list);

/*
 * link_list ����ü�� ��带 �߰��Ѵ�.
 * @param
 * node - �߰��� ��� 
 * @return
 * ������ 0�� ��ȯ
 * ���н� -1�� ��ȯ
 */
int link_list_add(struct link_list * list, struct link_node * node);

/*
 * link_list ���� �ش� ���� ���� ��带 �����Ѵ�.
 * @param
 * list - link_list ����ü
 * rule_num  - �� ��ȣ.
 * @return
 * ������ 0
 * ���н� -1�� ��ȯ.
 */
int link_list_del(struct link_list * list, int rule_num);

/*
 * ���� ����. ipaddr���� �ش��ϴ� ��� ��带 �����Ѵ�.
 * @param
 * ipaddr - ������ ip 
 * @return
 * ������ 0
 * ���н� -1�� ��ȯ.
 */
int link_list_del_ip(struct link_list * list, unsigned int ipaddr);

/*
 * ���� ����. portaddr���� �ش��ϴ� ��� ��带 �����Ѵ�.
 * @param
 * portaddr - ������ port 
 * @return
 * ������ 0
 * ���н� -1�� ��ȯ
 */
int link_list_del_port(struct link_list * list, unsigned short portaddr);

/*
 * list ��带 �ʱ�ȭ�Ѵ� (��� ��� ����)
 * @param 
 * list - �ʱ�ȭ�� link_list
 */
void link_list_clear(struct link_list * list);

/*
 * packet_info ����ü�� �����͸� link_list ����ü�� ��� ��Ī�Ѵ�.
 * @param
 * list - link_list ����ü
 * packet_info - info ����ü
 * @return 
 * PACKET_ACCEPT �Ǵ� PACKET_DROP ��ȯ
 */
enum PACKET_CHECK list_match(struct link_list * list, const struct packet_info * info);

/*
 * ����Ʈ�� ����� �� ������ �����´�.
 */
int get_rule_data(struct link_list * list, char * buf, int buf_size);

// @TODO ������ ����Լ�.
void link_list_print_all(struct link_list * list);
#endif
