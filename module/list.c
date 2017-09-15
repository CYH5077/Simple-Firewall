#include "list.h"

struct link_list rule_list;

struct link_node * link_node_create(const struct packet_info * info){
	struct link_node * node =
		(struct link_node *)kmalloc(sizeof(struct link_node), GFP_KERNEL);
	if(node == NULL)
		return NULL;
	//Value Setting
	node->rule_num = 0;
	node->next = NULL;
	
	node->data = *info;

	return node;
}

void link_list_init(struct link_list * list){
	list->rule_count = 0;
	list->start = list->end = NULL;
}

int link_list_add(struct link_list * list, struct link_node * node){
	if(node == NULL)
		return -1;
	node->rule_num = list->rule_count + 1;
	if(list->start == NULL){
		list->start = list->end = node;
	} else {
		list->end->next = node;
		list->end = list->end->next;
	}
	list->rule_count++;
	return 0;
}

//아래서 제거된 노드 뒤의 룰 번호를 보정한다.
static void link_list_node_rule_fix(struct link_node * node){
	while(node != NULL){
		node->rule_num--;
		node = node->next;
	}
}
int link_list_del(struct link_list * list, int rule_num){
	struct link_node * node = list->start;
	struct link_node * prev_node = NULL;
	while(node != NULL){
		if(node->rule_num == rule_num){
			if(prev_node == NULL){
				list->start = node->next;
			} else {
				if(list->end == node){
					list->end = prev_node;
					list->end->next = NULL;
				} else {
					prev_node->next = node->next;
				}
			}
			link_list_node_rule_fix(node->next);
			list->rule_count--;
			if((list->rule_count == 0) || (list->start == NULL))
				list->start = list->end = NULL;
			kfree(node);
			return 0;
		}
		prev_node = node;
		node = node->next;
	}
	return -1;
}

int link_list_del_ip(struct link_list * list, unsigned int ipaddr){
	int remove_count = 0;
	struct link_node * node = list->start;
	int remove_result = 0;
	unsigned char temp_rule_num = 0;
	while(node != NULL){
		temp_rule_num = node->rule_num;
		if((node->data.saddr == ipaddr) || (node->data.daddr == ipaddr)){
			node = node->next;
			remove_result = link_list_del(list, temp_rule_num);
			remove_count++;
			continue;
		}
		if(remove_result == -1)
			return -1;
		node = node->next;
	}
	return (remove_count > 0) ? 0 : -1;
}

int link_list_del_port(struct link_list * list, unsigned short portaddr){
	int remove_count = 0;
	struct link_node * node = list->start;
	int remove_result = 0;
	unsigned char temp_rule_num = 0;
	while(node != NULL){
		temp_rule_num = node->rule_num;
		if((node->data.sport == portaddr) || (node->data.dport == portaddr)){
			node = node->next;
			remove_result = link_list_del(list, temp_rule_num);
			remove_count++;
			continue;
		}
		if(remove_result == -1)
			return -1;
		node = node->next;
	}
	return (remove_count > 0) ? 0 : -1;
}

void link_list_clear(struct link_list * list){
	struct link_node * temp_node = NULL;
	while(temp_node != NULL){
		temp_node = list->start;
		list->start = list->start->next;
		list->rule_count--;
		kfree(temp_node);
	}
	list->start = list->end = NULL;
}

enum PACKET_CHECK list_match(struct link_list * list, const struct packet_info * info){
	struct link_node * node = list->start;
	struct packet_info node_data;
	while(node != NULL){
		node_data = node->data;
		if((info->protocol & IP_PROTOCOL) // IP Filter 
				&& (node_data.protocol & IP_PROTOCOL)){
			if((info->saddr == node_data.saddr)
					|| (info->daddr == node_data.daddr)){
				printk(KERN_INFO "IP_PROTOCOL DROP\n");
				return PACKET_DROP;
			}
		}
		
		if((info->protocol & UDP_PROTOCOL) // UDP Filter
				&& (node_data.protocol & UDP_PROTOCOL)){
			if((info->sport == node_data.sport)
					|| (info->dport == node_data.dport))
				return PACKET_DROP;
		} else if((info->protocol & TCP_PROTOCOL) // TCP Filter
				&& (node_data.protocol & TCP_PROTOCOL)){
			if((info->sport == node_data.sport)
					|| (info->dport == node_data.dport))
				return PACKET_DROP;
		}
		
		node = node->next;
	}
	return PACKET_ACCEPT;
}

int get_rule_data(struct link_list * list, char * buf, int buf_size){
	struct link_node * node = list->start;
	struct packet_info node_data;
	int copy_size = 0;
	while(node != NULL){
		node_data = node->data;
		//rule_num, protocol, saddr, daddr, sport, dport
		sprintf(buf, "%s%d %d %d %d %d %d", buf,
						  node->rule_num,
						  node_data.protocol,
						  node_data.saddr,
						  node_data.daddr,
						  node_data.sport,
						  node_data.dport);
		node = node->next;
		if(node != NULL)
			strcat(buf, "\n");
		copy_size += strlen(buf) - copy_size;
		if(copy_size >= buf_size)
			break;
	}
	return copy_size;
}

void link_list_print_all(struct link_list * list){
	struct link_node * node = list->start;
	while(node != NULL){
		printk("[Node data] : %d ", node->rule_num);
		node = node->next;
	}
	printk("\n");
}
