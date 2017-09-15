#ifndef __FIREWALL_CONST_HEADER__
#define __FIREWALL_CONST_HEADER__

//�� �߰� ���� �÷���
enum RULE {
	RULE_CREATE = 0,
	RULE_DELETE,
	RULE_DELETE_IP,
	RULE_DELETE_PORT,
	RULE_NONE
};

// ��Ŷ �����.
enum PACKET_CHECK {
	PACKET_ACCEPT = 0,
	PACKET_DROP
};

// ���� ������.
enum PROTOCOL_VALUE {
	TCP_PROTOCOL = 1 << 0,
	UDP_PROTOCOL = 1 << 1,
	IP_PROTOCOL  = 1 << 2
};

#endif
