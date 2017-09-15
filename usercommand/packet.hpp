#ifndef __FIREWALL_USERCOMMAND_PACKET_HEADER__
#define __FIREWALL_USERCOMMAND_PACKET_HEADER__
#include "../module/firewall_const.h"

struct PacketInfo {
	enum RULE flag;
	enum PROTOCOL_VALUE protocol;
	unsigned int saddr, daddr;
	unsigned short sport, dport;
	unsigned int temp_address;
};

struct RuleData{
	unsigned char rule_num;
	struct PacketInfo data;
};

void initPacketInfo(struct PakcetInfo * info);
#endif
