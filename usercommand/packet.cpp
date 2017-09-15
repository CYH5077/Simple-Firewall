#include "packet.hpp"

void initPacketInfo(struct PacketInfo * info){
	info->flag = RULE_NONE;
	info->protocol = IP_PROTOCOL;
	info->saddr = info->daddr = 0;
	info->sport = info->dport = 0;
}
