#include "firewall.hpp"

#include <iostream>
#include <iomanip>
#include <vector>

#include <cstdio>
#include <cstring>
#include <netinet/in.h>
#include <arpa/inet.h>

int Firewall::CreateDevice(std::string dev_name){
	return CreateDevice(dev_name, DEVICE_NUM);
}

int Firewall::CreateDevice(std::string dev_name, dev_t dev_num){
	this->dev_name = dev_name;
	if(mknod(dev_name.c_str(), S_IFCHR, (dev_num<<8)|1) == -1)
		return -1;
	firewall_dev_fd = open(dev_name.c_str(), O_RDWR);
	if(firewall_dev_fd == -1)
		return -1;
	return 0;
}

int Firewall::CreateRule(enum PROTOCOL_VALUE protocol,
			unsigned int saddr, unsigned int daddr,
			unsigned short sport, unsigned short dport){
	struct PacketInfo info;
	info.flag = RULE_CREATE;
	info.protocol = protocol;
	info.saddr = saddr;
	info.daddr = daddr;
	info.sport = sport;
	info.dport = dport;
	return WriteRule(&info);
}

int Firewall::DeleteRule(enum RULE delete_flag, unsigned int address){
	struct PacketInfo info;
	info.flag = delete_flag;
	info.temp_address = address;
	return WriteRule(&info);
}

int Firewall::WriteRule(const struct PacketInfo * info) {
	return write(this->firewall_dev_fd, (void*)info, 
						sizeof(struct PacketInfo));
}

int Firewall::ReadRule() {
	char buffer[10240] = {0,};
	
	read(firewall_dev_fd, buffer, 4096);
	
	//std::cout << buffer << std::endl;
	int ret_val = ReadParse(buffer);
	//std::cout << "Parse data count : " << ret_val << std::endl << std::endl;
	return ret_val;
}

int Firewall::ReadParse(char * data) {
	struct RuleData rule;
	struct PacketInfo * info = &rule.data;
	char * line_cut_data = NULL;
	char * next_data = NULL;
	
	rule_data.clear();

	while(true){
		if(line_cut_data == NULL)
			line_cut_data = strtok_r(data, "\n", &next_data);
		else
			line_cut_data = strtok_r(NULL, "\n", &next_data);

		if(line_cut_data == NULL)
			break;
		sscanf(line_cut_data, "%hhu %d %u %u %hu %hu", &rule.rule_num,
							   &info->protocol,
							   &info->saddr,
							   &info->daddr,
							   &info->sport,
							   &info->dport);
		rule_data.push_back(rule);
	}
	return rule_data.size();
}

static std::string UintToString(unsigned int ip){
	struct in_addr ip_addr = {(int)ip};
	/*unsigned char * ip_byte = (unsigned char *)&ip;
	char ip_str[40] = {0, };
	sprintf(ip_str, "%d.%d.%d.%d", ip_str[0], ip_str[1], ip_str[2], ip_str[3]);
	*/

	return inet_ntoa(ip_addr);
}

void Firewall::PrintAll(){
	ReadRule();

	struct PacketInfo info;

	std::cout.setf(std::ios::right);
	std::cout << std::setw(5)  << "Num" 
		  << std::setw(20) << "PROTOCOL" 
		  << std::setw(16) << "Source IP" 
		  << std::setw(16) << "Destination IP" 
		  << std::setw(17) << "Source Port" 
		  << std::setw(20) << "Destination Port" << std::endl;
	for(unsigned int i = 0; i < rule_data.size(); i++){
		info = rule_data[i].data;
		std::string protocol_str = "";

		if(GetProtocolStr(info.protocol, &protocol_str) == false)
			protocol_str = "UNKNOWN";

		std::cout << std::setw(5) << (unsigned int)rule_data[i].rule_num
			  << std::setw(20) << protocol_str
			  << std::setw(16) << UintToString(info.saddr)
			  << std::setw(16) << UintToString(info.daddr)
			  << std::setw(17) << info.sport
			  << std::setw(20) << info.dport << std::endl;
	}
}

bool Firewall::GetProtocolStr(enum PROTOCOL_VALUE protocol, std::string * str){
	(*str) = "";
	if(protocol & IP_PROTOCOL){
		(*str) += "IP_PROTOCOL";
	}

	if(protocol & TCP_PROTOCOL){
		(*str) += ((*str) == "") ? "" : ", ";
		(*str) += "TCP_PROTOCOL";
	} else if (protocol & UDP_PROTOCOL){
		(*str) += ((*str) == "") ? "" : ", ";
		(*str) += "UDP_PROTOCOL";
	}
	return ((*str) != "") ? true : false;
}

void Firewall::Close(){
	close(this->firewall_dev_fd);
	unlink(this->dev_name.c_str());
}
