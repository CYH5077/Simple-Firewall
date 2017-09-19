#include "usercommand.hpp"

#include <iostream>
#include <string>
#include <cstdlib>
#include <netinet/in.h>
#include <arpa/inet.h>

bool UserCommand::OpenFirewall(){
	if(firewall.CreateDevice(DEVICE_NAME) == -1){
		return false;
	}
	return true;
}

void UserCommand::CloseFirewall(){
	firewall.Close();
}

bool UserCommand::ParseArgv(int args, char * argv[]){
	if(args < 2){
		return false;
	}
	option_data.clear();

	bool option_flag = false;
	std::string option = "";
	std::string data = "";
	for(int i = 1; i < args; i++){
		if(option_flag){ //Data
			data = argv[i];
			option_data.insert(std::make_pair(option, data));
			option = data = "";
			option_flag = false;
		} else { // Option
			if(option != ""){
				std::cout << "Option : " << option << " Error" << std::endl;
				return false;
			} else if(argv[i][0] != '-') {
				std::cout << "Option : " << argv[i] << " Error" << std::endl;
				return false;
			}
			option = argv[i];
			option_flag = true;
		}
	}
	return true;
}


static enum RULE ruleOptionData(std::string data){
	if(data == "create"){
		return RULE_CREATE;
	} else if(data == "delete"){
		return RULE_DELETE;
	} else if(data == "delete_ip"){
		return RULE_DELETE_IP;
	} else if(data == "delete_port"){
		return RULE_DELETE_PORT;
	}
	return RULE_NONE;
}

bool UserCommand::CommandStart(){
	enum RULE rule = RULE_NONE;
	enum PROTOCOL_VALUE protocol;
	unsigned int saddr, daddr;
	unsigned short sport, dport;
	unsigned int address;
	address = saddr = daddr = sport = dport = 0;
	for(auto & iter : option_data){
		if(iter.first == "-rule") {
			rule = ruleOptionData(iter.second);
		} else {
			if(iter.first == "-saddr"){
				saddr = (unsigned int)inet_addr(iter.second.c_str());
				if(!(protocol & IP_PROTOCOL))
					protocol = IP_PROTOCOL;
			} else if(iter.first == "-daddr"){
				daddr = (unsigned int)inet_addr(iter.second.c_str());
				if(!(protocol & IP_PROTOCOL))
					protocol = IP_PROTOCOL;
			} else if(iter.first == "-protocol"){
				if(iter.second == "tcp")
					protocol = TCP_PROTOCOL;
				else if(iter.second == "udp")
					protocol = UDP_PROTOCOL;
				else {
					std::cout << "Protocol Error (tcp, udp)" << std::endl;
					return false;
				}
			} else if(iter.first == "-sport"){
				sport = atoi(iter.second.c_str());
			} else if(iter.first == "-dport"){
				dport = atoi(iter.second.c_str());
			} else if(iter.first == "-address"){
				address = (unsigned int)atoi(iter.second.c_str());
			} else if(iter.first == "-print"){
				firewall.PrintAll();
				return true;
			}
		}
	}
	if(rule == RULE_NONE){
		std::cout << "RULE Error" << std::endl;
		return false;
	} else if(rule == RULE_CREATE) {
		if(firewall.CreateRule(protocol, saddr, daddr, sport, dport) == -1){
			std::cout << "Create rule failed" << std::endl;
			return false;
		}
	} else if((rule == RULE_DELETE) || 
		  (rule == RULE_DELETE_IP) || 
		  (rule == RULE_DELETE_PORT)){
		if(firewall.DeleteRule(rule, address) == -1){
			std::cout << "Delete rule failed" << std::endl;
			return false;
		}
	}
	return true;
}
