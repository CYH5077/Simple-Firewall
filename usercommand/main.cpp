#include "usercommand.hpp"
#include "../module/firewall_const.h"

#include <iostream>

#include <cstdio>
int main(int argc, char * argv[]){
	UserCommand user;

	if(!user.OpenFirewall()){
		std::cout << "OpenFirewall() failed" << std::endl;
		return -1;
	}
	
	if(!user.ParseArgv(argc, argv)){
		std::cout << "Parse failed" << std::endl;
	}

	if(!user.CommandStart()){
		std::cout << "Command failed" << std::endl;
	}
	
	user.CloseFirewall();

	/*
	Firewall firewall;
	
	if(firewall.CreateDevice(DEVICE_NAME) == -1){
		std::cout << "CreateDevice() Failed" << std::endl;
		perror("????");
		return -1;
	}
	
	if(firewall.CreateRule(TCP_PROTOCOL, 0, 0, 0, 80) == -1)
		std::cout << "CreateRule() Failed" << std::endl;
	if(firewall.CreateRule(TCP_PROTOCOL, 1000, 0, 0, 8080) == -1)
		std::cout << "CreateRule() Failed" << std::endl;
	if(firewall.CreateRule(TCP_PROTOCOL, 0, 200, 0, 9000) == -1)
		std::cout << "CreateRule() Failed" << std::endl;
	if(firewall.CreateRule(TCP_PROTOCOL, 1000, 0, 0, 8080) == -1)
		std::cout << "CreateRule() Failed" << std::endl;
	if(firewall.CreateRule(TCP_PROTOCOL, 0, 200, 0, 9000) == -1)
		std::cout << "CreateRule() Failed" << std::endl;

	//firewall.ReadRule();
	firewall.PrintAll();

	int select_rule = 0;
	while(true){

		std::cout << "Delete Rule : ";
		std::cin >> select_rule;
		if(select_rule == 0)
			break;
		std::cout << "Delete rule number " << select_rule << std::endl;
		firewall.DeleteRule(RULE_DELETE, select_rule);	
		//firewall.ReadRule();
		firewall.PrintAll();
	}
	std::cout << "Delete destination port 9000" << std::endl;
	firewall.DeleteRule(RULE_DELETE_PORT, 9000);
	//firewall.ReadRule();
	firewall.PrintAll();
	
	firewall.Close();
	*/
	return 0;
}
