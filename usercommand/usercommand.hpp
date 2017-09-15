#ifndef __FIREWALL_USERCOMMAND_USERCOMMNAD_HEADER__
#define __FIREWALL_USERCOMMAND_USERCOMMNAD_HEADER__
#include "firewall.hpp"

#include <map>
#include <string>

class UserCommand{
public:
	UserCommand(){}
	~UserCommand(){}

	bool OpenFirewall();
	void CloseFirewall();

	bool ParseArgv(int args, char * argv[]);

	bool CommandStart();
private:
	Firewall firewall;
	//넘어온 옵션 <옵션, 값>
	std::map<std::string, std::string> option_data;
};
#endif
