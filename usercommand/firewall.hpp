#ifndef __FIREWALL_USERCOMMAND_CHRDEV_HEADER__
#define __FIREWALL_USERCOMMAND_CHRDEV_HEADER__
#include "packet.hpp"

#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>

#include <string>
#include <vector>

#define DEVICE_NAME "/dev/Firewall"
#define DEVICE_NUM 2000
class Firewall {
public:
	Firewall(){}
	~Firewall(){}

	int CreateDevice(std::string dev_name);
	int CreateDevice(std::string dev_name, dev_t dev_num);

	int CreateRule(enum PROTOCOL_VALUE protocol,
		      unsigned int saddr, unsigned int daddr,
		      unsigned short sport, unsigned short dport);
	int DeleteRule(enum RULE delete_flag, unsigned int address);
	int WriteRule(const struct PacketInfo * info);


	void PrintAll();
	void Close();
protected:
	int ReadRule();
	int ReadParse(char * data);
	bool GetProtocolStr(enum PROTOCOL_VALUE protocol, std::string * str);
private:
	int firewall_dev_fd;
	std::string dev_name;
	std::vector<struct RuleData> rule_data;
};

#endif
