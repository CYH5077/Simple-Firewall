#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>

#include "packet.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Choi-Y-H");
MODULE_DESCRIPTION("Simple Firewall");

static struct nf_hook_ops net_hook;

int firewall_install(void){
	net_hook.hook = packet_filter;
	net_hook.hooknum = 1; // 호출 순서번호.
	net_hook.pf = PF_INET; // ipv4
	net_hook.priority = NF_IP_PRI_FIRST; // 후킹된 함수들중 제일 먼저 실행


	nf_register_hook(&net_hook);
	return 0;
}

void firewall_delete(void){
	nf_unregister_hook(&net_hook);
}

module_init(firewall_install);
module_exit(firewall_delete);
