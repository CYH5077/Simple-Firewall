#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>

#include "packet.h"
#include "chrdevice.h"
#include "list.h"

struct link_list list;

int firewall_install(void){
	if(network_hook_register() != 0){
		printk(KERN_ALERT "Packet filter hook failed\n");
		return -1;
	}

	if(firewall_chrdev_register() != 0){
		printk(KERN_ALERT "Create character device failed\n");
		network_hook_unregister();
		return -1;
	}

	link_list_init(&list);
/*
	link_list_print_all(&list);
	link_list_del(&list, 1);
	link_list_print_all(&list);
	link_list_del(&list, 2);
	link_list_print_all(&list);
*/
	return 0;
}

void firewall_delete(void){
	network_hook_unregister();
	firewall_chrdev_unregister();
	link_list_clear(&list);
}

module_init(firewall_install);
module_exit(firewall_delete);


MODULE_LICENSE("GPL");
MODULE_AUTHOR("Choi-Y-H");
MODULE_DESCRIPTION("Simple Firewall");
