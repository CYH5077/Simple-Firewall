#include "chrdevice.h"
#include "list.h"

#include <asm/uaccess.h>

//rule_list
struct file_operations chr_dev;

int firewall_chrdev_register(void){
	chr_dev.owner = THIS_MODULE;
	chr_dev.open = chrdev_open;
	chr_dev.release = chrdev_close;
	chr_dev.write = chrdev_write;
	chr_dev.read = chrdev_read;

	return register_chrdev(CHR_MAIN_NUM, CHR_DEV_NAME, &chr_dev);
}

void firewall_chrdev_unregister(void){
	unregister_chrdev(CHR_MAIN_NUM, CHR_DEV_NAME);
}


//Open
int chrdev_open(struct inode *inode, struct file *filp){
	return 0;
}
//Close
int chrdev_close(struct inode *inode, struct file *filp){
	return 0;
}

//Rule 생성
static int create_rule(const struct packet_info * info){
	struct link_node * node = link_node_create(info);
	if(node == NULL)
		return -1;
	if(link_list_add(&rule_list, node) == -1)
		return -1;
	return 0;
}
//Rule 제거.
static int delete_rule(unsigned char rule_num){
	if(link_list_del(&rule_list, rule_num) == -1)
		return -1;
	return 0;
}
static int delete_rule_ip(unsigned int ipaddr){
	if(link_list_del_ip(&rule_list, ipaddr) == -1)
		return -1;
	return 0;
}
static int delete_rule_port(unsigned short port){
	if(link_list_del_port(&rule_list, port) == -1)
		return -1;
	return 0;
}
//Write
ssize_t chrdev_write(struct file *filp, const char *buf, size_t count, loff_t *f_pos){
	const struct packet_info *info = (struct packet_info *)buf;
	if(count != sizeof(struct packet_info))
		return -1;
	switch(info->flag){
	case RULE_CREATE:
		if(create_rule(info) == -1) return -1;
		break;
	case RULE_DELETE:
		if(delete_rule(info->temp_address) == -1) return -1;		
		break;
	case RULE_DELETE_IP:
		if(delete_rule_ip(info->temp_address) == -1) return -1;
		break;
	case RULE_DELETE_PORT:
		if(delete_rule_port(info->temp_address) == -1) return -1;
		break;
	default:
		return -1;
	}
	return 0;
}
//Read
ssize_t chrdev_read(struct file *filp, char *buf, size_t count, loff_t *f_pos){
	char kern_buf[10240] = {0, };
	int copy_size = 0;
	
	copy_size = get_rule_data(&rule_list, kern_buf, 10240);
	//printk(KERN_INFO "%s\n", kern_buf);
	copy_to_user(buf, kern_buf, copy_size);
	return 0;
}

