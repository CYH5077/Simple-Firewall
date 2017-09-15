#ifndef __FIREWALL_CHRDEV_HEADER__
#define __FIREWALL_CHRDEV_HEADER__
#include <linux/fs.h>

#define CHR_MAIN_NUM 2000
#define CHR_DEV_NAME "Firewall"

extern struct file_operations chr_dev;

/*
 * 문자 디바이스를 등록한다.
 * @return
 * 성공시 0 
 * 실패시 -1 반환
 */
int firewall_chrdev_register(void);

/*
 * 문자 디바이스를 등록 해제한다.
 */
void firewall_chrdev_unregister(void);

/*
 * 문자 디바이스 syscall 호출시 동작.
 */
int chrdev_open(struct inode *inode, struct file *filp);
int chrdev_close(struct inode *inode, struct file *filp);
ssize_t chrdev_write(struct file *filp, const char *buf, size_t count, loff_t *f_pos);
ssize_t chrdev_read(struct file *filp, char *buf, size_t count, loff_t *f_pos);
#endif
