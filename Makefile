MODULEFILES = $(wildcard *.c)

obj-m += firewall.o
firewall-objs += ./module.o ./packet.o

KERNDIR = /lib/modules/$(shell uname -r)/build
BUILDDIR = $(shell pwd)

all:
	$(MAKE) -C $(KERNDIR) M=$(BUILDDIR) modules
clean:
	$(MAKE) -C $(KERNDIR) M=$(BUILDDIR) clean
