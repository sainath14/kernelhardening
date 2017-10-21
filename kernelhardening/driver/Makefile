KERNELDIR:=/lib/modules/$(shell uname -r)/build
PWD=$(shell pwd)

obj-m += kernelhardening.o

kernelhardening-y := main.o cr0.o cr4.o configfs_setup.o policy.o vmcall.o

all:
	$(MAKE) -C $(KERNELDIR) M=$(PWD)

clean:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) clean

install:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules_install
