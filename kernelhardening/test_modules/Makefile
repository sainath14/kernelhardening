KERNELDIR:=/lib/modules/$(shell uname -r)/build
PWD=$(shell pwd)

INCLUDES = -I. \
	   -I/home/secondstorage/kernelhardening/kernelhardening/common/include

ccflags-y += $(INCLUDES)

obj-m += cr0-pg.o

cr0-pg-y := cr0_pg.o

all:
	$(MAKE) -C $(KERNELDIR) M=$(PWD)

clean:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) clean

install:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules_install
