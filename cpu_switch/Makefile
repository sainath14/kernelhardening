KERNELDIR:=/lib/modules/$(shell uname -r)/build
PWD=$(shell pwd)

obj-m += vmx-switch.o

vmx-switch-y := cpu_switch.o  vmexit.o ptable.o

all:
	$(MAKE) -C $(KERNELDIR) M=$(PWD)

clean:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) clean

install:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules_install
