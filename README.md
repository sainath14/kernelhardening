# kernelhardening

Hardware assisted virtualization features enforce security for memory and processor state. 
These can be leveraged to protect the kernel integrity for KVM guests and can also be extended to native linux
execution. For this linux has to run in non-root mode. We developed a linux module that helps switch all the 
processors on the system into non-root mode.

An example policy to protect CR0 bits from being modified is implemented.

Steps to tryout this module and example policy

1. Clone the repo locally on a linux system
2. Move to cpu_switch directory
3. Do a make
4. insmod vmx_switch.ko
5. Mount configfs at /config (check if configfs is already mounted - cat /proc/mounts)
6. Move to kernelhardening/driver directory
7. Do a make
8. insmod kernelhardening.ko
9. Move to /config/ikgt_agent and create directory CR0
10. Move to CR0 directory and create PG directory
11. Move to PG directory and do echo 1 > enable

Now the root mode is set up to protect CR0 bit manipulation.

For testing CR0 bit manipulation, do the following

1. Move to kernelhardening/test_modules directory
2. Do a make
3. insmod cr0-pg.ko

This module tries to write to reset PG bit in CR0 but fails.

Known issues:
Upon loading the module and after the processors are in non-root mode, system reboot leads to hang. So please avoid reboot!!!
