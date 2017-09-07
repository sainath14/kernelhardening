# nonrootswitch

Hardware assisted virtualization features enforce security for memory and processor state. 
These can be leveraged to protect the kernel integrity for KVM guests and can also be extended to native linux
execution. For this linux has to run in non-root mode. We developed a linux module that helps switch all the 
processors on the system into non-root mode. Efforts to implement example policies to protect memory and processor state 
is work in progress.

Steps to tryout this module

1. Clone the repo locally on a linux system
2. Move to cpu_switch directory
3. Do a make
4. insmod vmx_switch.ko

Upon loading this module, all the processors on the system are now in non-root mode.
