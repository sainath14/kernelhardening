#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/mm.h>
#include <linux/kthread.h>
#include <linux/smp.h>
#include <linux/slab.h>
#include <linux/compiler.h>
#include <linux/cpumask.h>
#include <linux/sched.h>

#include <asm/desc.h>
#include <asm/msr.h>
#include <asm/tlbflush.h>
#include <asm/kvm_host.h>
#include <asm/vmx.h>
#include <asm/msr-index.h>

#include "policy_common.h"

static int __init cr0_pg_init(void)
{
	unsigned long val;

	val = read_cr0();
	printk (KERN_ERR "value read from cr0 %lx\n", val);
	val = val & ~(1 << PG);
	printk (KERN_ERR "value after logical and %lx\n", val);
	write_cr0(val);
	asm volatile ("cpuid\n");
	val = read_cr0();
	printk (KERN_ERR "value read from cr0 %lx\n", val);
	return 0;
}

static void cr0_pg_exit(void)
{
	printk (KERN_ERR "module cr0_pg unloaded\n");
}

module_init(cr0_pg_init);
module_exit(cr0_pg_exit);
MODULE_LICENSE("GPL");
