#include <linux/smp.h>

#include "policy_common.h"
#include "common.h"
#include "vmx_common.h"

void asm_make_vmcall(unsigned int hypercall_id, void *params);

static void monitor_cpu_events_ex(void *info)
{
	cpu_event_params_t *params = info;

	printk (KERN_ERR "monitor_cpu_events called on %x\n", smp_processor_id());
	asm_make_vmcall(KERNEL_HARDENING_HYPERCALL, (void *)params);	
}

void monitor_cpu_events(unsigned long mask, bool enable, cpu_reg_t reg)
{
	cpu_event_params_t *params = NULL;
	
	params = kzalloc(sizeof(cpu_event_params_t), GFP_KERNEL);

	params->size = sizeof(cpu_event_params_t);
	params->req_id = CPU_MONITOR_REQ;
	params->cpu_reg = reg;
	params->enable = enable;
	params->mask = mask;

	printk (KERN_ERR "monitor_cpu_events called on %x\n", smp_processor_id());
	asm_make_vmcall(KERNEL_HARDENING_HYPERCALL, (void *)params);	
	smp_call_function_many(cpu_online_mask, monitor_cpu_events_ex, (void *)params, true);
}
