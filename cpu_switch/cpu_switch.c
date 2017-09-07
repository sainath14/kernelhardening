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

#define __ex(x) x

struct vmcs {
	u32 revision_id;
	u32 abort;
	char data[0];
};

struct vcpu_vmx {
        struct vmcs *pcpu_vmcs;
        struct vmcs *vmxarea;
        u64 vcpu_stack;
        unsigned long *regs;
	bool instruction_skipped;
};

static DEFINE_PER_CPU(struct vcpu_vmx, vcpu);
static DEFINE_PER_CPU(struct desc_ptr, host_gdt);
DEFINE_PER_CPU(unsigned long[NR_VCPU_REGS], reg_scratch);
DEFINE_PER_CPU(struct task_struct, root_thread);
DECLARE_BITMAP(all_cpus, NR_CPUS);
DECLARE_BITMAP(switch_done, NR_CPUS);
wait_queue_head_t root_thread_queue;
static pgd_t *host_cr3;
static DEFINE_MUTEX(ept_lock);

static struct vmcs_config {
	int size;
	int order;
	u32 basic_cap;
	u32 revision_id;
	u32 pin_based_exec_ctrl;
	u32 cpu_based_exec_ctrl;
	u32 cpu_based_2nd_exec_ctrl;
	u32 vmexit_ctrl;
	u32 vmentry_ctrl;
} vmcs_config;

static unsigned long *vmx_io_bitmap_a_switch;
static unsigned long *vmx_io_bitmap_b_switch;
static unsigned long *vmx_msr_bitmap_switch;
unsigned long *vmx_eptp_pml4 = NULL;
static bool ept_tables_set = 0;

static bool __read_mostly switch_on_load = 1;
module_param_named(switch_vmx, switch_on_load, bool, 0644);
void vmx_switch_and_exit_handle_vmexit(void);
void setup_ept_tables(void);
void dump_entries (u64 gpa);

static __always_inline unsigned long __vmcs_readl(unsigned long field)
{
	unsigned long value;

	asm volatile (ASM_VMX_VMREAD_RDX_RAX
		      : "=a"(value) : "d"(field) : "cc");
	return value;
}

static __always_inline u16 vmcs_read16(unsigned long field)
{
	return __vmcs_readl(field);
}

static __always_inline u32 vmcs_read32(unsigned long field)
{
	return __vmcs_readl(field);
}

static __always_inline u64 vmcs_read64(unsigned long field)
{
#ifdef CONFIG_X86_64
	return __vmcs_readl(field);
#else
	return __vmcs_readl(field) | ((u64)__vmcs_readl(field+1) << 32);
#endif
}

static __always_inline unsigned long vmcs_readl(unsigned long field)
{
	return __vmcs_readl(field);
}

static noinline void vmwrite_error(unsigned long field, unsigned long value)
{
	printk(KERN_ERR "vmwrite error: reg %lx value %lx (err %d)\n",
	       field, value, vmcs_read32(VM_INSTRUCTION_ERROR));
	dump_stack();
}

static __always_inline void __vmcs_writel(unsigned long field, unsigned long value)
{
	u8 error;

	asm volatile (__ex(ASM_VMX_VMWRITE_RAX_RDX) "; setna %0"
		       : "=q"(error) : "a"(value), "d"(field) : "cc");
	if (unlikely(error))
		vmwrite_error(field, value);
}

static __always_inline void vmcs_write16(unsigned long field, u16 value)
{
	__vmcs_writel(field, value);
}

static __always_inline void vmcs_write32(unsigned long field, u32 value)
{
	__vmcs_writel(field, value);
}

static __always_inline void vmcs_write64(unsigned long field, u64 value)
{
	__vmcs_writel(field, value);
#ifndef CONFIG_X86_64
	asm volatile ("");
	__vmcs_writel(field+1, value >> 32);
#endif
}

static __always_inline void vmcs_writel(unsigned long field, unsigned long value)
{
	__vmcs_writel(field, value);
}

static void cpu_vmxon(u64 addr)
{
	asm volatile (ASM_VMX_VMXON_RAX
			: : "a"(&addr), "m"(addr)
			: "memory", "cc");
}

static u64 construct_eptp(unsigned long root_hpa)
{
	u64 eptp;

	/* TODO write the value reading from MSR */
	eptp = VMX_EPT_DEFAULT_MT |
		VMX_EPT_DEFAULT_GAW << VMX_EPT_GAW_EPTP_SHIFT;

	eptp |= (root_hpa & PAGE_MASK);

	return eptp;
}

static void vmcs_load(struct vmcs *vmcs)
{
	u64 phys_addr = __pa(vmcs);
	u8 error;

	asm volatile (__ex(ASM_VMX_VMPTRLD_RAX) "; setna %0"
			: "=qm"(error) : "a"(&phys_addr), "m"(phys_addr)
			: "cc", "memory");
	if (error)
		printk(KERN_ERR "kvm: vmptrld %p/%llx failed\n",
		       vmcs, phys_addr);
}

static unsigned long segment_base(u16 selector)
{
	struct desc_ptr *gdt = this_cpu_ptr(&host_gdt);
	struct desc_struct *d;
	unsigned long table_base;
	unsigned long v;

	if (!(selector & ~3))
		return 0;

	table_base = gdt->address;

	if (selector & 4) {           /* from ldt */
		u16 ldt_selector = kvm_read_ldt();

		if (!(ldt_selector & ~3))
			return 0;

		table_base = segment_base(ldt_selector);
	}
	d = (struct desc_struct *)(table_base + (selector & ~7));
	v = get_desc_base(d);
#ifdef CONFIG_X86_64
       if (d->s == 0 && (d->type == 2 || d->type == 9 || d->type == 11))
               v |= ((unsigned long)((struct ldttss_desc64 *)d)->base3) << 32;
#endif
	return v;
}

static unsigned int segment_limit(u16 selector)
{
	struct desc_ptr *gdt = this_cpu_ptr(&host_gdt);
	struct desc_struct *d;
	unsigned long table_base;
	unsigned int l;

	if (!(selector & ~3))
		return 0;

	table_base = gdt->address;

	if (selector & 4) {           /* from ldt */
		u16 ldt_selector = kvm_read_ldt();

		if (!(ldt_selector & ~3))
			return 0;

		table_base = segment_base(ldt_selector);
	}
	d = (struct desc_struct *)(table_base + (selector & ~7));
	l = get_desc_limit(d);
	return l;	
}

static inline unsigned long kvm_read_tr_base(void)
{
	u16 tr;
	asm("str %0" : "=g"(tr));
	return segment_base(tr);
}

static struct vmcs *alloc_vmcs_cpu(int cpu)
{
	int node = cpu_to_node(cpu);
	struct page *pages;
	struct vmcs *vmcs;

	pages = __alloc_pages_node(node, GFP_KERNEL, vmcs_config.order);
	if (!pages)
		return NULL;
	vmcs = page_address(pages);
	memset(vmcs, 0, vmcs_config.size);
	vmcs->revision_id = vmcs_config.revision_id; /* vmcs revision id */
	printk (KERN_ERR "physical %lx virtual %lx\n revision_id %x", __pa(vmcs), (unsigned long)vmcs, vmcs->revision_id);
	return vmcs;
}

static __init int adjust_vmx_controls(u32 ctl_min, u32 ctl_opt,
				      u32 msr, u32 *result)
{
	u32 vmx_msr_low, vmx_msr_high;
	u32 ctl = ctl_min | ctl_opt;

	rdmsr(msr, vmx_msr_low, vmx_msr_high);

	ctl &= vmx_msr_high; /* bit == 0 in high word ==> must be zero */
	ctl |= vmx_msr_low;  /* bit == 1 in low word  ==> must be one  */

	/* Ensure minimum (required) set of control bits are supported. */
	if (ctl_min & ~ctl)
		return -EIO;

	*result = ctl;
	return 0;
}

static void skip_emulated_instruction(struct vcpu_vmx *vcpu)
{
	unsigned long rip;

	rip = vcpu->regs[VCPU_REGS_RIP];
	rip += vmcs_read32(VM_EXIT_INSTRUCTION_LEN);
	vcpu->regs[VCPU_REGS_RIP] = rip;
	vcpu->instruction_skipped = true;
}

void handle_cpuid (struct vcpu_vmx *vcpu)
{
	u32 eax, ebx, ecx, edx;
	eax = vcpu->regs[VCPU_REGS_RAX];
	ecx = vcpu->regs[VCPU_REGS_RCX];
	native_cpuid(&eax, &ebx, &ecx, &edx);
	vcpu->regs[VCPU_REGS_RAX] = eax;
	vcpu->regs[VCPU_REGS_RBX] = ebx;
	vcpu->regs[VCPU_REGS_RCX] = ecx;
	vcpu->regs[VCPU_REGS_RDX] = edx;
	skip_emulated_instruction(vcpu);
}


void vmx_switch_and_exit_handler (void)
{
	unsigned long *reg_area;
	struct vcpu_vmx *vcpu_ptr;	
	u32 vmexit_reason;	
	u64 gpa;

	printk ("I am in exit handler %d\n", smp_processor_id());
	reg_area = per_cpu(reg_scratch, smp_processor_id());
	vcpu_ptr = this_cpu_ptr(&vcpu);
	reg_area[VCPU_REGS_RIP] = vmcs_readl(GUEST_RIP);
	reg_area[VCPU_REGS_RSP] = vmcs_readl(GUEST_RSP);

	vmexit_reason = vmcs_readl(VM_EXIT_REASON);
	vcpu_ptr->instruction_skipped = false;
	
	switch (vmexit_reason) {
		case EXIT_REASON_CPUID:
			handle_cpuid(vcpu_ptr);
		break;
		case EXIT_REASON_EPT_MISCONFIG:
			gpa = vmcs_read64(GUEST_PHYSICAL_ADDRESS);
			printk (KERN_ERR "guest physical address 0x%llx\n", gpa);
			dump_entries(gpa);
		break;	
	}
	
	if (vcpu_ptr->instruction_skipped == true) {
		vmcs_writel(GUEST_RIP, reg_area[VCPU_REGS_RIP]);
	}
}

static __init int setup_vmcs_config(struct vmcs_config *vmcs_conf)
{
	u32 vmx_msr_low, vmx_msr_high;
	u32 min, opt, min2, opt2;
	u32 _pin_based_exec_control = 0;
	u32 _cpu_based_exec_control = 0;
	u32 _cpu_based_2nd_exec_control = 0;
	u32 _vmexit_control = 0;
	u32 _vmentry_control = 0;

	min = CPU_BASED_USE_MSR_BITMAPS |
	      CPU_BASED_ACTIVATE_SECONDARY_CONTROLS;
	opt = 0;
	if (adjust_vmx_controls(min, opt, MSR_IA32_VMX_PROCBASED_CTLS,
				&_cpu_based_exec_control) < 0)
		return -EIO;
	if (_cpu_based_exec_control & CPU_BASED_ACTIVATE_SECONDARY_CONTROLS) {
		min2 = SECONDARY_EXEC_ENABLE_EPT;
		opt2 = 0;
		if (adjust_vmx_controls(min2, opt2,
					MSR_IA32_VMX_PROCBASED_CTLS2,
					&_cpu_based_2nd_exec_control) < 0)
			return -EIO;
	}

	if(_cpu_based_2nd_exec_control & SECONDARY_EXEC_ENABLE_EPT) {
		_cpu_based_exec_control &= ~(CPU_BASED_CR3_LOAD_EXITING |
					     CPU_BASED_CR3_STORE_EXITING);
	}

	min = 0;
	opt = 0;
#ifdef CONFIG_X86_64
	min = VM_EXIT_HOST_ADDR_SPACE_SIZE  | VM_EXIT_LOAD_IA32_EFER | VM_EXIT_SAVE_IA32_EFER;
#endif
	if (adjust_vmx_controls(min, opt, MSR_IA32_VMX_EXIT_CTLS,
				&_vmexit_control) < 0) {
		printk (KERN_ERR "vmexit control failed\n");
		return -EIO;
	}

	min = PIN_BASED_NMI_EXITING;
	opt = 0;
	if (adjust_vmx_controls(min, opt, MSR_IA32_VMX_PINBASED_CTLS,
				&_pin_based_exec_control) < 0) {
		printk (KERN_ERR "pin based control failed\n");
		return -EIO;
	}

//	min = VM_ENTRY_LOAD_DEBUG_CONTROLS | VM_ENTRY_IA32E_MODE | VM_ENTRY_LOAD_IA32_EFER;
	min = VM_ENTRY_LOAD_DEBUG_CONTROLS | VM_ENTRY_IA32E_MODE;
	opt = VM_ENTRY_LOAD_IA32_EFER;
	if (adjust_vmx_controls(min, opt, MSR_IA32_VMX_ENTRY_CTLS,
				&_vmentry_control) < 0) {
		printk (KERN_ERR "vmentry control failed\n");
		return -EIO;
	}

	rdmsr(MSR_IA32_VMX_BASIC, vmx_msr_low, vmx_msr_high);

	/* IA-32 SDM Vol 3B: VMCS size is never greater than 4kB. */
	if ((vmx_msr_high & 0x1fff) > PAGE_SIZE)
		return -EIO;

#ifdef CONFIG_X86_64
	/* IA-32 SDM Vol 3B: 64-bit CPUs always have VMX_BASIC_MSR[48]==0. */
	if (vmx_msr_high & (1u<<16))
		return -EIO;
#endif

	/* Require Write-Back (WB) memory type for VMCS accesses. */
	if (((vmx_msr_high >> 18) & 15) != 6)
		return -EIO;

	vmcs_conf->size = vmx_msr_high & 0x1fff;
	vmcs_conf->order = get_order(vmcs_conf->size);
	vmcs_conf->basic_cap = vmx_msr_high & ~0x1fff;
	vmcs_conf->revision_id = vmx_msr_low;

	printk (KERN_ERR "VMCS revision read from msr %x\n", vmcs_conf->revision_id);
	vmcs_conf->pin_based_exec_ctrl = _pin_based_exec_control;
	vmcs_conf->cpu_based_exec_ctrl = _cpu_based_exec_control;
	vmcs_conf->cpu_based_2nd_exec_ctrl = _cpu_based_2nd_exec_control;
	vmcs_conf->vmexit_ctrl         = _vmexit_control;
	vmcs_conf->vmentry_ctrl        = _vmentry_control;

	return 0;
}


static noinline void load_guest_state_area(void) {

        u16 selector;
        u64 base;
        u32 limit, high, low;
        u32 access_rights;
        struct desc_ptr dt;
        unsigned long a;
	u16 tr;

        vmcs_writel(GUEST_CR0, read_cr0() & ~X86_CR0_TS);
        vmcs_writel(GUEST_CR3, read_cr3()); 
        vmcs_writel(GUEST_CR4, cr4_read_shadow());

        base = 0;
        limit = 0xffffffff;

        asm ("mov %%cs, %%ax\n"
             : "=a"(selector));
        vmcs_write16(GUEST_CS_SELECTOR, selector);

        asm ("lar %%ax, %%rax\n"
             : "=a"(access_rights) : "a"(selector));
        access_rights = access_rights >> 8;  //24.4.1 Guest Register State
        access_rights = access_rights & 0xf0ff;
        vmcs_write32(GUEST_CS_AR_BYTES, access_rights);
        vmcs_writel(GUEST_CS_BASE, base);
        vmcs_write32(GUEST_CS_LIMIT, limit);


        asm ("mov %%ss, %%ax\n"
             : "=a"(selector));
        vmcs_write16(GUEST_SS_SELECTOR, selector);

        asm ("lar %%ax, %%rax\n"
             : "=a"(access_rights) : "a"(selector));
        access_rights = access_rights >> 8;  //24.4.1 Guest Register State
        access_rights = access_rights & 0xf0ff;
        vmcs_write32(GUEST_SS_AR_BYTES, access_rights);
        vmcs_writel(GUEST_SS_BASE, base);
        vmcs_write32(GUEST_SS_LIMIT, limit);


        asm ("mov %%ds, %%ax\n"
             : "=a"(selector));
        vmcs_write16(GUEST_DS_SELECTOR, selector);
        if (selector == 0) {
        	vmcs_write32(GUEST_DS_AR_BYTES, 0x10000);
	} else {
        	asm ("lar %%ax, %%rax\n"
             		: "=a"(access_rights) : "a"(selector));
        	access_rights = access_rights >> 8;  //24.4.1 Guest Register State
        	access_rights = access_rights & 0xf0ff;
        	vmcs_write32(GUEST_DS_AR_BYTES, access_rights);
        	vmcs_writel(GUEST_DS_BASE, base);
        	vmcs_write32(GUEST_DS_LIMIT, limit);
	}


        asm ("mov %%es, %%ax\n"
             : "=a"(selector));
        vmcs_write16(GUEST_ES_SELECTOR, selector);
	if (selector == 0) {
		vmcs_write32(GUEST_ES_AR_BYTES, 0x10000);
	} else {
        	asm ("lar %%ax, %%rax\n"
             		: "=a"(access_rights) : "a"(selector));
        	access_rights = access_rights >> 8;  //24.4.1 Guest Register State
        	access_rights = access_rights & 0xf0ff;
        	vmcs_write32(GUEST_ES_AR_BYTES, access_rights);
        	vmcs_writel(GUEST_ES_BASE, base);
        	vmcs_write32(GUEST_ES_LIMIT, limit);
	}
        // get base for fs and gs from the register

        asm ("mov %%fs, %%ax\n"
             : "=a"(selector));
        vmcs_write16(GUEST_FS_SELECTOR, selector);
	if (selector == 0) {
		vmcs_write32(GUEST_FS_AR_BYTES, 0x10000);
	} else {
        	asm ("lar %%ax, %%rax\n"
             		: "=a"(access_rights) : "a"(selector));
        	access_rights = access_rights >> 8;  //24.4.1 Guest Register State
        	access_rights = access_rights & 0xf0ff;
        	vmcs_write32(GUEST_FS_AR_BYTES, access_rights);
	}
        vmcs_writel(GUEST_FS_BASE, read_msr(MSR_FS_BASE));
        vmcs_write32(GUEST_FS_LIMIT, limit);

        asm ("mov %%gs, %%ax\n"
             : "=a"(selector));
        vmcs_write16(GUEST_GS_SELECTOR, selector);
	if (selector == 0) {
		vmcs_write32(GUEST_GS_AR_BYTES, 0x10000);
	} else {
        	asm ("lar %%ax, %%rax\n"
             		: "=a"(access_rights) : "a"(selector));
        	access_rights = access_rights >> 8;  //24.4.1 Guest Register State
        	access_rights = access_rights & 0xf0ff;
        	vmcs_write32(GUEST_GS_AR_BYTES, access_rights);
	}
        vmcs_writel(GUEST_GS_BASE, read_msr(MSR_GS_BASE));
        vmcs_write32(GUEST_GS_LIMIT, limit);

        asm volatile ("str %0": "=r" (tr));	
        vmcs_write16(GUEST_TR_SELECTOR, tr);
	if (tr == 0) {
		vmcs_write32(GUEST_TR_AR_BYTES, 0x10000);
	} else {
        	asm ("lar %%ax, %%rax\n"
             		: "=a"(access_rights) : "a"(tr));
        	access_rights = access_rights >> 8;  //24.4.1 Guest Register State
        	access_rights = access_rights & 0xf0ff;
        	vmcs_writel(GUEST_TR_BASE, segment_base(tr));
        	vmcs_write32(GUEST_TR_LIMIT, segment_limit(tr));
        	vmcs_write32(GUEST_TR_AR_BYTES, access_rights);
	}

        vmcs_write16(GUEST_LDTR_SELECTOR, kvm_read_ldt());     
        vmcs_writel(GUEST_LDTR_BASE, base);
        vmcs_write32(GUEST_LDTR_LIMIT, limit);
        vmcs_write32(GUEST_LDTR_AR_BYTES, 0x10000);
        
        native_store_gdt(&dt);
        vmcs_writel(GUEST_GDTR_BASE, dt.address);
        vmcs_write32(GUEST_GDTR_LIMIT, dt.size);

        native_store_idt(&dt);
        vmcs_writel(GUEST_IDTR_BASE, dt.address);
        vmcs_write32(GUEST_IDTR_LIMIT, dt.size);

//MSR state

        vmcs_write64(GUEST_IA32_DEBUGCTL, 0);

        rdmsr(MSR_IA32_SYSENTER_CS, low, high);
        vmcs_write32(GUEST_SYSENTER_CS, low);

        rdmsrl(MSR_IA32_SYSENTER_ESP, a);
        vmcs_writel(GUEST_SYSENTER_ESP, a);

        rdmsrl(MSR_IA32_SYSENTER_EIP, a);
        vmcs_writel(GUEST_SYSENTER_EIP, a);


        rdmsrl(MSR_EFER, a);
        vmcs_write64(GUEST_IA32_EFER, a);

        rdmsrl(MSR_IA32_CR_PAT, a);
        vmcs_write64(GUEST_IA32_PAT, a);

//Guest non register state
        vmcs_write32(GUEST_ACTIVITY_STATE, GUEST_ACTIVITY_ACTIVE);
        vmcs_write32(GUEST_INTERRUPTIBILITY_INFO, 0);
        vmcs_writel(GUEST_PENDING_DBG_EXCEPTIONS, 0);
        vmcs_write64(VMCS_LINK_POINTER, -1ull);
        vmcs_write32(VMX_PREEMPTION_TIMER_VALUE, 0);
}

static noinline void load_host_state_area(void) {

        struct desc_ptr dt;
        u16 selector;
        u32 high,low;
        unsigned long a;
	u16 tr;

        vmcs_writel(HOST_CR0, read_cr0() & ~X86_CR0_TS);
        vmcs_writel(HOST_CR3, __pa(host_cr3)); 
        vmcs_writel(HOST_CR4, cr4_read_shadow());

        asm ("mov %%cs, %%ax\n"
             : "=a"(selector));
        vmcs_write16(HOST_CS_SELECTOR, selector);

        asm ("mov %%ss, %%ax\n"
             : "=a"(selector));
        vmcs_write16(HOST_SS_SELECTOR, selector);

        asm ("mov %%ds, %%ax\n"
             : "=a"(selector));
        vmcs_write16(HOST_DS_SELECTOR, selector);

        asm ("mov %%es, %%ax\n"
             : "=a"(selector));
        vmcs_write16(HOST_ES_SELECTOR, selector);

        asm ("mov %%fs, %%ax\n"
             : "=a"(selector));
        vmcs_write16(HOST_FS_SELECTOR, selector);
        vmcs_writel(HOST_FS_BASE, read_msr(MSR_FS_BASE));
        

        asm ("mov %%gs, %%ax\n"
             : "=a"(selector));
        vmcs_write16(HOST_GS_SELECTOR, selector);
        vmcs_writel(HOST_GS_BASE, read_msr(MSR_GS_BASE));


       asm volatile ("str %0": "=r" (tr));	
       vmcs_write16(HOST_TR_SELECTOR, tr);
       vmcs_writel(HOST_TR_BASE, segment_base(tr));

 
       native_store_gdt(&dt);
       vmcs_writel(HOST_GDTR_BASE, dt.address);

       native_store_idt(&dt);
       vmcs_writel(HOST_IDTR_BASE, dt.address);

//MSR area

        rdmsr(MSR_IA32_SYSENTER_CS, low, high);
        vmcs_write32(HOST_IA32_SYSENTER_CS, low);

        rdmsrl(MSR_IA32_SYSENTER_ESP, a);
        vmcs_writel(HOST_IA32_SYSENTER_ESP, a);

        rdmsrl(MSR_IA32_SYSENTER_EIP, a);
        vmcs_writel(HOST_IA32_SYSENTER_EIP, a);

        rdmsrl(MSR_EFER, a);
        vmcs_write64(HOST_IA32_EFER, a);

        rdmsrl(MSR_IA32_CR_PAT, a);
        vmcs_write64(HOST_IA32_PAT, a);
}

static void load_execution_control(void)
{
      u32 high, low;
      u64 eptp;
      u32 value;

      rdmsr(MSR_IA32_VMX_PINBASED_CTLS, low, high);
      value = 0x16;
      value = value | low;
      value = value & high;
      printk(KERN_ERR "PIN based controls into VMCS %x vs. vmcs_config %x\n", value, vmcs_config.pin_based_exec_ctrl);
      vmcs_write32(PIN_BASED_VM_EXEC_CONTROL, vmcs_config.pin_based_exec_ctrl);

      rdmsr(MSR_IA32_VMX_PROCBASED_CTLS, low, high);
      value = 0x94006172;
      value = value | low;
      value = value & high;
      printk(KERN_ERR "PROC based controls into VMCS %x vs. vmcs_config %x\n", value, vmcs_config.cpu_based_exec_ctrl);
      vmcs_write32(CPU_BASED_VM_EXEC_CONTROL, vmcs_config.cpu_based_exec_ctrl); //enable seconday controls

      rdmsr(MSR_IA32_VMX_PROCBASED_CTLS2, low, high);
      value = 0x0;
      value = value | low;
      value = value & high;
      printk(KERN_ERR "PROC based controls2 into VMCS %x vs. vmcs_config %x\n", value, vmcs_config.cpu_based_2nd_exec_ctrl);
//      vmcs_write32(SECONDARY_VM_EXEC_CONTROL, vmcs_config.cpu_based_2nd_exec_ctrl); //enable seconday controls
      vmcs_write32(SECONDARY_VM_EXEC_CONTROL, vmcs_config.cpu_based_2nd_exec_ctrl); //enable seconday controls


      vmcs_write32(EXCEPTION_BITMAP, 0);

      vmx_io_bitmap_a_switch = (unsigned long *)__get_free_page(GFP_KERNEL);
      memset(vmx_io_bitmap_a_switch, 0, PAGE_SIZE);
      printk(KERN_ERR "io bitmap a address 0x%lx\n", (unsigned long) vmx_io_bitmap_a_switch);
      vmcs_write64(IO_BITMAP_A, __pa(vmx_io_bitmap_a_switch));

      vmx_io_bitmap_b_switch = (unsigned long *)__get_free_page(GFP_KERNEL);
      memset(vmx_io_bitmap_b_switch, 0, PAGE_SIZE);
      printk(KERN_ERR "io bitmap b address  0x%lx\n", (unsigned long) vmx_io_bitmap_b_switch);
      vmcs_write64(IO_BITMAP_B, __pa(vmx_io_bitmap_b_switch));

      vmx_msr_bitmap_switch = (unsigned long *)__get_free_page(GFP_KERNEL);
      memset(vmx_msr_bitmap_switch, 0, PAGE_SIZE);
      vmcs_write64(MSR_BITMAP, __pa(vmx_msr_bitmap_switch));

      if (!ept_tables_set) {
         vmx_eptp_pml4 =  (unsigned long *)__get_free_page(GFP_KERNEL);
         memset(vmx_eptp_pml4, 0, PAGE_SIZE);
      }
      eptp = construct_eptp(__pa(vmx_eptp_pml4));
      printk(KERN_ERR "eptp in vmcs area  0x%lx\n", (unsigned long) eptp);
      
      vmcs_write64(EPT_POINTER, eptp);

      vmcs_writel(CR0_GUEST_HOST_MASK, 0); //guest owns the bits

      vmcs_writel(CR4_GUEST_HOST_MASK, 0);

      vmcs_write32(CR3_TARGET_COUNT, 0);

//MSR bitmap addresses - all bits shud be set to 0 
}

void load_vmentry_control(void)
{
      u32 low,high;
      u32 value;

      rdmsr(MSR_IA32_VMX_ENTRY_CTLS, low, high);
      value = 0x93ff;
      value = value | low;
      value = value & high;

      printk(KERN_ERR "ENTRY controls into VMCS %x vs. vmcs_config %x\n", value, vmcs_config.vmentry_ctrl);
      vmcs_write32(VM_ENTRY_CONTROLS, vmcs_config.vmentry_ctrl);
      vmcs_write32(VM_ENTRY_MSR_LOAD_COUNT, 0);
      vmcs_write32(VM_ENTRY_INTR_INFO_FIELD, 0);
}

void load_vmexit_control(void)
{
      u32 low,high;
      u32 value;

      rdmsr(MSR_IA32_VMX_EXIT_CTLS, low, high);
      value = 0x336fff;
      value = value | low;
      value = value & high;

      printk(KERN_ERR "EXIT controls into VMCS %x vs. vmcs_config %x\n", value, vmcs_config.vmexit_ctrl);
      vmcs_write32(VM_EXIT_CONTROLS, vmcs_config.vmexit_ctrl);
      vmcs_write32(VM_EXIT_MSR_STORE_COUNT, 0);
      vmcs_write32(VM_EXIT_MSR_LOAD_COUNT, 0);
}

static void enable_feature_control(void)
{
	u64 old, test_bits;

	rdmsrl(MSR_IA32_FEATURE_CONTROL, old);
	test_bits = FEATURE_CONTROL_LOCKED;
	test_bits |= FEATURE_CONTROL_VMXON_ENABLED_OUTSIDE_SMX;

	if ((old & test_bits) != test_bits) {
		wrmsrl(MSR_IA32_FEATURE_CONTROL, old | test_bits);
	}
}

static int switch_to_nonroot(void *data)
{
	struct vcpu_vmx *vcpu_ptr;
	int cpu;
	u64 phys_addr, host_rsp, host_rflags, guest_rip;
	bool test = false;

	cpu = get_cpu();

	if (test) {
		printk(KERN_ERR "I am on cpu %d\n", cpu);
		wait_event_interruptible(root_thread_queue, true);
		return 0;
	}
	vcpu_ptr = this_cpu_ptr(&vcpu);
	native_store_gdt(this_cpu_ptr(&host_gdt));
	vcpu_ptr->vcpu_stack = (u64) kmalloc(16384, GFP_KERNEL);
	memset((void *)vcpu_ptr->vcpu_stack, 0, 16384);

	enable_feature_control();

	vcpu_ptr->regs = per_cpu(reg_scratch, cpu);
	if(!(cr4_read_shadow() & X86_CR4_VMXE))
		cr4_set_bits(cr4_read_shadow() | X86_CR4_VMXE);

	vcpu_ptr->vmxarea = alloc_vmcs_cpu(cpu);
	phys_addr = __pa(vcpu_ptr->vmxarea);
	printk (KERN_ERR "physical %llx virtual %lx\n", phys_addr, (unsigned long)vcpu_ptr->vmxarea);
	cpu_vmxon(phys_addr);

	vcpu_ptr->pcpu_vmcs = alloc_vmcs_cpu(cpu);
	vmcs_load(vcpu_ptr->pcpu_vmcs);	

	load_guest_state_area();

	load_host_state_area();

	load_execution_control();

	load_vmexit_control();

	load_vmentry_control();

	mutex_lock(&ept_lock);
	if (!ept_tables_set) {
		ept_tables_set = 1;
		setup_ept_tables();
	}
	mutex_unlock(&ept_lock);

	asm("movq %%rsp, %%rax\n"
		:"=a"(host_rsp));
	vmcs_writel(HOST_RSP, (vcpu_ptr->vcpu_stack + 16384));
	vmcs_writel(GUEST_RSP, host_rsp);

	asm("pushfq\n");
	asm("popq %0\n"
		: "=m"(host_rflags) : :"memory");
	vmcs_writel(GUEST_RFLAGS, host_rflags);
	vmcs_writel(HOST_RIP, (unsigned long) vmx_switch_and_exit_handle_vmexit);
	asm("movq $vmentry_point, %0\n"
		:"=a"(guest_rip));
	vmcs_writel(GUEST_RIP, guest_rip);

	asm volatile (__ex(ASM_VMX_VMLAUNCH) "\n\t");
	asm("vmentry_point:");
	asm("cpuid");
	bitmap_set(switch_done, cpu, 1);
	put_cpu();

	wait_event_interruptible(root_thread_queue, true);
	return 0;
}

//switch to non-root API

int vmx_switch_to_nonroot (void)
{
	#ifdef DEBUG
	volatile bool test = false;
	#endif

	int cpu;
	struct task_struct* thread_ptr;

	#ifdef DEBUG
	printk (KERN_ERR "address of switch_to_nonroot %llx\n", (u64) switch_to_nonroot);

	while (test) {

	}
	#endif

	bitmap_zero(switch_done, NR_CPUS);
	for_each_online_cpu(cpu) {
		thread_ptr = kthread_create(switch_to_nonroot, NULL, "vmx-switch-%d", cpu);
		kthread_bind(thread_ptr, cpu);
		wake_up_process(thread_ptr);
	}

	while (!bitmap_equal((const long unsigned int *)&all_cpus, (const long unsigned int *)&switch_done, num_online_cpus())) { 
		schedule();	
	}	
	return 0;
}
EXPORT_SYMBOL(vmx_switch_to_nonroot);

//update policy API
/*
This function is called from configfs client module for any changes
in the configfs entries

create kthreads for each processor, in each thread issue vmcall to 
transfer to root mode.
*/


pgd_t *init_process_cr3(void)
{
	struct task_struct *task;
	for_each_process(task) {
		if(task->pid == (pid_t) 1)
			return task->mm->pgd;
	}
	return NULL;
}

static int __init nonroot_switch_init(void)
{
	setup_vmcs_config(&vmcs_config);
	init_waitqueue_head(&root_thread_queue);
	bitmap_fill((long unsigned int *)&all_cpus, num_online_cpus());
	host_cr3 = init_process_cr3();
	if (!host_cr3)
		goto err;
	if (switch_on_load)
		vmx_switch_to_nonroot();
err:
	return 0;
}

static void nonroot_switch_exit(void)
{
	printk (KERN_ERR "module vmx-switch unloaded\n");
}

module_init(nonroot_switch_init);
module_exit(nonroot_switch_exit);
MODULE_LICENSE("GPL");
