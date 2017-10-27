typedef enum {
	CPU_REG_CR0 = 0,
	CPU_REG_CR4,
	CPU_REG_UNKNOWN
}cpu_reg_t;

#define KERNEL_HARDENING_HYPERCALL 40

typedef enum {
	CPU_MONITOR_REQ = 1,
	MSR_MONITOR_REQ,
	MONITOR_REQ_END,
}call_id_t;

typedef struct {
	unsigned long size;
	call_id_t req_id;
	cpu_reg_t cpu_reg;
	bool enable;
	unsigned long mask;
} cpu_event_params_t;

void monitor_cpu_events(unsigned long mask, bool enable, cpu_reg_t reg);
