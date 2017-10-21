/*
* This is an example ikgt usage driver.
* Copyright (c) 2015, Intel Corporation.
*
* This program is free software; you can redistribute it and/or modify it
* under the terms and conditions of the GNU General Public License,
* version 2, as published by the Free Software Foundation.
*
* This program is distributed in the hope it will be useful, but WITHOUT
* ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
* FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
* more details.
*/

#ifndef _COMMON_H
#define _COMMON_H

#include <linux/module.h>
#include <linux/configfs.h>
#include <linux/slab.h>
#include <linux/stat.h>

#define DEBUG

#define DRIVER_NAME "ikgt_agent"
#define PREFIX "iKGT: "

#define PRINTK_INFO(fmt, args...)     printk(KERN_INFO PREFIX fmt, ##args)
#define PRINTK_ERROR(fmt, args...)    printk(KERN_ERR PREFIX fmt, ##args)
#define PRINTK_WARNING(fmt, args...)  printk(KERN_WARNING PREFIX fmt, ##args)

#define BIT(nr)	(1UL << (nr))

/* CR0 constants */
#define PE BIT(0)
#define MP BIT(1)
#define EM BIT(2)
#define TS BIT(3)
#define ET BIT(4)
#define NE BIT(5)
#define WP BIT(16)
#define AM BIT(18)
#define NW BIT(29)
#define CD BIT(30)
#define PG BIT(31)

/* CR4 constants */
#define VME BIT(0)
#define PVI BIT(1)
#define TSD BIT(2)
#define DE  BIT(3)
#define PSE BIT(4)
#define PAE BIT(5)
#define MCE BIT(6)
#define PGE BIT(7)
#define PCE BIT(8)
#define OSFXSR BIT(9)
#define OSXMMEXCPT BIT(10)
#define VMXE BIT(13)
#define SMXE BIT(14)
#define PCIDE BIT(17)
#define OSXSAVE BIT(18)
#define SMEP BIT(20)
#define SMAP BIT(21)

#define POLICY_ACT_LOG     BIT(0)
#define POLICY_ACT_SKIP    BIT(1)
#define POLICY_ACT_ALLOW   0
#define POLICY_ACT_STICKY  BIT(7)
#define LOG_MESSAGE_SIZE   120

#define POLICY_ACT_LOG_ALLOW   (POLICY_ACT_LOG | POLICY_ACT_ALLOW)
#define POLICY_ACT_LOG_SKIP    (POLICY_ACT_LOG | POLICY_ACT_SKIP)
#define POLICY_ACT_LOG_STICKY  (POLICY_ACT_LOG | POLICY_ACT_STICKY)

typedef struct _name_value_map {
	const char *name;
	unsigned long  bitmask;
}name_value_map;

struct group_node {
	struct config_group group;
};

static inline struct group_node *to_node(struct config_item *item)
{
	return item ? container_of(to_config_group(item), struct group_node,
		group) : NULL;
}

#define IKGT_CONFIGFS_TO_CONTAINER(__s)  \
	static inline struct __s  *to_##__s(struct config_item *item) \
{ \
	return item ? container_of(item, struct __s, item) : NULL; \
}

#define IKGT_CONFIGFS_ATTR_RO(__s, __name)	\
	static struct __s##_attribute __s##_attr_##__name = __CONFIGFS_ATTR_RO(_name, __s##_show_##__name);

#define IKGT_CONFIGFS_ATTR_RW(__s, __name)				\
	static struct __s##_attribute __s##_attr_##__name =	\
	__CONFIGFS_ATTR(__name, S_IRUGO | S_IWUSR, __s##_show_##__name, \
	__s##_store_##__name)

#define IKGT_UINT32_SHOW(__s, __name)	\
	static ssize_t __s##_##__name##_show(struct config_item *item, \
	char *page) \
{	\
	struct __s *__s = to_##__s(item); \
	return sprintf(page, "%u\n", __s->__name); \
}

#define IKGT_UINT32_HEX_SHOW(__s, __name)	\
	static ssize_t __s##_##__name##_show(struct config_item *item, \
	char *page) \
{	\
	struct __s *__s = to_##__s(item); \
	return sprintf(page, "0x%X\n", __s->__name); \
}

#define IKGT_UINT32_STORE(__s, __name)	\
	static ssize_t __s##_store_##__name(struct __s *item, \
	const char *page, \
	size_t count) \
{ \
	unsigned long value;\
	\
	if (kstrtoul(page, 0, &value)) \
	return -EINVAL; \
	item->__name = value; \
	\
	return count; \
}

#define IKGT_ULONG_HEX_SHOW(__s, __name)	\
	static ssize_t __s##_##__name##_show(struct config_item *item, \
	char *page) \
{	\
	struct __s *__s = to_##__s(item); \
	return sprintf(page, "0x%lX\n", __s->__name); \
}

#define IKGT_ULONG_HEX_STORE(__s, __name)	\
	static ssize_t __s##_store_##__name(struct __s *item, \
	const char *page, \
	size_t count) \
{ \
	unsigned long value;\
	\
	if (kstrtoul(page, 16, &value)) \
	return -EINVAL; \
	item->__name = value; \
	\
	return count; \
}

typedef uint8_t policy_action_r;
typedef uint8_t policy_action_w;
typedef uint8_t policy_action_x;

struct cr0_cfg {
	struct config_item item;
	bool enable;
	bool locked;
	policy_action_w write;
	unsigned long sticky_value;
};

struct cr4_cfg {
	struct config_item item;
	bool enable;
	bool locked;
	policy_action_w write;
	unsigned long sticky_value;
};

typedef enum _RESOURCE_ID {
        RESOURCE_ID_START = 1,

        RESOURCE_ID_CR0_PE = RESOURCE_ID_START,
        RESOURCE_ID_CR0_MP,
        RESOURCE_ID_CR0_EM,
        RESOURCE_ID_CR0_TS,
        RESOURCE_ID_CR0_ET,
        RESOURCE_ID_CR0_NE,
        RESOURCE_ID_CR0_WP,
        RESOURCE_ID_CR0_AM,
        RESOURCE_ID_CR0_NW,
        RESOURCE_ID_CR0_CD,
        RESOURCE_ID_CR0_PG,

        RESOURCE_ID_CR4_VME,
        RESOURCE_ID_CR4_PVI,
        RESOURCE_ID_CR4_TSD,
        RESOURCE_ID_CR4_DE,
        RESOURCE_ID_CR4_PSE,
        RESOURCE_ID_CR4_PAE,
        RESOURCE_ID_CR4_MCE,
        RESOURCE_ID_CR4_PGE,
        RESOURCE_ID_CR4_PCE,
        RESOURCE_ID_CR4_OSFXSR,
        RESOURCE_ID_CR4_OSXMMEXCPT,
        RESOURCE_ID_CR4_VMXE,
        RESOURCE_ID_CR4_SMXE,
        RESOURCE_ID_CR4_PCIDE,
        RESOURCE_ID_CR4_OSXSAVE,
        RESOURCE_ID_CR4_SMEP,
        RESOURCE_ID_CR4_SMAP,

        RESOURCE_ID_END,
        RESOURCE_ID_UNKNOWN
} RESOURCE_ID;

typedef enum {
	CPU_REG_CR0 = 0,
        CPU_REG_CR4,
	TMSL_CPU_REG_UNKNOWN
}cpu_reg_t;

typedef enum {
	CPU_MONITOR_HYPERCALL = 40,	
} call_id_t;

typedef struct {
        unsigned long size;
        cpu_reg_t cpu_reg;
        bool enable;
        unsigned long mask;
} cpu_event_params_t;

void monitor_cpu_events(unsigned long mask, bool enable, cpu_reg_t reg);
#endif /* _COMMON_H */
