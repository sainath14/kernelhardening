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

#include <linux/module.h>

#include "common.h"
#include "vmx_common.h"

static name_value_map cr0_bits[] = {
	{ "PE", PE},
	{ "MP", MP},
	{ "EM", EM},
	{ "TS", TS},
	{ "ET", ET},
	{ "NE", NE},
	{ "WP", WP},
	{ "AM", AM},
	{ "NW", NW},
	{ "CD", CD},
	{ "PG", PG},

	/* Table terminator */
	{}
};

static ssize_t cr0_cfg_enable_store(struct config_item *item,
									const char *page,
									size_t count);

static ssize_t cr0_cfg_write_store(struct config_item *item,
								   const char *page,
								   size_t count);

static ssize_t cr0_cfg_sticky_value_store(struct config_item *item,
										  const char *page,
										  size_t count);

/* to_cr0_cfg() function */
IKGT_CONFIGFS_TO_CONTAINER(cr0_cfg);

/* item operations */
IKGT_UINT32_SHOW(cr0_cfg, enable);
IKGT_UINT32_HEX_SHOW(cr0_cfg, write);
IKGT_ULONG_HEX_SHOW(cr0_cfg, sticky_value);

/* attributes */
CONFIGFS_ATTR(cr0_cfg_, enable);
CONFIGFS_ATTR(cr0_cfg_, write);
CONFIGFS_ATTR(cr0_cfg_, sticky_value);

static struct configfs_attribute *cr0_cfg_attrs[] = {
	&cr0_cfg_attr_enable,
	&cr0_cfg_attr_write,
	&cr0_cfg_attr_sticky_value,
	NULL,
};

static int valid_cr0_attr(const char *name)
{
	int i;

	for (i = 0; cr0_bits[i].name; i++) {
		if (strcasecmp(cr0_bits[i].name, name) == 0) {
			return i;
		}
	}

	return -1;
}

/*-------------------------------------------------------*
*  Function      : policy_set_cr0()
*  Purpose: send the CR0 policy settings to handler
*  Parameters: cr0_cfg, enable
*  Return: true=success, false=failure
*-------------------------------------------------------*/
static bool policy_set_cr0(struct cr0_cfg *cr0_cfg, bool enable)
{
	int idx = valid_cr0_attr(cr0_cfg->item.ci_name);
	unsigned long mask;

	if (idx < 0)
		return false;

	mask = cr0_bits[idx].bitmask;

	monitor_cpu_events(mask, enable, CPU_REG_CR0);

	return true;
}

static ssize_t cr0_cfg_write_store(struct config_item *item,
								   const char *page,
								   size_t count)
{
	unsigned long value;
	struct cr0_cfg *cr0_cfg = to_cr0_cfg(item);

	if (cr0_cfg->locked)
		return -EPERM;

	if (kstrtoul(page, 0, &value))
		return -EINVAL;

	cr0_cfg->write = value;

	return count;
}

static ssize_t cr0_cfg_sticky_value_store(struct config_item *item,
										  const char *page,
										  size_t count)
{
	unsigned long value;
	struct cr0_cfg *cr0_cfg = to_cr0_cfg(item);

	if (cr0_cfg->locked)
		return -EPERM;

	if (kstrtoul(page, 0, &value))
		return -EINVAL;

	cr0_cfg->sticky_value = value;

	return count;
}

static ssize_t cr0_cfg_enable_store(struct config_item *item,
									const char *page,
									size_t count)
{
	unsigned long value;
	bool ret = false;
	struct cr0_cfg *cr0_cfg = to_cr0_cfg(item);

	if (kstrtoul(page, 0, &value))
		return -EINVAL;

	if (cr0_cfg->locked) {
		PRINTK_INFO("Sticky is set and locked!\n");
		return -EPERM;
	}

	ret = policy_set_cr0(cr0_cfg, value);

	if (ret) {
		cr0_cfg->enable = value;
	}

	if (ret && (cr0_cfg->write & POLICY_ACT_STICKY))
		cr0_cfg->locked = true;

	return count;
}

static void cr0_cfg_release(struct config_item *item)
{
	kfree(to_cr0_cfg(item));
}

static struct configfs_item_operations cr0_cfg_ops = {
	.release		= cr0_cfg_release,
};

static struct config_item_type cr0_cfg_type = {
	.ct_item_ops	= &cr0_cfg_ops,
	.ct_attrs	= cr0_cfg_attrs,
	.ct_owner	= THIS_MODULE,
};

static struct config_item *cr0_make_item(struct config_group *group,
										 const char *name)
{
	struct cr0_cfg *cr0_cfg;

	PRINTK_INFO("create attr name %s\n", name);

	if (valid_cr0_attr(name) == -1) {
		PRINTK_ERROR("Invalid CR0 bit name\n");
		return NULL;
	}

	cr0_cfg = kzalloc(sizeof(struct cr0_cfg), GFP_KERNEL);
	if (!cr0_cfg) {
		return ERR_PTR(-ENOMEM);
	}

	config_item_init_type_name(&cr0_cfg->item, name,
		&cr0_cfg_type);


	return &cr0_cfg->item;
}

static ssize_t cr0_children_description_show(struct config_item *item,
	char *page)
{
	return sprintf(page,
		"CR0\n"
		"\n"
		"Used in protected mode to control operations .  \n"
		"items are readable and writable.\n");
}

CONFIGFS_ATTR_RO(cr0_children_, description);

static struct configfs_attribute *cr0_children_attrs[] = {
	&cr0_children_attr_description,
	NULL,
};

static void cr0_children_release(struct config_item *item)
{
	kfree(to_node(item));
}

static struct configfs_item_operations cr0_children_item_ops = {
	.release	= cr0_children_release,
};

static struct configfs_group_operations cr0_children_group_ops = {
	.make_item	= cr0_make_item,
};

static struct config_item_type cr0_children_type = {
	.ct_item_ops	= &cr0_children_item_ops,
	.ct_group_ops	= &cr0_children_group_ops,
	.ct_attrs	= cr0_children_attrs,
	.ct_owner	= THIS_MODULE,
};

struct config_item_type *get_cr0_children_type(void)
{
	return &cr0_children_type;
}
