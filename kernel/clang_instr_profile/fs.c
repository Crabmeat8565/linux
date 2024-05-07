// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2019	Sami Tolvanen <samitolvanen@google.com>, Google, Inc.
 * Copyright (C) 2024	Jinghao Jia   <jinghao7@illinois.edu>,   UIUC
 * Copyright (C) 2024	Wentao Zhang  <wentaoz5@illinois.edu>,   UIUC
 *
 * This software is licensed under the terms of the GNU General Public
 * License version 2, as published by the Free Software Foundation, and
 * may be copied, distributed, and modified under those terms.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 */

#define pr_fmt(fmt)	"clang_instr_profile: " fmt

#include <linux/kernel.h>
#include <linux/debugfs.h>
#include <linux/fs.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/spinlock.h>
#include "clang_instr_profile.h"

/*
 * This lock guards both profile count reset and serialization of the
 * profiling data. Keeping both of these activities separate via locking
 * ensures that we don't try to serialize data that's being reset.
 */
DEFINE_SPINLOCK(clang_instr_profile_lock);

static struct dentry *directory;

struct prf_private_data {
	char *buffer;
	unsigned long size;
};

/*
 * Raw profile data format:
 * https://llvm.org/docs/InstrProfileFormat.html#raw-profile-format. We will
 * only populate information that's relevant to basic Source-based Code Coverage
 * before serialization. Other features like binary IDs, continuous mode,
 * single-byte mode, value profiling, type profiling etc are not implemented.
 */

static void prf_fill_header(void **buffer)
{
	struct __llvm_profile_header *header = *(struct __llvm_profile_header **)buffer;

#ifdef CONFIG_64BIT
	header->magic = INSTR_PROF_RAW_MAGIC_64;
#else
	header->magic = INSTR_PROF_RAW_MAGIC_32;
#endif
	header->version = INSTR_PROF_RAW_VERSION;
	header->binary_ids_size = 0;
	header->num_data = prf_data_count();
	header->padding_bytes_before_counters = 0;
	header->num_counters = prf_cnts_count();
	header->padding_bytes_after_counters =
		prf_get_padding(prf_cnts_size());
	header->num_bitmap_bytes = prf_bits_size();
	header->padding_bytes_after_bitmap_bytes =
		prf_get_padding(prf_bits_size());
	header->names_size = prf_names_size();
	header->counters_delta = (u64)__llvm_prf_cnts_start -
				 (u64)__llvm_prf_data_start;
	header->bitmap_delta   = (u64)__llvm_prf_bits_start -
				 (u64)__llvm_prf_data_start;
	header->names_delta    = (u64)__llvm_prf_names_start;
#if defined(CONFIG_CC_IS_CLANG) && CONFIG_CLANG_VERSION >= 190000
	header->num_v_tables = 0;
	header->v_names_size = 0;
#endif
	header->value_kind_last = IPVK_LAST;

	*buffer += sizeof(*header);
}

/*
 * Copy the source into the buffer, incrementing the pointer into buffer in the
 * process.
 */
static void prf_copy_to_buffer(void **buffer, void *src, unsigned long size)
{
	memcpy(*buffer, src, size);
	*buffer += size;
}

static unsigned long prf_buffer_size(void)
{
	return sizeof(struct __llvm_profile_header) +
			prf_data_size() +
			prf_cnts_size() +
			prf_get_padding(prf_cnts_size()) +
			prf_bits_size() +
			prf_get_padding(prf_bits_size()) +
			prf_names_size() +
			prf_get_padding(prf_names_size());
}

/*
 * Serialize the profiling data into a format LLVM's tools can understand.
 */
static int prf_serialize(struct prf_private_data *p)
{
	int err = 0;
	void *buffer;

	p->size = prf_buffer_size();
	p->buffer = vzalloc(p->size);

	if (!p->buffer) {
		err = -ENOMEM;
		goto out;
	}

	buffer = p->buffer;

	prf_fill_header(&buffer);
	prf_copy_to_buffer(&buffer, __llvm_prf_data_start,  prf_data_size());
	prf_copy_to_buffer(&buffer, __llvm_prf_cnts_start,  prf_cnts_size());
	buffer += prf_get_padding(prf_cnts_size());
	prf_copy_to_buffer(&buffer, __llvm_prf_bits_start,  prf_bits_size());
	buffer += prf_get_padding(prf_bits_size());
	prf_copy_to_buffer(&buffer, __llvm_prf_names_start, prf_names_size());
	buffer += prf_get_padding(prf_names_size());

out:
	return err;
}

/*
 * open() implementation for clang_instr_profile. Creates a copy of the
 * profiling data set.
 */
static int prf_open(struct inode *inode, struct file *file)
{
	struct prf_private_data *data;
	unsigned long flags;
	int err;

	data = kzalloc(sizeof(*data), GFP_KERNEL);
	if (!data) {
		err = -ENOMEM;
		goto out;
	}

	flags = prf_lock();

	err = prf_serialize(data);
	if (unlikely(err)) {
		kfree(data);
		goto out_unlock;
	}

	file->private_data = data;

out_unlock:
	prf_unlock(flags);
out:
	return err;
}

/* read() implementation for clang_instr_profile. */
static ssize_t prf_read(struct file *file, char __user *buf, size_t count,
			loff_t *ppos)
{
	struct prf_private_data *data = file->private_data;

	if(!data)
		return -EBADF;

	return simple_read_from_buffer(buf, count, ppos, data->buffer,
				       data->size);
}

/*
 * release() implementation for clang_instr_profile. Release resources allocated
 * by open().
 */
static int prf_release(struct inode *inode, struct file *file)
{
	struct prf_private_data *data = file->private_data;

	if (data) {
		vfree(data->buffer);
		kfree(data);
	}

	return 0;
}

static const struct file_operations prf_fops = {
	.owner		= THIS_MODULE,
	.open		= prf_open,
	.read		= prf_read,
	.llseek		= default_llseek,
	.release	= prf_release
};

/* write() implementation for resetting clang_instr_profile's profile data. */
static ssize_t reset_write(struct file *file, const char __user *addr,
			   size_t len, loff_t *pos)
{
	unsigned long flags;

	flags = prf_lock();
	memset(__llvm_prf_cnts_start, 0, prf_cnts_size());
	memset(__llvm_prf_bits_start, 0, prf_bits_size());
	prf_unlock(flags);

	return len;
}

static const struct file_operations prf_reset_fops = {
	.owner		= THIS_MODULE,
	.write		= reset_write,
	.llseek		= noop_llseek,
};

/* Create debugfs entries. */
static int __init clang_instr_profile_init(void)
{
	directory = debugfs_create_dir("clang_instr_profile", NULL);
	if (!directory)
		goto err_remove;

	if (!debugfs_create_file("profraw", 0600, directory, NULL,
				 &prf_fops))
		goto err_remove;

	if (!debugfs_create_file("reset", 0200, directory, NULL,
				 &prf_reset_fops))
		goto err_remove;

	return 0;

err_remove:
	debugfs_remove_recursive(directory);
	pr_err("initialization failed\n");
	return -EIO;
}

/* Remove debugfs entries. */
static void __exit clang_instr_profile_exit(void)
{
	debugfs_remove_recursive(directory);
}

module_init(clang_instr_profile_init);
module_exit(clang_instr_profile_exit);
