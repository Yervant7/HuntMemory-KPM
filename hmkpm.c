// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2026 Yervant7
 *
 * KernelPatch Module (KPM) - [HMKPM]
 */

#include <common.h>
#include <compiler.h>
#include <hook.h>
#include <kpmodule.h>
#include <kputils.h>
#include <ksyms.h>
#include <ktypes.h>
#include <linux/err.h>
#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/mm_types.h>
#include <linux/printk.h>
#include <syscall.h>
#include <uapi/asm-generic/unistd.h>

KPM_NAME("HMKPM");
KPM_VERSION("2.1.0");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("Yervant7");
KPM_DESCRIPTION("A KernelPatch Module (KPM) HMKPM");

static bool hook_active = true;
static bool init_error = false;
static int mmap_lock_sem_offset = -1;

struct rw_semaphore;
extern bool is_su_allow_uid(uid_t uid);

#define U64_MAX				((u64)~0ULL)
#define HMKPM_TAG			"[HMKPM] "

#define hmkpm_info(fmt, ...)		logki(HMKPM_TAG fmt, ##__VA_ARGS__)
#define hmkpm_error(fmt, ...)		logke(HMKPM_TAG fmt, ##__VA_ARGS__)

static unsigned long hmkpm_lookup_symbol(const char *name);

#define hkfunc_match(func)							\
do {										\
	kf_##func = (typeof(kf_##func))hmkpm_lookup_symbol(#func);		\
	if (!kf_##func) {							\
		hmkpm_error("Failed to find kfunc %s\n", #func);		\
		init_error = true;						\
	}									\
} while (0)

#define hkvar_match(var)							\
do {										\
	kv_##var = (typeof(kv_##var))hmkpm_lookup_symbol(#var);			\
	if (!kv_##var) {							\
		hmkpm_error("Failed to find kvar %s\n", #var);			\
		init_error = true;						\
	}									\
} while (0)

void *kfunc_def(memset)(void *s, int c, size_t count);
unsigned long kfunc_def(__arch_copy_to_user)(void __user *to, const void *from, unsigned long n);
unsigned long kfunc_def(__arch_copy_from_user)(void *to, const void __user *from, unsigned long n);
long kfunc_def(probe_kernel_read)(void *dst, const void *src, size_t size);
long kfunc_def(probe_kernel_write)(void *dst, const void *src, size_t size);
long kfunc_def(copy_from_kernel_nofault)(void *dst, const void *src, size_t size);
long kfunc_def(copy_to_kernel_nofault)(void *dst, const void *src, size_t size);
struct task_struct *kfunc_def(find_task_by_vpid)(pid_t pid);
struct mm_struct *kfunc_def(get_task_mm)(struct task_struct *task);
void kfunc_def(mmput)(struct mm_struct *mm);
void kfunc_def(__rcu_read_lock)(void);
void kfunc_def(__rcu_read_unlock)(void);
void kfunc_def(down_read)(struct rw_semaphore *sem);
void kfunc_def(up_read)(struct rw_semaphore *sem);

u64 kvar_def(memstart_addr);
void *kvar_def(high_memory);

/* ========================================================================
 * Channel: getresuid, intercepted when arg0 == HMKPM_MAGIC.
 *
 *   arg0 = HMKPM_MAGIC / HMKPM_MAGIC_READ / HMKPM_MAGIC_WRITE / ...
 *   arg1 = pointer to request buffer
 *   arg2 = total buffer size
 *
 * Contiguous layouts in userspace:
 *   Single: [ hmkpm_req (pid, addr, size) | data[size] ]
 *   Batch:  [ hmkpm_batch_hdr (pid, count, data_total) |
 *             hmkpm_batch_entry[count] | data[data_total] ]
 * ======================================================================== */

#define HMKPM_MAGIC			0x484D4B504DULL /* "HMKPM" */
#define HMKPM_MAGIC_READ		(HMKPM_MAGIC + 1)
#define HMKPM_MAGIC_WRITE		(HMKPM_MAGIC + 2)
#define HMKPM_MAGIC_READ_BATCH		(HMKPM_MAGIC + 3)
#define HMKPM_MAGIC_WRITE_BATCH		(HMKPM_MAGIC + 4)
#define HMKPM_MAGIC_MAX			HMKPM_MAGIC_WRITE_BATCH

#define HMKPM_BATCH_CHUNK_ENTRIES	64U
#define HMKPM_MAX_BATCH_ENTRIES		65536U
#define HMKPM_MAX_ENTRY_SIZE		(64ULL << 20)
#define HMKPM_MAX_SINGLE_SIZE		(64ULL << 20)
#define HMKPM_MAX_BATCH_TOTAL_SIZE	(128ULL << 20)

struct hmkpm_batch_hdr {
	int32_t pid;
	uint32_t _pad;
	uint64_t count;
	uint64_t data_total;
};

struct hmkpm_batch_entry {
	uint64_t addr;
	uint64_t size;
};

struct hmkpm_req {
	int32_t pid;
	uint32_t _pad;
	uint64_t addr;
	uint64_t size;
};

#define HMKPM_BATCH_HDR_SIZE		((uint64_t)sizeof(struct hmkpm_batch_hdr))
#define HMKPM_BATCH_ENTRY_SIZE		((uint64_t)sizeof(struct hmkpm_batch_entry))
#define HMKPM_REQ_SIZE			((uint64_t)sizeof(struct hmkpm_req))

static inline long hmkpm_copy_from_kernel_nofault(void *dst, const void *src, size_t size)
{
	kfunc_call(copy_from_kernel_nofault, dst, src, size);
	kfunc_call(probe_kernel_read, dst, src, size);
	return -ENOSYS;
}

static inline long hmkpm_copy_to_kernel_nofault(void *dst, const void *src, size_t size)
{
	kfunc_call(copy_to_kernel_nofault, dst, src, size);
	kfunc_call(probe_kernel_write, dst, src, size);
	return -ENOSYS;
}

static uint64_t pgt_va_bits;
static uint64_t pgt_phys_offset;
static uint64_t pgt_page_offset;
static uint64_t pgt_linear_voffset;
static uint64_t pgt_page_shift;
static uint64_t pgt_page_size;
static uint64_t pgt_page_level;
static uint64_t pgt_user_limit;
static uint64_t pgt_phys_limit;
static uint64_t pgt_high_memory;
static bool pgt_tbi0;

static inline uint64_t pgt_phys_to_virt(uint64_t phys)
{
	return phys + pgt_linear_voffset;
}

static inline uint64_t pgt_virt_to_phys(uint64_t addr)
{
	return addr - pgt_linear_voffset;
}

static inline int validate_virt_range(uint64_t va, uint64_t size)
{
	uint64_t last;

	if (unlikely(size == 0))
		return -EINVAL;

	if (unlikely(va < pgt_page_offset))
		return -EFAULT;

	if (unlikely(va > U64_MAX - size))
		return -EFAULT;

	last = va + size - 1;
	if (unlikely(last >= pgt_high_memory))
		return -EFAULT;

	return 0;
}

static inline int validate_phys_range(uint64_t phys, uint64_t size)
{
	uint64_t last;

	if (unlikely(size == 0))
		return -EINVAL;

	if (unlikely(phys < pgt_phys_offset))
		return -EFAULT;

	if (unlikely(phys > U64_MAX - size))
		return -EFAULT;

	last = phys + size - 1;
	if (unlikely(last >= pgt_phys_limit))
		return -EFAULT;

	return 0;
}

static inline uint64_t pgt_untag_user_va(uint64_t va)
{
	/*
	 * If TBI0 is active, the top byte is ignored.
	 * This is important for tagged pointers on Android.
	 */
	if (pgt_tbi0)
		va &= 0x00FFFFFFFFFFFFFFULL;

	return va;
}

static inline uint64_t pgt_desc_to_phys(uint64_t desc)
{
	uint64_t addr_mask =
		(((1ULL << (48 - pgt_page_shift)) - 1) << pgt_page_shift);
	return desc & addr_mask;
}

/*
 * Block descriptors are typically allowed at levels 1 and 2.
 * Level 0 usually does not allow block descriptors.
 * Level 3 is page, not block.
 */
static inline bool pgt_block_allowed(int lv)
{
	if (pgt_page_shift == 14)
		return (lv == 2);
	else
		return (lv == 1 || lv == 2);
}

static uint64_t pgt_pgtable_to_tkpa(uint64_t pgd, uint64_t va)
{
	uint64_t table_va;
	uint64_t pxd_bits;
	uint64_t pxd_ptrs;
	int64_t start;
	int64_t lv;

	if (!pgd)
		return 0;

	if (pgd & (pgt_page_size - 1))
		return 0;

	if (validate_virt_range(pgd, pgt_page_size))
		return 0;

	va = pgt_untag_user_va(va);

	if (va >> pgt_va_bits)
		return 0;

	table_va = pgd;
	pxd_bits = pgt_page_shift - 3;
	pxd_ptrs = 1ULL << pxd_bits;
	start = 4 - (int64_t)pgt_page_level;

	for (lv = start; lv < 4; lv++) {
		uint64_t pxd_shift;
		uint64_t pxd_index;
		uint64_t top_bits;
		uint64_t entry_va;
		uint64_t desc = 0;
		uint64_t type;

		if (validate_virt_range(table_va, pgt_page_size))
			return 0;

		pxd_shift = (pgt_page_shift - 3) * (4 - lv) + 3;

		if (pxd_shift >= pgt_va_bits)
			return 0;

		pxd_index = (va >> pxd_shift) & (pxd_ptrs - 1);

		/*
		 * At the starting level, the table may not use all indices.
		 * This prevents accepting non-canonical VA with index outside the real
		 * range.
		 */
		top_bits = pgt_va_bits - pxd_shift;

		if (top_bits > pxd_bits)
			top_bits = pxd_bits;

		if (top_bits == 0)
			return 0;

		if (pxd_index >= (1ULL << top_bits))
			return 0;

		entry_va = table_va + pxd_index * 8;

		if (hmkpm_copy_from_kernel_nofault(&desc, (const void *)entry_va, sizeof(desc)) != 0)
			return 0;

		type = desc & 3ULL;

		/*
		 * Stage 1:
		 * 0b00 = invalid
		 * 0b10 = invalid/reserved
		 * 0b01 = block
		 * 0b11 = table/page
		 */
		if (type == 0ULL || type == 2ULL)
			return 0;

		/*
		 * Last level.
		 */
		if (lv == 3) {
			uint64_t base;

			/*
			 * At level 3, 0b11 is a page descriptor.
			 * 0b01 must not be treated as a valid block here.
			 */
			if (type != 3ULL)
				return 0;

			base = pgt_desc_to_phys(desc);

			if (base & (pgt_page_size - 1))
				return 0;

			if (validate_phys_range(base, pgt_page_size))
				return 0;

			return base | (va & (pgt_page_size - 1));
		}

		/*
		 * Block descriptor.
		 */
		if (type == 1ULL) {
			uint64_t block_bits;
			uint64_t block_size;
			uint64_t block_mask;
			uint64_t base;

			if (!pgt_block_allowed((int)lv))
				return 0;

			block_bits = (uint64_t)(3 - lv) * pxd_bits + pgt_page_shift;

			if (block_bits >= 64)
				return 0;

			block_size = 1ULL << block_bits;
			block_mask = block_size - 1;

			base = pgt_desc_to_phys(desc);

			/*
			 * Block must be aligned to the block size.
			 */
			if (base & block_mask)
				return 0;

			if (validate_phys_range(base, block_size))
				return 0;

			return (base & ~block_mask) | (va & block_mask);
		}

		/*
		 * Table descriptor.
		 */
		uint64_t next_pa = pgt_desc_to_phys(desc);

		/*
		 * Next table must be aligned to the granule.
		 */
		if (next_pa & (pgt_page_size - 1))
			return 0;

		if (validate_phys_range(next_pa, pgt_page_size))
			return 0;

		table_va = pgt_phys_to_virt(next_pa);
	}

	return 0;
}

static int pgt_pgtable_init(void)
{
	uint64_t tcr_el1;
	uint64_t t1sz;
	uint64_t va1_bits;
	uint64_t t0sz;
	uint64_t va0_bits;
	uint64_t tg0;
	uint64_t pxd_bits;
	int64_t start;

	asm volatile("mrs %0, tcr_el1" : "=r"(tcr_el1));

	t1sz = (tcr_el1 >> 16) & 0x3F;
	va1_bits = 64 - t1sz;

	/* TTBR0 / user VA */
	t0sz = tcr_el1 & 0x3F;
	va0_bits = 64 - t0sz;

	tg0 = (tcr_el1 >> 14) & 0x3ULL;

	if (va0_bits > 48 || va0_bits < 36) {
		hmkpm_error("Unsupported VA bits: %llu\n", va0_bits);
		return -EINVAL;
	}

	pgt_va_bits = va0_bits;
	pgt_user_limit = (1ULL << va0_bits) - 1;

	if (tg0 == 0) {
		pgt_page_shift = 12; /* 4KB */
	} else if (tg0 == 2) {
		pgt_page_shift = 14; /* 16KB */
	} else {
		hmkpm_error("Unsupported tg0: %llu\n", tg0);
		return -EINVAL;
	}

	pxd_bits = pgt_page_shift - 3;
	pgt_page_level = (va0_bits - 4) / pxd_bits;

	if (pgt_page_level != 3 && pgt_page_level != 4)
		return -EINVAL;

	start = 4 - (int64_t)pgt_page_level;

	if (start < 0 || start > 2)
		return -EINVAL;

	pgt_page_size = 1ULL << pgt_page_shift;

	if (kver >= VERSION(5, 4, 0)) {
		pgt_page_offset = (-(UL(1) << (va1_bits)));
	} else {
		pgt_page_offset = (UL(0xffffffffffffffff) - (UL(1) << (va1_bits - 1)) + 1);
	}

	hkvar_match(memstart_addr);
	if (!kv_memstart_addr) {
		hmkpm_error("Failed to resolve memstart_addr\n");
		return -EFAULT;
	}
	pgt_phys_offset = kvar_val(memstart_addr);
	pgt_linear_voffset = pgt_page_offset - pgt_phys_offset;

	pgt_tbi0 = !!(tcr_el1 & (1ULL << 37));

	hmkpm_info("Page table config: va0_bits=%llu, shift=%llu, size=0x%llx, level=%llu, tbi0=%d\n",
		   va0_bits, pgt_page_shift, pgt_page_size, pgt_page_level, pgt_tbi0);
	hmkpm_info("phys_offset=0x%llx, page_offset=0x%llx, linear_voffset=0x%llx\n",
		   pgt_phys_offset, pgt_page_offset, pgt_linear_voffset);

	return 0;
}

static inline int hmkpm_user_range_ok(const void __user *ptr, uint64_t len)
{
	uint64_t u;

	if (!ptr || len == 0)
		return 0;

	u = pgt_untag_user_va((uint64_t)ptr);

	if (u > pgt_user_limit)
		return 0;

	if (len - 1 > pgt_user_limit - u)
		return 0;

	return 1;
}

static __always_inline bool is_hmkpm_magic(uint64_t magic)
{
	return magic >= HMKPM_MAGIC && magic <= HMKPM_MAGIC_MAX;
}

#define min(a, b) ((a) < (b) ? (a) : (b))

static inline void hmkpm_mmap_read_lock(struct mm_struct *mm)
{
	if (mm && mmap_lock_sem_offset >= 0 && kf_down_read) {
		struct rw_semaphore *sem =
			(struct rw_semaphore *)((uintptr_t)mm + mmap_lock_sem_offset);
		kfunc(down_read)(sem);
	}
}

static inline void hmkpm_mmap_read_unlock(struct mm_struct *mm)
{
	if (mm && mmap_lock_sem_offset >= 0 && kf_up_read) {
		struct rw_semaphore *sem =
			(struct rw_semaphore *)((uintptr_t)mm + mmap_lock_sem_offset);
		kfunc(up_read)(sem);
	}
}

static void hmkpm_zero_user(void __user *dst, size_t size)
{
	static const uint8_t zero_chunk[128] = {0};

	while (size > 0) {
		size_t chunk = min(size, sizeof(zero_chunk));

		if (kfunc(__arch_copy_to_user)(dst, zero_chunk, chunk) != 0)
			break;
		dst = (void __user *)((uintptr_t)dst + chunk);
		size -= chunk;
	}
}

static ssize_t pgt_rw_mm(struct mm_struct *mm, uint64_t remote_va, size_t len, void __user *local_buf, bool is_write)
{
	ssize_t total = 0;
	uint64_t pgd = 0;

	if (!mm)
		return -ESRCH;

	if (mm_struct_offset.pgd_offset < 0)
		return -EINVAL;

	if (hmkpm_copy_from_kernel_nofault(&pgd,
					   (const void *)((uintptr_t)mm + mm_struct_offset.pgd_offset),
					   sizeof(pgd)) != 0 || !pgd)
		return -EFAULT;

	/* Page-by-page read/write loop */
	while (len > 0) {
		uint64_t tkpa = pgt_pgtable_to_tkpa(pgd, remote_va);
		unsigned long page_off;
		size_t chunk;
		void *tkva;
		unsigned long not_copied;
		unsigned long copied;

		if (!tkpa) {
			if (total > 0)
				break; /* partial read/write is OK */
			return -EFAULT;
		}

		page_off = remote_va & (pgt_page_size - 1);
		chunk = min(len, (size_t)(pgt_page_size - page_off));
		tkva = (void *)pgt_phys_to_virt(tkpa);

		if (!is_write) {
			/* __arch_copy_to_user returns number of bytes NOT copied (0=success) */
			not_copied = kfunc(__arch_copy_to_user)(local_buf, tkva, chunk);
		} else {
			/* __arch_copy_from_user returns number of bytes NOT copied (0=success) */
			not_copied = kfunc(__arch_copy_from_user)(tkva, local_buf, chunk);
		}

		copied = chunk - not_copied;
		total += (ssize_t)copied;

		if (not_copied)
			break; /* couldn't copy everything — stop */

		local_buf = (void __user *)((uintptr_t)local_buf + copied);
		remote_va += copied;
		len -= copied;
	}

	return total;
}

static ssize_t pgt_rw(pid_t pid, uint64_t remote_va, size_t len,
		      void __user *local_buf, bool is_write)
{
	struct task_struct *task = NULL;
	struct mm_struct *mm = NULL;
	ssize_t ret;

	if (pid <= 0)
		return -EINVAL;

	/* find_task_by_vpid requires RCU read-side protection */
	kfunc(__rcu_read_lock)();
	task = kfunc(find_task_by_vpid)(pid);
	if (!task) {
		kfunc(__rcu_read_unlock)();
		return -ESRCH;
	}

	/* get_task_mm increments mm refcount, safe to drop RCU after */
	mm = kfunc(get_task_mm)(task);
	kfunc(__rcu_read_unlock)();

	if (!mm)
		return -ESRCH;

	hmkpm_mmap_read_lock(mm);
	ret = pgt_rw_mm(mm, remote_va, len, local_buf, is_write);
	hmkpm_mmap_read_unlock(mm);

	kfunc(mmput)(mm);
	return ret;
}

static void hmkpm_handle_single(hook_fargs3_t *args, void __user *user_ptr, uint64_t total_len, uint64_t magic)
{
	struct hmkpm_req req;
	void __user *data_ptr;
	bool write_op = (magic == HMKPM_MAGIC_WRITE);
	ssize_t ret;

	if (total_len < HMKPM_REQ_SIZE) {
		args->ret = (uint64_t)(long)-EINVAL;
		return;
	}

	if (kfunc(__arch_copy_from_user)(&req, user_ptr, HMKPM_REQ_SIZE) != 0) {
		args->ret = (uint64_t)(long)-EFAULT;
		return;
	}

	if (req.size == 0) {
		if (total_len != HMKPM_REQ_SIZE)
			args->ret = (uint64_t)(long)-EINVAL;
		else
			args->ret = 0;
		return;
	}

	if ((uint64_t)req.size > HMKPM_MAX_SINGLE_SIZE) {
		args->ret = (uint64_t)(long)-E2BIG;
		return;
	}

	if (total_len != HMKPM_REQ_SIZE + (uint64_t)req.size) {
		args->ret = (uint64_t)(long)-EINVAL;
		return;
	}

	if (req.pid <= 0) {
		args->ret = (uint64_t)(long)-EINVAL;
		return;
	}

	if (req.addr > U64_MAX - (uint64_t)req.size) {
		args->ret = (uint64_t)(long)-EINVAL;
		return;
	}

	data_ptr = (void __user *)((uint8_t __user *)user_ptr + HMKPM_REQ_SIZE);

	ret = pgt_rw((pid_t)req.pid, req.addr, req.size, data_ptr, write_op);
	if (ret < 0) {
		args->ret = (uint64_t)(long)ret;
	} else if ((uint64_t)ret != req.size) {
		args->ret = (uint64_t)(long)-EFAULT;
	} else {
		args->ret = 0;
	}
}

static void hmkpm_handle_batch(hook_fargs3_t *args, void __user *user_ptr, uint64_t total_len, uint64_t magic)
{
	bool write_op = (magic == HMKPM_MAGIC_WRITE_BATCH);
	struct hmkpm_batch_hdr hdr;
	struct hmkpm_batch_entry chunk[HMKPM_BATCH_CHUNK_ENTRIES];
	uint64_t entries_bytes;
	uint64_t entries_end;
	uint64_t data_start;
	uint64_t io_end;
	uint64_t data_off = 0;
	uint32_t done = 0;
	int rc = 0;
	struct task_struct *task = NULL;
	struct mm_struct *mm = NULL;

	if (total_len < HMKPM_BATCH_HDR_SIZE) {
		rc = -EINVAL;
		goto out;
	}

	if (kfunc(__arch_copy_from_user)(&hdr, user_ptr, HMKPM_BATCH_HDR_SIZE) != 0) {
		rc = -EFAULT;
		goto out;
	}

	if (hdr.count == 0) {
		if (hdr.data_total != 0) {
			rc = -EINVAL;
			goto out;
		}

		if (write_op) {
			if (total_len != HMKPM_BATCH_HDR_SIZE)
				rc = -EINVAL;
		} else {
			if (total_len < HMKPM_BATCH_HDR_SIZE)
				rc = -EINVAL;
		}

		goto out;
	}

	if (hdr.count > HMKPM_MAX_BATCH_ENTRIES) {
		rc = -E2BIG;
		goto out;
	}

	if (hdr.data_total > HMKPM_MAX_BATCH_TOTAL_SIZE) {
		rc = -E2BIG;
		goto out;
	}

	if (hdr.pid <= 0) {
		rc = -EINVAL;
		goto out;
	}

	entries_bytes = (uint64_t)hdr.count * HMKPM_BATCH_ENTRY_SIZE;

	if (entries_bytes > U64_MAX - HMKPM_BATCH_HDR_SIZE) {
		rc = -E2BIG;
		goto out;
	}

	entries_end = HMKPM_BATCH_HDR_SIZE + entries_bytes;

	if (hdr.data_total > U64_MAX - entries_end) {
		rc = -E2BIG;
		goto out;
	}

	io_end = entries_end + hdr.data_total;

	if (write_op) {
		if (total_len != io_end) {
			rc = -EINVAL;
			goto out;
		}
	} else {
		if (total_len < io_end) {
			rc = -ERANGE;
			goto out;
		}
	}

	/* Obtain mm_struct for the batch PID */
	kfunc(__rcu_read_lock)();
	task = kfunc(find_task_by_vpid)((pid_t)hdr.pid);
	if (!task) {
		kfunc(__rcu_read_unlock)();
		rc = -ESRCH;
		goto out;
	}
	mm = kfunc(get_task_mm)(task);
	kfunc(__rcu_read_unlock)();

	if (!mm) {
		rc = -ESRCH;
		goto out;
	}

	/* Lock the mm for the entire batch of operations for page table stability */
	hmkpm_mmap_read_lock(mm);

	data_start = entries_end;

	while (done < hdr.count) {
		uint32_t chunk_count = hdr.count - done;
		uint64_t chunk_bytes;
		void __user *entry_src;
		uint32_t i;

		if (chunk_count > HMKPM_BATCH_CHUNK_ENTRIES)
			chunk_count = HMKPM_BATCH_CHUNK_ENTRIES;

		chunk_bytes = (uint64_t)chunk_count * HMKPM_BATCH_ENTRY_SIZE;

		entry_src = (void __user *)((uint8_t __user *)user_ptr +
					    HMKPM_BATCH_HDR_SIZE +
					    (uint64_t)done * HMKPM_BATCH_ENTRY_SIZE);

		if (kfunc(__arch_copy_from_user)((void *)chunk, entry_src, chunk_bytes) != 0) {
			rc = -EFAULT;
			goto out_mm;
		}

		for (i = 0; i < chunk_count; ++i) {
			struct hmkpm_batch_entry *e = &chunk[i];
			uint64_t req_size = e->size;
			void __user *data_ptr;
			ssize_t ret;

			if (req_size == 0)
				continue;

			if (req_size > HMKPM_MAX_ENTRY_SIZE) {
				rc = -E2BIG;
				goto out_mm;
			}

			if (req_size > hdr.data_total - data_off) {
				rc = -EINVAL;
				goto out_mm;
			}

			if (e->addr > U64_MAX - req_size) {
				e->size = 0;
				if (!write_op)
					hmkpm_zero_user((void __user *)((uint8_t __user *)user_ptr +
									data_start + data_off),
							req_size);
				data_off += req_size;
				continue;
			}

			data_ptr = (void __user *)((uint8_t __user *)user_ptr + data_start + data_off);

			ret = pgt_rw_mm(mm, e->addr, req_size, data_ptr, write_op);
			if (ret < 0) {
				/* Page walk / copy failed: mark size = 0 so userspace identifies the
				 * failed address */
				e->size = 0;
				if (!write_op)
					hmkpm_zero_user(data_ptr, req_size);
			} else if ((uint64_t)ret < req_size) {
				/* Partial copy: update to the actual amount transferred */
				e->size = (uint64_t)ret;
				if (!write_op)
					hmkpm_zero_user((void __user *)((uintptr_t)data_ptr + ret),
							req_size - (uint64_t)ret);
			} else {
				/* Full success */
				e->size = req_size;
			}

			/* Always advance by the requested size to maintain strict buffer
			 * alignment */
			data_off += req_size;
		}

		/* Return chunk with actual transferred sizes of each entry to userspace */
		if (kfunc(__arch_copy_to_user)(entry_src, chunk, chunk_bytes) != 0) {
			rc = -EFAULT;
			goto out_mm;
		}

		done += chunk_count;
	}

	if (unlikely(data_off != hdr.data_total)) {
		rc = -EINVAL;
		goto out_mm;
	}

out_mm:
	if (mm) {
		hmkpm_mmap_read_unlock(mm);
		kfunc(mmput)(mm);
		mm = NULL;
	}

out:
	args->ret = (uint64_t)(long)rc;
}

static void hmkpm_handle(hook_fargs3_t *args, void *udata)
{
	void __user *user_ptr;
	uint64_t total_len;
	uint64_t magic = syscall_argn(args, 0);
	uid_t uid;

	if (likely(!is_hmkpm_magic(magic)))
		return;

	if (!hook_active)
		return;

	uid = current_uid();
	if (!is_su_allow_uid(uid))
		return;

	args->skip_origin = 1;

	if (magic == HMKPM_MAGIC) {
		args->ret = (uint64_t)HMKPM_MAGIC;
		return;
	}

	user_ptr = (void __user *)syscall_argn(args, 1);
	total_len = syscall_argn(args, 2);

	if (total_len == 0) {
		args->ret = (uint64_t)(long)-EINVAL;
		return;
	}

	if (unlikely(!hmkpm_user_range_ok(user_ptr, total_len))) {
		args->ret = (uint64_t)(long)-EINVAL;
		return;
	}

	if (magic == HMKPM_MAGIC_READ || magic == HMKPM_MAGIC_WRITE) {
		hmkpm_handle_single(args, user_ptr, total_len, magic);
		return;
	}

	if (magic == HMKPM_MAGIC_READ_BATCH || magic == HMKPM_MAGIC_WRITE_BATCH) {
		hmkpm_handle_batch(args, user_ptr, total_len, magic);
		return;
	}

	args->ret = (uint64_t)(long)-EINVAL;
}

static bool insn_is_bl_or_b(unsigned long pc, u32 insn, unsigned long *target)
{
	u32 op = insn & 0xfc000000;
	s32 imm26;
	s64 delta;

	if (op != 0x94000000 && op != 0x14000000)
		return false;

	imm26 = (s32)(insn & 0x03ffffff);

	/* Sign-extend 26-bit immediate */
	if (imm26 & 0x02000000)
		imm26 |= 0xfc000000;

	delta = (s64)imm26 * 4;
	*target = (unsigned long)((s64)pc + delta);

	return true;
}

static unsigned long resolve_branch_target(unsigned long target)
{
	u32 target_insn;
	unsigned long next_target;
	int hops = 0;

	while (target && hops++ < 4) {
		if (hmkpm_copy_from_kernel_nofault((void *)&target_insn,
						   (const void *)target,
						   sizeof(target_insn)) != 0)
			break;

		/*
		 * If destination is an unconditional branch B <imm26>, follow the branch
		 * (trampoline / CFI / PLT)
		 */
		if ((target_insn & 0xfc000000) == 0x14000000) {
			if (insn_is_bl_or_b(target, target_insn, &next_target)) {
				target = next_target;
				continue;
			}
		}
		break;
	}
	return target;
}

static inline bool is_ret_insn(u32 insn)
{
	return (insn & 0xfffffc1f) == 0xd65f0000;
}

static bool insn_add_imm(u32 insn, unsigned int *rd, unsigned int *rn, unsigned long *imm)
{
	/* ADD Xd, Xn, #imm{, LSL #12} 64-bit */
	if ((insn & 0xff800000) != 0x91000000)
		return false;

	*rd = insn & 0x1f;
	*rn = (insn >> 5) & 0x1f;
	*imm = (insn >> 10) & 0xfff;

	/* Shift bit 22: LSL #12 */
	if ((insn >> 22) & 1)
		*imm <<= 12;

	return true;
}

static inline void make_cfi_name(char *dst, size_t dst_size, const char *name)
{
	const char *suffix = ".cfi_jt";
	size_t i = 0;

	while (name && *name && i + 1 < dst_size)
		dst[i++] = *name++;

	while (*suffix && i + 1 < dst_size)
		dst[i++] = *suffix++;

	dst[i] = '\0';
}

static unsigned long hmkpm_lookup_symbol(const char *name)
{
	unsigned long addr;

	if (!name || !kallsyms_lookup_name)
		return 0;

	addr = kallsyms_lookup_name(name);
	if (!addr) {
		char cfi_name[64];

		make_cfi_name(cfi_name, sizeof(cfi_name), name);
		addr = kallsyms_lookup_name(cfi_name);
	}
	return addr;
}

#define MAX_PROBE_FUNCS			8
#define MAX_PROBE_VOTES			64
#define MAX_SCAN_INSNS			2048UL
#define BACK_SCAN_MAX			8
#define OFFSET_MIN			8U
#define OFFSET_MAX			4096U

struct offset_vote {
	u32 offset;
	u32 count;
	u8 func_mask;
};

static struct offset_vote probe_votes[MAX_PROBE_VOTES];
static int nr_probe_votes;

static const char *const probe_func_names[MAX_PROBE_FUNCS] = {
	"vm_munmap", "__vm_munmap", "vm_brk_flags", "exit_mmap",
	"vm_mmap_pgoff", "do_munmap", "__do_munmap", "ksys_mmap_pgoff",
};

struct lock_symbol_def {
	const char *name;
};

static const struct lock_symbol_def lock_symbol_defs[] = {
	{"down_read"}, {"down_write"}, {"up_read"},
	{"up_write"}, {"down_read_killable"}, {"down_write_killable"},
	{"down_read_trylock"}, {"down_write_trylock"},
};
#define NR_PROBE_LOCKS			(sizeof(lock_symbol_defs) / sizeof(lock_symbol_defs[0]))

static int find_offset_before_branch(unsigned long branch_pc, unsigned int *offset)
{
	int i;

	for (i = 1; i <= BACK_SCAN_MAX; i++) {
		unsigned long pc = branch_pc - (unsigned long)i * 4;
		u32 insn;
		unsigned int rd, rn;
		unsigned long imm;
		u32 op;

		if (branch_pc < (unsigned long)i * 4)
			break;

		if (hmkpm_copy_from_kernel_nofault(&insn, (const void *)pc, sizeof(insn)) != 0)
			break;

		op = insn & 0xfc000000;

		/* If there is another branch or return, stop backward scan */
		if (op == 0x94000000 || op == 0x14000000)
			break;

		if (is_ret_insn(insn))
			break;

		if (insn_add_imm(insn, &rd, &rn, &imm)) {
			/*
			 * Look for ADD X0, Xn, #imm.
			 * rn == 31 represents SP (stack), which is not mm->mmap_sem.
			 */
			if (rd == 0 && rn != 31 && imm >= OFFSET_MIN && imm <= OFFSET_MAX &&
			    (imm & 7) == 0) {
				*offset = (unsigned int)imm;
				return 0;
			}

			/* If X0 was overwritten by another instruction, stop */
			if (rd == 0)
				break;
		}
	}

	return -ENOENT;
}

static void add_probe_vote(unsigned int offset, int func_idx)
{
	int i;

	if (offset < OFFSET_MIN || offset > OFFSET_MAX || (offset & 7) != 0)
		return;

	if (func_idx < 0 || func_idx >= MAX_PROBE_FUNCS)
		return;

	for (i = 0; i < nr_probe_votes; i++) {
		if (probe_votes[i].offset == offset) {
			probe_votes[i].count++;
			probe_votes[i].func_mask |= (u8)(1U << func_idx);
			return;
		}
	}

	if (nr_probe_votes < MAX_PROBE_VOTES) {
		probe_votes[nr_probe_votes].offset = offset;
		probe_votes[nr_probe_votes].count = 1;
		probe_votes[nr_probe_votes].func_mask = (u8)(1U << func_idx);
		nr_probe_votes++;
	}
}

static void scan_function_for_lock_offset(unsigned long func, unsigned long size, int func_idx,
					  const unsigned long *lock_addr,
					  const unsigned long *lock_resolved)
{
	unsigned long max_insns = size / 4;
	unsigned long i;

	if (!func || !size)
		return;

	if (max_insns > MAX_SCAN_INSNS)
		max_insns = MAX_SCAN_INSNS;

	for (i = 0; i < max_insns; i++) {
		unsigned long pc = func + i * 4;
		u32 insn;
		unsigned long target;
		unsigned long resolved_target;
		int j;

		if (hmkpm_copy_from_kernel_nofault(&insn, (const void *)pc, sizeof(insn)) != 0)
			break;

		if (!insn_is_bl_or_b(pc, insn, &target))
			continue;

		resolved_target = resolve_branch_target(target);

		for (j = 0; j < NR_PROBE_LOCKS; j++) {
			unsigned int off = 0;

			if (!lock_addr[j])
				continue;

			if (target == lock_addr[j] || resolved_target == lock_addr[j] ||
			    (lock_resolved[j] && (target == lock_resolved[j] ||
						 resolved_target == lock_resolved[j]))) {
				if (find_offset_before_branch(pc, &off) == 0)
					add_probe_vote(off, func_idx);
				break;
			}
		}
	}
}

static int pick_consensus_offset(unsigned int *offset, int valid_funcs)
{
	int i;
	int best = -1;
	u32 best_count = 0;
	int best_pop = -1;

	for (i = 0; i < nr_probe_votes; i++) {
		int pop = __builtin_popcount((unsigned int)probe_votes[i].func_mask);

		if (pop > best_pop ||
		    (pop == best_pop && probe_votes[i].count > best_count)) {
			best = i;
			best_count = probe_votes[i].count;
			best_pop = pop;
		}
	}

	if (best < 0)
		return -ENOENT;

	/*
	 * Require consensus across distinct functions or multiple occurrences,
	 * or accept trusted vote if only one candidate function could be resolved.
	 */
	if (best_pop < 2 && best_count < 2 && !(valid_funcs == 1 && best_count >= 1))
		return -ENOENT;

	if ((probe_votes[best].offset & 7) != 0)
		return -EINVAL;

	if (probe_votes[best].offset < OFFSET_MIN ||
	    probe_votes[best].offset > OFFSET_MAX)
		return -EINVAL;

	*offset = probe_votes[best].offset;
	return 0;
}

static int find_mm_mmap_sem_offset(unsigned int *offset)
{
	unsigned long lock_addr[NR_PROBE_LOCKS] = {0};
	unsigned long lock_resolved[NR_PROBE_LOCKS] = {0};
	unsigned long func_addr[MAX_PROBE_FUNCS] = {0};
	unsigned long func_size[MAX_PROBE_FUNCS] = {0};
	int (*kf_kallsyms_lookup_size_offset)(unsigned long addr, unsigned long *symbolsize, unsigned long *offset) = NULL;
	unsigned int off = 0;
	int valid_funcs = 0;
	int valid_locks = 0;
	int i, ret;

	if (!offset)
		return -EINVAL;

	nr_probe_votes = 0;
	kfunc(memset)(probe_votes, 0, sizeof(probe_votes));

	/* Resolve symbols for lock functions and their canonical targets */
	for (i = 0; i < NR_PROBE_LOCKS; i++) {
		lock_addr[i] = hmkpm_lookup_symbol(lock_symbol_defs[i].name);
		if (lock_addr[i]) {
			lock_resolved[i] = resolve_branch_target(lock_addr[i]);
			valid_locks++;
		}
	}

	if (valid_locks == 0) {
		hmkpm_error("mmap_sem probe: no lock symbols resolved\n");
		return -ENOENT;
	}

	/*
	 * Try to obtain exact function sizes via kallsyms_lookup_size_offset if
	 * available
	 */
	kf_kallsyms_lookup_size_offset =
		(typeof(kf_kallsyms_lookup_size_offset))hmkpm_lookup_symbol("kallsyms_lookup_size_offset");

	for (i = 0; i < MAX_PROBE_FUNCS; i++) {
		unsigned long size = 0;

		func_addr[i] = hmkpm_lookup_symbol(probe_func_names[i]);
		if (!func_addr[i])
			continue;

		if (kf_kallsyms_lookup_size_offset)
			kf_kallsyms_lookup_size_offset(func_addr[i], &size, NULL);

		if (!size)
			size = 256 * 4; /* Default: 256 instructions (1 KB) */

		func_size[i] = size & ~3UL;
		valid_funcs++;
	}

	if (valid_funcs == 0) {
		hmkpm_error("mmap_sem probe: no candidate functions resolved\n");
		return -ENOENT;
	}

	for (i = 0; i < MAX_PROBE_FUNCS; i++) {
		if (func_addr[i])
			scan_function_for_lock_offset(func_addr[i], func_size[i], i, lock_addr, lock_resolved);
	}

	ret = pick_consensus_offset(&off, valid_funcs);
	if (ret != 0) {
		hmkpm_error("mmap_sem probe: failed to find consensus offset\n");
		return ret;
	}

	*offset = off;
	hmkpm_info("mmap_sem probe: dynamically resolved offset = 0x%x (%u)\n", off, off);
	return 0;
}

static inline int get_mm_mmap_lock_offset(void)
{
	if (kver >= VERSION(6, 12, 0)) {
		return 136;
	} else if (kver >= VERSION(6, 6, 0)) {
		return 144;
	} else if (kver >= VERSION(6, 1, 0)) {
		return 96;
	} else if (kver >= VERSION(5, 15, 0)) {
		return 104;
	} else if (kver >= VERSION(5, 10, 0)) {
		return 112;
	} else {
		/*
		 * Kernels below 5.10 (pre-GKI): dynamically discovered via assembly
		 * disassembly
		 */
		unsigned int off = 0;

		if (find_mm_mmap_sem_offset(&off) == 0)
			return (int)off;

		return -ENOENT;
	}
}

static long module_init_handler(const char *args, const char *event, void *__user reserved)
{
	hook_err_t err;

	if (kver < VERSION(4, 0, 0) || kver >= VERSION(6, 13, 0)) {
		hmkpm_error("Kernel version not supported\n");
		return -EINVAL;
	}

	if (pgt_pgtable_init() != 0) {
		hmkpm_error("Page table initialization failed\n");
		return -ENOENT;
	}

	hkfunc_match(memset);
	kf___arch_copy_to_user =
		(typeof(kf___arch_copy_to_user))hmkpm_lookup_symbol("__arch_copy_to_user");
	if (!kf___arch_copy_to_user)
		kf___arch_copy_to_user =
			(typeof(kf___arch_copy_to_user))hmkpm_lookup_symbol("__copy_to_user");

	if (!kf___arch_copy_to_user) {
		hmkpm_error("Failed to find kfunc __arch_copy_to_user / __copy_to_user\n");
		init_error = true;
	}

	kf___arch_copy_from_user =
		(typeof(kf___arch_copy_from_user))hmkpm_lookup_symbol("__arch_copy_from_user");
	if (!kf___arch_copy_from_user)
		kf___arch_copy_from_user =
			(typeof(kf___arch_copy_from_user))hmkpm_lookup_symbol("__copy_from_user");

	if (!kf___arch_copy_from_user) {
		hmkpm_error("Failed to find kfunc __arch_copy_from_user / __copy_from_user\n");
		init_error = true;
	}

	hkfunc_match(find_task_by_vpid);
	hkfunc_match(get_task_mm);
	hkfunc_match(mmput);
	hkfunc_match(__rcu_read_lock);
	hkfunc_match(__rcu_read_unlock);
	hkfunc_match(down_read);
	hkfunc_match(up_read);

	hkvar_match(high_memory);
	if (!kv_high_memory) {
		hmkpm_error("Failed to resolve high_memory\n");
		return -ENOENT;
	}

	pgt_high_memory = (uint64_t)kvar_val(high_memory);
	pgt_phys_limit = pgt_virt_to_phys(pgt_high_memory);
	hmkpm_info("high_memory = 0x%llx\n", pgt_high_memory);

	kf_copy_from_kernel_nofault =
		(typeof(kf_copy_from_kernel_nofault))hmkpm_lookup_symbol("copy_from_kernel_nofault");
	if (!kf_copy_from_kernel_nofault) {
		hmkpm_info("Failed to find kfunc copy_from_kernel_nofault, using probe_kernel_read instead\n");
		hkfunc_match(probe_kernel_read);
	}

	kf_copy_to_kernel_nofault =
		(typeof(kf_copy_to_kernel_nofault))hmkpm_lookup_symbol("copy_to_kernel_nofault");
	if (!kf_copy_to_kernel_nofault) {
		hmkpm_info("Failed to find kfunc copy_to_kernel_nofault, using probe_kernel_write instead\n");
		hkfunc_match(probe_kernel_write);
	}

	mmap_lock_sem_offset = get_mm_mmap_lock_offset();
	if (mmap_lock_sem_offset >= 0) {
		hmkpm_info("mmap lock/sem offset = %d (0x%x)\n",
			   mmap_lock_sem_offset, mmap_lock_sem_offset);
	} else {
		hmkpm_error("Failed to determine mmap lock/sem offset, aborting...\n");
		return -ENOENT;
	}

	if (init_error) {
		hmkpm_error("Symbol resolution failed, aborting...\n");
		return -ENOENT;
	}

	err = hook_syscalln(__NR_getresuid, 3, (void *)hmkpm_handle, 0, 0);
	if (err) {
		hmkpm_error("install hook error: %d\n", err);
		return -ENOENT;
	}

	hmkpm_info("module loaded successfully\n");
	return 0;
}

/* Helper string and userspace response utilities */
static inline int kpm_isspace(char c)
{
	return (c == ' ' || c == '\t' || c == '\n' || c == '\r');
}

static const char *kpm_skip_spaces(const char *s)
{
	if (!s)
		return "";
	while (*s && kpm_isspace(*s))
		s++;
	return s;
}

static bool kpm_streq(const char *s1, const char *s2)
{
	if (!s1 || !s2)
		return false;
	while (*s1 && *s2) {
		if (*s1 != *s2)
			return false;
		s1++;
		s2++;
	}
	while (*s1 && kpm_isspace(*s1))
		s1++;
	return (*s1 == '\0' && *s2 == '\0');
}

static void send_user_msg(char __user *out_msg, int outlen, const char *msg)
{
	int len = 0;

	if (!out_msg || outlen <= 0 || !msg)
		return;

	while (msg[len] && len < outlen - 1)
		len++;

	compat_copy_to_user(out_msg, msg, len + 1);
}

static long module_control_handler(const char *args, char __user *out_msg, int outlen)
{
	const char *cmd = kpm_skip_spaces(args);
	long ret = 0;

	if (kpm_streq(cmd, "enable") || kpm_streq(cmd, "on") ||
	    kpm_streq(cmd, "start") || kpm_streq(cmd, "1")) {
		hook_active = true;
		send_user_msg(out_msg, outlen, "enabled\n");
	} else if (kpm_streq(cmd, "disable") || kpm_streq(cmd, "off") ||
		   kpm_streq(cmd, "stop") || kpm_streq(cmd, "0")) {
		hook_active = false;
		send_user_msg(out_msg, outlen, "disabled\n");
	} else if (kpm_streq(cmd, "status") || kpm_streq(cmd, "state") ||
		   kpm_streq(cmd, "get")) {
		if (hook_active)
			send_user_msg(out_msg, outlen, "active\n");
		else
			send_user_msg(out_msg, outlen, "inactive\n");
	} else if (kpm_streq(cmd, "toggle")) {
		if (hook_active) {
			hook_active = false;
			send_user_msg(out_msg, outlen, "toggled to disabled\n");
		} else {
			hook_active = true;
			send_user_msg(out_msg, outlen, "toggled to enabled\n");
		}
	} else {
		hmkpm_info("unknown control command: '%s'\n", cmd ? cmd : "(null)");
		send_user_msg(out_msg, outlen,
			      "unknown command. Available: enable | disable | status | toggle\n");
		ret = -EINVAL;
	}

	return ret;
}

static long module_cleanup_handler(void *__user reserved)
{
	unhook_syscalln(__NR_getresuid, (void *)hmkpm_handle, 0);
	hmkpm_info("module cleaned up\n");
	return 0;
}

KPM_INIT(module_init_handler);
KPM_CTL0(module_control_handler);
KPM_EXIT(module_cleanup_handler);
