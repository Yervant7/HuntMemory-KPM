// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2026 Yervant7
 *
 * KernelPatch Module (KPM) - [HMKPM]
 */

#include <asm/current.h>
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
KPM_VERSION("2.3.3");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("Yervant7");
KPM_DESCRIPTION("A KernelPatch Module (KPM) HMKPM");

static bool hook_active = true;
static bool init_error = false;
static int mmap_lock_sem_offset = -1;

struct rw_semaphore;
extern bool is_su_allow_uid(uid_t uid);
extern int kp_kconfig_enabled(const char *name) __attribute__((weak));

#define U64_MAX				((u64)~0ULL)
#define HMKPM_TAG			"[HMKPM] "

#define hmkpm_info(fmt, ...)        logki(HMKPM_TAG fmt, ##__VA_ARGS__)
#define hmkpm_warn(fmt, ...)        logkw(HMKPM_TAG fmt, ##__VA_ARGS__)
#define hmkpm_error(fmt, ...)       logke(HMKPM_TAG fmt, ##__VA_ARGS__)

void *memset(void *s, int c, size_t count)
{
    unsigned char *p = (unsigned char *)s;
    while (count--)
        *p++ = (unsigned char)c;
    return s;
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
static uint64_t pgt_pgd_align_mask;
static uint64_t pgt_pgd_size;
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

/* ========================================================================
 * Software PAN (CONFIG_ARM64_SW_TTBR0_PAN) Support
 * ======================================================================== */

static bool sw_pan_checked = false;
static bool sw_pan_enabled = false;
static uint64_t reserved_ttbr0_val = 0;

static void hmkpm_check_sw_pan_lazy(void)
{
	if (likely(sw_pan_checked))
		return;

	/* 1. Check via kp_kconfig_enabled (lazy check after boot completed) */
	if (kp_kconfig_enabled && kp_kconfig_enabled("CONFIG_ARM64_SW_TTBR0_PAN")) {
		sw_pan_enabled = true;
	}

	/* 2. Check if reserved_ttbr0 symbol exists in kernel */
	unsigned long sym_reserved = hmkpm_lookup_symbol("reserved_ttbr0");
	if (sym_reserved) {
		uint64_t pa = 0;
		if (hmkpm_copy_from_kernel_nofault(&pa, (const void *)sym_reserved, sizeof(pa)) == 0 && pa) {
			reserved_ttbr0_val = pa;
			sw_pan_enabled = true;
		}
	}

	/* 3. Check CPU Hardware PAN support via ID_AA64MMFR1_EL1 */
	if (!sw_pan_enabled && sym_reserved) {
		uint64_t mmfr1;
		asm volatile("mrs %0, id_aa64mmfr1_el1" : "=r"(mmfr1));
		if (((mmfr1 >> 20) & 0xFULL) == 0) {
			sw_pan_enabled = true;
		}
	}

	sw_pan_checked = true;
	if (sw_pan_enabled) {
		hmkpm_info("SW PAN detected: reserved_ttbr0=0x%llx\n", reserved_ttbr0_val);
	}
}

static inline uint64_t hmkpm_uaccess_enable(void)
{
	uint64_t old_ttbr0 = 0;

	hmkpm_check_sw_pan_lazy();

	if (unlikely(sw_pan_enabled)) {
		asm volatile("mrs %0, ttbr0_el1" : "=r"(old_ttbr0));
		struct task_struct *cur = current;
		if (cur && kf_get_task_mm && kf_mmput) {
			struct mm_struct *mm = kfunc(get_task_mm)(cur);
			if (mm) {
				uint64_t cur_pgd_va = 0;
				if (mm_struct_offset.pgd_offset >= 0) {
					hmkpm_copy_from_kernel_nofault(&cur_pgd_va,
						(const void *)((uintptr_t)mm + mm_struct_offset.pgd_offset),
						sizeof(cur_pgd_va));
				}
				kfunc(mmput)(mm);
				if (cur_pgd_va) {
					uint64_t cur_pgd_pa = pgt_virt_to_phys(cur_pgd_va);
					asm volatile("msr ttbr0_el1, %0\n isb\n" :: "r"(cur_pgd_pa) : "memory");
				}
			}
		}
	}

	return old_ttbr0;
}

static inline void hmkpm_uaccess_disable(uint64_t old_ttbr0)
{
	if (unlikely(sw_pan_enabled)) {
		uint64_t restore_val = reserved_ttbr0_val ? reserved_ttbr0_val : old_ttbr0;
		if (restore_val) {
			asm volatile("msr ttbr0_el1, %0\n isb\n" :: "r"(restore_val) : "memory");
		}
	}
}

static inline unsigned long hmkpm_copy_to_user(void __user *to, const void *from, unsigned long n)
{
	uint64_t flags = hmkpm_uaccess_enable();
	unsigned long ret = kfunc(__arch_copy_to_user)(to, from, n);
	hmkpm_uaccess_disable(flags);
	return ret;
}

static inline unsigned long hmkpm_copy_from_user(void *to, const void __user *from, unsigned long n)
{
	uint64_t flags = hmkpm_uaccess_enable();
	unsigned long ret = kfunc(__arch_copy_from_user)(to, from, n);
	hmkpm_uaccess_disable(flags);
	return ret;
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

	if (pgd & pgt_pgd_align_mask)
		return 0;

	if (validate_virt_range(pgd, pgt_pgd_size))
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
		 * This prevents accepting non-canonical VA with index outside the real range.
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

	/*
	 * Root page table (PGD) size and alignment calculation:
	 * In 4-level paging (48-bit VA, 4KB page) PGD is 512 entries = 4096 bytes (4KB aligned).
	 * In 3-level paging with reduced VA (e.g. 36-bit VA on older kernels),
	 * PGD has only (1 << (36 - 30)) = 64 entries = 512 bytes, so required alignment is 512 bytes.
	 */
	int64_t root_lv = 4 - (int64_t)pgt_page_level;
	uint64_t root_shift = (pgt_page_shift - 3) * (4 - root_lv) + 3;

	if (pgt_va_bits > root_shift) {
		uint64_t root_bits = pgt_va_bits - root_shift;
		pgt_pgd_size = (1ULL << root_bits) * 8;
		if (pgt_pgd_size < pgt_page_size) {
			/* Table is smaller than a page; align to table size (minimum 64 bytes) */
			pgt_pgd_align_mask = pgt_pgd_size - 1;
		} else {
			pgt_pgd_size = pgt_page_size;
			pgt_pgd_align_mask = pgt_page_size - 1;
		}
	} else {
		pgt_pgd_size = pgt_page_size;
		pgt_pgd_align_mask = pgt_page_size - 1;
	}

	/* In kernels >= 5.4.0, ARM64 standardizes full page alignment for PGD */
	if (kver >= VERSION(5, 4, 0)) {
		pgt_pgd_size = pgt_page_size;
		pgt_pgd_align_mask = pgt_page_size - 1;
	}

	if (kver >= VERSION(5, 4, 0)) {
		pgt_page_offset = -(UL(1) << va1_bits);
	} else if (kver >= VERSION(4, 6, 0)) {
		pgt_page_offset = -(UL(1) << (va1_bits - 1));
	} else {
		pgt_page_offset = -(UL(1) << va1_bits);
	}

	hkvar_match(memstart_addr);
	if (!kv_memstart_addr) {
		hmkpm_error("Failed to resolve memstart_addr\n");
		return -EFAULT;
	}
	pgt_phys_offset = kvar_val(memstart_addr);
	pgt_linear_voffset = pgt_page_offset - pgt_phys_offset;

	pgt_tbi0 = !!(tcr_el1 & (1ULL << 37));

	hmkpm_info("Page table config: va0_bits=%llu, shift=%llu, size=0x%llx, pgd_size=0x%llx, level=%llu, tbi0=%d\n",
		   va0_bits, pgt_page_shift, pgt_page_size, pgt_pgd_size, pgt_page_level, pgt_tbi0);
	hmkpm_info("phys_offset=0x%llx, page_offset=0x%llx, linear_voffset=0x%llx, pgd_align_mask=0x%llx\n",
		   pgt_phys_offset, pgt_page_offset, pgt_linear_voffset, pgt_pgd_align_mask);

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

		if (hmkpm_copy_to_user(dst, zero_chunk, chunk) != 0)
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
			/* hmkpm_copy_to_user returns number of bytes NOT copied (0=success) */
			not_copied = hmkpm_copy_to_user(local_buf, tkva, chunk);
		} else {
			/* hmkpm_copy_from_user returns number of bytes NOT copied (0=success) */
			not_copied = hmkpm_copy_from_user(tkva, local_buf, chunk);
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

	if (hmkpm_copy_from_user(&req, user_ptr, HMKPM_REQ_SIZE) != 0) {
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

	if (hmkpm_copy_from_user(&hdr, user_ptr, HMKPM_BATCH_HDR_SIZE) != 0) {
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

		if (hmkpm_copy_from_user((void *)chunk, entry_src, chunk_bytes) != 0) {
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
				/* Page walk / copy failed: mark size = 0 so userspace identifies the failed address */
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

			/* Always advance by the requested size to maintain strict buffer alignment */
			data_off += req_size;
		}

		/* Return chunk with actual transferred sizes of each entry to userspace */
		if (hmkpm_copy_to_user(entry_src, chunk, chunk_bytes) != 0) {
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

/* ========================================================================
 * Dynamic ARM64 Disassembly & mmap_sem Probe Scanner
 * ======================================================================== */

static inline unsigned int a64_insn_rd(u32 insn)
{
	return insn & 0x1f;
}

static inline unsigned int a64_insn_rn(u32 insn)
{
	return (insn >> 5) & 0x1f;
}

static inline unsigned int a64_insn_rm(u32 insn)
{
	return (insn >> 16) & 0x1f;
}

/*
 * NOP, BTI and various hint/PAC instructions reside in HINT space.
 * They may appear at the start of functions/trampolines in modern kernels.
 */
static inline bool insn_is_prologue_hint(u32 insn)
{
	return (insn & 0xfffff000) == 0xd5032000;
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

/*
 * Follows trampolines of the form:
 *
 *   target:
 *       b real_target
 *
 * or on kernels with BTI/PAC:
 *
 *   target:
 *       bti c
 *       b real_target
 *
 * If no B instruction is found after prologue hints, returns the target itself.
 */
static unsigned long resolve_branch_target(unsigned long target)
{
	unsigned long resolved = target;
	int hops = 0;

	while (resolved && hops++ < 4) {
		unsigned long cursor = resolved;
		bool found_b = false;
		int skip;

		for (skip = 0; skip < 3; skip++, cursor += 4) {
			u32 insn;
			unsigned long next;

			if (hmkpm_copy_from_kernel_nofault(&insn,
							   (const void *)cursor,
							   sizeof(insn)) != 0)
				break;

			if (insn_is_prologue_hint(insn))
				continue;

			/* Only unconditional B; BL is not a normal trampoline. */
			if ((insn & 0xfc000000) == 0x14000000 &&
			    insn_is_bl_or_b(cursor, insn, &next)) {
				resolved = next;
				found_b = true;
			}
			break;
		}

		if (!found_b)
			break;
	}

	return resolved;
}

static inline bool is_ret_insn(u32 insn)
{
	return (insn & 0xfffffc1f) == 0xd65f0000;
}

/*
 * Instructions that definitively exit or leave the function / subroutine.
 * Local conditional branches (B.cond, CBZ, CBNZ, TBZ, TBNZ) are NOT function exits.
 */
static bool insn_is_function_exit(u32 insn)
{
	/* RET */
	if (is_ret_insn(insn))
		return true;

	/* ERET */
	if (insn == 0xd69f03e0)
		return true;

	/* Indirect branch (BR) */
	if ((insn & 0xfffffc1f) == 0xd61f0000)
		return true;

	return false;
}

/*
 * Recognizes 64-bit atomic operations commonly used in inlined rwsem fast paths:
 * 1. LSE Atomics (ARMv8.1+): CAS, CASAL, CASA, CASL, LDADD, SWP, LDCLR, LDSET, LDEOR
 * 2. LL/SC (ARMv8.0): LDAXR, LDXR, STLXR, STXR
 */
static bool insn_is_atomic_rwsem_op(u32 insn, unsigned int *rn)
{
    unsigned int r;

    /*
     * 64-bit CAS / CASA / CASL / CASAL (LSE Atomics)
     *
     * Use a mask that ignores the variant bits but keeps the fixed class bits.
     */
    if ((insn & 0xffa07c00) == 0xc8a07c00) {
        r = a64_insn_rn(insn);
        if (r == 31)
            return false;
        *rn = r;
        return true;
    }

    /*
     * 64-bit LSE atomic memory operations:
     * LDADD, LDCLR, LDEOR, LDSET, SWP.
     *
     * A/R variant bits are ignored by the mask 0xff20fc00.
     */
    switch (insn & 0xff20fc00) {
    case 0xf8200000: /* LDADD / STADD */
    case 0xf8201000: /* LDCLR */
    case 0xf8202000: /* LDEOR */
    case 0xf8203000: /* LDSET */
    case 0xf8208000: /* SWP */
        r = a64_insn_rn(insn);
        if (r == 31)
            return false;
        *rn = r;
        return true;
    }

    /*
     * 64-bit LDXR / LDAXR (LL/SC Load-Exclusive)
     */
    if ((insn & 0xfffffc00) == 0xc85f7c00 || /* LDXR */
        (insn & 0xfffffc00) == 0xc85ffc00) { /* LDAXR */
        r = a64_insn_rn(insn);
        if (r == 31)
            return false;
        *rn = r;
        return true;
    }

    /*
     * 64-bit STLXR / STXR (LL/SC Store-Exclusive)
     */
    if ((insn & 0xffe0fc00) == 0xc8007c00 || /* STLXR */
        (insn & 0xffe0fc00) == 0xc800fc00) { /* STXR */
        r = a64_insn_rn(insn);
        if (r == 31)
            return false;
        *rn = r;
        return true;
    }

    return false;
}

/*
 * ADD/ADDS immediate 64-bit:
 *
 *   ADD  Xd, Xn, #imm{, LSL #12}
 *   ADDS Xd, Xn, #imm{, LSL #12}
 */
static bool insn_add_imm(u32 insn, unsigned int *rd, unsigned int *rn,
			 unsigned long *imm)
{
	u32 op = insn & 0xff800000;

	if (op != 0x91000000 && op != 0xb1000000)
		return false;

	*rd = a64_insn_rd(insn);
	*rn = a64_insn_rn(insn);
	*imm = (insn >> 10) & 0xfff;

	/* Shift bit 22: LSL #12 */
	if ((insn >> 22) & 1)
		*imm <<= 12;

	return true;
}

/*
 * MOV register:
 *
 *   MOV Xd, Xm  == ORR Xd, XZR, Xm  or  ADD Xd, Xm, #0
 *   MOV Wd, Wm  == ORR Wd, WZR, Wm  or  ADD Wd, Wm, #0
 */
static bool insn_is_mov_reg(u32 insn, unsigned int *rd, unsigned int *rm,
			    bool *is64)
{
	/* ORR Xd, XZR, Xm, LSL #0 */
	if ((insn & 0xffe0ffe0) == 0xaa0003e0) {
		*rd = a64_insn_rd(insn);
		*rm = a64_insn_rm(insn);
		*is64 = true;
		return true;
	}

	/* ORR Wd, WZR, Wm */
	if ((insn & 0xffe0ffe0) == 0x2a0003e0) {
		*rd = a64_insn_rd(insn);
		*rm = a64_insn_rm(insn);
		*is64 = false;
		return true;
	}

	/* ADD Xd, Xm, #0 */
	if ((insn & 0xffe003e0) == 0x91000000) {
		*rd = a64_insn_rd(insn);
		*rm = a64_insn_rn(insn);
		*is64 = true;
		return true;
	}

	/* ADD Wd, Wm, #0 */
	if ((insn & 0xffe003e0) == 0x11000000) {
		*rd = a64_insn_rd(insn);
		*rm = a64_insn_rn(insn);
		*is64 = false;
		return true;
	}

	return false;
}

/*
 * ADD/ADDS shifted/extended register 64-bit.
 *
 * Examples:
 *
 *   ADD Xd, Xn, Xm
 *   ADD Xd, Xn, Xm, LSL #n
 *   ADD Xd, Xn, Wm, UXTW
 *   ADD Xd, Xn, Wm, UXTW #n
 */
static bool insn_is_add_reg(u32 insn, unsigned int *rd, unsigned int *rn,
			    unsigned int *rm, bool *extended,
			    unsigned int *shift)
{
	/* ADD/ADDS shifted register, LSL only */
	if ((insn & 0xffe00000) == 0x8b000000 ||
	    (insn & 0xffe00000) == 0xab000000) {
		*rd = a64_insn_rd(insn);
		*rn = a64_insn_rn(insn);
		*rm = a64_insn_rm(insn);
		*extended = false;
		*shift = (insn >> 10) & 0x3f;
		return true;
	}

	/* ADD/ADDS extended register */
	if ((insn & 0xffe00000) == 0x8b200000 ||
	    (insn & 0xffe00000) == 0xab200000) {
		*rd = a64_insn_rd(insn);
		*rn = a64_insn_rn(insn);
		*rm = a64_insn_rm(insn);
		*extended = true;
		*shift = (insn >> 10) & 0x7;
		return true;
	}

	return false;
}

enum need_kind {
	NEED_ADDR,
	NEED_CONST,
};

enum wide_imm_op {
	WIDE_MOVZ,
	WIDE_MOVK,
	WIDE_MOVN,
};

/*
 * MOVZ/MOVK/MOVN wide immediate instructions.
 */
static bool insn_wide_imm(u32 insn, unsigned int *rd, unsigned int *hw,
			  unsigned long *imm16, enum wide_imm_op *type)
{
	switch (insn & 0xff800000) {
	case 0xd2800000:
		*type = WIDE_MOVZ; /* MOVZ X */
		break;
	case 0x52800000:
		*type = WIDE_MOVZ; /* MOVZ W */
		break;
	case 0xf2800000:
		*type = WIDE_MOVK; /* MOVK X */
		break;
	case 0x72800000:
		*type = WIDE_MOVK; /* MOVK W */
		break;
	case 0x92800000:
		*type = WIDE_MOVN; /* MOVN X */
		break;
	case 0x12800000:
		*type = WIDE_MOVN; /* MOVN W */
		break;
	default:
		return false;
	}

	*rd = a64_insn_rd(insn);
	*hw = (insn >> 21) & 0x3;
	*imm16 = (insn >> 5) & 0xffff;

	return true;
}

#define MAX_PROBE_FUNCS           32
#define MAX_PROBE_VOTES           64
#define MAX_SCAN_INSNS            4096UL
#define BACK_SCAN_MAX             32
#define OFFSET_MIN                8U
#define OFFSET_MAX                4096U

struct offset_vote {
	u32 offset;
	u32 count;
	u32 func_mask;
};

static struct offset_vote probe_votes[MAX_PROBE_VOTES];
static int nr_probe_votes;

/* Expanded list covering kernels 4.14 through 6.x+ and vendor inlines */
static const char *const probe_func_names[] = {
	"vm_munmap",
	"__vm_munmap",
	"vm_brk_flags",
	"do_brk_flags",
	"exit_mmap",
	"vm_mmap_pgoff",
	"do_munmap",
	"__do_munmap",
	"ksys_mmap_pgoff",
	"vm_mmap",
	"apply_mlockall_flags",
	"setup_arg_pages",
	"sys_munmap",
	"do_mmap",
	"mmap_region",
	"dup_mmap",
	"copy_process",
	"sys_mmap_pgoff",
	"use_mm",
	"unuse_mm",
	"__vma_link_rb",
	"vma_adjust",
	"find_vma",
	"mmput",
};
#define NR_PROBE_FUNCS (sizeof(probe_func_names) / sizeof(probe_func_names[0]))

static const char *const lock_symbol_names[] = {
	"down_read",
	"_down_read",
	"__down_read",
	"down_write",
	"_down_write",
	"__down_write",
	"up_read",
	"_up_read",
	"__up_read",
	"up_write",
	"_up_write",
	"__up_write",
	"down_read_killable",
	"down_write_killable",
	"down_read_trylock",
	"_down_read_trylock",
	"__down_read_trylock",
	"down_write_trylock",
	"rwsem_down_read",
	"rwsem_down_write",
	"rwsem_down_read_failed",
	"__rwsem_down_read_failed",
	"rwsem_down_write_failed",
	"__rwsem_down_write_failed",
	"rwsem_down_write_failed_killable",
	"__rwsem_down_write_failed_killable",
	"rwsem_down_read_slow",
	"rwsem_down_write_slow",
	"__rwsem_down_read_slowpath",
	"__rwsem_down_write_slowpath",
	"rwsem_optimistic_spin",
	"rwsem_spin_on_owner",
	"rwsem_wake",
	"__rwsem_wake",
	"__rwsem_up_read_failed",
	"rwsem_up_read",
	"rwsem_up_write",
};
#define NR_PROBE_LOCKS (sizeof(lock_symbol_names) / sizeof(lock_symbol_names[0]))

_Static_assert(NR_PROBE_FUNCS <= MAX_PROBE_FUNCS,
	       "MAX_PROBE_FUNCS must be greater than or equal to NR_PROBE_FUNCS");

static inline bool offset_is_valid(unsigned long imm)
{
	return imm >= OFFSET_MIN && imm <= OFFSET_MAX && (imm & 7) == 0;
}

/*
 * Heuristic: in ADD register, usually one operand is the base mm_struct
 * and the other is the offset/index.
 * We prefer choosing a temporary register as "constant" rather than
 * a callee-saved/frame pointer register, which is usually the base.
 */
static inline bool reg_is_likely_base(unsigned int r)
{
	return r == 29 || (r >= 19 && r <= 28);
}

static int choose_add_register_source(unsigned int rn, unsigned int rm,
				      bool extended)
{
	if (rn == 31 && rm == 31)
		return -1;

	/*
	 * In ADD extended, typically:
	 *   ADD Xd, Xbase, Woffset, UXTW
	 * so Rm is usually the offset.
	 */
	if (extended)
		return (rm != 31) ? (int)rm : (int)rn;

	if (rm == 31)
		return (int)rn;
	if (rn == 31)
		return (int)rm;

	if (reg_is_likely_base(rn) && !reg_is_likely_base(rm))
		return (int)rm;
	if (reg_is_likely_base(rm) && !reg_is_likely_base(rn))
		return (int)rn;

	/* Common convention: offset in Rm. */
	return (int)rm;
}

/*
 * Returns true if the instruction likely writes to reg.
 * Prevents scanning past an actual clobber of the tracked register.
 */
static bool insn_may_write_reg(u32 insn, unsigned int reg)
{
	unsigned int rd = a64_insn_rd(insn);

	if (reg == 31 || rd != reg)
		return false;

	/* STR (immediate 64-bit) -> reg in [4:0] is data stored, not destination */
	if ((insn & 0xffc00000) == 0xf9000000)
		return false;

	/* STP (64-bit store pair) -> reg in [4:0] is only stored data */
	if ((insn & 0xfe400000) == 0xa9000000)
		return false;

	/* Generic load/store: if bit 22 is 0, it is a store */
	if ((insn & 0x0e000000) == 0x0a000000) {
		if ((insn & 0x00400000) == 0)
			return false; /* store */
		return true; /* load */
	}

	if (insn_is_prologue_hint(insn))
		return false;

	return true;
}

static void add_probe_vote(unsigned int offset, int func_idx)
{
	int i;

	if (!offset_is_valid(offset))
		return;

	if (func_idx < 0 || func_idx >= MAX_PROBE_FUNCS)
		return;

	for (i = 0; i < nr_probe_votes; i++) {
		if (probe_votes[i].offset == offset) {
			probe_votes[i].count++;
			probe_votes[i].func_mask |= (u32)(1U << func_idx);
			return;
		}
	}

	if (nr_probe_votes < MAX_PROBE_VOTES) {
		probe_votes[nr_probe_votes].offset = offset;
		probe_votes[nr_probe_votes].count = 1;
		probe_votes[nr_probe_votes].func_mask = (u32)(1U << func_idx);
		nr_probe_votes++;
	}
}

/*
 * Backward scan from call site or atomic instruction site.
 * Tracks the register start_reg backwards looking for:
 *   add start_reg, xbase, #offset
 *   movz/movk/add combinations
 */
static int find_offset_before_pc_reg(unsigned long start_pc,
				     unsigned int start_reg,
				     unsigned int *offset)
{
	int i;
	int need_reg = (int)start_reg;
	enum need_kind need_kind = NEED_ADDR;
	unsigned int need_shift = 0;
	bool have_partial = false;
	u64 partial_val = 0;
	u64 partial_mask = 0;

	if (need_reg < 0 || need_reg >= 31)
		return -EINVAL;

	for (i = 1; i <= BACK_SCAN_MAX; i++) {
		unsigned long pc;
		u32 insn;
		unsigned int rd, rn, rm, hw;
		unsigned long imm, imm16;
		bool extended;
		bool is64;
		unsigned int add_shift;
		enum wide_imm_op wtype;

		/* Check underflow before computing pc. */
		if ((unsigned long)i * 4 > start_pc)
			break;

		pc = start_pc - (unsigned long)i * 4;

		if (hmkpm_copy_from_kernel_nofault(&insn,
						   (const void *)pc,
						   sizeof(insn)) != 0)
			break;

		/* Hard function returns / exits end the search */
		if (insn_is_function_exit(insn))
			break;

		/* 1. MOV register forwarding (ORR Xd, XZR, Xm or ADD Xd, Xm, #0) */
		if (insn_is_mov_reg(insn, &rd, &rm, &is64)) {
			if (rd == (unsigned int)need_reg) {
				if (rm == 31) /* Do not track XZR/SP */
					break;

				/* If we need a 64-bit address, 32-bit MOV is not sufficient */
				if (need_kind == NEED_ADDR && !is64)
					break;

				need_reg = (int)rm;
				continue;
			}
			continue;
		}

		/* 2. ADD/ADDS immediate */
		if (insn_add_imm(insn, &rd, &rn, &imm)) {
			if (rd == (unsigned int)need_reg) {
				if (imm == 0) {
					/* ADD Rd, Rn, #0 is MOV Rd, Rn */
					if (rn == 31)
						break;
					need_reg = (int)rn;
					continue;
				}

				/*
				 * If searching for the final address:
				 *   ADD Xn, Xbase, #offset
				 */
				if (need_kind == NEED_ADDR &&
				    rn != 31 &&
				    offset_is_valid(imm)) {
					*offset = (unsigned int)imm;
					return 0;
				}

				/* Overwrote need_reg with invalid offset; stop */
				break;
			}
			continue;
		}

		/* 3. ADD/ADDS register/extended (ADD X0, Xbase, Woffset, UXTW #shift) */
		if (insn_is_add_reg(insn, &rd, &rn, &rm, &extended,
				    &add_shift)) {
			if (rd == (unsigned int)need_reg) {
				int src;

				if (need_kind != NEED_ADDR)
					break;

				src = choose_add_register_source(rn, rm,
								 extended);
				if (src < 0 || src == 31)
					break;

				need_reg = src;
				need_kind = NEED_CONST;
				need_shift = add_shift;
				have_partial = false;
				partial_val = 0;
				partial_mask = 0;
				continue;
			}
			continue;
		}

		/* 4. MOVZ/MOVK/MOVN wide immediate */
		if (insn_wide_imm(insn, &rd, &hw, &imm16, &wtype)) {
			if (rd == (unsigned int)need_reg) {
				if (need_kind != NEED_CONST)
					break;

				if (wtype == WIDE_MOVN)
					break;

				if (wtype == WIDE_MOVK) {
					u64 hw_mask = 0xffffULL << (hw * 16);

					if (!have_partial) {
						have_partial = true;
						partial_val = 0;
						partial_mask = 0;
					}

					if (!(partial_mask & hw_mask)) {
						partial_val |= (u64)imm16 << (hw * 16);
						partial_mask |= hw_mask;
					}
					continue;
				}

				if (wtype == WIDE_MOVZ) {
					u64 movz_bits = (u64)imm16 << (hw * 16);
					u64 val;

					if (have_partial)
						val = partial_val |
						      (movz_bits & ~partial_mask);
					else
						val = movz_bits;

					if (need_shift >= 64)
						break;

					val <<= need_shift;

					if (offset_is_valid((unsigned long)val)) {
						*offset = (unsigned int)val;
						return 0;
					}

					break;
				}
			}
			continue;
		}

		/* 5. Clobber check */
		if (insn_may_write_reg(insn, (unsigned int)need_reg))
			break;
	}

	return -ENOENT;
}

static void scan_function_for_lock_offset(unsigned long func,
					  unsigned long size,
					  int func_idx,
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
		unsigned int atomic_rn = 0;
		int j;

		if (hmkpm_copy_from_kernel_nofault(&insn,
						   (const void *)pc,
						   sizeof(insn)) != 0)
			break;

		/*
		 * Strategy 1: Direct inlined atomic instruction (LSE atomics or LL/SC)
		 * Operating directly on struct mm_struct + offset
		 */
		if (insn_is_atomic_rwsem_op(insn, &atomic_rn)) {
			unsigned int off = 0;
			if (find_offset_before_pc_reg(pc, atomic_rn, &off) == 0) {
				add_probe_vote(off, func_idx);
			}
			continue;
		}

		/*
		 * Strategy 2: Branch to lock function or slowpath helper
		 */
		if (!insn_is_bl_or_b(pc, insn, &target))
			continue;

		resolved_target = resolve_branch_target(target);

		for (j = 0; j < NR_PROBE_LOCKS; j++) {
			unsigned int off = 0;

			if (!lock_addr[j])
				continue;

			if (target == lock_addr[j] ||
			    resolved_target == lock_addr[j] ||
			    (lock_resolved[j] &&
			     (target == lock_resolved[j] ||
			      resolved_target == lock_resolved[j]))) {
				if (find_offset_before_pc_reg(pc, 0, &off) == 0)
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
	int second = -1;
	int best_pop = -1;
	int second_pop = -1;
	u32 best_count = 0;
	u32 second_count = 0;

	for (i = 0; i < nr_probe_votes; i++) {
		int pop = __builtin_popcount((unsigned int)probe_votes[i].func_mask);

		if (pop > best_pop ||
		    (pop == best_pop && probe_votes[i].count > best_count)) {
			second = best;
			second_pop = best_pop;
			second_count = best_count;

			best = i;
			best_pop = pop;
			best_count = probe_votes[i].count;
		} else if (pop > second_pop ||
			   (pop == second_pop && probe_votes[i].count > second_count)) {
			second = i;
			second_pop = pop;
			second_count = probe_votes[i].count;
		}
	}

	if (best < 0)
		return -ENOENT;

	/*
	 * Acceptance rules:
	 * - Ideal: offset voted by >=2 distinct functions;
	 * - Acceptable: >=2 occurrences in the same function;
	 * - If only 1 candidate function is valid, accept 1 vote.
	 */
	if (best_pop < 2 && best_count < 2 &&
	    !(valid_funcs == 1 && best_count >= 1))
		return -ENOENT;

	/* Technical tie between top two candidates: better to fail than guess */
	if (second >= 0 &&
	    second_pop == best_pop &&
	    second_count == best_count)
		return -ENOENT;

	if (!offset_is_valid(probe_votes[best].offset))
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
	int (*kf_kallsyms_lookup_size_offset)(unsigned long addr,
					      unsigned long *symbolsize,
					      unsigned long *offset) = NULL;
	unsigned int off = 0;
	int valid_funcs = 0;
	int valid_locks = 0;
	int i, j, ret;

	if (!offset)
		return -EINVAL;

	nr_probe_votes = 0;
	kfunc(memset)(probe_votes, 0, sizeof(probe_votes));

	/* Resolve lock symbols and their canonical targets */
	for (i = 0; i < NR_PROBE_LOCKS; i++) {
		lock_addr[i] = hmkpm_lookup_symbol(lock_symbol_names[i]);
		if (!lock_addr[i])
			continue;

		lock_resolved[i] = resolve_branch_target(lock_addr[i]);
		valid_locks++;
	}

	if (valid_locks == 0) {
		hmkpm_error("mmap_sem probe: no lock symbols resolved\n");
		return -ENOENT;
	}

	/* Try to obtain real sizes via kallsyms_lookup_size_offset */
	kf_kallsyms_lookup_size_offset =
		(typeof(kf_kallsyms_lookup_size_offset))
		hmkpm_lookup_symbol("kallsyms_lookup_size_offset");

	for (i = 0; i < NR_PROBE_FUNCS; i++) {
		func_addr[i] = hmkpm_lookup_symbol(probe_func_names[i]);
		if (!func_addr[i])
			continue;
	}

	/* Remove aliases/duplicates so votes are not inflated */
	for (i = 0; i < NR_PROBE_FUNCS; i++) {
		if (!func_addr[i])
			continue;

		for (j = 0; j < i; j++) {
			if (func_addr[j] == func_addr[i]) {
				func_addr[i] = 0;
				break;
			}
		}
	}

	valid_funcs = 0;

	for (i = 0; i < NR_PROBE_FUNCS; i++) {
		unsigned long size = 0;

		if (!func_addr[i])
			continue;

		if (kf_kallsyms_lookup_size_offset)
			kf_kallsyms_lookup_size_offset(func_addr[i], &size, NULL);

		if (!size)
			size = 512 * 4; /* Default: 512 instructions / 2 KiB */

		if (size < 16 * 4)
			size = 16 * 4;

		func_size[i] = size & ~3UL;
		valid_funcs++;
	}

	if (valid_funcs == 0) {
		hmkpm_error("mmap_sem probe: no candidate functions resolved\n");
		return -ENOENT;
	}

	for (i = 0; i < NR_PROBE_FUNCS; i++) {
		if (!func_addr[i])
			continue;

		scan_function_for_lock_offset(func_addr[i], func_size[i], i,
					      lock_addr, lock_resolved);
	}

	ret = pick_consensus_offset(&off, valid_funcs);
	if (ret != 0) {
		hmkpm_error("mmap_sem probe: failed to find consensus offset\n");
		return ret;
	}

	*offset = off;
	hmkpm_info("mmap_sem probe: dynamically resolved offset = 0x%x (%u)\n",
		   off, off);

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
		 * Kernels below 5.10 (pre-GKI): dynamically discovered via assembly disassembly
		 */
		unsigned int off = 0;

		if (find_mm_mmap_sem_offset(&off) == 0)
			return (int)off;

		return -1;
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

	static const char *const arm64_memset_aliases[] = {
        "__memset",
        "memset",
        "__pi___memset",    /* PIE/KASLR stub */
        "__pi_memset",      /* PIE alias */
        "__asan_memset",    /* KASAN generic */
        "__hwasan_memset",  /* KASAN HW-tags (Kernel 5.11+) */
        "__mte_memset",     /* MTE tag memset (Kernel 5.10+) */
        "__arch_memset",    /* Custom vendor kernel (Qualcomm/MediaTek) */
        NULL
    };

    for (int i = 0; arm64_memset_aliases[i] != NULL; i++) {
        kf_memset = (typeof(kf_memset))hmkpm_lookup_symbol(arm64_memset_aliases[i]);
        if (kf_memset) {
            hmkpm_info("Resolved memset via symbol: %s (at %lx)\n", arm64_memset_aliases[i], kf_memset);
            break;
        }
	}

	if (!kf_memset) {
		hmkpm_error("Failed to find kfunc memset\n");
		init_error = true;
	}

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

	/* Optional lock routines (may be inlined in vendor kernels) */
	kf_down_read = (typeof(kf_down_read))hmkpm_lookup_symbol("down_read");
	if (!kf_down_read)
		kf_down_read = (typeof(kf_down_read))hmkpm_lookup_symbol("_down_read");
	if (!kf_down_read)
		kf_down_read = (typeof(kf_down_read))hmkpm_lookup_symbol("__down_read");

	kf_up_read = (typeof(kf_up_read))hmkpm_lookup_symbol("up_read");
	if (!kf_up_read)
		kf_up_read = (typeof(kf_up_read))hmkpm_lookup_symbol("_up_read");
	if (!kf_up_read)
		kf_up_read = (typeof(kf_up_read))hmkpm_lookup_symbol("__up_read");

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
	if (mmap_lock_sem_offset >= 0 && kf_down_read && kf_up_read) {
		hmkpm_info("mmap lock/sem offset = %d (0x%x)\n",
			   mmap_lock_sem_offset, mmap_lock_sem_offset);
	} else {
		hmkpm_warn("mmap lock/sem offset not resolved; running in lockless mode\n");
		mmap_lock_sem_offset = -1;
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
