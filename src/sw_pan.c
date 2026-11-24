// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2026 Yervant7
 *
 * HuntMemory-KPM (HMKPM) - Software PAN (CONFIG_ARM64_SW_TTBR0_PAN) & User Access
 */

#include <hmkpm_internal.h>

static bool sw_pan_enabled = false;
static bool sw_pan_use_kernel_uaccess = false;
static uint64_t reserved_ttbr0_pa = 0;

uint8_t hmkpm_get_sw_pan_mode(void)
{
	if (sw_pan_use_kernel_uaccess)
		return HMKPM_SW_PAN_KERNEL_UACCESS;
	if (sw_pan_enabled && reserved_ttbr0_pa != 0)
		return HMKPM_SW_PAN_MANUAL_TTBR0;
	return HMKPM_SW_PAN_OFF;
}

void hmkpm_sw_pan_init(void)
{
	uint64_t mmfr1 = 0;
	bool cpu_has_hw_pan;

	sw_pan_enabled = false;
	sw_pan_use_kernel_uaccess = false;
	reserved_ttbr0_pa = 0;

	asm volatile("mrs %0, id_aa64mmfr1_el1" : "=r"(mmfr1));
	cpu_has_hw_pan = (((mmfr1 >> 20) & 0xFULL) != 0);

	if (kp_kconfig_available()) {
		if (!kp_kconfig_enabled("CONFIG_ARM64_SW_TTBR0_PAN"))
			return;

		/*
		 * CONFIG_ARM64_SW_TTBR0_PAN is only active at runtime when hardware
		 * PAN is unavailable (ARMv8.0 CPU or CONFIG_ARM64_PAN disabled).
		 */
		if (!cpu_has_hw_pan || !kp_kconfig_enabled("CONFIG_ARM64_PAN"))
			sw_pan_enabled = true;
	} else if (!cpu_has_hw_pan) {
		/* No kconfig available on ARMv8.0 CPU: enable defensive SW PAN check */
		sw_pan_enabled = true;
	}

	if (!sw_pan_enabled)
		return;

	/* Prefer kernel-native _copy_from_user/_copy_to_user under SW PAN */
	kf__copy_from_user =
		(typeof(kf__copy_from_user))hmkpm_lookup_symbol("_copy_from_user");
	if (!kf__copy_from_user)
		kf__copy_from_user =
			(typeof(kf__copy_from_user))hmkpm_lookup_symbol("copy_from_user");

	kf__copy_to_user =
		(typeof(kf__copy_to_user))hmkpm_lookup_symbol("_copy_to_user");
	if (!kf__copy_to_user)
		kf__copy_to_user =
			(typeof(kf__copy_to_user))hmkpm_lookup_symbol("copy_to_user");

	if (kf__copy_from_user && kf__copy_to_user) {
		sw_pan_use_kernel_uaccess = true;
		hmkpm_info("SW PAN detected: using kernel _copy_from_user/_copy_to_user\n");
		return;
	}

	/*
	 * Fallback: resolve physical address of reserved_pg_dir (>= 5.9) or
	 * reserved_ttbr0 (< 5.9). The symbol points to a zeroed page table in the
	 * kernel image, so translate its symbol address via kimage_voffset rather
	 * than dereferencing its contents.
	 */
	unsigned long sym_reserved = hmkpm_lookup_symbol("reserved_pg_dir");
	if (!sym_reserved)
		sym_reserved = hmkpm_lookup_symbol("reserved_ttbr0");

	unsigned long sym_kimage_voff = hmkpm_lookup_symbol("kimage_voffset");
	if (sym_reserved && sym_kimage_voff) {
		uint64_t kimg_voff = 0;

		if (hmkpm_copy_from_kernel_nofault(&kimg_voff,
						   (const void *)sym_kimage_voff,
						   sizeof(kimg_voff)) == 0) {
			uint64_t pa = (uint64_t)sym_reserved - kimg_voff;
			uint64_t first_pte = 1;

			if (pa &&
			    (pa & (pgt_page_size - 1)) == 0 &&
			    validate_phys_range(pa, pgt_page_size) == 0 &&
			    hmkpm_copy_from_kernel_nofault(&first_pte,
							   (const void *)pgt_phys_to_virt(pa),
							   sizeof(first_pte)) == 0 &&
			    first_pte == 0) {
				reserved_ttbr0_pa = pa;
			}
		}
	}

	if (reserved_ttbr0_pa) {
		hmkpm_info("SW PAN detected: manual TTBR0 fallback active (reserved_pa=0x%llx)\n",
			   (unsigned long long)reserved_ttbr0_pa);
	} else {
		hmkpm_warn("SW PAN detected, but neither _copy_*_user nor reserved_pg_dir/reserved_ttbr0 PA could be resolved; disabling manual TTBR0 swap\n");
		sw_pan_enabled = false;
	}
}

static inline uint64_t hmkpm_uaccess_enable(void)
{
	if (likely(!sw_pan_enabled || sw_pan_use_kernel_uaccess || !reserved_ttbr0_pa))
		return 0;

	uint64_t old_ttbr0 = 0;
	uint64_t baddr_mask = 0x0000FFFFFFFFFFFFULL & ~(pgt_page_size - 1);

	asm volatile("mrs %0, ttbr0_el1" : "=r"(old_ttbr0));

	/* Only swap if TTBR0_EL1 currently points to reserved_pg_dir/reserved_ttbr0 */
	if ((old_ttbr0 & baddr_mask) != reserved_ttbr0_pa)
		return 0;

	struct task_struct *cur = current;
	if (!cur)
		return 0;

	struct mm_struct *mm = NULL;
	bool need_mmput = false;
	uint64_t saved_ttbr0 = 0;

	if (task_struct_offset.mm_offset >= 0) {
		hmkpm_copy_from_kernel_nofault(&mm,
			(const void *)((uintptr_t)cur + task_struct_offset.mm_offset),
			sizeof(mm));
	} else if (task_struct_offset.active_mm_offset >= 0) {
		hmkpm_copy_from_kernel_nofault(&mm,
			(const void *)((uintptr_t)cur + task_struct_offset.active_mm_offset),
			sizeof(mm));
	} else if (kf_get_task_mm) {
		mm = kfunc(get_task_mm)(cur);
		need_mmput = true;
	}

	if (mm && !is_bad_address(mm) && mm_struct_offset.pgd_offset >= 0) {
		uint64_t cur_pgd_va = 0;

		if (hmkpm_copy_from_kernel_nofault(&cur_pgd_va,
			(const void *)((uintptr_t)mm + mm_struct_offset.pgd_offset),
			sizeof(cur_pgd_va)) == 0 &&
		    cur_pgd_va &&
		    (cur_pgd_va & pgt_pgd_align_mask) == 0 &&
		    validate_virt_range(cur_pgd_va, pgt_pgd_size) == 0) {
			uint64_t cur_pgd_pa = pgt_virt_to_phys(cur_pgd_va);
			/* Preserve ASID (bits 63:48) from previous TTBR0 */
			uint64_t asid_mask = 0xFFFF000000000000ULL;
			uint64_t new_ttbr0 = (cur_pgd_pa & ~asid_mask) | (old_ttbr0 & asid_mask);

			asm volatile("msr ttbr0_el1, %0\n isb\n" :: "r"(new_ttbr0) : "memory");
			saved_ttbr0 = old_ttbr0;
		}
	}

	if (mm && need_mmput && kf_mmput)
		kfunc(mmput)(mm);

	return saved_ttbr0;
}

static inline void hmkpm_uaccess_disable(uint64_t saved_ttbr0)
{
	if (unlikely(saved_ttbr0 != 0)) {
		asm volatile("msr ttbr0_el1, %0\n isb\n" :: "r"(saved_ttbr0) : "memory");
	}
}

unsigned long hmkpm_copy_to_user(void __user *to, const void *from, unsigned long n)
{
	if (unlikely(sw_pan_use_kernel_uaccess))
		return kfunc(_copy_to_user)(to, from, n);

	uint64_t saved = hmkpm_uaccess_enable();
	unsigned long ret = kfunc(__arch_copy_to_user)(to, from, n);
	hmkpm_uaccess_disable(saved);
	return ret;
}

unsigned long hmkpm_copy_from_user(void *to, const void __user *from, unsigned long n)
{
	if (unlikely(sw_pan_use_kernel_uaccess))
		return kfunc(_copy_from_user)(to, from, n);

	uint64_t saved = hmkpm_uaccess_enable();
	unsigned long ret = kfunc(__arch_copy_from_user)(to, from, n);
	hmkpm_uaccess_disable(saved);
	return ret;
}

void hmkpm_zero_user(void __user *dst, size_t size)
{
	static const uint8_t zero_chunk[256] = {0};

	if (unlikely(sw_pan_use_kernel_uaccess)) {
		while (size > 0) {
			size_t chunk = min(size, sizeof(zero_chunk));

			if (kfunc(_copy_to_user)(dst, zero_chunk, chunk) != 0)
				break;
			dst = (void __user *)((uintptr_t)dst + chunk);
			size -= chunk;
		}
		return;
	}

	if (kf___arch_clear_user) {
		uint64_t saved = hmkpm_uaccess_enable();
		kfunc(__arch_clear_user)(dst, size);
		hmkpm_uaccess_disable(saved);
		return;
	}

	uint64_t saved = hmkpm_uaccess_enable();
	while (size > 0) {
		size_t chunk = min(size, sizeof(zero_chunk));

		if (kfunc(__arch_copy_to_user)(dst, zero_chunk, chunk) != 0)
			break;
		dst = (void __user *)((uintptr_t)dst + chunk);
		size -= chunk;
	}
	hmkpm_uaccess_disable(saved);
}
