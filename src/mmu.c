// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2026 Yervant7
 *
 * HuntMemory-KPM (HMKPM) - ARM64 Hardware Page Table Walker & MMU Geometry
 */

#include <hmkpm_internal.h>

uint64_t pgt_va_bits;
uint64_t pgt_phys_offset;
uint64_t pgt_page_offset;
uint64_t pgt_linear_voffset;
uint64_t pgt_page_shift;
uint64_t pgt_page_size;
uint64_t pgt_pgd_align_mask;
uint64_t pgt_pgd_size;
uint64_t pgt_page_level;
uint64_t pgt_user_limit;
uint64_t pgt_high_memory;
bool pgt_tbi0;

/* Bitmask of MAIR_EL1 attribute indices representing Normal memory (non-Device) */
static uint8_t pgt_normal_attr_mask;

static inline uint64_t pgt_desc_to_phys(uint64_t desc)
{
	uint64_t addr_mask =
		(((1ULL << (48 - pgt_page_shift)) - 1) << pgt_page_shift);
	return desc & addr_mask;
}

/*
 * Block descriptors are allowed at levels 1 and 2 for 4KB granule,
 * and only at level 2 for 16KB granule.
 */
static inline bool pgt_block_allowed(int lv)
{
	if (pgt_page_shift == 14)
		return (lv == 2);
	return (lv == 1 || lv == 2);
}

static inline bool pgt_attr_is_normal(uint64_t desc)
{
	unsigned int idx = (unsigned int)((desc >> 2) & 7ULL);

	return (pgt_normal_attr_mask & (uint8_t)(1U << idx)) != 0;
}

static inline bool pgt_decode_leaf(uint64_t desc, uint64_t va, uint64_t leaf_size,
				   bool is_block, bool is_write,
				   bool table_ro, bool table_no_user, bool table_uxn,
				   struct pgt_walk_result *out)
{
	uint64_t leaf_mask = leaf_size - 1;
	uint64_t base;
	uint32_t flags = HMKPM_PAGE_FLAG_PRESENT;
	bool is_ro;

	if (out)
		out->span_size = leaf_size;

	/* Reject non-EL0 or Device/MMIO descriptors to prevent SError */
	if (table_no_user || !(desc & (1ULL << 6)))
		return false;

	if (!pgt_attr_is_normal(desc))
		return false;

	/*
	 * Bit 7 is PTE_RDONLY (AP[2]); bit 51 is PTE_DBM/PTE_WRITE.
	 * Under ARMv8.1+ Hardware DBM, writable pages may carry both bits.
	 */
	is_ro = table_ro || ((desc & (1ULL << 7)) && !(desc & (1ULL << 51)));
	if (is_ro)
		flags |= HMKPM_PAGE_FLAG_RO;

	if (is_write && is_ro)
		return false;

	if (is_block)
		flags |= HMKPM_PAGE_FLAG_BLOCK;

	if (desc & ((1ULL << 55) | (1ULL << 51)))
		flags |= HMKPM_PAGE_FLAG_DIRTY;

	base = pgt_desc_to_phys(desc);
	if (base & leaf_mask)
		return false;

	if (validate_phys_range(base, leaf_size))
		return false;

	if (out) {
		out->pa = base | (va & leaf_mask);
		out->flags = flags;
		out->is_exec_user = !(table_uxn || (desc & (1ULL << 54)));
	}
	return true;
}

bool pgt_walk_va(uint64_t pgd, uint64_t va, bool is_write, struct pgt_walk_result *out)
{
	uint64_t table_va;
	uint64_t pxd_bits;
	uint64_t pxd_ptrs;
	int64_t start;
	int64_t lv;
	bool table_ro = false;
	bool table_no_user = false;
	bool table_uxn = false;

	if (out) {
		out->pa = 0;
		out->span_size = pgt_page_size;
		out->flags = 0;
		out->is_exec_user = false;
	}

	if (!pgd)
		return false;

	if (pgd & pgt_pgd_align_mask)
		return false;

	if (validate_virt_range(pgd, pgt_pgd_size))
		return false;

	va = pgt_untag_user_va(va);

	if (va >> pgt_va_bits)
		return false;

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
		uint64_t cur_table_size = (lv == start) ? pgt_pgd_size : pgt_page_size;

		if (validate_virt_range(table_va, cur_table_size))
			return false;

		pxd_shift = (pgt_page_shift - 3) * (4 - lv) + 3;

		if (pxd_shift >= pgt_va_bits)
			return false;

		pxd_index = (va >> pxd_shift) & (pxd_ptrs - 1);

		/*
		 * At the starting level, the root table may not use all indices.
		 * Prevents accepting out-of-range VAs at reduced VA widths.
		 */
		top_bits = pgt_va_bits - pxd_shift;
		if (top_bits > pxd_bits)
			top_bits = pxd_bits;

		if (top_bits == 0)
			return false;

		if (pxd_index >= (1ULL << top_bits))
			return false;

		entry_va = table_va + pxd_index * 8;

		if (hmkpm_copy_from_kernel_nofault(&desc, (const void *)entry_va, sizeof(desc)) != 0)
			return false;

		type = desc & 3ULL;

		/*
		 * ARM64 Stage-1 descriptor types:
		 *   0b00 = invalid
		 *   0b10 = invalid/reserved
		 *   0b01 = block (L1/L2)
		 *   0b11 = table (L0-L2) or page (L3)
		 */
		if (type == 0ULL || type == 2ULL) {
			if (out && pxd_shift < 64)
				out->span_size = 1ULL << pxd_shift;
			return false;
		}

		/* Level 3 page descriptor */
		if (lv == 3) {
			if (type != 3ULL)
				return false;

			return pgt_decode_leaf(desc, va, pgt_page_size, false, is_write,
					       table_ro, table_no_user, table_uxn, out);
		}

		/* Block descriptor (L1/L2 hugepage) */
		if (type == 1ULL) {
			uint64_t block_bits;

			if (!pgt_block_allowed((int)lv))
				return false;

			block_bits = (uint64_t)(3 - lv) * pxd_bits + pgt_page_shift;
			if (block_bits >= 64)
				return false;

			return pgt_decode_leaf(desc, va, 1ULL << block_bits, true, is_write,
					       table_ro, table_no_user, table_uxn, out);
		}

		/*
		 * Intermediate table descriptor attributes:
		 *   Bit 62 = APTable[2] (PTATTR_RDONLY): read-only for subsequent levels
		 *   Bit 61 = APTable[1] (PTATTR_USER):   EL0 access disallowed
		 *   Bit 60 = UXNTable   (PTATTR_XN):     EL0 execute disallowed
		 */
		if (desc & (1ULL << 62)) {
			table_ro = true;
			if (is_write) {
				if (out && pxd_shift < 64)
					out->span_size = 1ULL << pxd_shift;
				return false;
			}
		}
		if (desc & (1ULL << 61)) {
			table_no_user = true;
			if (out && pxd_shift < 64)
				out->span_size = 1ULL << pxd_shift;
			return false;
		}
		if (desc & (1ULL << 60))
			table_uxn = true;

		uint64_t next_pa = pgt_desc_to_phys(desc);
		if (next_pa & (pgt_page_size - 1))
			return false;

		if (validate_phys_range(next_pa, pgt_page_size))
			return false;

		table_va = pgt_phys_to_virt(next_pa);
	}

	return false;
}

uint64_t pgt_pgtable_to_tkpa(uint64_t pgd, uint64_t va, bool is_write)
{
	struct pgt_walk_result res;

	if (!pgt_walk_va(pgd, va, is_write, &res))
		return 0;

	return res.pa;
}

uint64_t pgt_pgtable_inspect(uint64_t pgd, uint64_t va, uint32_t *out_flags, uint32_t *out_page_size)
{
	struct pgt_walk_result res;

	if (out_flags)
		*out_flags = 0;
	if (out_page_size)
		*out_page_size = 0;

	if (!pgt_walk_va(pgd, va, false, &res))
		return 0;

	if (out_flags)
		*out_flags = res.flags;
	if (out_page_size)
		*out_page_size = (uint32_t)res.span_size;

	return res.pa;
}

#define HMKPM_REGION_PERM_MASK \
	(HMKPM_REGION_FLAG_READ | HMKPM_REGION_FLAG_WRITE | HMKPM_REGION_FLAG_EXEC)

_Static_assert(__builtin_offsetof(struct hmkpm_enum_hdr, next_va) ==
	       __builtin_offsetof(struct hmkpm_enum_hdr, regions_found) + sizeof(uint32_t),
	       "hmkpm_enum_hdr output fields must remain contiguous");
_Static_assert(__builtin_offsetof(struct hmkpm_enum_hdr, next_va) + sizeof(uint64_t) ==
	       sizeof(struct hmkpm_enum_hdr),
	       "hmkpm_enum_hdr output tail size mismatch");

struct hmkpm_enum_state {
	struct hmkpm_region_entry out_chunk[HMKPM_ENUM_CHUNK_ENTRIES];
	uint32_t chunk_count;
	uint32_t total_written;
	uint32_t regions_emitted;
	uint32_t max_regions;
	bool cur_valid;
	uint64_t cur_start;
	uint64_t cur_end;
	uint32_t cur_flags;
	bool limit_reached;
	uint64_t next_va;
};

static inline void hmkpm_enum_commit_cur(struct hmkpm_enum_state *st)
{
	if (st->chunk_count < HMKPM_ENUM_CHUNK_ENTRIES) {
		struct hmkpm_region_entry *dst = &st->out_chunk[st->chunk_count++];

		dst->start_va = st->cur_start;
		dst->size = st->cur_end - st->cur_start;
		dst->flags = st->cur_flags;
		dst->_pad = 0;
	}
	st->regions_emitted++;
	st->cur_valid = false;
}

static inline bool hmkpm_enum_emit_span(struct hmkpm_enum_state *st,
					uint64_t span_start, uint64_t span_end,
					uint32_t rflags)
{
	if (st->cur_valid) {
		if (span_start == st->cur_end &&
		    ((st->cur_flags ^ rflags) & HMKPM_REGION_PERM_MASK) == 0) {
			st->cur_end = span_end;
			st->cur_flags |= (rflags & HMKPM_REGION_FLAG_HAS_BLOCK);
			return true;
		}

		hmkpm_enum_commit_cur(st);
		if (st->regions_emitted >= st->max_regions) {
			st->limit_reached = true;
			st->next_va = span_start;
			return false;
		}
	}

	if (st->regions_emitted >= st->max_regions) {
		st->limit_reached = true;
		st->next_va = span_start;
		return false;
	}

	st->cur_valid = true;
	st->cur_start = span_start;
	st->cur_end = span_end;
	st->cur_flags = rflags;
	return true;
}

static inline void hmkpm_enum_close_on_gap(struct hmkpm_enum_state *st, uint64_t skip_end)
{
	if (!st->cur_valid)
		return;

	hmkpm_enum_commit_cur(st);
	if (st->regions_emitted >= st->max_regions) {
		st->limit_reached = true;
		st->next_va = skip_end;
	}
}

static inline uint32_t hmkpm_walk_res_to_region_flags(const struct pgt_walk_result *res)
{
	uint32_t rflags = HMKPM_REGION_FLAG_READ;

	if (!(res->flags & HMKPM_PAGE_FLAG_RO))
		rflags |= HMKPM_REGION_FLAG_WRITE;
	if (res->is_exec_user)
		rflags |= HMKPM_REGION_FLAG_EXEC;
	if (res->flags & HMKPM_PAGE_FLAG_BLOCK)
		rflags |= HMKPM_REGION_FLAG_HAS_BLOCK;
	return rflags;
}

static inline bool hmkpm_enum_filter_match(uint32_t enum_flags, uint32_t rflags)
{
	if ((enum_flags & HMKPM_ENUM_FLAG_WRITABLE_ONLY) &&
	    !(rflags & HMKPM_REGION_FLAG_WRITE))
		return false;
	if ((enum_flags & HMKPM_ENUM_FLAG_EXEC_ONLY) &&
	    !(rflags & HMKPM_REGION_FLAG_EXEC))
		return false;
	return true;
}

static int hmkpm_enum_flush_chunk(void __user *user_ptr, struct hmkpm_enum_state *st)
{
	void __user *dst;
	uint64_t bytes;

	if (st->chunk_count == 0)
		return 0;

	dst = (void __user *)((uint8_t __user *)user_ptr + HMKPM_ENUM_HDR_SIZE +
			      (uint64_t)st->total_written * HMKPM_REGION_ENTRY_SIZE);
	bytes = (uint64_t)st->chunk_count * HMKPM_REGION_ENTRY_SIZE;

	if (hmkpm_copy_to_user(dst, st->out_chunk, bytes) != 0)
		return -EFAULT;

	st->total_written += st->chunk_count;
	st->chunk_count = 0;
	return 0;
}

static int hmkpm_enum_write_hdr_out(void __user *user_ptr, uint32_t regions_found,
				    uint64_t next_va)
{
	struct {
		uint32_t regions_found;
		uint64_t next_va;
	} __attribute__((packed)) out_tail;
	void __user *dst = (void __user *)((uint8_t __user *)user_ptr +
					   __builtin_offsetof(struct hmkpm_enum_hdr, regions_found));

	out_tail.regions_found = regions_found;
	out_tail.next_va = next_va;

	if (hmkpm_copy_to_user(dst, &out_tail, sizeof(out_tail)) != 0)
		return -EFAULT;

	return 0;
}

void hmkpm_handle_enum_regions(hook_fargs3_t *args, void __user *user_ptr, uint64_t total_len)
{
	struct hmkpm_enum_hdr hdr;
	struct hmkpm_enum_state st;
	uint64_t entries_bytes;
	uint64_t va_space_end;
	uint64_t raw_start;
	uint64_t raw_end;
	uint64_t start_va;
	uint64_t end_va;
	uint64_t va;
	uint64_t pxd_bits;
	uint64_t pxd_ptrs;
	int64_t start_lv;
	unsigned int iters = 0;
	int rc = 0;
	struct task_struct *task = NULL;
	struct mm_struct *mm = NULL;
	uint64_t pgd = 0;

	if (total_len < HMKPM_ENUM_HDR_SIZE) {
		rc = -EINVAL;
		goto out;
	}

	if (hmkpm_copy_from_user(&hdr, user_ptr, HMKPM_ENUM_HDR_SIZE) != 0) {
		rc = -EFAULT;
		goto out;
	}

	if (hdr.pid <= 0) {
		rc = -EINVAL;
		goto out;
	}

	if (hdr.flags & ~HMKPM_ENUM_FLAGS_MASK) {
		rc = -EINVAL;
		goto out;
	}

	if (hdr.max_regions > HMKPM_MAX_ENUM_REGIONS) {
		rc = -E2BIG;
		goto out;
	}

	entries_bytes = (uint64_t)hdr.max_regions * HMKPM_REGION_ENTRY_SIZE;
	if (entries_bytes > U64_MAX - HMKPM_ENUM_HDR_SIZE) {
		rc = -E2BIG;
		goto out;
	}

	if (total_len < HMKPM_ENUM_HDR_SIZE + entries_bytes) {
		rc = -EINVAL;
		goto out;
	}

	va_space_end = 1ULL << pgt_va_bits;
	raw_start = pgt_untag_user_va(hdr.start_va);
	raw_end = (hdr.end_va == 0) ? va_space_end : pgt_untag_user_va(hdr.end_va);
	if (raw_end > va_space_end)
		raw_end = va_space_end;

	if (raw_start >= raw_end) {
		rc = hmkpm_enum_write_hdr_out(user_ptr, 0, 0);
		goto out;
	}

	if (hdr.max_regions == 0) {
		rc = -EINVAL;
		goto out;
	}

	start_va = raw_start & ~(pgt_page_size - 1);
	end_va = (raw_end + pgt_page_size - 1) & ~(pgt_page_size - 1);
	if (end_va == 0 || end_va > va_space_end)
		end_va = va_space_end;

	/* Obtain mm_struct for target PID */
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

	if (mm_struct_offset.pgd_offset < 0) {
		rc = -EINVAL;
		goto out_mm;
	}

	if (hmkpm_copy_from_kernel_nofault(&pgd,
					   (const void *)((uintptr_t)mm + mm_struct_offset.pgd_offset),
					   sizeof(pgd)) != 0 || !pgd) {
		rc = -EFAULT;
		goto out_mm;
	}

	if ((pgd & pgt_pgd_align_mask) || validate_virt_range(pgd, pgt_pgd_size) != 0) {
		rc = -EFAULT;
		goto out_mm;
	}

	st.chunk_count = 0;
	st.total_written = 0;
	st.regions_emitted = 0;
	st.max_regions = hdr.max_regions;
	st.cur_valid = false;
	st.cur_start = 0;
	st.cur_end = 0;
	st.cur_flags = 0;
	st.limit_reached = false;
	st.next_va = 0;

	va = start_va;
	pxd_bits = pgt_page_shift - 3;
	pxd_ptrs = 1ULL << pxd_bits;
	start_lv = 4 - (int64_t)pgt_page_level;

	while (va < end_va && !st.limit_reached) {
		uint64_t table_va = pgd;
		bool table_ro = false;
		bool table_no_user = false;
		bool table_uxn = false;
		bool reached_l3 = false;
		int64_t lv;

		hmkpm_mmap_read_lock(mm);

		for (lv = start_lv; lv < 3; lv++) {
			uint64_t pxd_shift = pxd_bits * (uint64_t)(4 - lv) + 3;
			uint64_t cur_table_size = (lv == start_lv) ? pgt_pgd_size : pgt_page_size;
			uint64_t pxd_span;
			uint64_t skip_base;
			uint64_t skip_end;
			uint64_t pxd_index;
			uint64_t top_bits;
			uint64_t desc = 0;
			uint64_t type;
			uint64_t next_pa;

			pxd_span = (pxd_shift < 64) ? (1ULL << pxd_shift) : 0;
			skip_base = (pxd_span != 0) ? (va & ~(pxd_span - 1)) : va;
			skip_end = (pxd_span != 0 && skip_base <= U64_MAX - pxd_span) ?
				   min(skip_base + pxd_span, end_va) : end_va;
			if (skip_end <= va)
				skip_end = end_va;

			if (validate_virt_range(table_va, cur_table_size) != 0 ||
			    pxd_shift >= pgt_va_bits) {
				hmkpm_enum_close_on_gap(&st, skip_end);
				va = skip_end;
				break;
			}

			top_bits = pgt_va_bits - pxd_shift;
			if (top_bits > pxd_bits)
				top_bits = pxd_bits;
			pxd_index = (va >> pxd_shift) & (pxd_ptrs - 1);

			if (top_bits == 0 || pxd_index >= (1ULL << top_bits) ||
			    hmkpm_copy_from_kernel_nofault(&desc,
							   (const void *)(table_va + pxd_index * 8),
							   sizeof(desc)) != 0) {
				hmkpm_enum_close_on_gap(&st, skip_end);
				va = skip_end;
				break;
			}

			type = desc & 3ULL;
			if (type == 0ULL || type == 2ULL) {
				hmkpm_enum_close_on_gap(&st, skip_end);
				va = skip_end;
				break;
			}

			if (type == 1ULL) {
				struct pgt_walk_result res;
				uint32_t rflags;

				if (!pgt_block_allowed((int)lv) || pxd_span == 0 ||
				    !pgt_decode_leaf(desc, va, pxd_span, true, false,
						     table_ro, table_no_user, table_uxn, &res)) {
					hmkpm_enum_close_on_gap(&st, skip_end);
					va = skip_end;
					break;
				}

				rflags = hmkpm_walk_res_to_region_flags(&res);
				if (!hmkpm_enum_filter_match(hdr.flags, rflags)) {
					hmkpm_enum_close_on_gap(&st, skip_end);
					va = skip_end;
					break;
				}

				if (hmkpm_enum_emit_span(&st, va, skip_end, rflags))
					va = skip_end;
				break;
			}

			/* Intermediate table descriptor (type == 3ULL) */
			if (desc & (1ULL << 62))
				table_ro = true;
			if (desc & (1ULL << 61))
				table_no_user = true;
			if (desc & (1ULL << 60))
				table_uxn = true;

			if (table_no_user) {
				hmkpm_enum_close_on_gap(&st, skip_end);
				va = skip_end;
				break;
			}

			next_pa = pgt_desc_to_phys(desc);
			if ((next_pa & (pgt_page_size - 1)) ||
			    validate_phys_range(next_pa, pgt_page_size) != 0) {
				hmkpm_enum_close_on_gap(&st, skip_end);
				va = skip_end;
				break;
			}

			table_va = pgt_phys_to_virt(next_pa);
			if (lv == 2)
				reached_l3 = true;
		}

		if (reached_l3 && !st.limit_reached && validate_virt_range(table_va, pgt_page_size) == 0) {
			uint64_t idx = (va >> pgt_page_shift) & (pxd_ptrs - 1);

			while (idx < pxd_ptrs && va < end_va && !st.limit_reached) {
				uint64_t desc = 0;
				uint64_t page_end = (va <= U64_MAX - pgt_page_size) ?
						    min(va + pgt_page_size, end_va) : end_va;
				struct pgt_walk_result res;
				uint32_t rflags;

				if (hmkpm_copy_from_kernel_nofault(&desc,
								   (const void *)(table_va + idx * 8),
								   sizeof(desc)) != 0 ||
				    (desc & 3ULL) != 3ULL ||
				    !pgt_decode_leaf(desc, va, pgt_page_size, false, false,
						     table_ro, table_no_user, table_uxn, &res)) {
					hmkpm_enum_close_on_gap(&st, page_end);
					va = page_end;
					idx++;
				} else {
					rflags = hmkpm_walk_res_to_region_flags(&res);
					if (!hmkpm_enum_filter_match(hdr.flags, rflags)) {
						hmkpm_enum_close_on_gap(&st, page_end);
						va = page_end;
						idx++;
					} else if (hmkpm_enum_emit_span(&st, va, page_end, rflags)) {
						va = page_end;
						idx++;
					}
				}

				if (st.chunk_count >= HMKPM_ENUM_CHUNK_ENTRIES)
					break;
			}
		}

		hmkpm_mmap_read_unlock(mm);

		if (st.chunk_count >= HMKPM_ENUM_CHUNK_ENTRIES || st.limit_reached) {
			rc = hmkpm_enum_flush_chunk(user_ptr, &st);
			if (rc != 0)
				goto out_mm;
		}

		if ((++iters & 63U) == 0)
			hmkpm_cond_resched();
	}

	if (!st.limit_reached && st.cur_valid)
		hmkpm_enum_commit_cur(&st);

	if (st.chunk_count > 0) {
		rc = hmkpm_enum_flush_chunk(user_ptr, &st);
		if (rc != 0)
			goto out_mm;
	}

	{
		uint64_t out_next_va = (st.limit_reached && st.next_va < end_va) ? st.next_va : 0;

		rc = hmkpm_enum_write_hdr_out(user_ptr, st.total_written, out_next_va);
	}

out_mm:
	if (mm) {
		kfunc(mmput)(mm);
		mm = NULL;
	}

out:
	args->ret = (uint64_t)(long)rc;
}

int pgt_pgtable_init(void)
{
	uint64_t tcr_el1;
	uint64_t mair_el1 = 0;
	uint64_t t1sz;
	uint64_t va1_bits;
	uint64_t t0sz;
	uint64_t va0_bits;
	uint64_t tg0;
	uint64_t pxd_bits;
	int64_t start;

	asm volatile("mrs %0, tcr_el1" : "=r"(tcr_el1));
	asm volatile("mrs %0, mair_el1" : "=r"(mair_el1));

	/*
	 * Classify MAIR_EL1 attribute indices:
	 *   attr[7:4] == 0x0 -> Device memory (nGnRnE/nGnRE/nGRE/GRE) -> rejected.
	 *   attr[7:4] != 0x0 with attr[3:0] != 0x0, or 0xF0 (ARMv8.5 MTE Tagged Normal) -> accepted.
	 */
	pgt_normal_attr_mask = 0;
	for (unsigned int idx = 0; idx < 8; idx++) {
		uint8_t attr = (uint8_t)((mair_el1 >> (idx * 8)) & 0xFFU);

		if ((attr & 0xF0U) != 0 && ((attr & 0x0FU) != 0 || attr == 0xF0U))
			pgt_normal_attr_mask |= (uint8_t)(1U << idx);
	}

	if (pgt_normal_attr_mask == 0) {
		hmkpm_error("No Normal memory attributes found in MAIR_EL1 (0x%llx)\n",
			    (unsigned long long)mair_el1);
		return -EINVAL;
	}

	t1sz = (tcr_el1 >> 16) & 0x3F;
	va1_bits = 64 - t1sz;
	if (va1_bits > 52 || va1_bits < 36) {
		hmkpm_error("Unsupported kernel VA bits: %llu\n", (unsigned long long)va1_bits);
		return -EINVAL;
	}

	/* TTBR0 / user VA */
	t0sz = tcr_el1 & 0x3F;
	va0_bits = 64 - t0sz;

	tg0 = (tcr_el1 >> 14) & 0x3ULL;

	if (va0_bits > 48 || va0_bits < 36) {
		hmkpm_error("Unsupported VA bits: %llu\n", (unsigned long long)va0_bits);
		return -EINVAL;
	}

	pgt_va_bits = va0_bits;
	pgt_user_limit = (1ULL << va0_bits) - 1;

	if (tg0 == 0) {
		pgt_page_shift = 12; /* 4KB */
	} else if (tg0 == 2) {
		pgt_page_shift = 14; /* 16KB */
	} else {
		hmkpm_error("Unsupported tg0: %llu\n", (unsigned long long)tg0);
		return -EINVAL;
	}

	pxd_bits = pgt_page_shift - 3;
	pgt_page_level = (va0_bits - 4) / pxd_bits;

	if (pgt_page_level != 2 && pgt_page_level != 3 && pgt_page_level != 4)
		return -EINVAL;

	start = 4 - (int64_t)pgt_page_level;
	if (start < 0 || start > 2)
		return -EINVAL;

	pgt_page_size = 1ULL << pgt_page_shift;

	/*
	 * Root page table (PGD) size and alignment calculation:
	 * Reduced-VA pre-5.4 kernels may allocate PGD smaller than a full page.
	 */
	int64_t root_lv = 4 - (int64_t)pgt_page_level;
	uint64_t root_shift = (pgt_page_shift - 3) * (4 - root_lv) + 3;

	if (pgt_va_bits > root_shift) {
		uint64_t root_bits = pgt_va_bits - root_shift;

		pgt_pgd_size = (1ULL << root_bits) * 8;
		if (pgt_pgd_size < pgt_page_size) {
			pgt_pgd_align_mask = pgt_pgd_size - 1;
		} else {
			pgt_pgd_size = pgt_page_size;
			pgt_pgd_align_mask = pgt_page_size - 1;
		}
	} else {
		pgt_pgd_size = pgt_page_size;
		pgt_pgd_align_mask = pgt_page_size - 1;
	}

	/* Kernels >= 5.4.0 standardize full-page PGD alignment on ARM64 */
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

	kv_memstart_addr = (typeof(kv_memstart_addr))hmkpm_lookup_symbol("memstart_addr");
	if (!kv_memstart_addr) {
		hmkpm_error("Failed to resolve memstart_addr\n");
		return -EFAULT;
	}
	pgt_phys_offset = kvar_val(memstart_addr);
	pgt_linear_voffset = pgt_page_offset - pgt_phys_offset;

	kv_high_memory = (typeof(kv_high_memory))hmkpm_lookup_symbol("high_memory");
	if (kv_high_memory) {
		pgt_high_memory = (uint64_t)kvar_val(high_memory);
	} else {
		pgt_high_memory = ~0ULL;
	}

	pgt_tbi0 = !!(tcr_el1 & (1ULL << 37));

	hmkpm_info("Page table config: va0_bits=%llu, shift=%llu, size=0x%llx, pgd_size=0x%llx, level=%llu, tbi0=%d, mair_norm=0x%02x\n",
		   (unsigned long long)va0_bits, (unsigned long long)pgt_page_shift,
		   (unsigned long long)pgt_page_size, (unsigned long long)pgt_pgd_size,
		   (unsigned long long)pgt_page_level, (int)pgt_tbi0,
		   (unsigned int)pgt_normal_attr_mask);
	hmkpm_info("phys_offset=0x%llx, page_offset=0x%llx, linear_voffset=0x%llx, high_mem=0x%llx, pgd_align_mask=0x%llx\n",
		   (unsigned long long)pgt_phys_offset, (unsigned long long)pgt_page_offset,
		   (unsigned long long)pgt_linear_voffset, (unsigned long long)pgt_high_memory,
		   (unsigned long long)pgt_pgd_align_mask);

	return 0;
}
