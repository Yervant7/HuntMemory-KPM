// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2026 Yervant7
 *
 * HuntMemory-KPM (HMKPM) - Process Memory I/O (Single, Batch, V2P) & Cache Coherency
 */

#include <hmkpm_internal.h>

/*
 * Synchronize D-cache to PoU and invalidate I-cache across the Inner Shareable
 * domain after writing to an EL0-executable page via the kernel linear map.
 * Respects ARMv8.2+ CTR_EL0.IDC (bit 28) and CTR_EL0.DIC (bit 29) hints.
 */
static inline void hmkpm_sync_icache_kva(const void *kva, size_t len)
{
	uint64_t ctr = 0;
	bool idc;
	bool dic;

	if (len == 0)
		return;

	asm volatile("mrs %0, ctr_el0" : "=r"(ctr));
	idc = ((ctr >> 28) & 1ULL) != 0;
	dic = ((ctr >> 29) & 1ULL) != 0;

	if (!idc) {
		uint64_t dline = 4ULL << ((ctr >> 16) & 0xFULL);
		uintptr_t addr;
		uintptr_t end;

		if (dline < 16)
			dline = 16;

		addr = (uintptr_t)kva & ~(uintptr_t)(dline - 1);
		end = (uintptr_t)kva + len;

		for (; addr < end; addr += dline)
			asm volatile("dc cvau, %0" :: "r"(addr) : "memory");
	}

	asm volatile("dsb ish" ::: "memory");

	if (!dic) {
		asm volatile("ic ialluis\n"
			     "dsb ish\n" ::: "memory");
	}

	asm volatile("isb" ::: "memory");
}

static __noinline ssize_t pgt_rw_mm(struct mm_struct *mm, uint64_t remote_va, size_t len,
				    void __user *local_buf, bool is_write)
{
	ssize_t total = 0;
	uint64_t pgd = 0;
	uint8_t bounce[HMKPM_BOUNCE_SIZE];
	unsigned int iters = 0;

	if (!mm)
		return -ESRCH;

	if (mm_struct_offset.pgd_offset < 0)
		return -EINVAL;

	/* In lockless mode, disallow writes to prevent concurrent mapping corruption */
	if (is_write && hmkpm_is_lockless())
		return -EOPNOTSUPP;

	if (hmkpm_copy_from_kernel_nofault(&pgd,
					   (const void *)((uintptr_t)mm + mm_struct_offset.pgd_offset),
					   sizeof(pgd)) != 0 || !pgd)
		return -EFAULT;

	/* Chunked read/write loop with stack-safe bounce buffer */
	while (len > 0) {
		unsigned long page_off = remote_va & (pgt_page_size - 1);
		size_t page_left = (size_t)(pgt_page_size - page_off);
		size_t chunk = min(len, page_left);
		struct pgt_walk_result walk;
		void *tkva;
		long rw_rc;

		chunk = min(chunk, (size_t)HMKPM_BOUNCE_SIZE);

		if (is_write) {
			/* Copy from caller userspace into bounce buffer outside target lock */
			unsigned long not_copied = hmkpm_copy_from_user(bounce, local_buf, chunk);
			if (not_copied) {
				if (not_copied == chunk) {
					if (total > 0)
						break;
					return -EFAULT;
				}
				chunk -= not_copied;
			}
		}

		/* Lock target mm for page table resolution and nofault in-kernel copy */
		hmkpm_mmap_read_lock(mm);

		if (!pgt_walk_va(pgd, remote_va, is_write, &walk)) {
			hmkpm_mmap_read_unlock(mm);
			if (total > 0)
				break;
			return -EFAULT;
		}

		tkva = (void *)pgt_phys_to_virt(walk.pa);

		if (is_write) {
			rw_rc = hmkpm_copy_to_kernel_nofault(tkva, bounce, chunk);
			if (likely(rw_rc == 0) && unlikely(walk.is_exec_user))
				hmkpm_sync_icache_kva(tkva, chunk);
		} else {
			rw_rc = hmkpm_copy_from_kernel_nofault(bounce, tkva, chunk);
		}

		hmkpm_mmap_read_unlock(mm);

		if (unlikely(rw_rc != 0)) {
			if (total > 0)
				break;
			return -EFAULT;
		}

		if (!is_write) {
			/* Copy from bounce buffer to caller userspace outside target lock */
			unsigned long not_copied = hmkpm_copy_to_user(local_buf, bounce, chunk);
			if (not_copied) {
				size_t copied = chunk - not_copied;
				total += (ssize_t)copied;
				break;
			}
		}

		total += (ssize_t)chunk;
		local_buf = (void __user *)((uintptr_t)local_buf + chunk);
		remote_va += chunk;
		len -= chunk;

		if ((++iters & 63U) == 0)
			hmkpm_cond_resched();
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

	ret = pgt_rw_mm(mm, remote_va, len, local_buf, is_write);

	kfunc(mmput)(mm);
	return ret;
}

/*
 * Fast coalesced read path for contiguous runs of small single-page READ_BATCH
 * entries. Holds target mmap_read_lock once for the whole group (with a 1-entry
 * page/block translation cache) and copies the combined transfer buffer to caller
 * userspace strictly outside the target lock to preserve deadlock safety.
 *
 * Marked __noinline so its local buffer does not stack on top of pgt_rw_mm().
 */
static __noinline int hmkpm_batch_read_group(struct mm_struct *mm, uint64_t pgd,
					     struct hmkpm_batch_entry *entries,
					     uint32_t count, size_t total_bytes,
					     void __user *dst_user)
{
	uint8_t cbuf[HMKPM_BATCH_COALESCE_BUF_SIZE];
	struct hmkpm_pt_cache cache;
	size_t local_off = 0;
	uint32_t k;

	if (total_bytes > sizeof(cbuf))
		return -EINVAL;

	hmkpm_pt_cache_init(&cache);
	hmkpm_mmap_read_lock(mm);

	for (k = 0; k < count; ++k) {
		uint64_t va = pgt_untag_user_va(entries[k].addr);
		size_t sz = (size_t)entries[k].size;
		uint64_t pa = 0;

		if (sz == 0)
			continue;

		if (hmkpm_pt_cache_translate(&cache, pgd, va, &pa) &&
		    hmkpm_copy_from_kernel_nofault(cbuf + local_off,
						   (const void *)pgt_phys_to_virt(pa),
						   sz) == 0) {
			entries[k].size = (uint64_t)sz;
		} else {
			entries[k].size = 0;
			hmkpm_memzero(cbuf + local_off, sz);
		}

		local_off += sz;
	}

	hmkpm_mmap_read_unlock(mm);

	if (hmkpm_copy_to_user(dst_user, cbuf, total_bytes) != 0)
		return -EFAULT;

	return 0;
}

static inline bool hmkpm_batch_entry_coalescable(const struct hmkpm_batch_entry *e)
{
	uint64_t va;
	uint64_t sz = e->size;

	if (sz == 0 || sz > HMKPM_BATCH_COALESCE_MAX_ENTRY)
		return false;

	va = pgt_untag_user_va(e->addr);
	if (va > U64_MAX - sz)
		return false;

	return ((va & (pgt_page_size - 1)) + sz) <= pgt_page_size;
}

void hmkpm_handle_single(hook_fargs3_t *args, void __user *user_ptr, uint64_t total_len, uint64_t magic)
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

	if (req.pid <= 0) {
		args->ret = (uint64_t)(long)-EINVAL;
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

	req.addr = pgt_untag_user_va(req.addr);

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

void hmkpm_handle_batch(hook_fargs3_t *args, void __user *user_ptr, uint64_t total_len, uint64_t magic)
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
	uint64_t pgd = 0;

	if (total_len < HMKPM_BATCH_HDR_SIZE) {
		rc = -EINVAL;
		goto out;
	}

	if (hmkpm_copy_from_user(&hdr, user_ptr, HMKPM_BATCH_HDR_SIZE) != 0) {
		rc = -EFAULT;
		goto out;
	}

	/* Fail fast on WRITE_BATCH in lockless mode, matching single WRITE semantics */
	if (write_op && hmkpm_is_lockless()) {
		rc = -EOPNOTSUPP;
		goto out;
	}

	if (hdr.pid <= 0) {
		rc = -EINVAL;
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

	data_start = entries_end;

	while (done < hdr.count) {
		uint32_t chunk_count = hdr.count - done;
		uint64_t chunk_bytes;
		void __user *entry_src;
		uint32_t i = 0;

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

		while (i < chunk_count) {
			struct hmkpm_batch_entry *e = &chunk[i];
			uint64_t req_size = e->size;
			uint64_t untagged_addr;
			void __user *data_ptr;
			ssize_t ret;

			if (req_size == 0) {
				i++;
				continue;
			}

			if (req_size > HMKPM_MAX_ENTRY_SIZE) {
				rc = -E2BIG;
				goto out_mm;
			}

			if (req_size > hdr.data_total - data_off) {
				rc = -EINVAL;
				goto out_mm;
			}

			/* Fast coalesced path for contiguous small single-page READ entries */
			if (!write_op && hmkpm_batch_entry_coalescable(e)) {
				uint32_t group_end = i;
				size_t group_bytes = 0;

				while (group_end < chunk_count) {
					struct hmkpm_batch_entry *ge = &chunk[group_end];
					uint64_t gsz = ge->size;

					if (gsz == 0) {
						group_end++;
						continue;
					}
					if (!hmkpm_batch_entry_coalescable(ge))
						break;
					if (gsz > hdr.data_total - (data_off + group_bytes))
						break;
					if (group_bytes + (size_t)gsz > HMKPM_BATCH_COALESCE_BUF_SIZE)
						break;

					group_bytes += (size_t)gsz;
					group_end++;
				}

				if (group_bytes > 0) {
					data_ptr = (void __user *)((uint8_t __user *)user_ptr +
								   data_start + data_off);
					rc = hmkpm_batch_read_group(mm, pgd, &chunk[i],
								    group_end - i, group_bytes,
								    data_ptr);
					if (rc != 0)
						goto out_mm;

					data_off += (uint64_t)group_bytes;
					i = group_end;
					continue;
				}
			}

			/* Preserve caller's e->addr untouched when returning chunk metadata */
			untagged_addr = pgt_untag_user_va(e->addr);
			data_ptr = (void __user *)((uint8_t __user *)user_ptr + data_start + data_off);

			if (untagged_addr > U64_MAX - req_size) {
				e->size = 0;
				if (!write_op)
					hmkpm_zero_user(data_ptr, req_size);
				data_off += req_size;
				i++;
				continue;
			}

			ret = pgt_rw_mm(mm, untagged_addr, req_size, data_ptr, write_op);
			if (ret < 0) {
				e->size = 0;
				if (!write_op)
					hmkpm_zero_user(data_ptr, req_size);
			} else if ((uint64_t)ret < req_size) {
				e->size = (uint64_t)ret;
				if (!write_op)
					hmkpm_zero_user((void __user *)((uintptr_t)data_ptr + ret),
							req_size - (uint64_t)ret);
			} else {
				e->size = req_size;
			}

			/* Always advance by requested size to maintain strict buffer alignment */
			data_off += req_size;
			i++;
		}

		/* Return chunk with actual transferred sizes of each entry to userspace */
		if (hmkpm_copy_to_user(entry_src, chunk, chunk_bytes) != 0) {
			rc = -EFAULT;
			goto out_mm;
		}

		done += chunk_count;
		hmkpm_cond_resched();
	}

	if (unlikely(data_off != hdr.data_total)) {
		rc = -EINVAL;
		goto out_mm;
	}

out_mm:
	if (mm) {
		kfunc(mmput)(mm);
		mm = NULL;
	}

out:
	args->ret = (uint64_t)(long)rc;
}

void hmkpm_handle_v2p_batch(hook_fargs3_t *args, void __user *user_ptr, uint64_t total_len)
{
	struct hmkpm_v2p_hdr hdr;
	struct hmkpm_v2p_entry chunk[HMKPM_V2P_CHUNK_ENTRIES];
	uint64_t entries_bytes;
	uint64_t total_req_bytes;
	uint32_t done = 0;
	int rc = 0;
	struct task_struct *task = NULL;
	struct mm_struct *mm = NULL;
	uint64_t pgd = 0;

	if (total_len < HMKPM_V2P_HDR_SIZE) {
		rc = -EINVAL;
		goto out;
	}

	if (hmkpm_copy_from_user(&hdr, user_ptr, HMKPM_V2P_HDR_SIZE) != 0) {
		rc = -EFAULT;
		goto out;
	}

	if (hdr.pid <= 0) {
		rc = -EINVAL;
		goto out;
	}

	if (hdr.count == 0) {
		rc = 0;
		goto out;
	}

	if (hdr.count > HMKPM_MAX_V2P_ENTRIES) {
		rc = -E2BIG;
		goto out;
	}

	entries_bytes = (uint64_t)hdr.count * HMKPM_V2P_ENTRY_SIZE;
	if (entries_bytes > U64_MAX - HMKPM_V2P_HDR_SIZE) {
		rc = -E2BIG;
		goto out;
	}

	total_req_bytes = HMKPM_V2P_HDR_SIZE + entries_bytes;
	if (total_len < total_req_bytes) {
		rc = -EINVAL;
		goto out;
	}

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

	while (done < hdr.count) {
		uint32_t chunk_count = hdr.count - done;
		uint64_t chunk_bytes;
		void __user *entry_ptr;
		uint32_t i;

		if (chunk_count > HMKPM_V2P_CHUNK_ENTRIES)
			chunk_count = HMKPM_V2P_CHUNK_ENTRIES;

		chunk_bytes = (uint64_t)chunk_count * HMKPM_V2P_ENTRY_SIZE;
		entry_ptr = (void __user *)((uint8_t __user *)user_ptr +
					    HMKPM_V2P_HDR_SIZE +
					    (uint64_t)done * HMKPM_V2P_ENTRY_SIZE);

		if (hmkpm_copy_from_user((void *)chunk, entry_ptr, chunk_bytes) != 0) {
			rc = -EFAULT;
			goto out_mm;
		}

		hmkpm_mmap_read_lock(mm);
		for (i = 0; i < chunk_count; ++i) {
			struct hmkpm_v2p_entry *e = &chunk[i];
			uint32_t flags = 0;
			uint32_t page_sz = 0;

			e->pa = pgt_pgtable_inspect(pgd, e->va, &flags, &page_sz);
			e->flags = flags;
			e->page_size = page_sz;
		}
		hmkpm_mmap_read_unlock(mm);

		if (hmkpm_copy_to_user(entry_ptr, chunk, chunk_bytes) != 0) {
			rc = -EFAULT;
			goto out_mm;
		}

		done += chunk_count;
		hmkpm_cond_resched();
	}

out_mm:
	if (mm) {
		kfunc(mmput)(mm);
		mm = NULL;
	}

out:
	args->ret = (uint64_t)(long)rc;
}

static inline bool hmkpm_va_add_s64(uint64_t va, int64_t off, uint64_t *out)
{
	if (off >= 0) {
		uint64_t uoff = (uint64_t)off;

		if (va > U64_MAX - uoff)
			return false;
		*out = va + uoff;
		return true;
	} else {
		/* Negate in unsigned space to avoid UB on INT64_MIN */
		uint64_t mag = 0ULL - (uint64_t)off;

		if (va < mag)
			return false;
		*out = va - mag;
		return true;
	}
}

static __noinline int hmkpm_chain_exec_one(struct mm_struct *mm, uint64_t pgd,
					   struct hmkpm_chain_req *req,
					   const int64_t *offsets,
					   void __user *data_dst)
{
	struct hmkpm_pt_cache cache;
	uint32_t orig_read_size = req->read_size;
	bool deref_last = (req->flags & HMKPM_CHAIN_FLAG_DEREF_LAST) != 0;
	bool ptr32 = (req->flags & HMKPM_CHAIN_FLAG_PTR32) != 0;
	size_t ptr_sz = ptr32 ? 4U : 8U;
	uint64_t va = pgt_untag_user_va(req->base_va);
	uint16_t hops = 0;

	req->resolved_va = 0;
	req->hops_done = 0;
	req->read_size = 0;
	req->status = HMKPM_CHAIN_STATUS_OK;

	hmkpm_pt_cache_init(&cache);
	hmkpm_mmap_read_lock(mm);

	if (req->depth == 0) {
		if (va == 0) {
			req->status = HMKPM_CHAIN_STATUS_FAULT_HOP;
			req->resolved_va = 0;
			req->hops_done = 0;
			goto out_unlock_zero;
		}
		if (deref_last) {
			uint8_t ptr_buf[8];
			uint64_t next_va;

			if (!hmkpm_read_locked_cached(&cache, pgd, va, ptr_buf, ptr_sz)) {
				req->status = HMKPM_CHAIN_STATUS_FAULT_HOP;
				req->resolved_va = va;
				req->hops_done = 0;
				goto out_unlock_zero;
			}
			next_va = ptr32 ? (uint64_t)hmkpm_get_unaligned_le32(ptr_buf) :
					  hmkpm_get_unaligned_le64(ptr_buf);
			va = pgt_untag_user_va(next_va);
			if (va == 0) {
				req->status = HMKPM_CHAIN_STATUS_FAULT_HOP;
				req->resolved_va = 0;
				req->hops_done = 0;
				goto out_unlock_zero;
			}
		}
	} else {
		uint32_t h;

		for (h = 0; h < req->depth; h++) {
			bool do_deref = (h + 1 < req->depth) || deref_last;

			if (va == 0) {
				req->status = HMKPM_CHAIN_STATUS_FAULT_HOP;
				req->resolved_va = 0;
				req->hops_done = hops;
				goto out_unlock_zero;
			}

			if (!hmkpm_va_add_s64(va, offsets[h], &va)) {
				req->status = HMKPM_CHAIN_STATUS_FAULT_HOP;
				req->resolved_va = 0;
				req->hops_done = hops;
				goto out_unlock_zero;
			}

			if (do_deref) {
				uint8_t ptr_buf[8];
				uint64_t next_va;

				if (va == 0 ||
				    !hmkpm_read_locked_cached(&cache, pgd, va, ptr_buf, ptr_sz)) {
					req->status = HMKPM_CHAIN_STATUS_FAULT_HOP;
					req->resolved_va = va;
					req->hops_done = hops;
					goto out_unlock_zero;
				}
				next_va = ptr32 ? (uint64_t)hmkpm_get_unaligned_le32(ptr_buf) :
						  hmkpm_get_unaligned_le64(ptr_buf);
				va = pgt_untag_user_va(next_va);
			}

			hops = (uint16_t)(h + 1);

			if (do_deref && va == 0) {
				req->status = HMKPM_CHAIN_STATUS_FAULT_HOP;
				req->resolved_va = 0;
				req->hops_done = hops;
				goto out_unlock_zero;
			}
		}
	}

	if (va == 0) {
		req->status = HMKPM_CHAIN_STATUS_FAULT_HOP;
		req->resolved_va = 0;
		req->hops_done = hops;
		goto out_unlock_zero;
	}

	req->resolved_va = va;
	req->hops_done = hops;

	if (orig_read_size == 0) {
		hmkpm_mmap_read_unlock(mm);
		req->status = HMKPM_CHAIN_STATUS_OK;
		return 0;
	}

	if (va > U64_MAX - (uint64_t)orig_read_size) {
		req->status = HMKPM_CHAIN_STATUS_FAULT_DATA;
		goto out_unlock_zero;
	}

	if (orig_read_size <= 512U) {
		uint8_t small_buf[512];
		bool ok = hmkpm_read_locked_cached(&cache, pgd, va, small_buf, orig_read_size);

		hmkpm_mmap_read_unlock(mm);

		if (!ok) {
			req->status = HMKPM_CHAIN_STATUS_FAULT_DATA;
			hmkpm_zero_user(data_dst, orig_read_size);
			return 0;
		}

		if (hmkpm_copy_to_user(data_dst, small_buf, orig_read_size) != 0)
			return -EFAULT;

		req->status = HMKPM_CHAIN_STATUS_OK;
		req->read_size = orig_read_size;
		return 0;
	}

	/* Multi-page or > 512-byte read fallback outside lock */
	hmkpm_mmap_read_unlock(mm);

	{
		ssize_t rd = pgt_rw_mm(mm, va, orig_read_size, data_dst, false);

		if (rd < 0) {
			req->status = HMKPM_CHAIN_STATUS_FAULT_DATA;
			req->read_size = 0;
			hmkpm_zero_user(data_dst, orig_read_size);
		} else if ((uint32_t)rd < orig_read_size) {
			req->status = HMKPM_CHAIN_STATUS_FAULT_DATA;
			req->read_size = (uint32_t)rd;
			hmkpm_zero_user((void __user *)((uint8_t __user *)data_dst + rd),
					orig_read_size - (uint32_t)rd);
		} else {
			req->status = HMKPM_CHAIN_STATUS_OK;
			req->read_size = orig_read_size;
		}
	}
	return 0;

out_unlock_zero:
	hmkpm_mmap_read_unlock(mm);
	if (orig_read_size > 0)
		hmkpm_zero_user(data_dst, orig_read_size);
	return 0;
}

void hmkpm_handle_read_chain(hook_fargs3_t *args, void __user *user_ptr, uint64_t total_len)
{
	struct hmkpm_chain_hdr hdr;
	struct hmkpm_chain_req chunk[HMKPM_CHAIN_CHUNK_REQS];
	int64_t off_buf[HMKPM_MAX_CHAIN_DEPTH];
	uint64_t reqs_bytes;
	uint64_t offsets_start;
	uint64_t offsets_bytes;
	uint64_t data_start;
	uint64_t expected_total;
	uint64_t off_cursor = 0;
	uint64_t data_cursor = 0;
	uint32_t done = 0;
	int rc = 0;
	struct task_struct *task = NULL;
	struct mm_struct *mm = NULL;
	uint64_t pgd = 0;

	if (total_len < HMKPM_CHAIN_HDR_SIZE) {
		rc = -EINVAL;
		goto out;
	}

	if (hmkpm_copy_from_user(&hdr, user_ptr, HMKPM_CHAIN_HDR_SIZE) != 0) {
		rc = -EFAULT;
		goto out;
	}

	if (hdr.pid <= 0) {
		rc = -EINVAL;
		goto out;
	}

	if (hdr.count == 0) {
		if (hdr.total_offsets != 0 || hdr.data_total != 0)
			rc = -EINVAL;
		goto out;
	}

	if (hdr.count > HMKPM_MAX_CHAIN_COUNT ||
	    hdr.total_offsets > HMKPM_MAX_CHAIN_TOTAL_OFFSETS ||
	    hdr.data_total > HMKPM_MAX_CHAIN_DATA_TOTAL) {
		rc = -E2BIG;
		goto out;
	}

	reqs_bytes = (uint64_t)hdr.count * HMKPM_CHAIN_REQ_SIZE;
	offsets_start = HMKPM_CHAIN_HDR_SIZE + reqs_bytes;
	offsets_bytes = hdr.total_offsets * sizeof(int64_t);
	if (offsets_bytes > U64_MAX - offsets_start) {
		rc = -E2BIG;
		goto out;
	}
	data_start = offsets_start + offsets_bytes;
	if (hdr.data_total > U64_MAX - data_start) {
		rc = -E2BIG;
		goto out;
	}
	expected_total = data_start + hdr.data_total;
	if (total_len < expected_total) {
		rc = -EINVAL;
		goto out;
	}

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

	while (done < hdr.count) {
		uint32_t chunk_count = hdr.count - done;
		uint64_t chunk_bytes;
		void __user *req_ptr;
		uint32_t i;

		if (chunk_count > HMKPM_CHAIN_CHUNK_REQS)
			chunk_count = HMKPM_CHAIN_CHUNK_REQS;

		chunk_bytes = (uint64_t)chunk_count * HMKPM_CHAIN_REQ_SIZE;
		req_ptr = (void __user *)((uint8_t __user *)user_ptr +
					  HMKPM_CHAIN_HDR_SIZE +
					  (uint64_t)done * HMKPM_CHAIN_REQ_SIZE);

		if (hmkpm_copy_from_user(chunk, req_ptr, chunk_bytes) != 0) {
			rc = -EFAULT;
			goto out_mm;
		}

		for (i = 0; i < chunk_count; i++) {
			struct hmkpm_chain_req *r = &chunk[i];
			uint32_t depth = r->depth;
			uint32_t orig_read_size = r->read_size;
			void __user *data_dst;

			if (depth > HMKPM_MAX_CHAIN_DEPTH ||
			    orig_read_size > HMKPM_MAX_CHAIN_READ_SIZE ||
			    (uint64_t)depth > hdr.total_offsets - off_cursor ||
			    (uint64_t)orig_read_size > hdr.data_total - data_cursor) {
				rc = -EINVAL;
				goto out_mm;
			}

			if (depth > 0) {
				void __user *off_src = (void __user *)((uint8_t __user *)user_ptr +
								       offsets_start +
								       off_cursor * sizeof(int64_t));
				if (hmkpm_copy_from_user(off_buf, off_src,
							 (uint64_t)depth * sizeof(int64_t)) != 0) {
					rc = -EFAULT;
					goto out_mm;
				}
			}

			data_dst = (void __user *)((uint8_t __user *)user_ptr +
						   data_start + data_cursor);

			if (r->flags & ~HMKPM_CHAIN_FLAGS_MASK) {
				r->status = HMKPM_CHAIN_STATUS_BAD_REQ;
				r->resolved_va = 0;
				r->hops_done = 0;
				r->read_size = 0;
				if (orig_read_size > 0)
					hmkpm_zero_user(data_dst, orig_read_size);
			} else {
				rc = hmkpm_chain_exec_one(mm, pgd, r, off_buf, data_dst);
				if (rc != 0)
					goto out_mm;
			}

			off_cursor += depth;
			data_cursor += orig_read_size;
		}

		if (hmkpm_copy_to_user(req_ptr, chunk, chunk_bytes) != 0) {
			rc = -EFAULT;
			goto out_mm;
		}

		done += chunk_count;
		hmkpm_cond_resched();
	}

	if (off_cursor != hdr.total_offsets || data_cursor != hdr.data_total)
		rc = -EINVAL;

out_mm:
	if (mm) {
		kfunc(mmput)(mm);
		mm = NULL;
	}

out:
	args->ret = (uint64_t)(long)rc;
}
