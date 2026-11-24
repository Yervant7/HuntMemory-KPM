/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026 Yervant7
 *
 * HuntMemory-KPM (HMKPM) Internal Kernel Module Header
 */

#ifndef _HMKPM_INTERNAL_H_
#define _HMKPM_INTERNAL_H_

#include <asm/current.h>
#include <barrier.h>
#include <common.h>
#include <compiler.h>
#include <hook.h>
#include <kconfig.h>
#include <kpmodule.h>
#include <kputils.h>
#include <ksyms.h>
#include <ktypes.h>
#include <linux/bitops.h>
#include <linux/err.h>
#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/mm_types.h>
#include <linux/printk.h>
#include <linux/sched.h>
#include <symbol.h>
#include <syscall.h>
#include <uapi/asm-generic/unistd.h>
#include <asm-generic/rwonce.h>

#include <hmkpm_uapi.h>

struct inode;
struct rw_semaphore;

#define U64_MAX				((u64)~0ULL)
#define HMKPM_TAG			"[HMKPM] "

#define hmkpm_info(fmt, ...)		logki(HMKPM_TAG fmt, ##__VA_ARGS__)
#define hmkpm_warn(fmt, ...)		logkw(HMKPM_TAG fmt, ##__VA_ARGS__)
#define hmkpm_error(fmt, ...)		logke(HMKPM_TAG fmt, ##__VA_ARGS__)

#ifndef min
#define min(a, b)			((a) < (b) ? (a) : (b))
#endif

/* Internal chunking & bounce buffer constants */
#define HMKPM_BOUNCE_SIZE		1024U
#define HMKPM_BATCH_CHUNK_ENTRIES	32U
#define HMKPM_BATCH_COALESCE_BUF_SIZE	512U
#define HMKPM_BATCH_COALESCE_MAX_ENTRY	256U
#define HMKPM_V2P_CHUNK_ENTRIES		64U
#define HMKPM_SCAN_MATCH_CHUNK		16U
#define HMKPM_SCAN_BUF_SIZE		512U
#define HMKPM_CHAIN_CHUNK_REQS		16U
#define HMKPM_REFINE_CHUNK_BYTES	256U /* 32 VAs or 16 (va, value) pairs */
#define HMKPM_ENUM_CHUNK_ENTRIES	32U

/* Shared module runtime state (defined in src/main.c) */
extern bool hook_active;
extern bool module_exiting;
extern int mmap_lock_sem_offset;
extern volatile int hmkpm_in_flight;

/* Dynamically resolved kernel functions & variables (defined in src/main.c) */
extern unsigned long kfunc_def(__arch_copy_to_user)(void __user *to, const void *from, unsigned long n);
extern unsigned long kfunc_def(__arch_copy_from_user)(void *to, const void __user *from, unsigned long n);
extern unsigned long kfunc_def(__arch_clear_user)(void __user *to, unsigned long n);
extern unsigned long kfunc_def(_copy_to_user)(void __user *to, const void *from, unsigned long n);
extern unsigned long kfunc_def(_copy_from_user)(void *to, const void __user *from, unsigned long n);
extern long kfunc_def(probe_kernel_read)(void *dst, const void *src, size_t size);
extern long kfunc_def(probe_kernel_write)(void *dst, const void *src, size_t size);
extern long kfunc_def(copy_from_kernel_nofault)(void *dst, const void *src, size_t size);
extern long kfunc_def(copy_to_kernel_nofault)(void *dst, const void *src, size_t size);
extern struct task_struct *kfunc_def(find_task_by_vpid)(pid_t pid);
extern struct mm_struct *kfunc_def(get_task_mm)(struct task_struct *task);
extern void kfunc_def(mmput)(struct mm_struct *mm);
extern void kfunc_def(__rcu_read_lock)(void);
extern void kfunc_def(__rcu_read_unlock)(void);
extern void kfunc_def(down_read)(struct rw_semaphore *sem);
extern void kfunc_def(up_read)(struct rw_semaphore *sem);
extern void kfunc_def(msleep)(unsigned int msecs);
extern void kfunc_def(schedule)(void);
extern int kfunc_def(_cond_resched)(void);

extern u64 kvar_def(memstart_addr);
extern void *kvar_def(high_memory);

/* MMU / page table geometry state (defined in src/mmu.c) */
extern uint64_t pgt_va_bits;
extern uint64_t pgt_phys_offset;
extern uint64_t pgt_page_offset;
extern uint64_t pgt_linear_voffset;
extern uint64_t pgt_page_shift;
extern uint64_t pgt_page_size;
extern uint64_t pgt_pgd_align_mask;
extern uint64_t pgt_pgd_size;
extern uint64_t pgt_page_level;
extern uint64_t pgt_user_limit;
extern uint64_t pgt_high_memory;
extern bool pgt_tbi0;

/* Unified hardware page table walk output */
struct pgt_walk_result {
	uint64_t pa;           /* Translated PA, or 0 on miss / permission reject */
	uint64_t span_size;    /* Leaf mapping size on hit, or empty subtree stride on miss */
	uint32_t flags;        /* HMKPM_PAGE_FLAG_* */
	bool     is_exec_user; /* True when EL0 execution is permitted on the leaf */
};

/* ARM64 LL/SC atomic helpers (avoid libgcc -moutline-atomics dependencies) */
static inline int hmkpm_atomic_read(const volatile int *v)
{
	int val;

	asm volatile("ldar %w0, %1"
		     : "=r"(val)
		     : "Q"(*v)
		     : "memory");
	return val;
}

static inline int hmkpm_atomic_add_return(volatile int *v, int delta)
{
	int result;
	unsigned int tmp;

	asm volatile("1: ldaxr %w0, %2\n"
		     "   add   %w0, %w0, %w3\n"
		     "   stlxr %w1, %w0, %2\n"
		     "   cbnz  %w1, 1b\n"
		     "   dmb   ish\n"
		     : "=&r"(result), "=&r"(tmp), "+Q"(*v)
		     : "r"(delta)
		     : "memory");
	return result;
}

static inline void hmkpm_enter_in_flight(void)
{
	hmkpm_atomic_add_return(&hmkpm_in_flight, 1);
}

static inline void hmkpm_leave_in_flight(void)
{
	hmkpm_atomic_add_return(&hmkpm_in_flight, -1);
}

static inline void hmkpm_cpu_relax(void)
{
	asm volatile("yield" ::: "memory");
}

static inline void hmkpm_memzero(void *dst, size_t n)
{
	volatile unsigned char *p = (volatile unsigned char *)dst;

	while (n--)
		*p++ = 0;
}

static inline uint16_t hmkpm_get_unaligned_le16(const void *p)
{
	const uint8_t *b = (const uint8_t *)p;

	return (uint16_t)b[0] | ((uint16_t)b[1] << 8);
}

static inline uint32_t hmkpm_get_unaligned_le32(const void *p)
{
	const uint8_t *b = (const uint8_t *)p;

	return (uint32_t)b[0] | ((uint32_t)b[1] << 8) |
	       ((uint32_t)b[2] << 16) | ((uint32_t)b[3] << 24);
}

static inline uint64_t hmkpm_get_unaligned_le64(const void *p)
{
	const uint8_t *b = (const uint8_t *)p;

	return (uint64_t)b[0] | ((uint64_t)b[1] << 8) |
	       ((uint64_t)b[2] << 16) | ((uint64_t)b[3] << 24) |
	       ((uint64_t)b[4] << 32) | ((uint64_t)b[5] << 40) |
	       ((uint64_t)b[6] << 48) | ((uint64_t)b[7] << 56);
}

/* Kernel nofault read/write wrappers */
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

/* Cooperative scheduling point (must only be called with no locks held) */
static inline void hmkpm_cond_resched(void)
{
	if (kf__cond_resched)
		kfunc(_cond_resched)();
}

/* Linear map & address validation helpers */
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
	uint64_t va;

	if (unlikely(size == 0))
		return -EINVAL;

	if (unlikely((phys >> 48) != 0))
		return -EFAULT;

	if (unlikely(phys > U64_MAX - size))
		return -EFAULT;

	va = pgt_phys_to_virt(phys);
	return validate_virt_range(va, size);
}

static inline uint64_t pgt_untag_user_va(uint64_t va)
{
	/*
	 * Top Byte Ignore (TBI0 / MTE / HWASan tagged pointers).
	 * Clears the top 8 bits only when TCR_EL1.TBI0 is enabled.
	 */
	if (likely(pgt_tbi0))
		return va & 0x00FFFFFFFFFFFFFFULL;
	return va;
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

static inline bool hmkpm_is_lockless(void)
{
	return (mmap_lock_sem_offset < 0);
}

static inline void hmkpm_mmap_read_lock(struct mm_struct *mm)
{
	if (mm && !hmkpm_is_lockless() && kf_down_read) {
		struct rw_semaphore *sem =
			(struct rw_semaphore *)((uintptr_t)mm + mmap_lock_sem_offset);
		kfunc(down_read)(sem);
	}
}

static inline void hmkpm_mmap_read_unlock(struct mm_struct *mm)
{
	if (mm && !hmkpm_is_lockless() && kf_up_read) {
		struct rw_semaphore *sem =
			(struct rw_semaphore *)((uintptr_t)mm + mmap_lock_sem_offset);
		kfunc(up_read)(sem);
	}
}

/* Bounded string-formatting & command-parsing helpers (no snprintf dependency) */
struct hmkpm_strbuf {
	char *buf;
	size_t cap;
	size_t pos;
};

static inline void hmkpm_sb_init(struct hmkpm_strbuf *sb, char *buf, size_t cap)
{
	sb->buf = buf;
	sb->cap = cap;
	sb->pos = 0;
	if (buf && cap > 0)
		buf[0] = '\0';
}

static inline void hmkpm_sb_putc(struct hmkpm_strbuf *sb, char c)
{
	if (!sb->buf || sb->cap == 0)
		return;
	if (sb->pos + 1 < sb->cap) {
		sb->buf[sb->pos++] = c;
		sb->buf[sb->pos] = '\0';
	}
}

static inline void hmkpm_sb_puts(struct hmkpm_strbuf *sb, const char *s)
{
	if (!s)
		return;
	while (*s)
		hmkpm_sb_putc(sb, *s++);
}

static inline void hmkpm_sb_put_u64(struct hmkpm_strbuf *sb, uint64_t val)
{
	char tmp[24];
	size_t n = 0;

	if (val == 0) {
		hmkpm_sb_putc(sb, '0');
		return;
	}

	while (val > 0 && n < sizeof(tmp)) {
		uint64_t q = val / 10ULL;
		uint64_t r = val - q * 10ULL;

		tmp[n++] = (char)('0' + r);
		val = q;
	}

	while (n > 0)
		hmkpm_sb_putc(sb, tmp[--n]);
}

static inline void hmkpm_sb_put_i32(struct hmkpm_strbuf *sb, int32_t val)
{
	uint64_t mag;

	if (val < 0) {
		hmkpm_sb_putc(sb, '-');
		mag = (uint64_t)(-(int64_t)val);
	} else {
		mag = (uint64_t)val;
	}
	hmkpm_sb_put_u64(sb, mag);
}

static inline int hmkpm_isspace(char c)
{
	return (c == ' ' || c == '\t' || c == '\n' || c == '\r');
}

static inline const char *hmkpm_skip_spaces(const char *s)
{
	if (!s)
		return "";
	while (*s && hmkpm_isspace(*s))
		s++;
	return s;
}

static inline bool hmkpm_streq(const char *s1, const char *s2)
{
	if (!s1 || !s2)
		return false;
	while (*s1 && *s2) {
		if (*s1 != *s2)
			return false;
		s1++;
		s2++;
	}
	while (*s1 && hmkpm_isspace(*s1))
		s1++;
	return (*s1 == '\0' && *s2 == '\0');
}

static inline bool hmkpm_match_prefix_word(const char *s, const char *prefix,
					   const char **rest_out)
{
	if (!s || !prefix)
		return false;
	while (*prefix) {
		if (*s != *prefix)
			return false;
		s++;
		prefix++;
	}
	if (*s != '\0' && !hmkpm_isspace(*s))
		return false;
	if (rest_out)
		*rest_out = hmkpm_skip_spaces(s);
	return true;
}

static inline const char *hmkpm_fsnotify_mode_name(uint8_t mode)
{
	switch (mode) {
	case HMKPM_FSNOTIFY_GLOBAL:
		return "global";
	case HMKPM_FSNOTIFY_CALLER_PIDS:
		return "pids";
	default:
		return "off";
	}
}

/* Cross-module entry points */

/* src/main.c */
unsigned long hmkpm_lookup_symbol(const char *name);

/* src/sw_pan.c */
void hmkpm_sw_pan_init(void);
uint8_t hmkpm_get_sw_pan_mode(void);
unsigned long hmkpm_copy_to_user(void __user *to, const void *from, unsigned long n);
unsigned long hmkpm_copy_from_user(void *to, const void __user *from, unsigned long n);
void hmkpm_zero_user(void __user *dst, size_t size);

/* src/mmu.c */
int pgt_pgtable_init(void);
bool pgt_walk_va(uint64_t pgd, uint64_t va, bool is_write, struct pgt_walk_result *out);
uint64_t pgt_pgtable_to_tkpa(uint64_t pgd, uint64_t va, bool is_write);
uint64_t pgt_pgtable_inspect(uint64_t pgd, uint64_t va, uint32_t *out_flags, uint32_t *out_page_size);
void hmkpm_handle_enum_regions(hook_fargs3_t *args, void __user *user_ptr, uint64_t total_len);

/* src/io.c */
void hmkpm_handle_single(hook_fargs3_t *args, void __user *user_ptr, uint64_t total_len, uint64_t magic);
void hmkpm_handle_batch(hook_fargs3_t *args, void __user *user_ptr, uint64_t total_len, uint64_t magic);
void hmkpm_handle_v2p_batch(hook_fargs3_t *args, void __user *user_ptr, uint64_t total_len);
void hmkpm_handle_read_chain(hook_fargs3_t *args, void __user *user_ptr, uint64_t total_len);

/* src/scan.c */
void hmkpm_handle_scan_kernel(hook_fargs3_t *args, void __user *user_ptr, uint64_t total_len);
void hmkpm_handle_scan_refine(hook_fargs3_t *args, void __user *user_ptr, uint64_t total_len);

/* src/fsnotify_filter.c */
void hmkpm_fsnotify_init(void);
void hmkpm_fsnotify_exit(void);
bool hmkpm_fsnotify_is_hooked(void);
uint8_t hmkpm_get_fsnotify_mode(void);
long hmkpm_fsnotify_ctl(const char *subcmd, char *out_buf, size_t out_cap);

/* src/disasm_legacy.c */
int find_mm_mmap_sem_offset(unsigned int *offset);

/* 1-entry page/block translation cache & small locked read helper */
struct hmkpm_pt_cache {
	bool valid;
	uint64_t va_base;
	uint64_t span_mask;
	uint64_t pa_base;
};

static inline void hmkpm_pt_cache_init(struct hmkpm_pt_cache *cache)
{
	cache->valid = false;
	cache->va_base = 0;
	cache->span_mask = 0;
	cache->pa_base = 0;
}

static inline bool hmkpm_pt_cache_translate(struct hmkpm_pt_cache *cache,
					    uint64_t pgd, uint64_t va,
					    uint64_t *out_pa)
{
	struct pgt_walk_result walk;

	va = pgt_untag_user_va(va);
	if (cache->valid && (va & ~cache->span_mask) == cache->va_base) {
		*out_pa = cache->pa_base | (va & cache->span_mask);
		return true;
	}

	if (!pgt_walk_va(pgd, va, false, &walk))
		return false;

	cache->span_mask = walk.span_size - 1;
	cache->va_base = va & ~cache->span_mask;
	cache->pa_base = walk.pa & ~cache->span_mask;
	cache->valid = true;
	*out_pa = walk.pa;
	return true;
}

static inline bool hmkpm_read_locked_cached(struct hmkpm_pt_cache *cache,
					    uint64_t pgd, uint64_t va,
					    void *dst, size_t sz)
{
	uint8_t *out = (uint8_t *)dst;
	size_t done = 0;

	va = pgt_untag_user_va(va);
	if (sz == 0)
		return true;
	if (va > U64_MAX - sz)
		return false;

	while (done < sz) {
		uint64_t cur_va = va + done;
		uint64_t page_off = cur_va & (pgt_page_size - 1);
		size_t page_left = (size_t)(pgt_page_size - page_off);
		size_t chunk = min(sz - done, page_left);
		uint64_t pa = 0;

		if (!hmkpm_pt_cache_translate(cache, pgd, cur_va, &pa))
			return false;

		if (hmkpm_copy_from_kernel_nofault(out + done,
						   (const void *)pgt_phys_to_virt(pa),
						   chunk) != 0)
			return false;

		done += chunk;
	}
	return true;
}

static inline uint64_t hmkpm_get_active_features(void)
{
	uint64_t feat = HMKPM_FEATURE_READ | HMKPM_FEATURE_READ_BATCH |
			HMKPM_FEATURE_V2P_BATCH | HMKPM_FEATURE_SCAN_KERNEL |
			HMKPM_FEATURE_READ_CHAIN | HMKPM_FEATURE_SCAN_REFINE |
			HMKPM_FEATURE_ENUM_REGIONS | HMKPM_FEATURE_SCAN_EXT;

	if (!hmkpm_is_lockless()) {
		feat |= (HMKPM_FEATURE_WRITE | HMKPM_FEATURE_WRITE_BATCH);
	} else {
		feat |= HMKPM_FEATURE_LOCKLESS;
	}

	if (hmkpm_fsnotify_is_hooked())
		feat |= HMKPM_FEATURE_FSNOTIFY_FILTER;

	return feat;
}

#endif /* _HMKPM_INTERNAL_H_ */
