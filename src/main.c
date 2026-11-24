// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2026 Yervant7
 *
 * HuntMemory-KPM (HMKPM) - Module Lifecycle, Symbol Resolution, and Syscall Dispatch
 */

#include <hmkpm_internal.h>

KPM_NAME("HMKPM");
KPM_VERSION(HMKPM_VERSION_STR);
KPM_LICENSE("GPL v2");
KPM_AUTHOR("Yervant7");
KPM_DESCRIPTION("KernelPatch Module (KPM) HMKPM");

/* Shared module runtime state */
bool hook_active = true;
bool module_exiting = false;
int mmap_lock_sem_offset = -1;
volatile int hmkpm_in_flight = 0;

/* Local lifecycle state */
static bool syscall_hooked = false;
static uint8_t mmap_lock_source = HMKPM_LOCK_SRC_LOCKLESS;

/* Dynamically resolved kernel functions & variables */
unsigned long kfunc_def(__arch_copy_to_user)(void __user *to, const void *from, unsigned long n);
unsigned long kfunc_def(__arch_copy_from_user)(void *to, const void __user *from, unsigned long n);
unsigned long kfunc_def(__arch_clear_user)(void __user *to, unsigned long n);
unsigned long kfunc_def(_copy_to_user)(void __user *to, const void *from, unsigned long n);
unsigned long kfunc_def(_copy_from_user)(void *to, const void __user *from, unsigned long n);
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
void kfunc_def(msleep)(unsigned int msecs);
void kfunc_def(schedule)(void);
int kfunc_def(_cond_resched)(void);

u64 kvar_def(memstart_addr);
void *kvar_def(high_memory);

/*
 * Minimal local memset fallback for compiler-synthesized zero-initializations
 * (e.g. aggregate `= {0}` in disasm_legacy.c), since KernelPatch does not
 * export memset via KP_EXPORT_SYMBOL.
 */
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

unsigned long hmkpm_lookup_symbol(const char *name)
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

static __always_inline bool is_hmkpm_magic(uint64_t magic)
{
	return magic >= HMKPM_MAGIC && magic <= HMKPM_MAGIC_MAX;
}

static void hmkpm_handle(hook_fargs3_t *args, void *udata)
{
	void __user *user_ptr;
	uint64_t total_len;
	uint64_t magic = syscall_argn(args, 0);
	uid_t uid;

	(void)udata;

	if (likely(!is_hmkpm_magic(magic)))
		return;

	if (unlikely(READ_ONCE(module_exiting)) || !READ_ONCE(hook_active))
		return;

	uid = current_uid();
	if (uid != 0)
		return;

	/*
	 * Track in-flight HMKPM operations so module_cleanup_handler() can drain
	 * active callers before KernelPatch frees module executable memory.
	 */
	hmkpm_enter_in_flight();
	if (unlikely(READ_ONCE(module_exiting) || !READ_ONCE(hook_active)))
		goto out_leave;

	args->skip_origin = 1;

	if (magic == HMKPM_MAGIC) {
		user_ptr = (void __user *)syscall_argn(args, 1);
		total_len = syscall_argn(args, 2);

		/*
		 * Fast ret-only probe passes (NULL, 0). Any non-zero pointer or
		 * length must describe a valid writable user buffer.
		 */
		if (user_ptr != NULL || total_len > 0) {
			struct hmkpm_version_info info;
			const char *vstr = HMKPM_VERSION_STR;
			size_t vlen = 0;
			size_t copy_sz;

			if (!user_ptr || total_len == 0 ||
			    !hmkpm_user_range_ok(user_ptr, total_len)) {
				args->ret = (uint64_t)(long)-EINVAL;
				goto out_leave;
			}

			hmkpm_memzero(&info, sizeof(info));
			info.magic = HMKPM_MAGIC;
			info.struct_size = (uint32_t)sizeof(info);
			info.version_code = HMKPM_VERSION_CODE;
			info.version_major = HMKPM_VERSION_MAJOR;
			info.version_minor = HMKPM_VERSION_MINOR;
			info.version_patch = HMKPM_VERSION_PATCH;
			info.is_lockless = hmkpm_is_lockless() ? 1 : 0;
			info.lock_source = hmkpm_is_lockless() ? HMKPM_LOCK_SRC_LOCKLESS : mmap_lock_source;
			info.mmap_lock_offset = mmap_lock_sem_offset;
			info.page_size = (uint32_t)pgt_page_size;
			info.kver = kver;
			info.va_bits = (uint8_t)pgt_va_bits;
			info.tbi0 = pgt_tbi0 ? 1 : 0;
			info.sw_pan_mode = hmkpm_get_sw_pan_mode();
			info.fsnotify_mode = hmkpm_get_fsnotify_mode();
			info.features = hmkpm_get_active_features();

			while (vstr[vlen] && vlen < sizeof(info.version_str) - 1) {
				info.version_str[vlen] = vstr[vlen];
				vlen++;
			}
			info.version_str[vlen] = '\0';

			copy_sz = min((size_t)total_len, sizeof(info));
			if (hmkpm_copy_to_user(user_ptr, &info, copy_sz) != 0) {
				args->ret = (uint64_t)(long)-EFAULT;
				goto out_leave;
			}
		}

		/* Return combined 64-bit value: version_code in top 24 bits, HMKPM_MAGIC in bottom 40 bits */
		args->ret = (((uint64_t)HMKPM_VERSION_CODE << 40) | (HMKPM_MAGIC & 0xFFFFFFFFFFULL));
		goto out_leave;
	}

	user_ptr = (void __user *)syscall_argn(args, 1);
	total_len = syscall_argn(args, 2);

	if (total_len == 0) {
		args->ret = (uint64_t)(long)-EINVAL;
		goto out_leave;
	}

	if (unlikely(!hmkpm_user_range_ok(user_ptr, total_len))) {
		args->ret = (uint64_t)(long)-EINVAL;
		goto out_leave;
	}

	if (magic == HMKPM_MAGIC_READ || magic == HMKPM_MAGIC_WRITE) {
		hmkpm_handle_single(args, user_ptr, total_len, magic);
		goto out_leave;
	}

	if (magic == HMKPM_MAGIC_READ_BATCH || magic == HMKPM_MAGIC_WRITE_BATCH) {
		hmkpm_handle_batch(args, user_ptr, total_len, magic);
		goto out_leave;
	}

	if (magic == HMKPM_MAGIC_V2P_BATCH) {
		hmkpm_handle_v2p_batch(args, user_ptr, total_len);
		goto out_leave;
	}

	if (magic == HMKPM_MAGIC_SCAN_KERNEL) {
		hmkpm_handle_scan_kernel(args, user_ptr, total_len);
		goto out_leave;
	}

	if (magic == HMKPM_MAGIC_READ_CHAIN) {
		hmkpm_handle_read_chain(args, user_ptr, total_len);
		goto out_leave;
	}

	if (magic == HMKPM_MAGIC_SCAN_REFINE) {
		hmkpm_handle_scan_refine(args, user_ptr, total_len);
		goto out_leave;
	}

	if (magic == HMKPM_MAGIC_ENUM_REGIONS) {
		hmkpm_handle_enum_regions(args, user_ptr, total_len);
		goto out_leave;
	}

	args->ret = (uint64_t)(long)-EINVAL;

out_leave:
	hmkpm_leave_in_flight();
}

static int hmkpm_resolve_mmap_lock_btf(void)
{
	typedef int (*kp_btf_available_fn)(void);
	typedef long (*kp_btf_member_offset_fn)(const char *struct_name, const char *member);
	typedef long (*kp_btf_type_size_fn)(const char *name);

	kp_btf_available_fn btf_avail =
		(kp_btf_available_fn)symbol_lookup_name("kp_btf_available");
	kp_btf_member_offset_fn btf_off =
		(kp_btf_member_offset_fn)symbol_lookup_name("kp_btf_member_offset");
	kp_btf_type_size_fn btf_size =
		(kp_btf_type_size_fn)symbol_lookup_name("kp_btf_type_size");

	if (!btf_avail || !btf_off || !btf_avail())
		return -1;

	long off = btf_off("mm_struct", "mmap_lock");
	if (off < 0)
		off = btf_off("mm_struct", "mmap_sem");

	if (off < 8 || off >= 4096 || (off & 7) != 0) {
		hmkpm_warn("BTF mm_struct->mmap_lock lookup returned invalid offset (%ld)\n", off);
		return -1;
	}

	if (mm_struct_offset.pgd_offset >= 0 && off == mm_struct_offset.pgd_offset) {
		hmkpm_warn("BTF mm_struct->mmap_lock (%ld) collides with pgd_offset (%d)\n",
			   off, (int)mm_struct_offset.pgd_offset);
		return -1;
	}

	if (btf_size) {
		long mm_sz = btf_size("mm_struct");

		if (mm_sz > 0 && off + 32 > mm_sz) {
			hmkpm_warn("BTF mm_struct->mmap_lock (%ld) exceeds struct size (%ld)\n",
				   off, mm_sz);
			return -1;
		}
	}

	hmkpm_info("mmap_lock offset resolved via BTF: %ld (0x%lx)\n", off, off);
	return (int)off;
}

/*
 * Cross-validate a hardcoded GKI mm_struct->mmap_lock offset against runtime
 * offsets discovered by KernelPatch in mm_struct_offset.
 */
static int hmkpm_validate_gki_mmap_lock_offset(int off)
{
	if (off < 8 || off >= 4096 || (off & 7) != 0)
		return -1;

	if (mm_struct_offset.pgd_offset >= 0 && off <= mm_struct_offset.pgd_offset)
		return -1;

	if (mm_struct_offset.map_count_offset >= 0 && off <= mm_struct_offset.map_count_offset)
		return -1;

	if (mm_struct_offset.total_vm_offset >= 0 && off + 32 > mm_struct_offset.total_vm_offset)
		return -1;

	if (mm_struct_offset.start_code_offset >= 0 && off + 32 > mm_struct_offset.start_code_offset)
		return -1;

	return off;
}

static bool hmkpm_validate_init_mm_rwsem(int off)
{
	unsigned long init_mm_addr;
	uint64_t count = 0;

	if (off < 8 || off >= 4096 || (off & 7) != 0)
		return false;

	init_mm_addr = hmkpm_lookup_symbol("init_mm");
	if (!init_mm_addr || is_bad_address((void *)init_mm_addr))
		return false;

	if (hmkpm_copy_from_kernel_nofault(&count,
					   (const void *)((uintptr_t)init_mm_addr + (uintptr_t)off),
					   sizeof(count)) != 0 || count != 0)
		return false;

	for (uintptr_t w_off = 8; w_off <= 48; w_off += 8) {
		struct {
			uint64_t next;
			uint64_t prev;
		} lh;
		uintptr_t list_va = (uintptr_t)init_mm_addr + (uintptr_t)off + w_off;

		if (hmkpm_copy_from_kernel_nofault(&lh, (const void *)list_va, sizeof(lh)) != 0)
			return false;

		if (lh.next == (uint64_t)list_va && lh.prev == (uint64_t)list_va)
			return true;
	}

	return false;
}

static int get_mm_mmap_lock_offset(void)
{
	if (kver >= VERSION(5, 10, 0)) {
		int btf_off = hmkpm_resolve_mmap_lock_btf();
		int gki_off;
		unsigned int disasm_off = 0;

		if (btf_off >= 0) {
			mmap_lock_source = HMKPM_LOCK_SRC_BTF;
			return btf_off;
		}

		if (kver >= VERSION(6, 12, 0)) {
			gki_off = 136;
		} else if (kver >= VERSION(6, 6, 0)) {
			gki_off = 144;
		} else if (kver >= VERSION(6, 1, 0)) {
			gki_off = 96;
		} else if (kver >= VERSION(5, 15, 0)) {
			gki_off = 104;
		} else {
			gki_off = 112;
		}

		if (find_mm_mmap_sem_offset(&disasm_off) == 0 &&
		    hmkpm_validate_gki_mmap_lock_offset((int)disasm_off) >= 0) {
			if ((int)disasm_off == gki_off) {
				hmkpm_info("mmap_lock offset using disasm-confirmed GKI fallback: %d (0x%x)\n",
					   gki_off, gki_off);
				mmap_lock_source = HMKPM_LOCK_SRC_GKI_VALIDATED;
				return gki_off;
			}

			hmkpm_info("mmap_lock offset resolved via disassembler on >= 5.10 (GKI=%d): %u (0x%x)\n",
				   gki_off, disasm_off, disasm_off);
			mmap_lock_source = HMKPM_LOCK_SRC_DISASM_LEGACY;
			return (int)disasm_off;
		}

		if (hmkpm_validate_gki_mmap_lock_offset(gki_off) >= 0 &&
		    hmkpm_validate_init_mm_rwsem(gki_off)) {
			hmkpm_info("mmap_lock offset using init_mm-validated GKI fallback: %d (0x%x)\n",
				   gki_off, gki_off);
			mmap_lock_source = HMKPM_LOCK_SRC_GKI_VALIDATED;
			return gki_off;
		}

		hmkpm_warn("GKI fallback mmap_lock offset (%d) failed layout and init_mm rwsem validation "
			   "(pgd=%d, map_count=%d, total_vm=%d, start_code=%d); falling back to lockless mode\n",
			   gki_off, (int)mm_struct_offset.pgd_offset,
			   (int)mm_struct_offset.map_count_offset,
			   (int)mm_struct_offset.total_vm_offset,
			   (int)mm_struct_offset.start_code_offset);
		mmap_lock_source = HMKPM_LOCK_SRC_LOCKLESS;
		return -1;
	} else {
		/*
		 * Kernels below 5.10 (pre-GKI): dynamically discovered via legacy ARM64 disassembler
		 */
		unsigned int off = 0;

		if (find_mm_mmap_sem_offset(&off) == 0) {
			mmap_lock_source = HMKPM_LOCK_SRC_DISASM_LEGACY;
			return (int)off;
		}

		mmap_lock_source = HMKPM_LOCK_SRC_LOCKLESS;
		return -1;
	}
}

#define HMKPM_UNLOAD_DRAIN_MS		5000U
#define HMKPM_UNLOAD_GRACE_MS		10U
#define HMKPM_UNLOAD_SPIN_LIMIT		1000000U

static void hmkpm_drain_in_flight(void)
{
	unsigned int waited = 0;
	int remaining;

	if (kf_msleep) {
		while (hmkpm_atomic_read(&hmkpm_in_flight) > 0 && waited < HMKPM_UNLOAD_DRAIN_MS) {
			kfunc(msleep)(1);
			waited++;
		}
		/* Brief grace window for non-sleeping hook prologues (e.g. fsnotify / fast-path) */
		kfunc(msleep)(HMKPM_UNLOAD_GRACE_MS);
	} else if (kf_schedule) {
		while (hmkpm_atomic_read(&hmkpm_in_flight) > 0 && waited < HMKPM_UNLOAD_SPIN_LIMIT) {
			kfunc(schedule)();
			waited++;
		}
	} else {
		while (hmkpm_atomic_read(&hmkpm_in_flight) > 0 && waited < HMKPM_UNLOAD_SPIN_LIMIT) {
			hmkpm_cpu_relax();
			waited++;
		}
	}

	remaining = hmkpm_atomic_read(&hmkpm_in_flight);
	if (remaining > 0)
		hmkpm_warn("in-flight drain timed out with %d active request(s)\n", remaining);
}

static long module_init_handler(const char *args, const char *event, void *__user reserved)
{
	bool init_error = false;
	hook_err_t err;

	(void)args;
	(void)event;
	(void)reserved;

	if (kver < VERSION(4, 14, 0) || kver >= VERSION(6, 13, 0)) {
		hmkpm_error("Kernel version not supported\n");
		return -EINVAL;
	}

	if (pgt_pgtable_init() != 0) {
		hmkpm_error("Page table initialization failed\n");
		return -ENOENT;
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

	kf___arch_clear_user =
		(typeof(kf___arch_clear_user))hmkpm_lookup_symbol("__arch_clear_user");
	if (!kf___arch_clear_user)
		kf___arch_clear_user =
			(typeof(kf___arch_clear_user))hmkpm_lookup_symbol("__clear_user");
	if (!kf___arch_clear_user)
		kf___arch_clear_user =
			(typeof(kf___arch_clear_user))hmkpm_lookup_symbol("clear_user");

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

	/* Optional sleep/yield helpers for cooperative unload drain and long loops */
	kf_msleep = (typeof(kf_msleep))hmkpm_lookup_symbol("msleep");
	kf_schedule = (typeof(kf_schedule))hmkpm_lookup_symbol("schedule");
	kf__cond_resched = (typeof(kf__cond_resched))hmkpm_lookup_symbol("__cond_resched");
	if (!kf__cond_resched)
		kf__cond_resched = (typeof(kf__cond_resched))hmkpm_lookup_symbol("_cond_resched");

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

	if (init_error) {
		hmkpm_error("Symbol resolution failed, aborting...\n");
		return -ENOENT;
	}

	/* Initialize SW PAN after nofault helpers and paging geometry are ready */
	hmkpm_sw_pan_init();

	mmap_lock_sem_offset = get_mm_mmap_lock_offset();
	if (mmap_lock_sem_offset >= 0 && kf_down_read && kf_up_read) {
		hmkpm_info("mmap lock/sem offset = %d (0x%x) [source=%u]\n",
			   mmap_lock_sem_offset, mmap_lock_sem_offset,
			   (unsigned int)mmap_lock_source);
	} else {
		hmkpm_warn("mmap lock/sem offset not resolved or rw_semaphore ops missing; running in lockless mode\n");
		mmap_lock_sem_offset = -1;
		mmap_lock_source = HMKPM_LOCK_SRC_LOCKLESS;
	}

	hmkpm_fsnotify_init();

	err = hook_syscalln_override(__NR_getresuid, 3, hmkpm_handle, 0, 0);
	if (err) {
		hmkpm_error("install hook error: %d\n", err);
		WRITE_ONCE(module_exiting, true);
		smp_mb();
		hmkpm_fsnotify_exit();
		hmkpm_drain_in_flight();
		return -ENOENT;
	}
	syscall_hooked = true;

	hmkpm_info("module v%s loaded successfully\n", HMKPM_VERSION_STR);
	return 0;
}

static inline const char *hmkpm_lock_source_str(uint8_t src)
{
	switch (src) {
	case HMKPM_LOCK_SRC_BTF:
		return "btf";
	case HMKPM_LOCK_SRC_GKI_VALIDATED:
		return "gki_validated";
	case HMKPM_LOCK_SRC_DISASM_LEGACY:
		return "disasm_legacy";
	default:
		return "lockless";
	}
}

static inline const char *hmkpm_sw_pan_str(uint8_t mode)
{
	switch (mode) {
	case HMKPM_SW_PAN_KERNEL_UACCESS:
		return "kernel_uaccess";
	case HMKPM_SW_PAN_MANUAL_TTBR0:
		return "manual_ttbr0";
	default:
		return "off";
	}
}

static void hmkpm_format_info(char *buf, size_t cap)
{
	struct hmkpm_strbuf sb;
	uint8_t lock_src = hmkpm_is_lockless() ? HMKPM_LOCK_SRC_LOCKLESS : mmap_lock_source;
	uint8_t sw_pan = hmkpm_get_sw_pan_mode();
	uint8_t fsn = hmkpm_get_fsnotify_mode();

	hmkpm_sb_init(&sb, buf, cap);
	hmkpm_sb_puts(&sb, "ver=");
	hmkpm_sb_puts(&sb, HMKPM_VERSION_STR);
	hmkpm_sb_puts(&sb, " active=");
	hmkpm_sb_putc(&sb, READ_ONCE(hook_active) ? '1' : '0');
	hmkpm_sb_puts(&sb, " kver=");
	hmkpm_sb_put_u64(&sb, (kver >> 16) & 0xFFU);
	hmkpm_sb_putc(&sb, '.');
	hmkpm_sb_put_u64(&sb, (kver >> 8) & 0xFFU);
	hmkpm_sb_putc(&sb, '.');
	hmkpm_sb_put_u64(&sb, kver & 0xFFU);
	hmkpm_sb_puts(&sb, " page=");
	hmkpm_sb_put_u64(&sb, pgt_page_size);
	hmkpm_sb_puts(&sb, " va=");
	hmkpm_sb_put_u64(&sb, pgt_va_bits);
	hmkpm_sb_puts(&sb, " tbi0=");
	hmkpm_sb_putc(&sb, pgt_tbi0 ? '1' : '0');
	hmkpm_sb_puts(&sb, " lock=");
	hmkpm_sb_puts(&sb, hmkpm_lock_source_str(lock_src));
	hmkpm_sb_putc(&sb, '(');
	hmkpm_sb_put_i32(&sb, mmap_lock_sem_offset);
	hmkpm_sb_puts(&sb, ") sw_pan=");
	hmkpm_sb_puts(&sb, hmkpm_sw_pan_str(sw_pan));
	hmkpm_sb_puts(&sb, " fsnotify=");
	hmkpm_sb_puts(&sb, hmkpm_fsnotify_mode_name(fsn));
	hmkpm_sb_putc(&sb, '\n');
}

static void send_user_msg(char __user *out_msg, int outlen, const char *msg)
{
	int len = 0;
	char zero = '\0';

	if (!out_msg || outlen <= 0 || !msg)
		return;

	while (msg[len] && len < outlen - 1)
		len++;

	if (hmkpm_user_range_ok(out_msg, (uint64_t)(len + 1))) {
		if (len > 0 && hmkpm_copy_to_user(out_msg, msg, (unsigned long)len) != 0)
			return;
		(void)hmkpm_copy_to_user((char __user *)out_msg + len, &zero, 1);
		return;
	}

	if (len > 0) {
		if (compat_copy_to_user(out_msg, msg, len) < 0)
			return;
	}

	(void)compat_copy_to_user((char __user *)out_msg + len, &zero, 1);
}

static long module_control_handler(const char *args, char __user *out_msg, int outlen)
{
	const char *cmd = hmkpm_skip_spaces(args);
	const char *subcmd = NULL;
	char msg_buf[256];
	long ret = 0;

	if (unlikely(READ_ONCE(module_exiting))) {
		send_user_msg(out_msg, outlen, "exiting\n");
		return -EBUSY;
	}

	if (hmkpm_streq(cmd, "enable") || hmkpm_streq(cmd, "on") ||
	    hmkpm_streq(cmd, "start") || hmkpm_streq(cmd, "1")) {
		WRITE_ONCE(hook_active, true);
		send_user_msg(out_msg, outlen, "enabled\n");
	} else if (hmkpm_streq(cmd, "disable") || hmkpm_streq(cmd, "off") ||
		   hmkpm_streq(cmd, "stop") || hmkpm_streq(cmd, "0")) {
		WRITE_ONCE(hook_active, false);
		send_user_msg(out_msg, outlen, "disabled\n");
	} else if (hmkpm_streq(cmd, "status") || hmkpm_streq(cmd, "state") ||
		   hmkpm_streq(cmd, "get")) {
		if (READ_ONCE(hook_active))
			send_user_msg(out_msg, outlen, "active\n");
		else
			send_user_msg(out_msg, outlen, "inactive\n");
	} else if (hmkpm_streq(cmd, "toggle")) {
		if (READ_ONCE(hook_active)) {
			WRITE_ONCE(hook_active, false);
			send_user_msg(out_msg, outlen, "toggled to disabled\n");
		} else {
			WRITE_ONCE(hook_active, true);
			send_user_msg(out_msg, outlen, "toggled to enabled\n");
		}
	} else if (hmkpm_streq(cmd, "info") || hmkpm_streq(cmd, "diag")) {
		hmkpm_format_info(msg_buf, sizeof(msg_buf));
		send_user_msg(out_msg, outlen, msg_buf);
	} else if (hmkpm_match_prefix_word(cmd, "fsnotify", &subcmd)) {
		ret = hmkpm_fsnotify_ctl(subcmd, msg_buf, sizeof(msg_buf));
		send_user_msg(out_msg, outlen, msg_buf);
	} else {
		hmkpm_info("unknown control command: '%s'\n", cmd ? cmd : "(null)");
		send_user_msg(out_msg, outlen,
			      "unknown command. Available: enable | disable | status | toggle | info | fsnotify <subcmd>\n");
		ret = -EINVAL;
	}

	return ret;
}

extern uintptr_t *sys_call_table;

static void hmkpm_unhook_getresuid(void)
{
	if (!syscall_hooked)
		return;

	unhook_syscalln(__NR_getresuid, (void *)hmkpm_handle, 0);
	if (syscall_hook_global_enabled()) {
		/*
		 * Mirror hook_syscalln_override() fallback selection when the global
		 * dispatcher is attached at el0_svc_common entry: use fp_unwrap when
		 * sys_call_table is present, or inline_unwrap only when absent.
		 */
		if (sys_call_table)
			fp_unwrap_syscalln(__NR_getresuid, 0, (void *)hmkpm_handle, 0);
		else
			inline_unwrap_syscalln(__NR_getresuid, 0, (void *)hmkpm_handle, 0);
	}
	syscall_hooked = false;
}

static long module_cleanup_handler(void *__user reserved)
{
	(void)reserved;

	WRITE_ONCE(module_exiting, true);
	WRITE_ONCE(hook_active, false);
	smp_mb();

	hmkpm_fsnotify_exit();
	hmkpm_unhook_getresuid();
	hmkpm_drain_in_flight();

	hmkpm_info("module cleaned up\n");
	return 0;
}

KPM_INIT(module_init_handler);
KPM_CTL0(module_control_handler);
KPM_EXIT(module_cleanup_handler);
