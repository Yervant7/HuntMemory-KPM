// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2026 Yervant7
 *
 * HuntMemory-KPM (HMKPM) - /proc fsnotify Event Filter (Linux 5.10 - 6.12)
 */

#include <hmkpm_internal.h>

#define PROC_SUPER_MAGIC	0x9fa0

/* Default GKI 5.10 to 6.12 offsets (overridden dynamically via BTF when available) */
#define SUPER_BLOCK_OFF		40
#define MAGIC_OFF		96

#define HMKPM_FSNOTIFY_MAX_PIDS	8U

static unsigned long fsnotify_addr = 0;
static bool fsnotify_hooked = false;
static int fsnotify_inode_sb_off = SUPER_BLOCK_OFF;
static int fsnotify_sb_magic_off = MAGIC_OFF;
static int fsnotify_tgid_off = -1;
static pid_t (*kf_fsnotify_task_pid_nr_ns)(struct task_struct *task,
					   enum pid_type type,
					   struct pid_namespace *ns) = NULL;
static volatile uint8_t fsnotify_mode = HMKPM_FSNOTIFY_OFF;
static volatile int32_t fsnotify_caller_pids[HMKPM_FSNOTIFY_MAX_PIDS];

static void hmkpm_fsnotify_resolve_offsets(void)
{
	typedef int (*kp_btf_available_fn)(void);
	typedef long (*kp_btf_member_offset_fn)(const char *struct_name, const char *member);

	kp_btf_available_fn btf_avail =
		(kp_btf_available_fn)symbol_lookup_name("kp_btf_available");
	kp_btf_member_offset_fn btf_off =
		(kp_btf_member_offset_fn)symbol_lookup_name("kp_btf_member_offset");

	fsnotify_inode_sb_off = SUPER_BLOCK_OFF;
	fsnotify_sb_magic_off = MAGIC_OFF;
	fsnotify_tgid_off = (task_struct_offset.tgid_offset >= 0 &&
			     (task_struct_offset.tgid_offset & 3) == 0) ?
			    (int)task_struct_offset.tgid_offset : -1;

	if (btf_avail && btf_off && btf_avail()) {
		long sb_off = btf_off("inode", "i_sb");
		long magic_off = btf_off("super_block", "s_magic");

		if (fsnotify_tgid_off < 0) {
			long tgid_off = btf_off("task_struct", "tgid");

			if (tgid_off >= 0 && tgid_off < 0x4000 && (tgid_off & 3) == 0)
				fsnotify_tgid_off = (int)tgid_off;
		}

		if (sb_off >= 0 && sb_off < 4096 && (sb_off & 7) == 0 &&
		    magic_off >= 0 && magic_off < 4096 && (magic_off & 7) == 0) {
			fsnotify_inode_sb_off = (int)sb_off;
			fsnotify_sb_magic_off = (int)magic_off;
			hmkpm_info("fsnotify offsets resolved via BTF: inode.i_sb=%d, super_block.s_magic=%d\n",
				   fsnotify_inode_sb_off, fsnotify_sb_magic_off);
			return;
		}
		hmkpm_warn("fsnotify BTF lookup returned invalid offsets (i_sb=%ld, s_magic=%ld), using GKI fallback\n",
			   sb_off, magic_off);
	}

	hmkpm_info("fsnotify offsets using GKI fallback: inode.i_sb=%d, super_block.s_magic=%d\n",
		   fsnotify_inode_sb_off, fsnotify_sb_magic_off);
}

static inline bool hmkpm_fsnotify_can_resolve_tgid(void)
{
	if (fsnotify_tgid_off >= 0 && (fsnotify_tgid_off & 3) == 0)
		return true;
	if (task_struct_offset.tgid_offset >= 0 &&
	    (task_struct_offset.tgid_offset & 3) == 0)
		return true;
	return (kf_fsnotify_task_pid_nr_ns != NULL);
}

static inline bool hmkpm_fsnotify_current_tgid(int32_t *out_tgid)
{
	struct task_struct *cur = current;
	int tgid_off;

	if (!cur || is_bad_address(cur))
		return false;

	tgid_off = (fsnotify_tgid_off >= 0) ? fsnotify_tgid_off :
					      (int)task_struct_offset.tgid_offset;
	if (tgid_off >= 0 && (tgid_off & 3) == 0) {
		int32_t tgid = 0;

		if (hmkpm_copy_from_kernel_nofault(&tgid,
						   (const void *)((uintptr_t)cur + (uintptr_t)tgid_off),
						   sizeof(tgid)) == 0 && tgid > 0) {
			*out_tgid = tgid;
			return true;
		}
	}

	if (kf_fsnotify_task_pid_nr_ns) {
		pid_t tgid = kf_fsnotify_task_pid_nr_ns(cur, PIDTYPE_TGID, NULL);

		if (tgid > 0) {
			*out_tgid = (int32_t)tgid;
			return true;
		}
	}

	return false;
}

static inline bool is_proc_inode(const struct inode *inode)
{
	uintptr_t i_addr = (uintptr_t)inode;
	uintptr_t sb_addr = 0;
	unsigned long s_magic = 0;

	if (!i_addr || is_bad_address((void *)i_addr) || (i_addr & 7) || i_addr >= (uintptr_t)-4096UL)
		return false;

	if (hmkpm_copy_from_kernel_nofault(&sb_addr,
					   (const void *)(i_addr + (uintptr_t)fsnotify_inode_sb_off),
					   sizeof(sb_addr)) != 0)
		return false;

	if (!sb_addr || is_bad_address((void *)sb_addr) || (sb_addr & 7) || sb_addr >= (uintptr_t)-4096UL)
		return false;

	if (hmkpm_copy_from_kernel_nofault(&s_magic,
					   (const void *)(sb_addr + (uintptr_t)fsnotify_sb_magic_off),
					   sizeof(s_magic)) != 0)
		return false;

	return (s_magic == PROC_SUPER_MAGIC);
}

/*
 * int fsnotify(__u32 mask, const void *data, int data_type, struct inode *dir,
 *              const struct qstr *file_name, struct inode *inode, u32 cookie)
 */
static void before_fsnotify(hook_fargs7_t *args, void *udata)
{
	struct inode *dir;
	struct inode *inode;
	uint8_t mode;

	(void)udata;

	if (unlikely(READ_ONCE(module_exiting)) || !READ_ONCE(hook_active) || !args)
		return;

	mode = READ_ONCE(fsnotify_mode);
	if (mode == HMKPM_FSNOTIFY_OFF)
		return;

	dir   = (struct inode *)args->arg3;
	inode = (struct inode *)args->arg5;
	if (!inode && !dir)
		return;

	hmkpm_enter_in_flight();
	if (unlikely(READ_ONCE(module_exiting)) || !READ_ONCE(hook_active))
		goto out_leave;

	if (mode == HMKPM_FSNOTIFY_CALLER_PIDS) {
		int32_t cur_tgid = 0;
		bool match = false;
		unsigned int i;

		if (!hmkpm_fsnotify_current_tgid(&cur_tgid))
			goto out_leave;

		smp_rmb();
		for (i = 0; i < HMKPM_FSNOTIFY_MAX_PIDS; i++) {
			if (READ_ONCE(fsnotify_caller_pids[i]) == cur_tgid) {
				match = true;
				break;
			}
		}

		if (!match)
			goto out_leave;
	} else if (mode != HMKPM_FSNOTIFY_GLOBAL) {
		goto out_leave;
	}

	if ((inode && is_proc_inode(inode)) ||
	    (dir && dir != inode && is_proc_inode(dir))) {
		args->skip_origin = 1;
		args->ret = 0;
	}

out_leave:
	hmkpm_leave_in_flight();
}

static int hmkpm_parse_pos_pid(const char *s, int32_t *out_pid)
{
	uint64_t val = 0;
	bool has_digit = false;

	s = hmkpm_skip_spaces(s);
	if (!s || !*s)
		return -EINVAL;

	while (*s >= '0' && *s <= '9') {
		has_digit = true;
		val = val * 10ULL + (uint64_t)(*s - '0');
		if (val > 2147483647ULL)
			return -EINVAL;
		s++;
	}

	if (!has_digit || val == 0)
		return -EINVAL;

	s = hmkpm_skip_spaces(s);
	if (*s != '\0')
		return -EINVAL;

	*out_pid = (int32_t)val;
	return 0;
}

static void hmkpm_fsnotify_format_status(char *out_buf, size_t out_cap)
{
	struct hmkpm_strbuf sb;
	bool hooked = READ_ONCE(fsnotify_hooked);
	uint8_t mode = hooked ? READ_ONCE(fsnotify_mode) : HMKPM_FSNOTIFY_OFF;
	bool first = true;
	unsigned int i;

	hmkpm_sb_init(&sb, out_buf, out_cap);
	hmkpm_sb_puts(&sb, "fsnotify: hooked=");
	hmkpm_sb_putc(&sb, hooked ? '1' : '0');
	hmkpm_sb_puts(&sb, " mode=");
	hmkpm_sb_puts(&sb, hmkpm_fsnotify_mode_name(mode));
	hmkpm_sb_puts(&sb, " pids=[");

	smp_rmb();
	for (i = 0; i < HMKPM_FSNOTIFY_MAX_PIDS; i++) {
		int32_t pid = READ_ONCE(fsnotify_caller_pids[i]);

		if (pid <= 0)
			continue;
		if (!first)
			hmkpm_sb_putc(&sb, ',');
		hmkpm_sb_put_i32(&sb, pid);
		first = false;
	}
	hmkpm_sb_puts(&sb, "]\n");
}

bool hmkpm_fsnotify_is_hooked(void)
{
	return READ_ONCE(fsnotify_hooked);
}

uint8_t hmkpm_get_fsnotify_mode(void)
{
	if (!READ_ONCE(fsnotify_hooked))
		return HMKPM_FSNOTIFY_OFF;
	return READ_ONCE(fsnotify_mode);
}

long hmkpm_fsnotify_ctl(const char *subcmd, char *out_buf, size_t out_cap)
{
	const char *cmd = hmkpm_skip_spaces(subcmd);
	const char *arg = NULL;
	struct hmkpm_strbuf sb;

	if (*cmd == '\0' || hmkpm_streq(cmd, "status")) {
		hmkpm_fsnotify_format_status(out_buf, out_cap);
		return 0;
	}

	hmkpm_sb_init(&sb, out_buf, out_cap);

	if (!READ_ONCE(fsnotify_hooked)) {
		hmkpm_sb_puts(&sb, "fsnotify: hook not installed\n");
		return -EOPNOTSUPP;
	}

	if (hmkpm_streq(cmd, "global")) {
		WRITE_ONCE(fsnotify_mode, HMKPM_FSNOTIFY_GLOBAL);
		smp_wmb();
		hmkpm_sb_puts(&sb, "fsnotify: mode=global\n");
		return 0;
	}

	if (hmkpm_streq(cmd, "off")) {
		WRITE_ONCE(fsnotify_mode, HMKPM_FSNOTIFY_OFF);
		smp_wmb();
		hmkpm_sb_puts(&sb, "fsnotify: mode=off\n");
		return 0;
	}

	if (hmkpm_streq(cmd, "pids")) {
		if (!hmkpm_fsnotify_can_resolve_tgid()) {
			hmkpm_sb_puts(&sb, "fsnotify: tgid_offset unavailable\n");
			return -EOPNOTSUPP;
		}
		WRITE_ONCE(fsnotify_mode, HMKPM_FSNOTIFY_CALLER_PIDS);
		smp_wmb();
		hmkpm_sb_puts(&sb, "fsnotify: mode=pids\n");
		return 0;
	}

	if (hmkpm_match_prefix_word(cmd, "add", &arg)) {
		int32_t pid = 0;
		int free_idx = -1;
		unsigned int i;

		if (hmkpm_parse_pos_pid(arg, &pid) != 0) {
			hmkpm_sb_puts(&sb, "fsnotify: invalid pid\n");
			return -EINVAL;
		}

		for (i = 0; i < HMKPM_FSNOTIFY_MAX_PIDS; i++) {
			int32_t cur = READ_ONCE(fsnotify_caller_pids[i]);

			if (cur == pid) {
				hmkpm_sb_puts(&sb, "fsnotify: pid ");
				hmkpm_sb_put_i32(&sb, pid);
				hmkpm_sb_puts(&sb, " already in allowlist\n");
				return 0;
			}
			if (cur <= 0 && free_idx < 0)
				free_idx = (int)i;
		}

		if (free_idx < 0) {
			hmkpm_sb_puts(&sb, "fsnotify: allowlist full\n");
			return -ENOSPC;
		}

		smp_wmb();
		WRITE_ONCE(fsnotify_caller_pids[free_idx], pid);
		smp_wmb();
		hmkpm_sb_puts(&sb, "fsnotify: added pid ");
		hmkpm_sb_put_i32(&sb, pid);
		hmkpm_sb_putc(&sb, '\n');
		return 0;
	}

	if (hmkpm_match_prefix_word(cmd, "del", &arg)) {
		int32_t pid = 0;
		unsigned int i;

		if (hmkpm_parse_pos_pid(arg, &pid) != 0) {
			hmkpm_sb_puts(&sb, "fsnotify: invalid pid\n");
			return -EINVAL;
		}

		for (i = 0; i < HMKPM_FSNOTIFY_MAX_PIDS; i++) {
			if (READ_ONCE(fsnotify_caller_pids[i]) == pid) {
				WRITE_ONCE(fsnotify_caller_pids[i], 0);
				smp_wmb();
				hmkpm_sb_puts(&sb, "fsnotify: removed pid ");
				hmkpm_sb_put_i32(&sb, pid);
				hmkpm_sb_putc(&sb, '\n');
				return 0;
			}
		}

		hmkpm_sb_puts(&sb, "fsnotify: pid ");
		hmkpm_sb_put_i32(&sb, pid);
		hmkpm_sb_puts(&sb, " not found\n");
		return -ENOENT;
	}

	if (hmkpm_streq(cmd, "clear")) {
		unsigned int i;

		for (i = 0; i < HMKPM_FSNOTIFY_MAX_PIDS; i++)
			WRITE_ONCE(fsnotify_caller_pids[i], 0);
		smp_wmb();
		hmkpm_sb_puts(&sb, "fsnotify: allowlist cleared\n");
		return 0;
	}

	hmkpm_sb_puts(&sb, "fsnotify: unknown subcommand. Available: status | global | off | pids | add <pid> | del <pid> | clear\n");
	return -EINVAL;
}

void hmkpm_fsnotify_init(void)
{
	hook_err_t err;
	unsigned int i;

	for (i = 0; i < HMKPM_FSNOTIFY_MAX_PIDS; i++)
		WRITE_ONCE(fsnotify_caller_pids[i], 0);
	WRITE_ONCE(fsnotify_mode, HMKPM_FSNOTIFY_OFF);
	WRITE_ONCE(fsnotify_hooked, false);
	fsnotify_tgid_off = -1;
	kf_fsnotify_task_pid_nr_ns = NULL;

	if (kver < VERSION(5, 10, 0))
		return;

	hmkpm_fsnotify_resolve_offsets();
	kf_fsnotify_task_pid_nr_ns =
		(typeof(kf_fsnotify_task_pid_nr_ns))hmkpm_lookup_symbol("__task_pid_nr_ns");
	fsnotify_addr = hmkpm_lookup_symbol("fsnotify");
	if (!fsnotify_addr) {
		hmkpm_info("fsnotify_addr not found, skipping fsnotify hook\n");
		return;
	}

	err = hook_wrap7((void *)fsnotify_addr, before_fsnotify, 0, 0);
	if (err) {
		hmkpm_error("hook installation of fsnotify failed: %d\n", err);
		WRITE_ONCE(fsnotify_hooked, false);
	} else {
		WRITE_ONCE(fsnotify_hooked, true);
		smp_wmb();
		WRITE_ONCE(fsnotify_mode, HMKPM_FSNOTIFY_GLOBAL);
	}
}

void hmkpm_fsnotify_exit(void)
{
	WRITE_ONCE(fsnotify_mode, HMKPM_FSNOTIFY_OFF);
	smp_wmb();
	if (READ_ONCE(fsnotify_hooked) && fsnotify_addr) {
		hook_unwrap((void *)fsnotify_addr, before_fsnotify, 0);
		WRITE_ONCE(fsnotify_hooked, false);
	}
}
