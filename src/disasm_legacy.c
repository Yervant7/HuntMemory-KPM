// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2026 Yervant7
 *
 * HuntMemory-KPM (HMKPM) - Legacy ARM64 Disassembler for mmap_sem Offset (< 5.10)
 */

#include <hmkpm_internal.h>

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
	 * 64-bit STXR / STLXR (LL/SC Store-Exclusive)
	 */
	if ((insn & 0xffe0fc00) == 0xc8007c00 || /* STXR */
	    (insn & 0xffe0fc00) == 0xc800fc00) { /* STLXR */
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

	/* ORR Xd, Xm, XZR */
	if ((insn & 0xfffffc00) == 0xaa1f0000) {
		*rd = a64_insn_rd(insn);
		*rm = a64_insn_rn(insn);
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

	/* ORR Wd, Wm, WZR */
	if ((insn & 0xfffffc00) == 0x2a1f0000) {
		*rd = a64_insn_rd(insn);
		*rm = a64_insn_rn(insn);
		*is64 = false;
		return true;
	}

	/* ADD Xd, Xm, #0 */
	if ((insn & 0xfffffc00) == 0x91000000) {
		*rd = a64_insn_rd(insn);
		*rm = a64_insn_rn(insn);
		*is64 = true;
		return true;
	}

	/* ADD Wd, Wm, #0 */
	if ((insn & 0xfffffc00) == 0x11000000) {
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

	/* Branch instructions (B.cond, CBZ, CBNZ, TBZ, TBNZ, B) do not write to registers */
	if ((insn & 0xff000010) == 0x54000000 || /* B.cond */
	    (insn & 0x7e000000) == 0x34000000 || /* CBZ / CBNZ */
	    (insn & 0x7e000000) == 0x36000000 || /* TBZ / TBNZ */
	    (insn & 0xfc000000) == 0x14000000)   /* B */
		return false;

	/* STR (immediate 32/64-bit) -> reg in [4:0] is data stored, not destination */
	if ((insn & 0xbfc00000) == 0xb9000000)
		return false;

	/* STRB / STRH (immediate) -> reg in [4:0] is data stored */
	if ((insn & 0xffc00000) == 0x39000000 || /* STRB */
	    (insn & 0xffc00000) == 0x79000000)   /* STRH */
		return false;

	/* STP (32-bit and 64-bit store pair) -> reg in [4:0] is only stored data */
	if ((insn & 0x3e400000) == 0x28000000)
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

			if (find_offset_before_pc_reg(pc, atomic_rn, &off) == 0)
				add_probe_vote(off, func_idx);
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
		int pop = hweight32(probe_votes[i].func_mask);

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

int find_mm_mmap_sem_offset(unsigned int *offset)
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
	hmkpm_memzero(probe_votes, sizeof(probe_votes));

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
