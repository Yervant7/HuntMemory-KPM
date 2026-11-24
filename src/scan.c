// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2026 Yervant7
 *
 * HuntMemory-KPM (HMKPM) - In-Kernel Memory Scanner (Integer IEEE-754, Nofault, Subtree Skip)
 */

#include <hmkpm_internal.h>

_Static_assert(HMKPM_SCAN_BUF_SIZE >= 2 * (HMKPM_MAX_PATTERN_LEN - 1),
	       "HMKPM_SCAN_BUF_SIZE must fit maximum cross-page scan window");
_Static_assert((HMKPM_SCAN_MATCH_CHUNK % 2U) == 0,
	       "HMKPM_SCAN_MATCH_CHUNK must be even for value-pair union");
_Static_assert(__builtin_offsetof(struct hmkpm_scan_hdr, resume_va) ==
	       __builtin_offsetof(struct hmkpm_scan_hdr, matches_found) + sizeof(uint64_t),
	       "hmkpm_scan_hdr output tail layout mismatch");
_Static_assert(__builtin_offsetof(struct hmkpm_scan_hdr, resume_range_idx) ==
	       __builtin_offsetof(struct hmkpm_scan_hdr, resume_va) + sizeof(uint64_t),
	       "hmkpm_scan_hdr output tail layout mismatch");
_Static_assert(__builtin_offsetof(struct hmkpm_scan_hdr, scan_status) ==
	       __builtin_offsetof(struct hmkpm_scan_hdr, resume_range_idx) + sizeof(uint32_t),
	       "hmkpm_scan_hdr output tail layout mismatch");
_Static_assert(__builtin_offsetof(struct hmkpm_scan_hdr, scan_status) + sizeof(uint32_t) ==
	       sizeof(struct hmkpm_scan_hdr),
	       "hmkpm_scan_hdr output tail size mismatch");

union hmkpm_scan_match_chunk {
	uint64_t va[HMKPM_SCAN_MATCH_CHUNK];
	struct hmkpm_scan_val_match pair[HMKPM_SCAN_MATCH_CHUNK / 2U];
};

_Static_assert(sizeof(union hmkpm_scan_match_chunk) ==
	       HMKPM_SCAN_MATCH_CHUNK * sizeof(uint64_t),
	       "hmkpm_scan_match_chunk size mismatch");

struct hmkpm_scan_ctx {
	uint8_t type;
	uint8_t op; /* enum hmkpm_scan_op */
	uint64_t pattern_len;
	uint64_t exact_val;
	uint64_t exact_mask;
	uint64_t exact_val_masked;
	uint64_t range_u_min;
	uint64_t range_u_max;
	int64_t range_i_min;
	int64_t range_i_max;
	const uint8_t *pat;
	const uint8_t *mask;
	int32_t f32_min_ord;
	int32_t f32_max_ord;
	int64_t f64_min_ord;
	int64_t f64_max_ord;
};

static inline bool f32_is_nan(uint32_t u)
{
	return ((u & 0x7F800000U) == 0x7F800000U) && (u & 0x007FFFFFU);
}

static inline bool f64_is_nan(uint64_t u)
{
	return ((u & 0x7FF0000000000000ULL) == 0x7FF0000000000000ULL) &&
	       (u & 0x000FFFFFFFFFFFFFULL);
}

static inline int32_t f32_to_orderable(uint32_t u)
{
	if (f32_is_nan(u))
		return (-2147483647 - 1);
	if (u == 0x80000000U)
		return 0;
	if (u & 0x80000000U)
		return -(int32_t)(u & 0x7FFFFFFFU);
	return (int32_t)u;
}

static inline int64_t f64_to_orderable(uint64_t u)
{
	if (f64_is_nan(u))
		return (-9223372036854775807LL - 1);
	if (u == 0x8000000000000000ULL)
		return 0;
	if (u & 0x8000000000000000ULL)
		return -(int64_t)(u & 0x7FFFFFFFFFFFFFFFULL);
	return (int64_t)u;
}

static inline uint32_t hmkpm_scan_type_size(uint8_t type, uint64_t pattern_len)
{
	switch (type) {
	case HMKPM_SCAN_TYPE_I8:
	case HMKPM_SCAN_TYPE_U8:
		return 1;
	case HMKPM_SCAN_TYPE_I16:
	case HMKPM_SCAN_TYPE_U16:
		return 2;
	case HMKPM_SCAN_TYPE_I32:
	case HMKPM_SCAN_TYPE_U32:
	case HMKPM_SCAN_TYPE_F32:
		return 4;
	case HMKPM_SCAN_TYPE_I64:
	case HMKPM_SCAN_TYPE_U64:
	case HMKPM_SCAN_TYPE_F64:
		return 8;
	case HMKPM_SCAN_TYPE_BYTES:
		return (uint32_t)pattern_len;
	default:
		return 0;
	}
}

static inline uint64_t hmkpm_read_scalar_u64(const void *ptr, uint8_t type)
{
	switch (type) {
	case HMKPM_SCAN_TYPE_I8:
	case HMKPM_SCAN_TYPE_U8:
		return (uint64_t)(*(const uint8_t *)ptr);
	case HMKPM_SCAN_TYPE_I16:
	case HMKPM_SCAN_TYPE_U16:
		return (uint64_t)hmkpm_get_unaligned_le16(ptr);
	case HMKPM_SCAN_TYPE_I32:
	case HMKPM_SCAN_TYPE_U32:
	case HMKPM_SCAN_TYPE_F32:
		return (uint64_t)hmkpm_get_unaligned_le32(ptr);
	case HMKPM_SCAN_TYPE_I64:
	case HMKPM_SCAN_TYPE_U64:
	case HMKPM_SCAN_TYPE_F64:
		return hmkpm_get_unaligned_le64(ptr);
	default:
		return 0;
	}
}

static inline bool hmkpm_float_criteria_valid(uint8_t type, uint8_t scan_op,
					      uint64_t exact_val,
					      uint64_t rmin, uint64_t rmax)
{
	if (type == HMKPM_SCAN_TYPE_F32) {
		if (scan_op == HMKPM_SCAN_OP_RANGE || scan_op == HMKPM_SCAN_OP_NOT_RANGE) {
			if (f32_is_nan((uint32_t)rmin) || f32_is_nan((uint32_t)rmax))
				return false;
		} else if (scan_op == HMKPM_SCAN_OP_EXACT || scan_op == HMKPM_SCAN_OP_NEQ) {
			if (f32_is_nan((uint32_t)exact_val))
				return false;
		}
	} else if (type == HMKPM_SCAN_TYPE_F64) {
		if (scan_op == HMKPM_SCAN_OP_RANGE || scan_op == HMKPM_SCAN_OP_NOT_RANGE) {
			if (f64_is_nan(rmin) || f64_is_nan(rmax))
				return false;
		} else if (scan_op == HMKPM_SCAN_OP_EXACT || scan_op == HMKPM_SCAN_OP_NEQ) {
			if (f64_is_nan(exact_val))
				return false;
		}
	}
	return true;
}

static inline void hmkpm_scan_ctx_init(struct hmkpm_scan_ctx *ctx,
				       uint8_t type, uint8_t scan_op,
				       uint64_t pattern_len,
				       uint64_t exact_val, uint64_t exact_mask,
				       uint64_t range_u_min, uint64_t range_u_max,
				       int64_t range_i_min, int64_t range_i_max,
				       const uint8_t *pat, const uint8_t *mask)
{
	ctx->type = type;
	ctx->op = scan_op;
	ctx->pattern_len = pattern_len;
	ctx->exact_val = exact_val;
	ctx->exact_mask = exact_mask;
	ctx->exact_val_masked = exact_val & exact_mask;
	ctx->range_u_min = range_u_min;
	ctx->range_u_max = range_u_max;
	ctx->range_i_min = range_i_min;
	ctx->range_i_max = range_i_max;
	ctx->pat = pat;
	ctx->mask = mask;
	ctx->f32_min_ord = f32_to_orderable((uint32_t)range_u_min);
	ctx->f32_max_ord = f32_to_orderable((uint32_t)range_u_max);
	ctx->f64_min_ord = f64_to_orderable(range_u_min);
	ctx->f64_max_ord = f64_to_orderable(range_u_max);
}

static inline bool hmkpm_check_match(const void *ptr, const struct hmkpm_scan_ctx *ctx)
{
	switch (ctx->type) {
	case HMKPM_SCAN_TYPE_U8: {
		uint8_t v = *(const uint8_t *)ptr;
		uint8_t t = (uint8_t)ctx->exact_val;
		uint8_t lo = (uint8_t)ctx->range_u_min;
		uint8_t hi = (uint8_t)ctx->range_u_max;

		if (ctx->op == HMKPM_SCAN_OP_EXACT)
			return v == t;
		if (ctx->op == HMKPM_SCAN_OP_NEQ)
			return v != t;
		if (ctx->op == HMKPM_SCAN_OP_RANGE)
			return (v >= lo && v <= hi);
		if (ctx->op == HMKPM_SCAN_OP_NOT_RANGE)
			return (v < lo || v > hi);
		if (ctx->op == HMKPM_SCAN_OP_MASK)
			return ((v & (uint8_t)ctx->exact_mask) == (uint8_t)ctx->exact_val_masked);
		break;
	}
	case HMKPM_SCAN_TYPE_I8: {
		int8_t v = *(const int8_t *)ptr;
		int8_t t = (int8_t)ctx->exact_val;
		int8_t lo = (int8_t)ctx->range_i_min;
		int8_t hi = (int8_t)ctx->range_i_max;

		if (ctx->op == HMKPM_SCAN_OP_EXACT)
			return v == t;
		if (ctx->op == HMKPM_SCAN_OP_NEQ)
			return v != t;
		if (ctx->op == HMKPM_SCAN_OP_RANGE)
			return (v >= lo && v <= hi);
		if (ctx->op == HMKPM_SCAN_OP_NOT_RANGE)
			return (v < lo || v > hi);
		if (ctx->op == HMKPM_SCAN_OP_MASK)
			return (((uint8_t)v & (uint8_t)ctx->exact_mask) ==
				(uint8_t)ctx->exact_val_masked);
		break;
	}
	case HMKPM_SCAN_TYPE_U16: {
		uint16_t v = hmkpm_get_unaligned_le16(ptr);
		uint16_t t = (uint16_t)ctx->exact_val;
		uint16_t lo = (uint16_t)ctx->range_u_min;
		uint16_t hi = (uint16_t)ctx->range_u_max;

		if (ctx->op == HMKPM_SCAN_OP_EXACT)
			return v == t;
		if (ctx->op == HMKPM_SCAN_OP_NEQ)
			return v != t;
		if (ctx->op == HMKPM_SCAN_OP_RANGE)
			return (v >= lo && v <= hi);
		if (ctx->op == HMKPM_SCAN_OP_NOT_RANGE)
			return (v < lo || v > hi);
		if (ctx->op == HMKPM_SCAN_OP_MASK)
			return ((v & (uint16_t)ctx->exact_mask) == (uint16_t)ctx->exact_val_masked);
		break;
	}
	case HMKPM_SCAN_TYPE_I16: {
		int16_t v = (int16_t)hmkpm_get_unaligned_le16(ptr);
		int16_t t = (int16_t)ctx->exact_val;
		int16_t lo = (int16_t)ctx->range_i_min;
		int16_t hi = (int16_t)ctx->range_i_max;

		if (ctx->op == HMKPM_SCAN_OP_EXACT)
			return v == t;
		if (ctx->op == HMKPM_SCAN_OP_NEQ)
			return v != t;
		if (ctx->op == HMKPM_SCAN_OP_RANGE)
			return (v >= lo && v <= hi);
		if (ctx->op == HMKPM_SCAN_OP_NOT_RANGE)
			return (v < lo || v > hi);
		if (ctx->op == HMKPM_SCAN_OP_MASK)
			return (((uint16_t)v & (uint16_t)ctx->exact_mask) ==
				(uint16_t)ctx->exact_val_masked);
		break;
	}
	case HMKPM_SCAN_TYPE_U32: {
		uint32_t v = hmkpm_get_unaligned_le32(ptr);
		uint32_t t = (uint32_t)ctx->exact_val;
		uint32_t lo = (uint32_t)ctx->range_u_min;
		uint32_t hi = (uint32_t)ctx->range_u_max;

		if (ctx->op == HMKPM_SCAN_OP_EXACT)
			return v == t;
		if (ctx->op == HMKPM_SCAN_OP_NEQ)
			return v != t;
		if (ctx->op == HMKPM_SCAN_OP_RANGE)
			return (v >= lo && v <= hi);
		if (ctx->op == HMKPM_SCAN_OP_NOT_RANGE)
			return (v < lo || v > hi);
		if (ctx->op == HMKPM_SCAN_OP_MASK)
			return ((v & (uint32_t)ctx->exact_mask) == (uint32_t)ctx->exact_val_masked);
		break;
	}
	case HMKPM_SCAN_TYPE_I32: {
		int32_t v = (int32_t)hmkpm_get_unaligned_le32(ptr);
		int32_t t = (int32_t)ctx->exact_val;
		int32_t lo = (int32_t)ctx->range_i_min;
		int32_t hi = (int32_t)ctx->range_i_max;

		if (ctx->op == HMKPM_SCAN_OP_EXACT)
			return v == t;
		if (ctx->op == HMKPM_SCAN_OP_NEQ)
			return v != t;
		if (ctx->op == HMKPM_SCAN_OP_RANGE)
			return (v >= lo && v <= hi);
		if (ctx->op == HMKPM_SCAN_OP_NOT_RANGE)
			return (v < lo || v > hi);
		if (ctx->op == HMKPM_SCAN_OP_MASK)
			return (((uint32_t)v & (uint32_t)ctx->exact_mask) ==
				(uint32_t)ctx->exact_val_masked);
		break;
	}
	case HMKPM_SCAN_TYPE_U64: {
		uint64_t v = hmkpm_get_unaligned_le64(ptr);
		uint64_t t = ctx->exact_val;
		uint64_t lo = ctx->range_u_min;
		uint64_t hi = ctx->range_u_max;

		if (ctx->op == HMKPM_SCAN_OP_EXACT)
			return v == t;
		if (ctx->op == HMKPM_SCAN_OP_NEQ)
			return v != t;
		if (ctx->op == HMKPM_SCAN_OP_RANGE)
			return (v >= lo && v <= hi);
		if (ctx->op == HMKPM_SCAN_OP_NOT_RANGE)
			return (v < lo || v > hi);
		if (ctx->op == HMKPM_SCAN_OP_MASK)
			return ((v & ctx->exact_mask) == ctx->exact_val_masked);
		break;
	}
	case HMKPM_SCAN_TYPE_I64: {
		int64_t v = (int64_t)hmkpm_get_unaligned_le64(ptr);
		int64_t t = (int64_t)ctx->exact_val;
		int64_t lo = ctx->range_i_min;
		int64_t hi = ctx->range_i_max;

		if (ctx->op == HMKPM_SCAN_OP_EXACT)
			return v == t;
		if (ctx->op == HMKPM_SCAN_OP_NEQ)
			return v != t;
		if (ctx->op == HMKPM_SCAN_OP_RANGE)
			return (v >= lo && v <= hi);
		if (ctx->op == HMKPM_SCAN_OP_NOT_RANGE)
			return (v < lo || v > hi);
		if (ctx->op == HMKPM_SCAN_OP_MASK)
			return (((uint64_t)v & ctx->exact_mask) == ctx->exact_val_masked);
		break;
	}
	case HMKPM_SCAN_TYPE_F32: {
		uint32_t v = hmkpm_get_unaligned_le32(ptr);
		uint32_t target = (uint32_t)ctx->exact_val;

		if (ctx->op == HMKPM_SCAN_OP_EXACT) {
			if (v == target)
				return true;
			if ((v == 0x00000000U || v == 0x80000000U) &&
			    (target == 0x00000000U || target == 0x80000000U))
				return true;
			return false;
		}
		if (ctx->op == HMKPM_SCAN_OP_NEQ) {
			if (f32_is_nan(v))
				return false;
			if (v == target)
				return false;
			if ((v == 0x00000000U || v == 0x80000000U) &&
			    (target == 0x00000000U || target == 0x80000000U))
				return false;
			return true;
		}
		if (ctx->op == HMKPM_SCAN_OP_RANGE || ctx->op == HMKPM_SCAN_OP_NOT_RANGE) {
			int32_t vo;
			bool in_range;

			if (f32_is_nan(v))
				return false;
			vo = f32_to_orderable(v);
			in_range = (vo >= ctx->f32_min_ord && vo <= ctx->f32_max_ord);
			return (ctx->op == HMKPM_SCAN_OP_RANGE) ? in_range : !in_range;
		}
		break;
	}
	case HMKPM_SCAN_TYPE_F64: {
		uint64_t v = hmkpm_get_unaligned_le64(ptr);
		uint64_t target = ctx->exact_val;

		if (ctx->op == HMKPM_SCAN_OP_EXACT) {
			if (v == target)
				return true;
			if ((v == 0x0000000000000000ULL || v == 0x8000000000000000ULL) &&
			    (target == 0x0000000000000000ULL || target == 0x8000000000000000ULL))
				return true;
			return false;
		}
		if (ctx->op == HMKPM_SCAN_OP_NEQ) {
			if (f64_is_nan(v))
				return false;
			if (v == target)
				return false;
			if ((v == 0x0000000000000000ULL || v == 0x8000000000000000ULL) &&
			    (target == 0x0000000000000000ULL || target == 0x8000000000000000ULL))
				return false;
			return true;
		}
		if (ctx->op == HMKPM_SCAN_OP_RANGE || ctx->op == HMKPM_SCAN_OP_NOT_RANGE) {
			int64_t vo;
			bool in_range;

			if (f64_is_nan(v))
				return false;
			vo = f64_to_orderable(v);
			in_range = (vo >= ctx->f64_min_ord && vo <= ctx->f64_max_ord);
			return (ctx->op == HMKPM_SCAN_OP_RANGE) ? in_range : !in_range;
		}
		break;
	}
	case HMKPM_SCAN_TYPE_BYTES: {
		const uint8_t *b = (const uint8_t *)ptr;
		uint64_t plen = ctx->pattern_len;

		if (ctx->op == HMKPM_SCAN_OP_EXACT) {
			for (uint64_t i = 0; i < plen; i++) {
				if (b[i] != ctx->pat[i])
					return false;
			}
			return true;
		}
		if (ctx->op == HMKPM_SCAN_OP_NEQ) {
			for (uint64_t i = 0; i < plen; i++) {
				if (b[i] != ctx->pat[i])
					return true;
			}
			return false;
		}
		if (ctx->op == HMKPM_SCAN_OP_MASK) {
			/* ctx->pat is pre-masked with ctx->mask before entering the scan loop */
			for (uint64_t i = 0; i < plen; i++) {
				if ((b[i] & ctx->mask[i]) != ctx->pat[i])
					return false;
			}
			return true;
		}
		break;
	}
	default:
		break;
	}
	return false;
}

static __noinline int hmkpm_scan_flush_matches(struct mm_struct *mm,
					     void __user *user_matches_ptr,
					     const union hmkpm_scan_match_chunk *chunk,
					     uint32_t *match_chunk_count,
					     uint64_t total_matches_before_inc,
					     uint32_t chunk_cap,
					     bool with_values)
{
	uint64_t write_idx = total_matches_before_inc - chunk_cap + 1;
	size_t elem_sz = with_values ? HMKPM_SCAN_VAL_MATCH_SIZE : sizeof(uint64_t);
	void __user *dst = (void __user *)((uint8_t __user *)user_matches_ptr + write_idx * elem_sz);
	unsigned long not_copied;

	hmkpm_mmap_read_unlock(mm);
	not_copied = hmkpm_copy_to_user(dst, chunk, (unsigned long)chunk_cap * elem_sz);
	if (not_copied != 0)
		return -EFAULT;

	hmkpm_mmap_read_lock(mm);
	*match_chunk_count = 0;
	return 0;
}

static inline bool hmkpm_scan_range_is_empty(const struct hmkpm_scan_ctx *ctx)
{
	if (ctx->op != HMKPM_SCAN_OP_RANGE)
		return false;

	switch (ctx->type) {
	case HMKPM_SCAN_TYPE_U8:
		return (uint8_t)ctx->range_u_min > (uint8_t)ctx->range_u_max;
	case HMKPM_SCAN_TYPE_I8:
		return (int8_t)ctx->range_i_min > (int8_t)ctx->range_i_max;
	case HMKPM_SCAN_TYPE_U16:
		return (uint16_t)ctx->range_u_min > (uint16_t)ctx->range_u_max;
	case HMKPM_SCAN_TYPE_I16:
		return (int16_t)ctx->range_i_min > (int16_t)ctx->range_i_max;
	case HMKPM_SCAN_TYPE_U32:
		return (uint32_t)ctx->range_u_min > (uint32_t)ctx->range_u_max;
	case HMKPM_SCAN_TYPE_I32:
		return (int32_t)ctx->range_i_min > (int32_t)ctx->range_i_max;
	case HMKPM_SCAN_TYPE_U64:
		return ctx->range_u_min > ctx->range_u_max;
	case HMKPM_SCAN_TYPE_I64:
		return ctx->range_i_min > ctx->range_i_max;
	case HMKPM_SCAN_TYPE_F32:
		return ctx->f32_min_ord > ctx->f32_max_ord;
	case HMKPM_SCAN_TYPE_F64:
		return ctx->f64_min_ord > ctx->f64_max_ord;
	default:
		return false;
	}
}

static int hmkpm_scan_write_hdr_out(void __user *user_ptr, uint64_t matches_found,
				    uint64_t resume_va, uint32_t resume_range_idx,
				    uint32_t scan_status)
{
	struct {
		uint64_t matches_found;
		uint64_t resume_va;
		uint32_t resume_range_idx;
		uint32_t scan_status;
	} out_tail;
	void __user *dst = (void __user *)((uint8_t __user *)user_ptr +
					   __builtin_offsetof(struct hmkpm_scan_hdr, matches_found));

	out_tail.matches_found = matches_found;
	out_tail.resume_va = resume_va;
	out_tail.resume_range_idx = resume_range_idx;
	out_tail.scan_status = scan_status;

	if (hmkpm_copy_to_user(dst, &out_tail, sizeof(out_tail)) != 0)
		return -EFAULT;

	return 0;
}

static inline int hmkpm_scan_record_match(struct mm_struct *mm,
					  void __user *user_matches_ptr,
					  union hmkpm_scan_match_chunk *chunk,
					  uint32_t *match_chunk_count,
					  uint64_t *total_matches,
					  uint32_t max_matches,
					  uint32_t chunk_cap,
					  bool with_values,
					  bool stop_on_max,
					  uint64_t match_va,
					  const void *val_ptr,
					  uint8_t type,
					  uint32_t align_step,
					  uint32_t r_idx,
					  uint32_t range_count,
					  uint64_t end_va,
					  uint32_t type_size,
					  bool *scan_done,
					  bool *need_retranslate,
					  uint64_t *out_resume_va,
					  uint32_t *out_resume_range_idx,
					  uint32_t *out_scan_status)
{
	if (*total_matches < (uint64_t)max_matches) {
		if (with_values) {
			chunk->pair[*match_chunk_count].va = match_va;
			chunk->pair[*match_chunk_count].value = hmkpm_read_scalar_u64(val_ptr, type);
		} else {
			chunk->va[*match_chunk_count] = match_va;
		}
		(*match_chunk_count)++;
		if (*match_chunk_count == chunk_cap) {
			int rc = hmkpm_scan_flush_matches(mm, user_matches_ptr, chunk,
							  match_chunk_count, *total_matches,
							  chunk_cap, with_values);
			if (rc != 0)
				return rc;
			*need_retranslate = true;
		}
	} else if (!stop_on_max && max_matches > 0 &&
		   *total_matches == (uint64_t)max_matches) {
		*out_resume_range_idx = r_idx;
		*out_resume_va = match_va;
		*out_scan_status = HMKPM_SCAN_STATUS_TRUNCATED;
	}

	(*total_matches)++;
	if (stop_on_max && *total_matches >= (uint64_t)max_matches) {
		*scan_done = true;
		if (match_va <= U64_MAX - align_step &&
		    match_va + align_step < end_va &&
		    end_va - (match_va + align_step) >= type_size) {
			*out_resume_range_idx = r_idx;
			*out_resume_va = match_va + align_step;
			*out_scan_status = HMKPM_SCAN_STATUS_TRUNCATED;
		} else if (r_idx + 1 < range_count) {
			*out_resume_range_idx = r_idx + 1;
			*out_resume_va = 0;
			*out_scan_status = HMKPM_SCAN_STATUS_TRUNCATED;
		} else {
			*out_resume_range_idx = range_count;
			*out_resume_va = 0;
			*out_scan_status = HMKPM_SCAN_STATUS_COMPLETE;
		}
	}

	return 0;
}

void hmkpm_handle_scan_kernel(hook_fargs3_t *args, void __user *user_ptr, uint64_t total_len)
{
	struct hmkpm_scan_hdr hdr;
	struct hmkpm_scan_ctx ctx;
	uint8_t pattern_buf[HMKPM_MAX_PATTERN_LEN];
	uint8_t mask_buf[HMKPM_MAX_PATTERN_LEN];
	uint8_t scan_buf[HMKPM_SCAN_BUF_SIZE];
	union hmkpm_scan_match_chunk match_chunk;
	uint32_t match_chunk_count = 0;
	uint64_t total_matches = 0;
	uint64_t ranges_bytes;
	uint64_t pattern_bytes = 0;
	uint64_t mask_bytes = 0;
	uint64_t matches_start;
	uint64_t matches_bytes;
	uint64_t total_req_bytes;
	uint32_t type_size;
	uint32_t align_step;
	uint32_t start_r_idx = 0;
	uint64_t resume_in_va = 0;
	uint64_t out_resume_va = 0;
	uint32_t out_resume_range_idx;
	uint32_t out_scan_status = HMKPM_SCAN_STATUS_COMPLETE;
	bool with_values;
	bool is_resume;
	uint32_t chunk_cap;
	size_t match_elem_size;
	bool stop_on_max;
	bool scan_done = false;
	unsigned int pages_walked = 0;
	int rc = 0;
	struct task_struct *task = NULL;
	struct mm_struct *mm = NULL;
	uint64_t pgd = 0;
	void __user *user_matches_ptr;

	if (total_len < HMKPM_SCAN_HDR_SIZE) {
		rc = -EINVAL;
		goto out;
	}

	if (hmkpm_copy_from_user(&hdr, user_ptr, HMKPM_SCAN_HDR_SIZE) != 0) {
		rc = -EFAULT;
		goto out;
	}

	if (hdr.pid <= 0) {
		rc = -EINVAL;
		goto out;
	}

	if (hdr.flags & ~HMKPM_SCAN_FLAGS_MASK) {
		rc = -EINVAL;
		goto out;
	}

	if (hdr.range_count == 0 || hdr.range_count > HMKPM_MAX_SCAN_RANGES) {
		rc = -EINVAL;
		goto out;
	}

	if (hdr.type < HMKPM_SCAN_TYPE_I8 || hdr.type > HMKPM_SCAN_TYPE_BYTES) {
		rc = -EINVAL;
		goto out;
	}

	if (hdr.op < HMKPM_SCAN_OP_EXACT || hdr.op > HMKPM_SCAN_OP_NOT_RANGE) {
		rc = -EINVAL;
		goto out;
	}

	with_values = (hdr.flags & HMKPM_SCAN_FLAG_WITH_VALUES) != 0;
	is_resume = (hdr.flags & HMKPM_SCAN_FLAG_RESUME) != 0;

	if (hdr.type == HMKPM_SCAN_TYPE_BYTES &&
	    (hdr.op == HMKPM_SCAN_OP_RANGE || hdr.op == HMKPM_SCAN_OP_NOT_RANGE || with_values)) {
		rc = -EINVAL;
		goto out;
	}

	if ((hdr.type == HMKPM_SCAN_TYPE_F32 || hdr.type == HMKPM_SCAN_TYPE_F64) &&
	    hdr.op == HMKPM_SCAN_OP_MASK) {
		rc = -EINVAL;
		goto out;
	}

	if (!hmkpm_float_criteria_valid(hdr.type, hdr.op, hdr.criteria.exact.val,
					hdr.criteria.range_u.min, hdr.criteria.range_u.max)) {
		rc = -EINVAL;
		goto out;
	}

	if (is_resume) {
		if (hdr.resume_range_idx > hdr.range_count) {
			rc = -EINVAL;
			goto out;
		}
		start_r_idx = hdr.resume_range_idx;
		resume_in_va = pgt_untag_user_va(hdr.resume_va);
	}

	if (hdr.type == HMKPM_SCAN_TYPE_BYTES) {
		if (hdr.pattern_len == 0 || hdr.pattern_len > HMKPM_MAX_PATTERN_LEN) {
			rc = -EINVAL;
			goto out;
		}
		pattern_bytes = hdr.pattern_len;
		if (hdr.op == HMKPM_SCAN_OP_MASK)
			mask_bytes = hdr.pattern_len;
	}

	type_size = hmkpm_scan_type_size(hdr.type, hdr.pattern_len);
	if (type_size == 0) {
		rc = -EINVAL;
		goto out;
	}

	if (hdr.align == 0) {
		align_step = (type_size <= 8 && hdr.type != HMKPM_SCAN_TYPE_BYTES) ? type_size : 1;
	} else if (hdr.align == 1 || hdr.align == 2 || hdr.align == 4 || hdr.align == 8) {
		align_step = hdr.align;
	} else {
		rc = -EINVAL;
		goto out;
	}

	if (hdr.max_matches > HMKPM_MAX_SCAN_MATCHES) {
		rc = -E2BIG;
		goto out;
	}

	chunk_cap = with_values ? (HMKPM_SCAN_MATCH_CHUNK / 2U) : HMKPM_SCAN_MATCH_CHUNK;
	match_elem_size = with_values ? HMKPM_SCAN_VAL_MATCH_SIZE : sizeof(uint64_t);

	ranges_bytes = (uint64_t)hdr.range_count * HMKPM_SCAN_RANGE_SIZE;
	if (ranges_bytes > U64_MAX - HMKPM_SCAN_HDR_SIZE) {
		rc = -E2BIG;
		goto out;
	}

	matches_start = HMKPM_SCAN_HDR_SIZE + ranges_bytes;
	if (pattern_bytes + mask_bytes > U64_MAX - matches_start) {
		rc = -E2BIG;
		goto out;
	}
	matches_start += pattern_bytes + mask_bytes;

	matches_bytes = (uint64_t)hdr.max_matches * match_elem_size;
	if (matches_bytes > U64_MAX - matches_start) {
		rc = -E2BIG;
		goto out;
	}

	total_req_bytes = matches_start + matches_bytes;
	if (total_len < total_req_bytes) {
		rc = -EINVAL;
		goto out;
	}

	/* Copy pattern and mask if needed */
	if (hdr.type == HMKPM_SCAN_TYPE_BYTES) {
		void __user *pat_ptr = (void __user *)((uint8_t __user *)user_ptr +
						       HMKPM_SCAN_HDR_SIZE + ranges_bytes);
		if (hmkpm_copy_from_user(pattern_buf, pat_ptr, pattern_bytes) != 0) {
			rc = -EFAULT;
			goto out;
		}
		if (hdr.op == HMKPM_SCAN_OP_MASK) {
			void __user *mask_ptr = (void __user *)((uint8_t __user *)pat_ptr + pattern_bytes);
			if (hmkpm_copy_from_user(mask_buf, mask_ptr, mask_bytes) != 0) {
				rc = -EFAULT;
				goto out;
			}
			for (uint64_t i = 0; i < pattern_bytes; i++)
				pattern_buf[i] &= mask_buf[i];
		}
	}

	/* Precompute invariant scan criteria outside inner loops */
	hmkpm_scan_ctx_init(&ctx, hdr.type, hdr.op, hdr.pattern_len,
			    hdr.criteria.exact.val, hdr.criteria.exact.mask,
			    hdr.criteria.range_u.min, hdr.criteria.range_u.max,
			    hdr.criteria.range_i.min, hdr.criteria.range_i.max,
			    pattern_buf, mask_buf);

	/*
	 * Early-stop is the default whenever max_matches > 0 unless the caller
	 * explicitly requests full counting via HMKPM_SCAN_FLAG_COUNT_ALL.
	 */
	stop_on_max = !(hdr.flags & HMKPM_SCAN_FLAG_COUNT_ALL) && (hdr.max_matches > 0);
	out_resume_range_idx = hdr.range_count;

	/* Short-circuit inverted ranges without walking target memory */
	if (hmkpm_scan_range_is_empty(&ctx)) {
		rc = hmkpm_scan_write_hdr_out(user_ptr, 0, 0, hdr.range_count,
					      HMKPM_SCAN_STATUS_COMPLETE);
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

	user_matches_ptr = (void __user *)((uint8_t __user *)user_ptr + matches_start);

	/* Iterate through ranges */
	for (uint32_t r_idx = start_r_idx; r_idx < hdr.range_count && !scan_done; ++r_idx) {
		struct hmkpm_scan_range r;
		void __user *r_ptr = (void __user *)((uint8_t __user *)user_ptr +
						     HMKPM_SCAN_HDR_SIZE +
						     (uint64_t)r_idx * HMKPM_SCAN_RANGE_SIZE);
		if (hmkpm_copy_from_user(&r, r_ptr, HMKPM_SCAN_RANGE_SIZE) != 0) {
			rc = -EFAULT;
			goto out_mm;
		}

		if (r.size == 0)
			continue;

		uint64_t start_va = pgt_untag_user_va(r.start_va);
		if (start_va > U64_MAX - r.size)
			continue;

		uint64_t end_va = start_va + r.size;
		uint64_t cur_va = start_va;

		if (is_resume && r_idx == start_r_idx && resume_in_va > cur_va)
			cur_va = resume_in_va;

		/* Align cur_va to alignment boundary */
		if (cur_va % align_step != 0) {
			uint64_t pad = align_step - (cur_va % align_step);
			if (cur_va > U64_MAX - pad)
				continue;
			cur_va += pad;
		}

		if (cur_va >= end_va || end_va - cur_va < type_size)
			continue;

		while (cur_va < end_va && (end_va - cur_va >= type_size) && !scan_done) {
			uint64_t page_base = cur_va & ~(pgt_page_size - 1);
			uint64_t page_off = cur_va - page_base;
			uint64_t bytes_left_in_page = pgt_page_size - page_off;
			uint64_t bytes_to_scan = min(bytes_left_in_page, end_va - cur_va);
			struct pgt_walk_result walk;
			bool need_retranslate = false;
			bool page_aborted = false;

			hmkpm_mmap_read_lock(mm);

			if (!pgt_walk_va(pgd, cur_va, false, &walk)) {
				/*
				 * Unmapped page or empty upper table: skip the entire
				 * invalid subtree stride (e.g. 2 MiB / 1 GiB) in O(1).
				 */
				uint64_t skip_span = (walk.span_size >= pgt_page_size) ?
						     walk.span_size : pgt_page_size;
				uint64_t skip_base = cur_va & ~(skip_span - 1);

				hmkpm_mmap_read_unlock(mm);

				if ((++pages_walked & 63U) == 0)
					hmkpm_cond_resched();

				if (skip_base > U64_MAX - skip_span)
					break;
				cur_va = skip_base + skip_span;
				if (cur_va % align_step != 0) {
					uint64_t pad = align_step - (cur_va % align_step);
					if (cur_va > U64_MAX - pad)
						break;
					cur_va += pad;
				}
				if (cur_va >= end_va || end_va - cur_va < type_size)
					break;
				continue;
			}

			const uint8_t *tkva = (const uint8_t *)pgt_phys_to_virt(walk.pa);

			/* Scan within the current page via nofault-copied stack slices */
			uint64_t off = 0;
			while (off + type_size <= bytes_to_scan && !scan_done) {
				if (unlikely(need_retranslate)) {
					if (!pgt_walk_va(pgd, cur_va, false, &walk)) {
						page_aborted = true;
						break;
					}
					tkva = (const uint8_t *)pgt_phys_to_virt(walk.pa);
					need_retranslate = false;
				}

				uint64_t copy_len = min((uint64_t)sizeof(scan_buf), bytes_to_scan - off);
				if (hmkpm_copy_from_kernel_nofault(scan_buf, tkva + off, (size_t)copy_len) != 0) {
					page_aborted = true;
					break;
				}

				uint64_t local_off = 0;
				while (local_off + type_size <= copy_len) {
					if (hmkpm_check_match(scan_buf + local_off, &ctx)) {
						uint64_t match_va = cur_va + off + local_off;

						rc = hmkpm_scan_record_match(mm, user_matches_ptr, &match_chunk,
									     &match_chunk_count, &total_matches,
									     hdr.max_matches, chunk_cap,
									     with_values, stop_on_max,
									     match_va, scan_buf + local_off,
									     hdr.type, align_step,
									     r_idx, hdr.range_count,
									     end_va, type_size,
									     &scan_done, &need_retranslate,
									     &out_resume_va,
									     &out_resume_range_idx,
									     &out_scan_status);
						if (rc != 0)
							goto out_mm;
						if (scan_done)
							break;
					}
					local_off += align_step;
				}

				off += local_off;
			}

			/* Handle cross-page split boundary if item straddles page edge */
			if (!scan_done && !page_aborted && off < bytes_to_scan &&
			    (end_va - (cur_va + off) >= type_size) && type_size > 1) {
				if (unlikely(need_retranslate)) {
					if (!pgt_walk_va(pgd, cur_va, false, &walk))
						page_aborted = true;
					else
						tkva = (const uint8_t *)pgt_phys_to_virt(walk.pa);
					need_retranslate = false;
				}

				if (!page_aborted) {
					uint64_t next_page_va = page_base + pgt_page_size;
					struct pgt_walk_result next_walk;

					if (pgt_walk_va(pgd, next_page_va, false, &next_walk)) {
						const uint8_t *next_tkva =
							(const uint8_t *)pgt_phys_to_virt(next_walk.pa);
						uint64_t first_len = bytes_to_scan - off;
						uint64_t second_len = min((uint64_t)(type_size - 1),
									  end_va - next_page_va);

						if (first_len <= sizeof(scan_buf) &&
						    second_len <= sizeof(scan_buf) - first_len &&
						    hmkpm_copy_from_kernel_nofault(scan_buf, tkva + off,
										   (size_t)first_len) == 0 &&
						    hmkpm_copy_from_kernel_nofault(scan_buf + first_len, next_tkva,
										   (size_t)second_len) == 0) {
							uint64_t local_off = 0;
							while (off + local_off < bytes_to_scan &&
							       (end_va - (cur_va + off + local_off) >= type_size)) {
								if (hmkpm_check_match(scan_buf + local_off, &ctx)) {
									uint64_t match_va = cur_va + off + local_off;

									rc = hmkpm_scan_record_match(mm, user_matches_ptr, &match_chunk,
												     &match_chunk_count, &total_matches,
												     hdr.max_matches, chunk_cap,
												     with_values, stop_on_max,
												     match_va, scan_buf + local_off,
												     hdr.type, align_step,
												     r_idx, hdr.range_count,
												     end_va, type_size,
												     &scan_done, &need_retranslate,
												     &out_resume_va,
												     &out_resume_range_idx,
												     &out_scan_status);
									if (rc != 0)
										goto out_mm;
									if (scan_done)
										break;
								}
								local_off += align_step;
							}
						}
					}
				}
			}

			hmkpm_mmap_read_unlock(mm);

			if ((++pages_walked & 63U) == 0)
				hmkpm_cond_resched();

			cur_va += bytes_to_scan;
		}
	}

	/* Flush any pending matches in chunk */
	if (match_chunk_count > 0) {
		uint64_t stored = min(total_matches, (uint64_t)hdr.max_matches);
		uint64_t write_idx = stored - match_chunk_count;
		void __user *dst = (void __user *)((uint8_t __user *)user_matches_ptr +
						   write_idx * match_elem_size);
		if (hmkpm_copy_to_user(dst, &match_chunk,
				       (uint64_t)match_chunk_count * match_elem_size) != 0) {
			rc = -EFAULT;
			goto out_mm;
		}
		match_chunk_count = 0;
	}

	/* Write back matches_found, resume_va, resume_range_idx, and scan_status */
	rc = hmkpm_scan_write_hdr_out(user_ptr, total_matches, out_resume_va,
				      out_resume_range_idx, out_scan_status);

out_mm:
	if (mm) {
		kfunc(mmput)(mm);
		mm = NULL;
	}

out:
	args->ret = (uint64_t)(long)rc;
}

static inline uint8_t hmkpm_refine_op_to_scan_op(uint8_t refine_op)
{
	switch (refine_op) {
	case HMKPM_REFINE_OP_EXACT:
		return HMKPM_SCAN_OP_EXACT;
	case HMKPM_REFINE_OP_NEQ:
		return HMKPM_SCAN_OP_NEQ;
	case HMKPM_REFINE_OP_RANGE:
		return HMKPM_SCAN_OP_RANGE;
	case HMKPM_REFINE_OP_NOT_RANGE:
		return HMKPM_SCAN_OP_NOT_RANGE;
	case HMKPM_REFINE_OP_MASK:
		return HMKPM_SCAN_OP_MASK;
	default:
		return 0;
	}
}

static inline bool hmkpm_cmp_delta_u64(uint64_t cur, uint64_t prev, uint8_t refine_op)
{
	switch (refine_op) {
	case HMKPM_REFINE_OP_CHANGED:
		return cur != prev;
	case HMKPM_REFINE_OP_UNCHANGED:
		return cur == prev;
	case HMKPM_REFINE_OP_INCREASED:
		return cur > prev;
	case HMKPM_REFINE_OP_DECREASED:
		return cur < prev;
	default:
		return false;
	}
}

static inline bool hmkpm_cmp_delta_i64(int64_t cur, int64_t prev, uint8_t refine_op)
{
	switch (refine_op) {
	case HMKPM_REFINE_OP_CHANGED:
		return cur != prev;
	case HMKPM_REFINE_OP_UNCHANGED:
		return cur == prev;
	case HMKPM_REFINE_OP_INCREASED:
		return cur > prev;
	case HMKPM_REFINE_OP_DECREASED:
		return cur < prev;
	default:
		return false;
	}
}

static inline bool hmkpm_check_refine_delta(const void *cur_ptr, uint64_t prev_raw,
					    uint8_t type, uint8_t refine_op)
{
	switch (type) {
	case HMKPM_SCAN_TYPE_U8:
		return hmkpm_cmp_delta_u64((uint64_t)(*(const uint8_t *)cur_ptr),
					   (uint64_t)(uint8_t)prev_raw, refine_op);
	case HMKPM_SCAN_TYPE_I8:
		return hmkpm_cmp_delta_i64((int64_t)(*(const int8_t *)cur_ptr),
					   (int64_t)(int8_t)(uint8_t)prev_raw, refine_op);
	case HMKPM_SCAN_TYPE_U16:
		return hmkpm_cmp_delta_u64((uint64_t)hmkpm_get_unaligned_le16(cur_ptr),
					   (uint64_t)(uint16_t)prev_raw, refine_op);
	case HMKPM_SCAN_TYPE_I16:
		return hmkpm_cmp_delta_i64((int64_t)(int16_t)hmkpm_get_unaligned_le16(cur_ptr),
					   (int64_t)(int16_t)(uint16_t)prev_raw, refine_op);
	case HMKPM_SCAN_TYPE_U32:
		return hmkpm_cmp_delta_u64((uint64_t)hmkpm_get_unaligned_le32(cur_ptr),
					   (uint64_t)(uint32_t)prev_raw, refine_op);
	case HMKPM_SCAN_TYPE_I32:
		return hmkpm_cmp_delta_i64((int64_t)(int32_t)hmkpm_get_unaligned_le32(cur_ptr),
					   (int64_t)(int32_t)(uint32_t)prev_raw, refine_op);
	case HMKPM_SCAN_TYPE_U64:
		return hmkpm_cmp_delta_u64(hmkpm_get_unaligned_le64(cur_ptr),
					   prev_raw, refine_op);
	case HMKPM_SCAN_TYPE_I64:
		return hmkpm_cmp_delta_i64((int64_t)hmkpm_get_unaligned_le64(cur_ptr),
					   (int64_t)prev_raw, refine_op);
	case HMKPM_SCAN_TYPE_F32: {
		uint32_t cur = hmkpm_get_unaligned_le32(cur_ptr);
		uint32_t prev = (uint32_t)prev_raw;

		if (f32_is_nan(cur) || f32_is_nan(prev))
			return false;
		return hmkpm_cmp_delta_i64((int64_t)f32_to_orderable(cur),
					   (int64_t)f32_to_orderable(prev), refine_op);
	}
	case HMKPM_SCAN_TYPE_F64: {
		uint64_t cur = hmkpm_get_unaligned_le64(cur_ptr);

		if (f64_is_nan(cur) || f64_is_nan(prev_raw))
			return false;
		return hmkpm_cmp_delta_i64(f64_to_orderable(cur),
					   f64_to_orderable(prev_raw), refine_op);
	}
	default:
		return false;
	}
}

static int hmkpm_refine_write_count(void __user *user_ptr, uint64_t matches_found)
{
	void __user *dst = (void __user *)((uint8_t __user *)user_ptr +
					   __builtin_offsetof(struct hmkpm_refine_hdr, matches_found));

	if (hmkpm_copy_to_user(dst, &matches_found, sizeof(matches_found)) != 0)
		return -EFAULT;
	return 0;
}

void hmkpm_handle_scan_refine(hook_fargs3_t *args, void __user *user_ptr, uint64_t total_len)
{
	struct hmkpm_refine_hdr hdr;
	struct hmkpm_scan_ctx ctx;
	union {
		uint64_t va[HMKPM_REFINE_CHUNK_BYTES / sizeof(uint64_t)];
		struct hmkpm_scan_val_match pair[HMKPM_REFINE_CHUNK_BYTES / HMKPM_SCAN_VAL_MATCH_SIZE];
	} in_chunk, out_chunk;
	bool with_values;
	bool is_delta_op;
	uint8_t scan_op = 0;
	uint32_t type_size;
	uint32_t chunk_cap;
	size_t elem_size;
	uint64_t items_bytes;
	uint64_t cap;
	uint64_t out_written = 0;
	uint32_t in_idx = 0;
	unsigned int chunk_iters = 0;
	int rc = 0;
	struct task_struct *task = NULL;
	struct mm_struct *mm = NULL;
	uint64_t pgd = 0;
	uint8_t __user *items_base;

	if (total_len < HMKPM_REFINE_HDR_SIZE) {
		rc = -EINVAL;
		goto out;
	}

	if (hmkpm_copy_from_user(&hdr, user_ptr, HMKPM_REFINE_HDR_SIZE) != 0) {
		rc = -EFAULT;
		goto out;
	}

	if (hdr.pid <= 0) {
		rc = -EINVAL;
		goto out;
	}

	if (hdr.flags & ~HMKPM_REFINE_FLAGS_MASK) {
		rc = -EINVAL;
		goto out;
	}

	if (hdr.type < HMKPM_SCAN_TYPE_I8 || hdr.type > HMKPM_SCAN_TYPE_F64) {
		rc = -EINVAL;
		goto out;
	}

	if (hdr.op < HMKPM_REFINE_OP_EXACT || hdr.op > HMKPM_REFINE_OP_DECREASED) {
		rc = -EINVAL;
		goto out;
	}

	with_values = (hdr.flags & HMKPM_REFINE_FLAG_WITH_VALUES) != 0;
	is_delta_op = (hdr.op >= HMKPM_REFINE_OP_CHANGED);

	if (is_delta_op && !with_values) {
		rc = -EINVAL;
		goto out;
	}

	if (!is_delta_op) {
		scan_op = hmkpm_refine_op_to_scan_op(hdr.op);
		if (scan_op == 0) {
			rc = -EINVAL;
			goto out;
		}
		if ((hdr.type == HMKPM_SCAN_TYPE_F32 || hdr.type == HMKPM_SCAN_TYPE_F64) &&
		    scan_op == HMKPM_SCAN_OP_MASK) {
			rc = -EINVAL;
			goto out;
		}
		if (!hmkpm_float_criteria_valid(hdr.type, scan_op, hdr.criteria.exact.val,
						hdr.criteria.range_u.min, hdr.criteria.range_u.max)) {
			rc = -EINVAL;
			goto out;
		}
	}

	if (hdr.count > HMKPM_MAX_REFINE_COUNT) {
		rc = -E2BIG;
		goto out;
	}

	type_size = hmkpm_scan_type_size(hdr.type, 0);
	if (type_size == 0) {
		rc = -EINVAL;
		goto out;
	}

	elem_size = with_values ? HMKPM_SCAN_VAL_MATCH_SIZE : sizeof(uint64_t);
	chunk_cap = with_values ? (HMKPM_REFINE_CHUNK_BYTES / HMKPM_SCAN_VAL_MATCH_SIZE) :
				  (HMKPM_REFINE_CHUNK_BYTES / sizeof(uint64_t));

	items_bytes = (uint64_t)hdr.count * elem_size;
	if (items_bytes > U64_MAX - HMKPM_REFINE_HDR_SIZE) {
		rc = -E2BIG;
		goto out;
	}

	if (total_len < HMKPM_REFINE_HDR_SIZE + items_bytes) {
		rc = -EINVAL;
		goto out;
	}

	if (hdr.count == 0) {
		rc = hmkpm_refine_write_count(user_ptr, 0);
		goto out;
	}

	hmkpm_scan_ctx_init(&ctx, hdr.type, scan_op, 0,
			    hdr.criteria.exact.val, hdr.criteria.exact.mask,
			    hdr.criteria.range_u.min, hdr.criteria.range_u.max,
			    hdr.criteria.range_i.min, hdr.criteria.range_i.max,
			    NULL, NULL);

	if (!is_delta_op && hmkpm_scan_range_is_empty(&ctx)) {
		rc = hmkpm_refine_write_count(user_ptr, 0);
		goto out;
	}

	cap = (hdr.max_matches == 0 || hdr.max_matches > hdr.count) ? hdr.count : hdr.max_matches;

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

	items_base = (uint8_t __user *)user_ptr + HMKPM_REFINE_HDR_SIZE;

	while (in_idx < hdr.count && out_written < cap) {
		uint32_t batch = hdr.count - in_idx;
		uint32_t out_n = 0;
		struct hmkpm_pt_cache cache;
		void __user *in_ptr;
		uint32_t i;

		if (batch > chunk_cap)
			batch = chunk_cap;

		in_ptr = (void __user *)(items_base + (uint64_t)in_idx * elem_size);
		if (hmkpm_copy_from_user(&in_chunk, in_ptr, (uint64_t)batch * elem_size) != 0) {
			rc = -EFAULT;
			goto out_mm;
		}

		hmkpm_pt_cache_init(&cache);
		hmkpm_mmap_read_lock(mm);

		for (i = 0; i < batch && (out_written + out_n) < cap; i++) {
			uint64_t orig_va = with_values ? in_chunk.pair[i].va : in_chunk.va[i];
			uint8_t val_buf[8];
			bool matched;

			if (!hmkpm_read_locked_cached(&cache, pgd, orig_va, val_buf, type_size))
				continue;

			if (is_delta_op) {
				matched = hmkpm_check_refine_delta(val_buf, in_chunk.pair[i].value,
								   hdr.type, hdr.op);
			} else {
				matched = hmkpm_check_match(val_buf, &ctx);
			}

			if (matched) {
				if (with_values) {
					out_chunk.pair[out_n].va = orig_va;
					out_chunk.pair[out_n].value = hmkpm_read_scalar_u64(val_buf, hdr.type);
				} else {
					out_chunk.va[out_n] = orig_va;
				}
				out_n++;
			}
		}

		hmkpm_mmap_read_unlock(mm);

		if (out_n > 0) {
			void __user *out_ptr = (void __user *)(items_base + out_written * elem_size);

			if (hmkpm_copy_to_user(out_ptr, &out_chunk, (uint64_t)out_n * elem_size) != 0) {
				rc = -EFAULT;
				goto out_mm;
			}
			out_written += out_n;
		}

		in_idx += batch;
		if ((++chunk_iters & 15U) == 0)
			hmkpm_cond_resched();
	}

	rc = hmkpm_refine_write_count(user_ptr, out_written);

out_mm:
	if (mm) {
		kfunc(mmput)(mm);
		mm = NULL;
	}

out:
	args->ret = (uint64_t)(long)rc;
}
