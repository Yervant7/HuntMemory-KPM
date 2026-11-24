/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026 Yervant7
 *
 * HuntMemory-KPM (HMKPM) Userspace / Kernel Shared Protocol UAPI (v3.0.0)
 *
 * Channel: __NR_getresuid dispatched when arg0 matches a valid HMKPM magic:
 *
 *   syscall(__NR_getresuid, magic, user_buffer, total_len);
 *
 * Contiguous buffer layouts in userspace:
 *   Probe:       [ hmkpm_version_info (80B) ] (optional; NULL/0 for fast ret-only probe)
 *   Single:      [ hmkpm_req (24B) | data[size] ]
 *   Batch:       [ hmkpm_batch_hdr (24B) | hmkpm_batch_entry[count] | data[data_total] ]
 *   V2P:         [ hmkpm_v2p_hdr (16B) | hmkpm_v2p_entry[count] ]
 *   Scan:        [ hmkpm_scan_hdr (64B) | hmkpm_scan_range[range_count] |
 *                  pattern[pattern_len] | mask[pattern_len] |
 *                  matches (uint64_t[max_matches] or hmkpm_scan_val_match[max_matches]) ]
 *   Read Chain:  [ hmkpm_chain_hdr (24B) | hmkpm_chain_req[count] |
 *                  int64_t offsets[total_offsets] | data[data_total] ]
 *   Scan Refine: [ hmkpm_refine_hdr (48B) |
 *                  items (uint64_t[count] or hmkpm_scan_val_match[count]) ]
 *   Enum Region: [ hmkpm_enum_hdr (40B) | hmkpm_region_entry[max_regions] ]
 */

#ifndef _HMKPM_UAPI_H_
#define _HMKPM_UAPI_H_

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Version Information */
#define HMKPM_VERSION_MAJOR		3
#define HMKPM_VERSION_MINOR		0
#define HMKPM_VERSION_PATCH		0
#define HMKPM_VERSION_CODE		(((uint32_t)HMKPM_VERSION_MAJOR << 16) | \
					 ((uint32_t)HMKPM_VERSION_MINOR << 8) | \
					 ((uint32_t)HMKPM_VERSION_PATCH))
#define HMKPM_VERSION_STR		"3.0.0"

/* Protocol Magic Codes */
#define HMKPM_MAGIC			0x484D4B504DULL /* "HMKPM" */
#define HMKPM_MAGIC_READ		(HMKPM_MAGIC + 1)
#define HMKPM_MAGIC_WRITE		(HMKPM_MAGIC + 2)
#define HMKPM_MAGIC_READ_BATCH		(HMKPM_MAGIC + 3)
#define HMKPM_MAGIC_WRITE_BATCH		(HMKPM_MAGIC + 4)
#define HMKPM_MAGIC_V2P_BATCH		(HMKPM_MAGIC + 5)
#define HMKPM_MAGIC_SCAN_KERNEL		(HMKPM_MAGIC + 6)
#define HMKPM_MAGIC_READ_CHAIN		(HMKPM_MAGIC + 7)
#define HMKPM_MAGIC_SCAN_REFINE		(HMKPM_MAGIC + 8)
#define HMKPM_MAGIC_ENUM_REGIONS	(HMKPM_MAGIC + 9)
#define HMKPM_MAGIC_MAX			HMKPM_MAGIC_ENUM_REGIONS

/* Feature Flags */
#define HMKPM_FEATURE_READ		(1ULL << 0)
#define HMKPM_FEATURE_WRITE		(1ULL << 1)
#define HMKPM_FEATURE_READ_BATCH	(1ULL << 2)
#define HMKPM_FEATURE_WRITE_BATCH	(1ULL << 3)
#define HMKPM_FEATURE_V2P_BATCH		(1ULL << 4)
#define HMKPM_FEATURE_SCAN_KERNEL	(1ULL << 5)
#define HMKPM_FEATURE_LOCKLESS		(1ULL << 6)
#define HMKPM_FEATURE_READ_CHAIN	(1ULL << 7)
#define HMKPM_FEATURE_SCAN_REFINE	(1ULL << 8)
#define HMKPM_FEATURE_ENUM_REGIONS	(1ULL << 9)
#define HMKPM_FEATURE_SCAN_EXT		(1ULL << 10)
#define HMKPM_FEATURE_FSNOTIFY_FILTER	(1ULL << 11)
#define HMKPM_ALL_FEATURES		(HMKPM_FEATURE_READ | HMKPM_FEATURE_WRITE | \
					 HMKPM_FEATURE_READ_BATCH | HMKPM_FEATURE_WRITE_BATCH | \
					 HMKPM_FEATURE_V2P_BATCH | HMKPM_FEATURE_SCAN_KERNEL | \
					 HMKPM_FEATURE_READ_CHAIN | HMKPM_FEATURE_SCAN_REFINE | \
					 HMKPM_FEATURE_ENUM_REGIONS | HMKPM_FEATURE_SCAN_EXT)

/* Runtime Telemetry Enumerations */
enum hmkpm_lock_source {
	HMKPM_LOCK_SRC_LOCKLESS		= 0,
	HMKPM_LOCK_SRC_BTF		= 1,
	HMKPM_LOCK_SRC_GKI_VALIDATED	= 2,
	HMKPM_LOCK_SRC_DISASM_LEGACY	= 3,
};

enum hmkpm_sw_pan_mode {
	HMKPM_SW_PAN_OFF		= 0,
	HMKPM_SW_PAN_KERNEL_UACCESS	= 1,
	HMKPM_SW_PAN_MANUAL_TTBR0	= 2,
};

enum hmkpm_fsnotify_mode {
	HMKPM_FSNOTIFY_OFF		= 0,
	HMKPM_FSNOTIFY_GLOBAL		= 1,
	HMKPM_FSNOTIFY_CALLER_PIDS	= 2,
};

/* Transfer & Batch Limits */
#define HMKPM_MAX_BATCH_ENTRIES		65536U
#define HMKPM_MAX_ENTRY_SIZE		(64ULL << 20)
#define HMKPM_MAX_SINGLE_SIZE		(64ULL << 20)
#define HMKPM_MAX_BATCH_TOTAL_SIZE	(128ULL << 20)

/* V2P Page Flags & Limits */
#define HMKPM_PAGE_FLAG_PRESENT		(1U << 0)
#define HMKPM_PAGE_FLAG_RO		(1U << 1)
#define HMKPM_PAGE_FLAG_DIRTY		(1U << 2)
#define HMKPM_PAGE_FLAG_BLOCK		(1U << 3)

#define HMKPM_MAX_V2P_ENTRIES		65536U

/* Scan Types, Operations, Flags, Status & Limits */
enum hmkpm_scan_type {
	HMKPM_SCAN_TYPE_I8	= 1,
	HMKPM_SCAN_TYPE_U8	= 2,
	HMKPM_SCAN_TYPE_I16	= 3,
	HMKPM_SCAN_TYPE_U16	= 4,
	HMKPM_SCAN_TYPE_I32	= 5,
	HMKPM_SCAN_TYPE_U32	= 6,
	HMKPM_SCAN_TYPE_I64	= 7,
	HMKPM_SCAN_TYPE_U64	= 8,
	HMKPM_SCAN_TYPE_F32	= 9,
	HMKPM_SCAN_TYPE_F64	= 10,
	HMKPM_SCAN_TYPE_BYTES	= 11,
};

enum hmkpm_scan_op {
	HMKPM_SCAN_OP_EXACT	= 1,
	HMKPM_SCAN_OP_RANGE	= 2,
	HMKPM_SCAN_OP_MASK	= 3,
	HMKPM_SCAN_OP_NEQ	= 4,
	HMKPM_SCAN_OP_NOT_RANGE	= 5,
};

/*
 * Scan header flags (struct hmkpm_scan_hdr.flags):
 *   Default (0): Early-stop once max_matches entries are stored (when max_matches > 0).
 *   HMKPM_SCAN_FLAG_COUNT_ALL:   Continue scanning all ranges after reaching max_matches
 *                                to compute the exact total match count in matches_found.
 *   HMKPM_SCAN_FLAG_WITH_VALUES: Output struct hmkpm_scan_val_match (va, value) pairs
 *                                instead of bare uint64_t VAs (scalar types I8..F64 only).
 *   HMKPM_SCAN_FLAG_RESUME:      Resume from input (resume_range_idx, resume_va) cursor.
 */
#define HMKPM_SCAN_FLAG_COUNT_ALL	(1U << 0)
#define HMKPM_SCAN_FLAG_WITH_VALUES	(1U << 1)
#define HMKPM_SCAN_FLAG_RESUME		(1U << 2)
#define HMKPM_SCAN_FLAGS_MASK		(HMKPM_SCAN_FLAG_COUNT_ALL | \
					 HMKPM_SCAN_FLAG_WITH_VALUES | \
					 HMKPM_SCAN_FLAG_RESUME)

#define HMKPM_SCAN_STATUS_COMPLETE	0U
#define HMKPM_SCAN_STATUS_TRUNCATED	1U

#define HMKPM_MAX_SCAN_RANGES		4096U
#define HMKPM_MAX_PATTERN_LEN		256U
#define HMKPM_MAX_SCAN_MATCHES		1048576U

/* Pointer Chain Resolution Flags, Status & Limits */
#define HMKPM_CHAIN_FLAG_DEREF_LAST	(1U << 0)
#define HMKPM_CHAIN_FLAG_PTR32		(1U << 1)
#define HMKPM_CHAIN_FLAGS_MASK		(HMKPM_CHAIN_FLAG_DEREF_LAST | HMKPM_CHAIN_FLAG_PTR32)

#define HMKPM_CHAIN_STATUS_OK		0U
#define HMKPM_CHAIN_STATUS_FAULT_HOP	1U
#define HMKPM_CHAIN_STATUS_FAULT_DATA	2U
#define HMKPM_CHAIN_STATUS_BAD_REQ	3U

#define HMKPM_MAX_CHAIN_COUNT		1024U
#define HMKPM_MAX_CHAIN_DEPTH		32U
#define HMKPM_MAX_CHAIN_TOTAL_OFFSETS	16384U
#define HMKPM_MAX_CHAIN_READ_SIZE	4096U
#define HMKPM_MAX_CHAIN_DATA_TOTAL	(4ULL << 20)

/* In-Kernel Scan Refinement Operations, Flags & Limits */
enum hmkpm_refine_op {
	HMKPM_REFINE_OP_EXACT		= 1,
	HMKPM_REFINE_OP_NEQ		= 2,
	HMKPM_REFINE_OP_RANGE		= 3,
	HMKPM_REFINE_OP_NOT_RANGE	= 4,
	HMKPM_REFINE_OP_MASK		= 5,
	HMKPM_REFINE_OP_CHANGED		= 6,
	HMKPM_REFINE_OP_UNCHANGED	= 7,
	HMKPM_REFINE_OP_INCREASED	= 8,
	HMKPM_REFINE_OP_DECREASED	= 9,
};

#define HMKPM_REFINE_FLAG_WITH_VALUES	(1U << 0)
#define HMKPM_REFINE_FLAGS_MASK		(HMKPM_REFINE_FLAG_WITH_VALUES)
#define HMKPM_MAX_REFINE_COUNT		1048576U

/* Mapped-Region Enumeration Flags & Limits */
#define HMKPM_REGION_FLAG_READ		(1U << 0)
#define HMKPM_REGION_FLAG_WRITE		(1U << 1)
#define HMKPM_REGION_FLAG_EXEC		(1U << 2)
#define HMKPM_REGION_FLAG_HAS_BLOCK	(1U << 3)

#define HMKPM_ENUM_FLAG_WRITABLE_ONLY	(1U << 0)
#define HMKPM_ENUM_FLAG_EXEC_ONLY	(1U << 1)
#define HMKPM_ENUM_FLAGS_MASK		(HMKPM_ENUM_FLAG_WRITABLE_ONLY | HMKPM_ENUM_FLAG_EXEC_ONLY)

#define HMKPM_MAX_ENUM_REGIONS		16384U

/* Probe & Version Information (80 bytes) */
struct hmkpm_version_info {
	uint64_t magic;            /* HMKPM_MAGIC */
	uint32_t struct_size;      /* sizeof(struct hmkpm_version_info) == 80 */
	uint32_t version_code;     /* (major << 16) | (minor << 8) | patch */
	uint16_t version_major;    /* e.g. 3 */
	uint16_t version_minor;    /* e.g. 0 */
	uint16_t version_patch;    /* e.g. 0 */
	uint8_t  is_lockless;      /* 1 if running in lockless mode, 0 otherwise */
	uint8_t  lock_source;      /* enum hmkpm_lock_source */
	int32_t  mmap_lock_offset; /* Resolved mmap_lock/sem offset, or -1 if lockless */
	uint32_t page_size;        /* Hardware page granule (4096 or 16384) */
	uint32_t kver;             /* KernelPatch kver: (major << 16) | (minor << 8) | patch */
	uint8_t  va_bits;          /* TTBR0 user VA bit-width (36..48) */
	uint8_t  tbi0;             /* 1 if TCR_EL1.TBI0 is active */
	uint8_t  sw_pan_mode;      /* enum hmkpm_sw_pan_mode */
	uint8_t  fsnotify_mode;    /* enum hmkpm_fsnotify_mode */
	uint64_t features;         /* Active HMKPM_FEATURE_* bitmask */
	uint64_t reserved[2];      /* Reserved for future telemetry (zeroed) */
	char     version_str[16];  /* NUL-terminated version string (e.g. "3.0.0") */
};

/* Single Request Header (24 bytes) */
struct hmkpm_req {
	int32_t  pid;
	uint32_t _pad;
	uint64_t addr;
	uint64_t size;
};

/* Batch Request Header (24 bytes) & Entry (16 bytes) */
struct hmkpm_batch_hdr {
	int32_t  pid;
	uint32_t _pad;
	uint64_t count;
	uint64_t data_total;
};

struct hmkpm_batch_entry {
	uint64_t addr;
	uint64_t size;
};

/* V2P Batch Header (16 bytes) & Entry (24 bytes) */
struct hmkpm_v2p_hdr {
	int32_t  pid;
	uint32_t _pad;
	uint64_t count;
};

struct hmkpm_v2p_entry {
	uint64_t va;
	uint64_t pa;
	uint32_t flags;
	uint32_t page_size;
};

/* Kernel Scan Range (16 bytes), Value Match (16 bytes) & Header (64 bytes) */
struct hmkpm_scan_range {
	uint64_t start_va;
	uint64_t size;
};

struct hmkpm_scan_val_match {
	uint64_t va;
	uint64_t value; /* Zero-extended raw little-endian scalar bits */
};

struct hmkpm_scan_hdr {
	int32_t  pid;
	uint8_t  type;
	uint8_t  op;
	uint8_t  align;
	uint8_t  flags;            /* HMKPM_SCAN_FLAG_* */
	uint32_t range_count;
	uint32_t max_matches;
	uint64_t pattern_len;
	union {
		struct {
			uint64_t val;
			uint64_t mask;
		} exact;
		struct {
			uint64_t min;
			uint64_t max;
		} range_u;
		struct {
			int64_t min;
			int64_t max;
		} range_i;
	} criteria;
	uint64_t matches_found;    /* Output: total matches found (or stored on early-stop) */
	uint64_t resume_va;        /* In/Out: cursor VA when HMKPM_SCAN_FLAG_RESUME or truncated */
	uint32_t resume_range_idx; /* In/Out: cursor range index (== range_count when complete) */
	uint32_t scan_status;      /* Output: HMKPM_SCAN_STATUS_* */
};

/* Pointer Chain Header (24 bytes) & Request (32 bytes) */
struct hmkpm_chain_hdr {
	int32_t  pid;
	uint32_t count;
	uint64_t total_offsets;
	uint64_t data_total;
};

struct hmkpm_chain_req {
	uint64_t base_va;     /* Input: base virtual address */
	uint64_t resolved_va; /* Output: final resolved VA (or faulting hop VA) */
	uint32_t depth;       /* Input: offset count for this chain (0..HMKPM_MAX_CHAIN_DEPTH) */
	uint32_t read_size;   /* Input: requested bytes at resolved_va; Output: actual bytes read */
	uint16_t flags;       /* Input: HMKPM_CHAIN_FLAG_* */
	uint16_t hops_done;   /* Output: number of offsets applied successfully */
	uint32_t status;      /* Output: HMKPM_CHAIN_STATUS_* */
};

/* Scan Refinement Header (48 bytes) */
struct hmkpm_refine_hdr {
	int32_t  pid;
	uint8_t  type;          /* HMKPM_SCAN_TYPE_I8 .. HMKPM_SCAN_TYPE_F64 */
	uint8_t  op;            /* enum hmkpm_refine_op */
	uint8_t  flags;         /* HMKPM_REFINE_FLAG_* */
	uint8_t  _pad;
	uint32_t count;         /* Input: candidate entries count */
	uint32_t max_matches;   /* Input: output cap (0 = count) */
	union {
		struct {
			uint64_t val;
			uint64_t mask;
		} exact;
		struct {
			uint64_t min;
			uint64_t max;
		} range_u;
		struct {
			int64_t min;
			int64_t max;
		} range_i;
	} criteria;
	uint64_t matches_found; /* Output: surviving entries compacted in [0..matches_found-1] */
	uint64_t _reserved;
};

/* Mapped-Region Enumeration Header (40 bytes) & Entry (24 bytes) */
struct hmkpm_enum_hdr {
	int32_t  pid;
	uint32_t flags;         /* HMKPM_ENUM_FLAG_* */
	uint64_t start_va;      /* Input: inclusive start VA (0 = beginning) */
	uint64_t end_va;        /* Input: exclusive end VA (0 = full user VA space) */
	uint32_t max_regions;   /* Input: capacity of trailing hmkpm_region_entry array */
	uint32_t regions_found; /* Output: number of entries written */
	uint64_t next_va;       /* Output: next cursor VA (0 when enumeration complete) */
};

struct hmkpm_region_entry {
	uint64_t start_va;
	uint64_t size;
	uint32_t flags;         /* HMKPM_REGION_FLAG_* */
	uint32_t _pad;
};

#define HMKPM_REQ_SIZE			((uint64_t)sizeof(struct hmkpm_req))
#define HMKPM_BATCH_HDR_SIZE		((uint64_t)sizeof(struct hmkpm_batch_hdr))
#define HMKPM_BATCH_ENTRY_SIZE		((uint64_t)sizeof(struct hmkpm_batch_entry))
#define HMKPM_V2P_HDR_SIZE		((uint64_t)sizeof(struct hmkpm_v2p_hdr))
#define HMKPM_V2P_ENTRY_SIZE		((uint64_t)sizeof(struct hmkpm_v2p_entry))
#define HMKPM_SCAN_HDR_SIZE		((uint64_t)sizeof(struct hmkpm_scan_hdr))
#define HMKPM_SCAN_RANGE_SIZE		((uint64_t)sizeof(struct hmkpm_scan_range))
#define HMKPM_SCAN_VAL_MATCH_SIZE	((uint64_t)sizeof(struct hmkpm_scan_val_match))
#define HMKPM_CHAIN_HDR_SIZE		((uint64_t)sizeof(struct hmkpm_chain_hdr))
#define HMKPM_CHAIN_REQ_SIZE		((uint64_t)sizeof(struct hmkpm_chain_req))
#define HMKPM_REFINE_HDR_SIZE		((uint64_t)sizeof(struct hmkpm_refine_hdr))
#define HMKPM_ENUM_HDR_SIZE		((uint64_t)sizeof(struct hmkpm_enum_hdr))
#define HMKPM_REGION_ENTRY_SIZE		((uint64_t)sizeof(struct hmkpm_region_entry))

#if defined(__cplusplus) && (__cplusplus >= 201103L)
#define HMKPM_STATIC_ASSERT(cond, msg)	static_assert(cond, msg)
#elif defined(__STDC_VERSION__) && (__STDC_VERSION__ >= 201112L)
#define HMKPM_STATIC_ASSERT(cond, msg)	_Static_assert(cond, msg)
#else
#define HMKPM_STATIC_ASSERT(cond, msg)
#endif

HMKPM_STATIC_ASSERT(sizeof(struct hmkpm_version_info) == 80, "hmkpm_version_info size mismatch");
HMKPM_STATIC_ASSERT(sizeof(struct hmkpm_req) == 24, "hmkpm_req size mismatch");
HMKPM_STATIC_ASSERT(sizeof(struct hmkpm_batch_hdr) == 24, "hmkpm_batch_hdr size mismatch");
HMKPM_STATIC_ASSERT(sizeof(struct hmkpm_batch_entry) == 16, "hmkpm_batch_entry size mismatch");
HMKPM_STATIC_ASSERT(sizeof(struct hmkpm_v2p_hdr) == 16, "hmkpm_v2p_hdr size mismatch");
HMKPM_STATIC_ASSERT(sizeof(struct hmkpm_v2p_entry) == 24, "hmkpm_v2p_entry size mismatch");
HMKPM_STATIC_ASSERT(sizeof(struct hmkpm_scan_range) == 16, "hmkpm_scan_range size mismatch");
HMKPM_STATIC_ASSERT(sizeof(struct hmkpm_scan_val_match) == 16, "hmkpm_scan_val_match size mismatch");
HMKPM_STATIC_ASSERT(sizeof(struct hmkpm_scan_hdr) == 64, "hmkpm_scan_hdr size mismatch");
HMKPM_STATIC_ASSERT(sizeof(struct hmkpm_chain_hdr) == 24, "hmkpm_chain_hdr size mismatch");
HMKPM_STATIC_ASSERT(sizeof(struct hmkpm_chain_req) == 32, "hmkpm_chain_req size mismatch");
HMKPM_STATIC_ASSERT(sizeof(struct hmkpm_refine_hdr) == 48, "hmkpm_refine_hdr size mismatch");
HMKPM_STATIC_ASSERT(sizeof(struct hmkpm_enum_hdr) == 40, "hmkpm_enum_hdr size mismatch");
HMKPM_STATIC_ASSERT(sizeof(struct hmkpm_region_entry) == 24, "hmkpm_region_entry size mismatch");

#ifdef __cplusplus
}
#endif

#endif /* _HMKPM_UAPI_H_ */
