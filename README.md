# HuntMemory-KPM (HMKPM)

<p align="center">
  <img src="https://img.shields.io/badge/Architecture-ARM64%20(aarch64)-blue?style=for-the-badge" alt="Architecture">
  <img src="https://img.shields.io/badge/Kernel%20Support-4.14%20--%206.12-green?style=for-the-badge" alt="Kernel Support">
  <img src="https://img.shields.io/badge/Framework-KernelPatch%20>=%200.13.9-orange?style=for-the-badge" alt="KernelPatch Module">
  <img src="https://img.shields.io/badge/License-GPL%202.0-red?style=for-the-badge" alt="License">
</p>

---

## Overview

**HuntMemory-KPM (`HMKPM`)** is a pure-C **KernelPatch Module (KPM)** for ARM64 (`aarch64`) Android/Linux kernels (**4.14** up to **< 6.13.0**).

It provides direct process memory read, write, virtual-to-physical (`V2P`) translation, and in-kernel memory scanning by walking hardware page tables (MMU translation) directly in kernel space, reducing the context-switch and per-call overhead compared to standard userspace interfaces such as `ptrace` or `process_vm_readv`.

---

## Features

- **Unified Hardware Page Table Walker & Region Enumeration (`src/mmu.c`)**:
  - Translates target virtual addresses (VA) directly into physical addresses (PA) and kernel linear-map addresses via target `mm_struct->pgd`.
  - Supports **4KB** and **16KB** page granules (`TG0`) and **36-bit to 48-bit** user virtual address spaces (`T0SZ` from `TCR_EL1`).
  - Full support for Level 1 and Level 2 **Block descriptors (HugePages)**, `APTable[2]` (`PTATTR_RDONLY`) propagation, `PTE_RDONLY`/Hardware DBM (`bit 51`), and `PTE_USER` checks.
  - **`MAIR_EL1` Normal-Memory Validation**: classifies `MAIR_EL1` attribute indices at load time and rejects Device/MMIO descriptors to prevent synchronous external aborts (`SError`), while preserving Normal WB/WT/NC and ARMv8.5 MTE Tagged Normal (`0xF0`) mappings.
  - ARM64 **Tagged Pointer (`TBI0`)** unwrapping gated by `TCR_EL1.TBI0`.
  - **Page-Table Region Enumeration (`HMKPM_MAGIC_ENUM_REGIONS`)**: iteratively walks `PGD→PUD→PMD→PTE` with zero VMA/Maple Tree dependency across `4.14–6.12`, coalescing contiguous resident spans with matching `R/W/X` permissions, supporting `WRITABLE_ONLY` / `EXEC_ONLY` filters and lossless cursor pagination.

- **Single, Coalesced Batch, V2P & Pointer Chain I/O (`src/io.c`)**:
  - **Single I/O**: read/write transfers up to **64 MB** per syscall using a stack-bounded 1024-byte bounce buffer and `copy_from_kernel_nofault` / `copy_to_kernel_nofault`.
  - **Batch I/O**: multi-address read/write transfers up to **65,536 entries** and **128 MB** per syscall, processed in chunks of 32 entries with a coalesced fast-path (1-entry page/block translation cache) for contiguous small `READ_BATCH` entries.
  - **In-Kernel Pointer Chain Resolution (`HMKPM_MAGIC_READ_CHAIN`)**: resolves up to **1,024** multi-hop pointer chains (`depth <= 32`, signed `int64_t` offsets, optional `DEREF_LAST` and `PTR32`, safe cross-page pointer reads) and optionally reads final target data in a single syscall.
  - **Deadlock-Safe Locking**: `copy_from_user` / `copy_to_user` always execute strictly **outside** target `mmap_lock` / `mmap_sem`, with cooperative `_cond_resched()` scheduling points across long loops.
  - **ARM64 Cache Coherency**: writes to EL0-executable pages (`!PTE_UXN`) automatically synchronize D-cache to PoU (`dc cvau`) and invalidate I-cache (`ic ialluis`), respecting `CTR_EL0.IDC` and `CTR_EL0.DIC`.
  - **Batch V2P Translation**: resolves up to **65,536** VAs per call, returning physical address, page flags (`PRESENT`, `RO`, `DIRTY`, `BLOCK`), and mapping size.

- **Accelerated In-Kernel Memory Scanner & Refinement (`src/scan.c`)**:
  - Scans up to **4,096** virtual ranges per call across `I8`–`U64`, `F32`/`F64` (order-preserving integer IEEE-754 arithmetic under `-mgeneral-regs-only`), and masked `BYTES` patterns up to 256 bytes, including cross-page boundary matches.
  - **Extended Operators, Value Pairs & Cursor Pagination**: supports `EXACT`, `NEQ`, `RANGE`, `NOT_RANGE`, and `MASK`, optional `(va, value)` pair output (`HMKPM_SCAN_FLAG_WITH_VALUES`), and resumable cursor pagination (`HMKPM_SCAN_FLAG_RESUME`, `resume_va`, `resume_range_idx`, `scan_status`).
  - **In-Kernel Scan Refinement (`HMKPM_MAGIC_SCAN_REFINE`)**: filters up to **1,048,576** candidate addresses or `(va, value)` pairs directly in kernel space (`EXACT`, `NEQ`, `RANGE`, `NOT_RANGE`, `MASK`, `CHANGED`, `UNCHANGED`, `INCREASED`, `DECREASED`) with *in-place* compaction and updated scalar values.
  - **O(1) Empty-Subtree Skipping**: skips unmapped upper page-table entries (`2 MiB`, `32 MiB`, `1 GiB`, etc.) in a single walk step.
  - **Default Early-Stop Contract**: stops immediately once `max_matches` results are collected (`flags == 0`, when `max_matches > 0`), or counts all matches across every range when `HMKPM_SCAN_FLAG_COUNT_ALL` is set.

- **`/proc` fsnotify Event Filter (`src/fsnotify_filter.c`)**:
  - On kernels `>= 5.10.0`, registers an `fsnotify` callback to filter events for `PROC_SUPER_MAGIC` (`0x9fa0`) inodes.
  - Dynamically resolves `inode.i_sb` and `super_block.s_magic` offsets via KernelPatch BTF when available (with GKI fallback) and uses `copy_from_kernel_nofault` for every dereference.
  - Supports runtime scoping via `KPM_CTL0`: `global` (all processes), `off` (disabled), or `pids` (caller-TGID allowlist up to 8 entries via `task_struct_offset.tgid_offset`).

- **Universal Kernel Compatibility (Linux 4.14 to < 6.13.0)**:
  - **Android GKI & Modern Kernels (`5.10–6.12`)**: resolves `mm_struct->mmap_lock` via KernelPatch BTF first, falling back to a layout-validated GKI offset table (or safe read-only *lockless* mode if layout invariants do not match).
  - **Pre-5.10 OEM/Non-GKI Kernels (`4.14–5.4`)**: stabilized runtime ARM64 disassembler (`src/disasm_legacy.c`) with consensus voting to locate `mm_struct->mmap_sem`.
  - **Software PAN (`src/sw_pan.c`)**: supports `CONFIG_ARM64_SW_TTBR0_PAN` via kernel `_copy_from_user`/`_copy_to_user` or validated `reserved_pg_dir`/`reserved_ttbr0` fallback.
  - **Safe Unload Lifecycle**: tracks in-flight syscalls with inline ARM64 LL/SC atomics and drains active callers cleanly during `KPM_EXIT`.

- **Shared Userspace/Kernel UAPI (`include/hmkpm_uapi.h`)**:
  - Standalone C11/C++17 header defining all version constants, magics, feature flags, protocol structs, and compile-time `_Static_assert` size checks.

---

## System Requirements

| Requirement | Specification |
| :--- | :--- |
| **Target Architecture** | ARM64 (`aarch64`) |
| **Kernel Version** | Linux `4.14.0` up to `< 6.13.0` |
| **Framework** | [KernelPatch](https://github.com/bmax121/KernelPatch) `>= 0.13.9` (APatch / KernelPatch / [KPM-Manager](https://github.com/Yervant7/KPM-Manager)) |
| **Vendored Headers** | `KPM-Headers/` (KernelPatch `0.13.9`, vendored directly in-tree — no git submodules required) |
| **Compiler** | GCC ARM64 Cross-Compiler (`aarch64-none-elf-gcc` 12.2+ or `aarch64-linux-gnu-gcc`) |

---

## Repository Layout

```text
HuntMemory-KPM/
├── include/
│   └── hmkpm_uapi.h         # Shared C/C++ userspace & kernel protocol UAPI (v3.0.0)
├── src/
│   ├── hmkpm_internal.h     # Internal kernel declarations, inline atomics & helpers
│   ├── main.c               # KPM lifecycle, BTF mmap_lock resolution, syscall dispatch
│   ├── sw_pan.c             # Software PAN detection & user-memory transfer wrappers
│   ├── mmu.c                # TCR_EL1/MAIR_EL1 setup, pgt_walk_va() & ENUM_REGIONS
│   ├── io.c                 # Single, Batch, V2P, READ_CHAIN & ARM64 I-Cache sync
│   ├── scan.c               # In-kernel scanner (SCAN_KERNEL & SCAN_REFINE)
│   ├── fsnotify_filter.c    # /proc fsnotify event filter (BTF + nofault + PID scoping)
│   └── disasm_legacy.c      # Legacy ARM64 disassembler for mmap_sem (< 5.10)
├── KPM-Headers/             # Vendored KernelPatch 0.13.9 headers (read-only)
└── Makefile                 # Cross-compiles src/*.c and links single hmkpm.kpm (ld -r)
```

---

## Building from Source

```bash
git clone https://github.com/Yervant7/HuntMemory-KPM.git
cd HuntMemory-KPM
make
```

To use a custom cross-compiler prefix:

```bash
make TARGET_COMPILE=aarch64-linux-gnu-
```

This compiles all translation units under `src/` and produces a single relocatable KernelPatch module `hmkpm.kpm` (`ld -r`) in the repository root.

---

## Protocol & Architecture

HuntMemory-KPM dispatches `__NR_getresuid` for UID 0 callers when `arg0` matches one of the defined magic codes (see [include/hmkpm_uapi.h](include/hmkpm_uapi.h)):

```c
syscall(__NR_getresuid, magic, user_buffer, total_size);
```

### Magic Codes

| Identifier | Value | Operation |
| :--- | :--- | :--- |
| `HMKPM_MAGIC` | `0x484D4B504D` | Handshake / Probe (returns version in `ret` & optional `struct hmkpm_version_info`) |
| `HMKPM_MAGIC_READ` | `0x484D4B504E` | Single Process Memory Read |
| `HMKPM_MAGIC_WRITE` | `0x484D4B504F` | Single Process Memory Write |
| `HMKPM_MAGIC_READ_BATCH` | `0x484D4B5050` | Batch Process Memory Read |
| `HMKPM_MAGIC_WRITE_BATCH` | `0x484D4B5051` | Batch Process Memory Write |
| `HMKPM_MAGIC_V2P_BATCH` | `0x484D4B5052` | Direct Virtual-to-Physical Translation Batch |
| `HMKPM_MAGIC_SCAN_KERNEL` | `0x484D4B5053` | Accelerated In-Kernel Memory Scanner |
| `HMKPM_MAGIC_READ_CHAIN` | `0x484D4B5054` | In-Kernel Multi-Hop Pointer Chain Resolution |
| `HMKPM_MAGIC_SCAN_REFINE` | `0x484D4B5055` | In-Kernel Scan Candidate Refinement (*in-place*) |
| `HMKPM_MAGIC_ENUM_REGIONS` | `0x484D4B5056` | Hardware Page-Table Mapped-Region Enumeration |

### Memory Layouts

#### 1. Probe / Handshake Layout
```c
#include "hmkpm_uapi.h"

struct hmkpm_version_info version_info; // 80 bytes (v3.0.0 telemetry)
long ret = syscall(__NR_getresuid, HMKPM_MAGIC, &version_info, sizeof(version_info));
// ret: ((HMKPM_VERSION_CODE << 40) | HMKPM_MAGIC)
// version_info.struct_size: 80, version_info.version_str: "3.0.0"
// Fast ret-only probe: syscall(__NR_getresuid, HMKPM_MAGIC, NULL, 0);
// Passing a non-NULL invalid pointer or mismatched (ptr, len) returns -EINVAL.
```

#### 2. Single Request Layout
```text
[ struct hmkpm_req (24 bytes) ] [ Data Buffer (size bytes) ]
```

#### 3. Batch Request Layout
```text
[ struct hmkpm_batch_hdr (24 bytes) ]
[ struct hmkpm_batch_entry[count] (16 bytes each) ]
[ Data Buffer (data_total bytes) ]
```

#### 4. V2P Batch Layout
```text
[ struct hmkpm_v2p_hdr (16 bytes) ]
[ struct hmkpm_v2p_entry[count] (24 bytes each) ]
```

#### 5. Kernel Memory Scan Layout
```text
[ struct hmkpm_scan_hdr (64 bytes) ]
[ struct hmkpm_scan_range[range_count] (16 bytes each) ]
[ Pattern / Mask Bytes (optional) ]
[ Output Matches: uint64_t[max_matches] or struct hmkpm_scan_val_match[max_matches] ]
```

#### 6. Pointer Chain Read Layout
```text
[ struct hmkpm_chain_hdr (24 bytes) ]
[ struct hmkpm_chain_req[count] (32 bytes each) ]
[ int64_t offsets[total_offsets] (8 bytes each) ]
[ Data Buffer (data_total bytes) ]
```

#### 7. Scan Refinement Layout
```text
[ struct hmkpm_refine_hdr (48 bytes) ]
[ Candidates (in-place): uint64_t[count] or struct hmkpm_scan_val_match[count] ]
```

#### 8. Mapped-Region Enumeration Layout
```text
[ struct hmkpm_enum_hdr (40 bytes) ]
[ struct hmkpm_region_entry[max_regions] (24 bytes each) ]
```

---

## Runtime Control Interface

HuntMemory-KPM supports runtime control commands via `kpmctl` or the KernelPatch `KPM_CTL0` interface:

| Command | Action |
| :--- | :--- |
| `enable` / `on` / `start` / `1` | Enable syscall dispatch and `/proc` event filtering |
| `disable` / `off` / `stop` / `0` | Disable syscall dispatch and `/proc` event filtering |
| `status` / `state` / `get` | Query current status (`active` / `inactive`) |
| `toggle` | Toggle current active state |
| `info` / `diag` | Query compact runtime telemetry (`ver`, `active`, `kver`, `page`, `va`, `tbi0`, `lock`, `sw_pan`, `fsnotify`) |
| `fsnotify [status\|global\|off\|pids\|add <pid>\|del <pid>\|clear]` | Configure or inspect `/proc` `fsnotify` event filtering scope |

---

## License

This project is licensed under the **GNU General Public License (GPL) 2.0**.
See the [LICENSE](LICENSE) file or visit [GNU GPL 2.0](https://www.gnu.org/licenses/old-licenses/gpl-2.0.html) for full details.

---

## Author

- **Yervant7** – [GitHub Profile](https://github.com/Yervant7)
