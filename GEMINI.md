# GEMINI.md — HuntMemory-KPM (HMKPM)

Technical reference and development guidelines for agents and maintainers of the **HuntMemory-KPM** repository.

> **Language Rule:** Keep `GEMINI.md`, repository documentation, and code comments strictly in **English**. Always update `GEMINI.md` in English regardless of the conversation language.

---

## 1. Overview

**HuntMemory-KPM (`HMKPM`)** is a pure-C **KernelPatch Module (KPM)** for **ARM64 (`aarch64`)**, targeting Linux/Android kernels **4.14 to 6.12** (`4.14.0 <= kver < 6.13.0`).

It provides kernel-space memory reading, writing, virtual-to-physical (`V2P`) translation, and memory scanning directly via **hardware page table walking (MMU)**, exposing a communication channel through a `__NR_getresuid` syscall dispatch hook and filtering `/proc` fsnotify events via an `fsnotify` hook.

> **Important:** This project is **not** a standard LKM (`.ko`). The final build artifact is a relocatable object `hmkpm.kpm` (`ld -r`) loaded by the **KernelPatch** framework.

---

## 2. Environment & Production Constraints

- **Production target profile:**
  - **Modern Android GKI (`5.10–6.12`)** and **legacy OEM/non-GKI (`4.14–5.4`)**.
  - Runtime: **APatch / KPM-Manager** with **KernelPatch `>= 0.13.9`** (required by `hook_syscalln_override` and KernelPatch BTF exports).
- **Top priority:** **Stability and zero-panic** take precedence over any experimental feature or risky optimization.
- **ABI & structure evolution policy:**
  - The author controls both the KPM module and the userspace client: **the protocol ABI (`include/hmkpm_uapi.h`, `__NR_getresuid`, magic codes, structs) may evolve freely** when needed (always keeping `HMKPM_VERSION_*`, `_Static_assert` checks, and feature flags up to date).
  - The modular layout under `include/` and `src/` must continue linking into the single relocatable object `hmkpm.kpm` via `${LD} -r`.

---

## 3. Frozen, Active, and Untouchable Components

Agents must strictly respect the following boundaries:

| Component | Status | Rule for Agents |
| :--- | :--- | :--- |
| **`KPM-Headers/`** | **Untouchable (read-only)** | Vendored KernelPatch `0.13.9` dependency. **Never** edit files inside this directory. |
| **`src/fsnotify_filter.c` (`/proc` fsnotify event filter)** | **Active requirement** | **Must not be removed.** Only fix or harden it (BTF offsets, `nofault` reads, safe scoping). |
| **`src/disasm_legacy.c` (ARM64 Disassembler for `< 5.10`)** | **Legacy / stabilized** | **Do not refactor or alter** preemptively. Only touch for a proven bug on `< 5.10` kernels. |
| **UAPI Protocol (`include/hmkpm_uapi.h`) & `src/` Modules** | **Evolvable** | May evolve in sync with the userspace client while preserving zero-panic invariants. |

---

## 4. Directory Structure & Key Files

```text
HuntMemory-KPM/
├── include/
│   └── hmkpm_uapi.h                     # Shared C11/C++17 userspace & kernel UAPI (v3.0.0)
├── src/
│   ├── hmkpm_internal.h                 # Internal kernel declarations, LL/SC atomics & helpers
│   ├── main.c                           # KPM lifecycle, BTF mmap_lock resolution, syscall dispatch
│   ├── sw_pan.c                         # Software PAN (CONFIG_ARM64_SW_TTBR0_PAN) & uaccess
│   ├── mmu.c                            # TCR_EL1/MAIR_EL1 setup, pgt_walk_va() & ENUM_REGIONS
│   ├── io.c                             # Single, Batch, V2P, READ_CHAIN I/O & ARM64 I-Cache sync
│   ├── scan.c                           # In-kernel scanner (SCAN_KERNEL & SCAN_REFINE)
│   ├── fsnotify_filter.c                # /proc fsnotify event filter (BTF, nofault & PID scoping)
│   └── disasm_legacy.c                  # [Legacy/stabilized] ARM64 disassembler for mmap_sem (< 5.10)
├── Makefile                             # ARM64 cross-compile build -> single hmkpm.kpm (ld -r)
├── README.md                            # Public overview, build, and protocol documentation
├── GEMINI.md                            # This architecture, constraints, and roadmap guide
├── LICENSE                              # GNU GPL v2.0
├── .gitignore                           # Ignores build artifacts (*.o, *.kpm, *.ko, etc.)
├── .agents/
│   └── rules/
│       ├── kernelpatch-module.md        # KPM environment/safety rules for agents
│       └── terminology.md               # Neutral Linux kernel engineering terminology rule
├── .github/
│   └── workflows/
│       ├── build.yml                    # Automated CI build, nm -u audit, stack check & UAPI check
│       └── release.yml                  # Manual (workflow_dispatch) GitHub Release pipeline
└── KPM-Headers/                         # [READ-ONLY] Vendored KernelPatch 0.13.9 headers/sources
    ├── base/
    ├── include/                         # Public KernelPatch headers (kpmodule.h, hook.h, ktypes.h...)
    ├── linux/                           # Minimal subset of Linux/ARM64 headers
    ├── patch/                           # Internal patch/syscall/ksyms/kbtf headers (patch/include/)
    └── x86/
```

---

## 5. Dependencies & Build

### Build Time
- **Toolchain:** ARM64 GCC cross-compiler (`aarch64-none-elf-` default; configurable via `TARGET_COMPILE=aarch64-linux-gnu-`). CI uses `arm-gnu-toolchain-12.2.rel1-x86_64-aarch64-none-elf`.
- **Headers:** `include/`, `src/`, and `KPM-Headers/` only (configurable via `KP_DIR`). Does not depend on a full Linux kernel header tree.
- **Critical flags (`Makefile`):**
  - `-Wall -Werror=implicit-function-declaration -Wundef -O2 -std=gnu11`
  - `-fno-builtin -fno-builtin-memset -fno-pic -fno-PIC -fno-pie -fno-PIE`
  - `-fno-asynchronous-unwind-tables -fno-unwind-tables -fno-stack-protector -fno-common`
  - `-mgeneral-regs-only` *(forbids FPU/NEON usage; `F32`/`F64` comparisons use IEEE-754 integer arithmetic)*
  - `-mcmodel=small`
  - Optional `EXTRA_CFLAGS` (used by CI for `-Wframe-larger-than=1792`).
- **Linking:** `${LD} -r -o hmkpm.kpm ${objs}`.

### Runtime
- **Framework:** KernelPatch `>= 0.13.9`.
- **Kernel:** ARM64 Linux `4.14.0` up to `< 6.13.0`.
- **Dynamically resolved symbols (`kallsyms_lookup_name` + `.cfi_jt` fallback):**
  - **Required:** `memstart_addr`, `__arch_copy_to_user`/`__copy_to_user`, `__arch_copy_from_user`/`__copy_from_user`, `find_task_by_vpid`, `get_task_mm`, `mmput`, `__rcu_read_lock`, `__rcu_read_unlock`, `copy_from_kernel_nofault`/`probe_kernel_read`, `copy_to_kernel_nofault`/`probe_kernel_write`.
  - **Optional / fallback:** `high_memory` (fallback `~0ULL`), `__arch_clear_user`/`__clear_user`/`clear_user` (fallback `copy_to_user` zero loop), `_copy_from_user`/`_copy_to_user` (preferred under SW PAN), `down_read`/`up_read` (fallback *lockless* mode), `msleep`/`schedule` (unload drain), `__cond_resched`/`_cond_resched` (long-loop yielding), `reserved_pg_dir`/`reserved_ttbr0` + `kimage_voffset`, `kallsyms_lookup_size_offset`, `fsnotify` (`kver >= 5.10.0`), and KernelPatch BTF symbols (`kp_btf_available`, `kp_btf_member_offset`, `kp_btf_type_size`) via `symbol_lookup_name`.

---

## 6. Current Architecture (`v3.0.0`)

| Module | File | Responsibility |
| :--- | :--- | :--- |
| **Shared UAPI** | `include/hmkpm_uapi.h` | Version (`3.0.0`), magics (`0x484D4B504D`..`+9`), feature flags, extended telemetry (`hmkpm_version_info` 80 B), scan/refine/chain/region structs, and C11/C++17 `_Static_assert` checks across all 14 ABI structs. |
| **Internal Header** | `src/hmkpm_internal.h` | Cross-module declarations, inline ARM64 LL/SC atomics (`ldar`/`ldaxr`/`stlxr`), `hmkpm_memzero`, bounded `hmkpm_strbuf` formatting & command parsing, 1-entry `hmkpm_pt_cache` + cross-page `hmkpm_read_locked_cached()`, `nofault` wrappers, `hmkpm_cond_resched`, range & `TBI0` helpers. |
| **Lifecycle & Dispatch** | `src/main.c` | `KPM_*` metadata, CFI-safe symbol lookup, BTF + disassembler/init_mm-validated GKI `mmap_lock` resolution with `mmap_lock_source` tracking, `__NR_getresuid` dispatcher (`+0..+9`) with unified `hmkpm_in_flight` tracking, `KPM_CTL0` (`enable`/`disable`/`status`/`toggle`/`info`/`diag`/`fsnotify` via `hmkpm_copy_to_user`), defensive `unhook_syscalln` + `sys_call_table`-gated `fp`/`inline` unwrap and cooperative drain in `KPM_EXIT`. |
| **Software PAN** | `src/sw_pan.c` | Detects active SW PAN (`CONFIG_ARM64_SW_TTBR0_PAN` without active HW PAN), prefers kernel `_copy_from_user`/`_copy_to_user` (with `copy_from_user`/`copy_to_user` fallback), falls back to `kimage_voffset`-translated and zero-verified `reserved_pg_dir`/`reserved_ttbr0` swap, and reports `hmkpm_get_sw_pan_mode()`. |
| **MMU & Page Walker** | `src/mmu.c` | Reads `TCR_EL1` and `MAIR_EL1` (Normal-memory attribute mask rejecting Device/MMIO), implements unified `pgt_walk_va()` with shared `pgt_decode_leaf()` (preserving leaf/subtree `span_size` on rejections), `pgt_pgtable_to_tkpa` / `pgt_pgtable_inspect` wrappers, and iterative `ENUM_REGIONS` (`hmkpm_handle_enum_regions`) with contiguous `R/W/X` coalescing and cursor pagination. |
| **I/O, V2P & Chain Engine** | `src/io.c` | `pgt_rw_mm` (1024B stack bounce, `nofault` reads/writes, ARM64 `dc cvau`/`ic ialluis` sync on executable writes), coalesced `READ_BATCH` fast-path, chunked `READ/WRITE_BATCH` (32 entries, lockless `WRITE_BATCH` `-EOPNOTSUPP`), `V2P_BATCH`, and `READ_CHAIN` (`hmkpm_handle_read_chain` + `hmkpm_chain_exec_one` with signed offsets, `PTR32`, `DEREF_LAST`, and cross-page pointer reads). |
| **Scanner & Refinement** | `src/scan.c` | `SCAN_KERNEL` (up to 4,096 ranges, `nofault` slices, O(1) empty-subtree skip, `EXACT`/`NEQ`/`RANGE`/`NOT_RANGE`/`MASK`, `WITH_VALUES` pairs, `RESUME` cursor pagination, `NaN` rejection, default early-stop + `COUNT_ALL` truncation cursor) and `SCAN_REFINE` (up to 1,048,576 candidates, *in-place* compaction, value & delta ops). |
| **`/proc` Event Filter** | `src/fsnotify_filter.c` | On kernels `>= 5.10.0`, resolves `inode.i_sb` and `super_block.s_magic` via BTF (GKI fallback), hooks `fsnotify` (`hook_wrap7`) with `hmkpm_in_flight` tracking, filters `PROC_SUPER_MAGIC` (`0x9fa0`) inodes via `nofault` reads, and supports runtime `global`/`off`/`pids` (8-entry TGID allowlist via `tgid_offset` or `__task_pid_nr_ns` fallback) control. |
| **ARM64 Disassembler** | `src/disasm_legacy.c` | *[Legacy/stabilized]* For `< 5.10` kernels, decodes 24 candidate functions (LSE/LL-SC atomics and branches to 37 lock symbols) using backward register tracking and consensus voting. |

---

## 7. Data Flow

### 7.1 Initialization (`KPM_INIT` → `module_init_handler`)
1. Validates kernel version range (`4.14.0 <= kver < 6.13.0`).
2. `pgt_pgtable_init()`: reads `TCR_EL1` and `MAIR_EL1`, computes paging geometry and Normal-memory mask, resolves `memstart_addr` and `high_memory`.
3. Resolves required and optional `kfunc` symbols (including `copy_from_kernel_nofault`/`probe_kernel_read`, `copy_to_kernel_nofault`/`probe_kernel_write`, `msleep`, `schedule`, `_cond_resched`); aborts early if any required symbol is missing.
4. `hmkpm_sw_pan_init()`: runs after `nofault` helpers and paging geometry are initialized.
5. `get_mm_mmap_lock_offset()`: uses BTF (`mm_struct->mmap_lock`) → disassembler cross-check (`find_mm_mmap_sem_offset()`) / `init_mm` `rw_semaphore` layout validation (`hmkpm_validate_init_mm_rwsem()`) for `>= 5.10`, or `find_mm_mmap_sem_offset()` for `< 5.10`. On failure or missing `down_read`/`up_read`, enables **lockless mode** (`mmap_lock_sem_offset = -1`, writes disabled).
6. `hmkpm_fsnotify_init()`: resolves BTF/GKI offsets plus optional `__task_pid_nr_ns` fallback and installs `fsnotify` hook on `kver >= 5.10.0`.
7. Installs `__NR_getresuid` hook via `hook_syscalln_override` (rolls back `hmkpm_fsnotify_exit()` and drains `hmkpm_in_flight` on failure).

### 7.2 Userspace → Kernel Request (`__NR_getresuid`)
```text
Userspace: syscall(__NR_getresuid, magic, user_buf, total_len)
   │
   ▼
hmkpm_handle()
   ├─ !is_hmkpm_magic(magic) || module_exiting || !hook_active || current_uid() != 0 ──► original syscall
   ├─ hmkpm_atomic_add_return(&hmkpm_in_flight, +1)  (re-checks module_exiting / hook_active)
   ├─ args->skip_origin = 1
   ├─ HMKPM_MAGIC            ──► (NULL, 0) fast probe, or validates user_buf/len (-EINVAL) + copies hmkpm_version_info (80 B)
   ├─ Validates total_len > 0 and hmkpm_user_range_ok(user_buf, total_len)
   ├─ READ / WRITE           ──► hmkpm_handle_single()      ──► pgt_rw() ──► pgt_rw_mm()
   ├─ READ_BATCH/WRITE_BATCH ──► hmkpm_handle_batch()       ──► RCU/mm ──► chunk(32) ──► coalesced READ / pgt_rw_mm()
   ├─ V2P_BATCH              ──► hmkpm_handle_v2p_batch()   ──► RCU/mm ──► chunk(64) ──► pgt_pgtable_inspect()
   ├─ SCAN_KERNEL            ──► hmkpm_handle_scan_kernel() ──► RCU/mm ──► pgt_walk_va() + subtree skip + nofault slices
   ├─ READ_CHAIN             ──► hmkpm_handle_read_chain()  ──► RCU/mm ──► chunk(16) ──► hmkpm_chain_exec_one()
   ├─ SCAN_REFINE            ──► hmkpm_handle_scan_refine() ──► RCU/mm ──► 256B chunks + in-place compaction
   ├─ ENUM_REGIONS           ──► hmkpm_handle_enum_regions()──► RCU/mm ──► iterative HW PT walk + coalescing
   └─ out_leave: hmkpm_atomic_add_return(&hmkpm_in_flight, -1)
```

### 7.3 Process & Memory Resolution (`pgt_rw_mm`)
1. `rcu_read_lock()` → `find_task_by_vpid(pid)` → `get_task_mm(task)` → `rcu_read_unlock()`.
2. Reads `mm->pgd` via `hmkpm_copy_from_kernel_nofault`.
3. Loops in chunks up to `min(len, page_left, 1024)`:
   - Write: `hmkpm_copy_from_user` → `bounce[1024]` **outside** `mmap_lock`.
   - Acquires `hmkpm_mmap_read_lock(mm)` → `pgt_walk_va(pgd, va, is_write, &walk)` → linear KVA (`pgt_phys_to_virt`) → `hmkpm_copy_from/to_kernel_nofault` (+ `hmkpm_sync_icache_kva` on executable writes) → releases `hmkpm_mmap_read_unlock(mm)`.
   - Read: `hmkpm_copy_to_user` from `bounce[1024]` → userspace **outside** `mmap_lock`.
   - Yields cooperatively via `hmkpm_cond_resched()` every 64 iterations (outside lock).
4. Releases reference via `mmput(mm)`.

---

## 8. Coding Standards & Safety

- **Language/Style:** Pure C (`gnu11`), Linux kernel style (tab indentation, `static inline`, centralized cleanup via `goto out_mm` / `goto out`, negative `-errno` return codes).
- **Mandatory safety (zero-panic):**
  - `NULL` checks across all traversals (`task_struct`, `mm_struct`, `inode`, `super_block`, userspace pointers).
  - Integer overflow guards (`U64_MAX - size`), userspace VA bounds (`hmkpm_user_range_ok`) and linear KVA bounds (`validate_virt_range` / `validate_phys_range`), `TBI0`-gated untagging (`pgt_untag_user_va`), `READ_ONCE`/`WRITE_ONCE` on shared flags.
  - All remote/speculative kernel accesses must use `copy_from_kernel_nofault` / `copy_to_kernel_nofault` (with `probe_kernel_*` fallback).
  - Never call `copy_from_user` / `copy_to_user` while holding target `mmap_read_lock`.
- **No dynamic heap / no FPU / no libgcc atomics:** Bounded stack frames (`<= 1792 B`, checked by CI), no floating-point instructions (`-mgeneral-regs-only`), and inline ARM64 LL/SC atomics rather than `-moutline-atomics`.
- **CFI compatibility:** Always resolve kernel symbols via `hmkpm_lookup_symbol()` (with `.cfi_jt` fallback).
- **Terminology & documentation language:** Keep `GEMINI.md`, `README.md`, and all code comments in concise, neutral technical English per `.agents/rules/terminology.md`.

---

## 9. Roadmap Status

### Future — Optional Post-Verification Extensions
- **B3 (Layer 2):** Optional BTF-gated VMA/Maple Tree lookup for file/module region naming.
- **B5:** Optional COW-safe write mode (`access_process_vm` outside `mmap_lock`) for read-only `MAP_PRIVATE` pages.
- **B6 (Extended):** Multi-predicate struct pattern matching in `SCAN_KERNEL`.
