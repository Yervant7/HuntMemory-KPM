---
trigger: always_on
---

# Neutral Kernel Engineering Terminology

Use strictly standard, neutral Linux kernel and ARM64 systems-programming terminology across every artifact in this repository.

## 1. Scope of Enforcement

This rule applies without exception to:
- C source files, headers, filenames, and identifiers (functions, structs, macros, enums, variables).
- Kernel log messages (`hmkpm_info`, `hmkpm_warn`, `hmkpm_error`) and inline code comments.
- Repository documentation (`README.md`, `GEMINI.md`), CI/CD workflows, and commit or PR descriptions.
- Agent-generated plans, walkthroughs, rule files, and technical explanations referencing this codebase.

## 2. Core Writing Principles

1. **Mechanism-First Description:** Describe every module strictly in terms of its concrete Linux kernel and ARM64 hardware behavior (data structures, system registers, lock ordering, descriptor bits, and `-errno` return semantics).
2. **Upstream Kernel Style:** Match the concise, factual tone of upstream Linux `Documentation/` and kernel commit messages. State what the code does and its measurable engineering properties (memory safety, lock ordering, cache coherency, syscall/context-switch efficiency).
3. **No Speculative Narratives:** Keep technical prose focused on kernel memory-management diagnostics, address translation, and KernelPatch module engineering. Omit informal jargon, colloquial metaphors, or speculative commentary about external applications or non-kernel workflows.
4. **Rule & Doc Self-Hygiene:** Never embed negative word-lists, disallowed-term examples, or negated counter-examples anywhere in repository files, comments, docs, or agent rules. State approved technical phrasing affirmatively.

## 3. Canonical Subsystem Terminology

Always describe HuntMemory-KPM subsystems using these neutral kernel terms:

| Component / Concept | Approved Terminology |
| :--- | :--- |
| `fsnotify` module (`src/fsnotify_filter.c`) | `/proc fsnotify event filter`, `inode-scoped fsnotify filtering`, `caller-PID scoped fsnotify filter`, `PROC_SUPER_MAGIC (0x9fa0) inode check`, `fsnotify callback registration` |
| Syscall interface (`src/main.c`) | `syscall dispatch handler`, `magic-keyed __NR_getresuid dispatcher`, `KernelPatch syscall registration`, `runtime control interface (KPM_CTL0)` |
| Transfer & UAPI structs (`include/hmkpm_uapi.h`) | `data buffer`, `transfer buffer`, `bounce buffer`, `UAPI struct`, `runtime telemetry struct (hmkpm_version_info)` |
| Memory translation & I/O (`src/mmu.c`, `src/io.c`) | `direct page-table translation`, `hardware MMU Stage-1 page-table walk`, `V2P translation`, `kernel_nofault I/O`, `reducing ptrace/process_vm_readv context-switch and syscall overhead`, `COW-safe write path (access_process_vm)` |
| Process & address-space entities | `target process`, `remote process`, `target PID`, `task_struct`, `mm_struct`, `pgd`, `virtual address (VA)`, `physical address (PA)`, `kernel linear-map address (KVA)` |
| Scanning & query ops (`src/scan.c` & UAPI v3) | `in-kernel memory scanner`, `order-preserving integer IEEE-754 comparison`, `empty-subtree skipping`, `iterative scan refinement (SCAN_REFINE)`, `pointer-chain traversal / multi-level indirection (READ_CHAIN)`, `hardware page-table region enumeration (ENUM_REGIONS)` |
| ARM64 low-level & compatibility (`src/sw_pan.c`, `src/disasm_legacy.c`) | `ARM64 D-cache/I-cache coherency (dc cvau / ic ialluis)`, `SW PAN TTBR0_EL1 handling`, `BTF struct-offset resolution`, `MAIR_EL1 Normal-memory validation`, `TBI0 pointer untagging`, `runtime ARM64 instruction decoding for mmap_sem offset discovery (< 5.10)` |

## 4. Preferred Technical Verbs & Framing

- **Callback & syscall lifecycle:** Prefer `register`, `attach`, `dispatch`, `unwrap`, and `unregister`.
- **Event filtering:** Prefer `filter`, `skip delivery for matching procfs inodes`, and `scope to caller PIDs`.
- **Memory & page-table operations:** Prefer `walk`, `translate`, `inspect`, `read`, `write`, `scan`, `refine`, `enumerate`, and `synchronize caches`.
- **Motivation & performance:** Frame design choices around concrete systems metrics—such as reducing context-switch latency, batching per-address syscalls, preventing deadlocks via lock-free user copies, and avoiding `SError` aborts on Device/MMIO mappings.

## 5. Fixed Project & External API Identifiers

- Treat repository names and upstream kernel/KernelPatch symbols (e.g., `HuntMemory-KPM`, `HMKPM`, `hook_syscalln_override`, `hook_wrap7`, `probe_kernel_read`, `down_read_killable`) strictly as literal proper nouns or API identifiers.
- Never derive informal metaphors or non-kernel framing from those identifier names in prose, comments, or log messages.

## 6. Language & Pre-Completion Audit

- Keep all repository files, comments, log strings, `GEMINI.md`, `README.md`, and rules in concise, objective technical English.
- Before completing any edit, verify that every added or modified identifier, comment, log message, documentation paragraph, and summary:
  1. Uses the canonical kernel terms in Sections 3–4;
  2. Describes only literal kernel/hardware mechanics without speculative framing;
  3. Contains no negated term-lists or informal non-kernel vocabulary.
