---
trigger: always_on
---

# Development Environment

## Target Architecture

- ARM64 (aarch64)

## Framework

- KernelPatch Module (KPM) by bmax121

### Restrictions

- DO NOT use the classic structure of an LKM (Loadable Kernel Module). This project does NOT generate a standard .ko file.
- The final binary must be compiled into the format accepted by KernelPatch (.kpm).
- Do not depend on full kernel headers of specific kernel tree versions (KernelPatch is designed to be compatible across multiple kernel versions).

# Critical Differences KPM vs LKM

1. Symbol Resolution: KPM relies on KernelPatch to resolve symbols dynamically at runtime via modified internal kallsyms tables. Do not use traditional EXPORT_SYMBOL export routines.
2. Native Hooking: Prefer macros and APIs provided by the KernelPatch ecosystem for `inline-hook` and `syscall-table-hook` instead of attempting to rebuild manual WP/BP register manipulation on ARM64.

# Code Generation Guidelines

Style

- Pure C focused on embedded Linux Kernel (Android 4.0 to 6.12).

Safety

- Always add NULL pointer checks across all struct traversals such as `task_struct` and `mm_struct`, as failures here cause an instant Kernel Panic and device reboot.
