# HuntMemory-KPM HMKPM

<p align="center">
  <img src="https://img.shields.io/badge/Architecture-ARM64%20(aarch64)-blue?style=for-the-badge" alt="Architecture">
  <img src="https://img.shields.io/badge/Kernel%20Support-4.0%20--%206.12+-green?style=for-the-badge" alt="Kernel Support">
  <img src="https://img.shields.io/badge/Framework-KernelPatch%20Module-orange?style=for-the-badge" alt="KernelPatch Module">
  <img src="https://img.shields.io/badge/License-GPL%202.0-red?style=for-the-badge" alt="License">
</p>

---

## 📖 Overview

**HuntMemory-KPM** is a high-performance, low-overhead **KernelPatch Module (KPM)** engineered for ARM64 Android kernels (Linux 4.0 up to 6.12+).

It delivers fast, direct process memory read and write operations by walking hardware page tables (MMU translation) directly in kernel space, completely bypassing the overhead, detection vectors, and limitations of traditional userspace debugging methods such as `ptrace` or `process_vm_readv`.

---

## ✨ Features

- **Hardware Page Table Walking (Direct MMU Resolution)**:
  - Translates target virtual addresses (VA) directly into physical addresses (PA) and kernel virtual addresses via target process `pgd`.
  - Supports **4KB** and **16KB** page granules (`TG0`).
  - Supports **36-bit to 48-bit** user virtual address spaces (`T0SZ` from `TCR_EL1`).
  - Full support for Level 1 and Level 2 **Block descriptors (HugePages/Superpages)**.
  - Transparent ARM64 **Tagged Pointer (TBI0 - Top Byte Ignore)** unwrapping.

- **Batch & Single Memory I/O**:
  - **Single Operations**: High-speed single read/write transfers up to 64 MB per call.
  - **Batch Operations**: Aggregated multi-address read/write transfers up to **65,536 entries** and **128 MB** per syscall, drastically eliminating userspace/kernel context switches.
  - Atomic `mmap_lock` / `mmap_sem` acquisition across the entire batch sequence for consistency and stability.

- **Universal Kernel Compatibility (Linux 4.0 to 6.12+)**:
  - **Pre-5.10 Kernels**: Dynamic runtime disassembly and CFI-safe branch tracing to automatically discover `mm_struct->mmap_sem` offsets across non-GKI OEM kernels.
  - **Android GKI (5.10, 5.15, 6.1, 6.6, 6.12)**: Deterministic, validated struct offsets.
  - Dynamic adaptation for `memstart_addr`, `high_memory`, and kernel linear mapping changes.

- **Fault-Tolerant & Safe Execution**:
  - Safe kernel read/write primitives (`copy_from_kernel_nofault` / `probe_kernel_read`) to prevent kernel panics on unmapped pages.
  - Strict input validation, integer overflow protections, and user address bounds checking.
  - Proper RCU lifecycle management (`rcu_read_lock` / `rcu_read_unlock`) and memory descriptor reference counting (`get_task_mm` / `mmput`).

- **Privilege & Access Control**:
  - Validates caller permissions against superuser privileges (`is_su_allow_uid(current_uid())`).
  - Syscall interception via `__NR_getresuid` using KernelPatch hook infrastructure.

- **Runtime Control Interface**:
  - Dynamically enable, disable, toggle, or query module status at runtime via `KPM_CTL0`.

---

## 🛠️ System Requirements

| Requirement | Specification |
| :--- | :--- |
| **Target Architecture** | ARM64 (`aarch64`) |
| **Kernel Version** | Linux `4.0` to `6.12+` |
| **Framework** | [KernelPatch](https://github.com/bmax121/KernelPatch) or compatible (APatch / KernelPatch / [KPM-Manager](https://github.com/Yervant7/KPM-Manager) > 0.13.0) |
| **Compiler** | GCC ARM64 Cross-Compiler (`aarch64-none-elf-gcc` or `aarch64-linux-gnu-gcc`) |

---

## 🚀 Building from Source

### 1. Clone Repository with Submodules

```bash
git clone --recursive https://github.com/Yervant7/HuntMemory-KPM.git
cd HuntMemory-KPM
```

> **Note**: If you already cloned without submodules, initialize them with:
>
> ```bash
> git submodule update --init --recursive
> ```

### 2. Build the KPM Binary

Ensure `aarch64-none-elf-gcc` is in your `PATH`:

```bash
make
```

Or specify a custom cross-compiler:

```bash
make TARGET_COMPILE=aarch64-linux-gnu-
```

The output file `hmkpm.kpm` will be generated in the root directory.

---

## 📡 Protocol & Architecture

HuntMemory-KPM intercepts `__NR_getresuid` when `arg0` matches one of the defined magic codes:

```
syscall(__NR_getresuid, magic, user_buffer, total_size);
```

### Magic Codes

| Identifier | Value | Operation |
| :--- | :--- | :--- |
| `HMKPM_MAGIC` | `0x484D4B504D` | Handshake / Availability Check |
| `HMKPM_MAGIC_READ` | `0x484D4B504E` | Single Process Memory Read |
| `HMKPM_MAGIC_WRITE` | `0x484D4B504F` | Single Process Memory Write |
| `HMKPM_MAGIC_READ_BATCH` | `0x484D4B5050` | Batch Process Memory Read |
| `HMKPM_MAGIC_WRITE_BATCH` | `0x484D4B5051` | Batch Process Memory Write |

### Memory Layouts

#### 1. Single Request Layout

```
[ struct hmkpm_req (24 bytes) ] [ Data Payload (size bytes) ]
```

#### 2. Batch Request Layout

```
[ struct hmkpm_batch_hdr (24 bytes) ]
[ struct hmkpm_batch_entry[count] (16 bytes each) ]
[ Data Payload (data_total bytes) ]
```

---

## 🎛️ Runtime Control Interface

HuntMemory-KPM supports runtime control commands via `kpmctl` or the KernelPatch module control interface:

| Command | Action |
| :--- | :--- |
| `enable` / `on` / `1` | Enable memory hook processing |
| `disable` / `off` / `0` | Disable memory hook processing |
| `status` / `state` | Query current status (`active` / `inactive`) |
| `toggle` | Toggle current active state |

---

## 📜 License

This project is licensed under the **GNU General Public License (GPL) 2.0**.  
See the [LICENSE](LICENSE) file or visit [GNU GPL 2.0](https://www.gnu.org/licenses/old-licenses/gpl-2.0.html) for full details.

---

## 👤 Author

- **Yervant7** – [GitHub Profile](https://github.com/Yervant7)
