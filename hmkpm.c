// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2026 Yervant7
 * 
 * KernelPatch Module (KPM) - [HMKPM]
 */


#include <common.h>
#include <compiler.h>
#include <hook.h>
#include <kpmodule.h>
#include <kputils.h>
#include <ksyms.h>
#include <kconfig.h>
#include <ktypes.h>
#include <syscall.h>
#include <barrier.h>
#include <linux/err.h>
#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/mm_types.h>
#include <linux/printk.h>
#include <linux/build_bug.h>
#include <uapi/asm-generic/unistd.h>

KPM_NAME("HMKPM");
KPM_VERSION("2.0.0");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("Yervant7");
KPM_DESCRIPTION("A KernelPatch Module (KPM) HMKPM");

static bool init_error = false;
static int mmap_lock_sem_offset = -1;

struct rw_semaphore;
extern bool is_su_allow_uid(uid_t uid);

#define U64_MAX ((u64)~0ULL)
#define HMKPM_TAG "[HMKPM] "

#define hmkpm_info(fmt, ...) logki(HMKPM_TAG fmt, ##__VA_ARGS__)
#define hmkpm_error(fmt, ...) logke(HMKPM_TAG fmt, ##__VA_ARGS__)

#define hkfunc_match(func)                         \
    do {                                           \
        kfunc_lookup_name(func);                  \
        if (!kf_##func) {                          \
            hmkpm_error("Failed to find kfunc %s\n", #func); \
            init_error = true;                     \
        }                                          \
    } while (0)

#define hkvar_match(var)                           \
    do {                                           \
        kvar_lookup_name(var);                     \
        if (!kv_##var) {                           \
            hmkpm_error("Failed to find kvar %s\n", #var); \
            init_error = true;                     \
        }                                          \
    } while (0)

unsigned long kfunc_def(__arch_copy_to_user)(void __user *to, const void *from, unsigned long n);
unsigned long kfunc_def(__arch_copy_from_user)(void *to, const void __user *from, unsigned long n);
long kfunc_def(probe_kernel_read)(void* dst, const void* src, size_t size);
long kfunc_def(probe_kernel_write)(void *dst, const void *src, size_t size);
long kfunc_def(copy_from_kernel_nofault)(void* dst, const void* src, size_t size);
long kfunc_def(copy_to_kernel_nofault)(void *dst, const void *src, size_t size);
struct task_struct *kfunc_def(find_task_by_vpid)(pid_t pid);
struct mm_struct *kfunc_def(get_task_mm)(struct task_struct *task);
void kfunc_def(mmput)(struct mm_struct *mm);
void kfunc_def(__rcu_read_lock)(void);
void kfunc_def(__rcu_read_unlock)(void);
void kfunc_def(down_read)(struct rw_semaphore *sem);
void kfunc_def(up_read)(struct rw_semaphore *sem);

u64 kvar_def(memstart_addr);
void * kvar_def(high_memory);

/* ========================================================================
 * Canal: getresuid, interceptado quando arg0 == HMKPM_MAGIC.
 *
 *   arg0 = HMKPM_MAGIC / HMKPM_MAGIC_READ / HMKPM_MAGIC_WRITE / ...
 *   arg1 = ponteiro para o buffer de requisição
 *   arg2 = tamanho total do buffer
 *
 * Layouts contíguos em userspace:
 *   Single: [ hmkpm_req (pid, addr, size) | data[size] ]
 *   Batch:  [ hmkpm_batch_hdr (pid, count, data_total) | hmkpm_batch_entry[count] | data[data_total] ]
 * ======================================================================== */

#define HMKPM_MAGIC 0x484D4B504DULL /* "HMKPM" */
#define HMKPM_MAGIC_READ   (HMKPM_MAGIC + 1)
#define HMKPM_MAGIC_WRITE  (HMKPM_MAGIC + 2)
#define HMKPM_MAGIC_READ_BATCH  (HMKPM_MAGIC + 3)
#define HMKPM_MAGIC_WRITE_BATCH (HMKPM_MAGIC + 4)
#define HMKPM_MAGIC_MAX         HMKPM_MAGIC_WRITE_BATCH

#define HMKPM_BATCH_CHUNK_ENTRIES 64U
#define HMKPM_MAX_BATCH_ENTRIES 65536U
#define HMKPM_MAX_ENTRY_SIZE       (64ULL << 20)
#define HMKPM_MAX_SINGLE_SIZE      (64ULL << 20)
#define HMKPM_MAX_BATCH_TOTAL_SIZE (128ULL << 20)

struct hmkpm_batch_hdr {
    int32_t pid;
    uint32_t _pad;
    uint64_t count;
    uint64_t data_total;
};

struct hmkpm_batch_entry {
    uint64_t addr;
    uint64_t size;
};

struct hmkpm_req {
    int32_t pid;
    uint32_t _pad;
    uint64_t addr;
    uint64_t size;
};

#define HMKPM_BATCH_HDR_SIZE   ((uint64_t)sizeof(struct hmkpm_batch_hdr))
#define HMKPM_BATCH_ENTRY_SIZE ((uint64_t)sizeof(struct hmkpm_batch_entry))
#define HMKPM_REQ_SIZE         ((uint64_t)sizeof(struct hmkpm_req))

static inline long hmkpm_copy_from_kernel_nofault(void* dst, const void* src, size_t size) {
  kfunc_call(copy_from_kernel_nofault, dst, src, size);
  kfunc_call(probe_kernel_read, dst, src, size);
  return -ENOSYS;
}

static inline long hmkpm_copy_to_kernel_nofault(void *dst, const void *src, size_t size) {
  kfunc_call(copy_to_kernel_nofault, dst, src, size);
  kfunc_call(probe_kernel_write, dst, src, size);
  return -ENOSYS;
}

static uint64_t pgt_va_bits;
static uint64_t pgt_phys_offset;
static uint64_t pgt_page_offset;
static uint64_t pgt_linear_voffset;
static uint64_t pgt_page_shift;
static uint64_t pgt_page_size;
static uint64_t pgt_page_level;
static uint64_t pgt_user_limit;
static uint64_t pgt_phys_limit;
static uint64_t pgt_high_memory;
static bool pgt_tbi0;

static inline uint64_t pgt_phys_to_virt(uint64_t phys) {
  return phys + pgt_linear_voffset;
}

static inline uint64_t pgt_virt_to_phys(uint64_t addr) {
  return addr - pgt_linear_voffset;
}

static inline int validate_virt_range(uint64_t va, uint64_t size)
{
    if (unlikely(size == 0))
        return -EINVAL;

    if (unlikely(va < pgt_page_offset))
        return -EFAULT;

    if (unlikely(va > U64_MAX - size))
        return -EFAULT;

    uint64_t last = va + size - 1;

    if (unlikely(last >= pgt_high_memory))
        return -EFAULT;

    return 0;
}

static inline int validate_phys_range(uint64_t phys, uint64_t size)
{
    if (unlikely(size == 0))
        return -EINVAL;

    if (unlikely(phys < pgt_phys_offset))
        return -EFAULT;

    if (unlikely(phys > U64_MAX - size))
        return -EFAULT;

    uint64_t last = phys + size - 1;

    if (unlikely(last >= pgt_phys_limit))
        return -EFAULT;

    return 0;
}

static inline uint64_t pgt_untag_user_va(uint64_t va)
{
    /*
     * Se TBI0 estiver ativo, o byte superior é ignorado.
     * Isso é importante para pointers tagged em Android.
     */
    if (pgt_tbi0)
        va &= 0x00FFFFFFFFFFFFFFULL;

    return va;
}

static inline uint64_t pgt_desc_to_phys(uint64_t desc)
{
    uint64_t addr_mask = (((1ULL << (48 - pgt_page_shift)) - 1) << pgt_page_shift);
    return desc & addr_mask;
}

/*
 * Block descriptors normalmente são permitidos em level 1 e 2.
 * Level 0 não costuma permitir block.
 * Level 3 é page, não block.
 */
static inline bool pgt_block_allowed(int lv)
{
    if (pgt_page_shift == 14)
        return (lv == 2);
    else
        return (lv == 1 || lv == 2);
}

static uint64_t pgt_pgtable_to_tkpa(uint64_t pgd, uint64_t va)
{
    uint64_t tkpa;
    if (!pgd)
        return 0;

    if (pgd & (pgt_page_size - 1))
        return 0;

    if (validate_virt_range(pgd, pgt_page_size))
        return 0;

    va = pgt_untag_user_va(va);

    if (va >> pgt_va_bits)
        return 0;

    uint64_t table_va = pgd;
    uint64_t pxd_bits = pgt_page_shift - 3;
    uint64_t pxd_ptrs = 1ULL << pxd_bits;

    int64_t start = 4 - (int64_t)pgt_page_level;

    for (int64_t lv = start; lv < 4; lv++) {
        if (validate_virt_range(table_va, pgt_page_size))
            return 0;

        uint64_t pxd_shift = (pgt_page_shift - 3) * (4 - lv) + 3;

        if (pxd_shift >= pgt_va_bits)
            return 0;

        uint64_t pxd_index = (va >> pxd_shift) & (pxd_ptrs - 1);

        /*
         * No nível inicial, a tabela pode não usar todos os índices.
         * Isso evita aceitar VA não-canônico com índice fora da faixa real.
         */
        uint64_t top_bits = pgt_va_bits - pxd_shift;

        if (top_bits > pxd_bits)
            top_bits = pxd_bits;

        if (top_bits == 0)
            return 0;

        if (pxd_index >= (1ULL << top_bits))
            return 0;

        uint64_t entry_va = table_va + pxd_index * 8;
        uint64_t desc = 0;

        if (hmkpm_copy_from_kernel_nofault(&desc, (const void *)entry_va, sizeof(desc)) != 0)
            return 0;

        uint64_t type = desc & 3ULL;

        /*
         * Stage 1:
         * 0b00 = invalid
         * 0b10 = invalid/reserved
         * 0b01 = block
         * 0b11 = table/page
         */
        if (type == 0ULL || type == 2ULL)
            return 0;

        /*
         * Último nível.
         */
        if (lv == 3) {
            /*
             * No level 3, 0b11 é page descriptor.
             * 0b01 não deve ser tratado como block válido aqui.
             */
            if (type != 3ULL)
                return 0;

            uint64_t base = pgt_desc_to_phys(desc);

            if (base & (pgt_page_size - 1))
                return 0;

            if (validate_phys_range(base, pgt_page_size))
                return 0;

            return base | (va & (pgt_page_size - 1));
        }

        /*
         * Block descriptor.
         */
        if (type == 1ULL) {
            if (!pgt_block_allowed((int)lv))
                return 0;

            uint64_t block_bits =
                (uint64_t)(3 - lv) * pxd_bits + pgt_page_shift;

            if (block_bits >= 64)
                return 0;

            uint64_t block_size = 1ULL << block_bits;
            uint64_t block_mask = block_size - 1;

            uint64_t base = pgt_desc_to_phys(desc);

            /*
             * Block precisa estar alinhado ao tamanho do bloco.
             */
            if (base & block_mask)
                return 0;

            if (validate_phys_range(base, block_size))
                return 0;

            return (base & ~block_mask) | (va & block_mask);
        }

        /*
         * Table descriptor.
         */
        uint64_t next_pa = pgt_desc_to_phys(desc);

        /*
         * Próxima tabela precisa estar alinhada ao granule.
         */
        if (next_pa & (pgt_page_size - 1))
            return 0;

        if (validate_phys_range(next_pa, pgt_page_size))
            return 0;

        table_va = pgt_phys_to_virt(next_pa);
    }

    return 0;
}

static int pgt_pgtable_init(void) {
  uint64_t tcr_el1;
  asm volatile("mrs %0, tcr_el1" : "=r"(tcr_el1));

  uint64_t t1sz = (tcr_el1 >> 16) & 0x3F;
  uint64_t va1_bits = 64 - t1sz;

  /* TTBR0 / user VA */
  uint64_t t0sz = tcr_el1 & 0x3F;
  uint64_t va0_bits = 64 - t0sz;

  uint64_t tg0 = (tcr_el1 >> 14) & 0x3ULL;

  if (va0_bits > 48 || va0_bits < 36) {
    hmkpm_error("Unsupported VA bits: %llu\n", va0_bits);
    return -EINVAL;
  }

  pgt_va_bits = va0_bits;
  pgt_user_limit = (1ULL << va0_bits) - 1;

  if (tg0 == 0) pgt_page_shift = 12;  /* 4KB */
  else if (tg0 == 2) pgt_page_shift = 14;  /* 16KB */
  else {
    hmkpm_error("Unsupported tg0: %llu\n", tg0);
    return -EINVAL;
  }

  uint64_t pxd_bits = pgt_page_shift - 3;

  pgt_page_level = (va0_bits - 4) / pxd_bits;

  if (pgt_page_level != 3 && pgt_page_level != 4)
    return -EINVAL;

  int64_t start = 4 - (int64_t)pgt_page_level;

  if (start < 0 || start > 2)
    return -EINVAL;

  pgt_page_size = 1ULL << pgt_page_shift;

  if (kver >= VERSION(5, 4, 0)) {
    pgt_page_offset = (-(UL(1) << (va1_bits)));
  } else {
    pgt_page_offset = (UL(0xffffffffffffffff) - (UL(1) << (va1_bits - 1)) + 1);
  }

  hkvar_match(memstart_addr);
  if (!kv_memstart_addr) {
    hmkpm_error("Failed to resolve memstart_addr\n");
    return -EFAULT;
  }
  pgt_phys_offset = kvar_val(memstart_addr);
  pgt_linear_voffset = pgt_page_offset - pgt_phys_offset;

  pgt_tbi0 = !!(tcr_el1 & (1ULL << 37));

  hmkpm_info("Page table config: va0_bits=%llu, shift=%llu, size=0x%llx, level=%llu, tbi0=%d\n",
             va0_bits, pgt_page_shift, pgt_page_size, pgt_page_level, pgt_tbi0);
  hmkpm_info("phys_offset=0x%llx, page_offset=0x%llx, linear_voffset=0x%llx\n",
             pgt_phys_offset, pgt_page_offset, pgt_linear_voffset);

  return 0;
}

static inline int hmkpm_user_range_ok(const void __user *ptr, uint64_t len)
{
    if (!ptr || len == 0)
        return 0;

    uint64_t u = pgt_untag_user_va((uint64_t)ptr);

    if (u > pgt_user_limit)
        return 0;

    if (len - 1 > pgt_user_limit - u)
        return 0;

    return 1;
}

static __always_inline bool is_hmkpm_magic(uint64_t magic)
{
    return magic >= HMKPM_MAGIC && magic <= HMKPM_MAGIC_MAX;
}

#define min(a, b) ((a) < (b) ? (a) : (b))

static inline void hmkpm_mmap_read_lock(struct mm_struct *mm)
{
    if (mm && mmap_lock_sem_offset >= 0 && kf_down_read) {
        struct rw_semaphore *sem = (struct rw_semaphore *)((uintptr_t)mm + mmap_lock_sem_offset);
        kfunc(down_read)(sem);
    }
}

static inline void hmkpm_mmap_read_unlock(struct mm_struct *mm)
{
    if (mm && mmap_lock_sem_offset >= 0 && kf_up_read) {
        struct rw_semaphore *sem = (struct rw_semaphore *)((uintptr_t)mm + mmap_lock_sem_offset);
        kfunc(up_read)(sem);
    }
}

static void hmkpm_zero_user(void __user *dst, size_t size)
{
    static const uint8_t zero_chunk[128] = {0};
    while (size > 0) {
        size_t chunk = min(size, sizeof(zero_chunk));
        if (kfunc(__arch_copy_to_user)(dst, zero_chunk, chunk) != 0)
            break;
        dst = (void __user *)((uintptr_t)dst + chunk);
        size -= chunk;
    }
}

static ssize_t pgt_rw_mm(struct mm_struct *mm, uint64_t remote_va, size_t len,
                         void __user *local_buf, bool is_write)
{
    ssize_t total = 0;

    if (!mm)
        return -ESRCH;

    if (mm_struct_offset.pgd_offset < 0)
        return -EINVAL;

    uint64_t pgd = 0;
    if (hmkpm_copy_from_kernel_nofault(&pgd, (const void *)((uintptr_t)mm + mm_struct_offset.pgd_offset), sizeof(pgd)) != 0 || !pgd)
        return -EFAULT;

    /* Page-by-page read/write loop */
    while (len > 0) {
        uint64_t tkpa = pgt_pgtable_to_tkpa(pgd, remote_va);
        if (!tkpa) {
            if (total > 0)
                break; /* partial read/write is OK */
            return -EFAULT;
        }

        unsigned long page_off = remote_va & (pgt_page_size - 1);
        size_t chunk = min(len, (size_t)(pgt_page_size - page_off));

        void *tkva = (void *)pgt_phys_to_virt(tkpa);
        unsigned long not_copied;

        if (!is_write) {
            /* __arch_copy_to_user returns number of bytes NOT copied (0=success) */
            not_copied = kfunc(__arch_copy_to_user)(local_buf, tkva, chunk);
        } else {
            /* __arch_copy_from_user returns number of bytes NOT copied (0=success) */
            not_copied = kfunc(__arch_copy_from_user)(tkva, local_buf, chunk);
        }

        unsigned long copied = chunk - not_copied;
        total += (ssize_t)copied;

        if (not_copied)
            break; /* couldn't copy everything — stop */

        local_buf = (void __user *)((uintptr_t)local_buf + copied);
        remote_va += copied;
        len -= copied;
    }

    return total;
}

static ssize_t pgt_rw(pid_t pid, uint64_t remote_va, size_t len,
                      void __user *local_buf, bool is_write)
{
    struct task_struct *task = NULL;
    struct mm_struct *mm = NULL;
    ssize_t ret;

    if (pid <= 0)
        return -EINVAL;

    /* find_task_by_vpid requires RCU read-side protection */
    kfunc(__rcu_read_lock)();
    task = kfunc(find_task_by_vpid)(pid);
    if (!task) {
        kfunc(__rcu_read_unlock)();
        return -ESRCH;
    }

    /* get_task_mm increments mm refcount, safe to drop RCU after */
    mm = kfunc(get_task_mm)(task);
    kfunc(__rcu_read_unlock)();

    if (!mm)
        return -ESRCH;

    hmkpm_mmap_read_lock(mm);
    ret = pgt_rw_mm(mm, remote_va, len, local_buf, is_write);
    hmkpm_mmap_read_unlock(mm);

    kfunc(mmput)(mm);
    return ret;
}

static void hmkpm_handle_single(hook_fargs3_t *args,
                                void __user *user_ptr,
                                uint64_t total_len,
                                uint64_t magic)
{
    struct hmkpm_req req;
    void __user *data_ptr;
    bool write_op = (magic == HMKPM_MAGIC_WRITE);

    if (total_len < HMKPM_REQ_SIZE) {
        args->ret = (uint64_t)(long)-EINVAL;
        return;
    }

    if (kfunc(__arch_copy_from_user)(&req, user_ptr, HMKPM_REQ_SIZE) != 0) {
        args->ret = (uint64_t)(long)-EFAULT;
        return;
    }

    if (req.size == 0) {
        if (total_len != HMKPM_REQ_SIZE)
            args->ret = (uint64_t)(long)-EINVAL;
        else
            args->ret = 0;
        return;
    }

    if ((uint64_t)req.size > HMKPM_MAX_SINGLE_SIZE) {
        args->ret = (uint64_t)(long)-E2BIG;
        return;
    }

    if (total_len != HMKPM_REQ_SIZE + (uint64_t)req.size) {
        args->ret = (uint64_t)(long)-EINVAL;
        return;
    }

    if (req.pid <= 0) {
        args->ret = (uint64_t)(long)-EINVAL;
        return;
    }

    data_ptr = (void __user *)((uint8_t __user *)user_ptr + HMKPM_REQ_SIZE);

    ssize_t ret = pgt_rw((pid_t)req.pid, req.addr, req.size, data_ptr, write_op);
    if (ret < 0) {
        args->ret = (uint64_t)(long)ret;
    } else if ((uint64_t)ret != req.size) {
        args->ret = (uint64_t)(long)-EFAULT;
    } else {
        args->ret = 0;
    }
}

static void hmkpm_handle_batch(hook_fargs3_t *args,
                               void __user *user_ptr,
                               uint64_t total_len,
                               uint64_t magic)
{
    bool write_op = (magic == HMKPM_MAGIC_WRITE_BATCH);
    struct hmkpm_batch_hdr hdr;
    struct hmkpm_batch_entry chunk[HMKPM_BATCH_CHUNK_ENTRIES];

    uint64_t entries_bytes;
    uint64_t entries_end;
    uint64_t data_start;
    uint64_t io_end;
    uint64_t data_off = 0;
    uint32_t done = 0;
    int rc = 0;

    struct task_struct *task = NULL;
    struct mm_struct *mm = NULL;

    if (total_len < HMKPM_BATCH_HDR_SIZE) {
        rc = -EINVAL;
        goto out;
    }

    if (kfunc(__arch_copy_from_user)(&hdr, user_ptr, HMKPM_BATCH_HDR_SIZE) != 0) {
        rc = -EFAULT;
        goto out;
    }

    if (hdr.count == 0) {
        if (hdr.data_total != 0) {
            rc = -EINVAL;
            goto out;
        }

        if (write_op) {
            if (total_len != HMKPM_BATCH_HDR_SIZE)
                rc = -EINVAL;
        } else {
            if (total_len < HMKPM_BATCH_HDR_SIZE)
                rc = -EINVAL;
        }

        goto out;
    }

    if (hdr.count > HMKPM_MAX_BATCH_ENTRIES) {
        rc = -E2BIG;
        goto out;
    }

    if (hdr.data_total > HMKPM_MAX_BATCH_TOTAL_SIZE) {
        rc = -E2BIG;
        goto out;
    }

    if (hdr.pid <= 0) {
        rc = -EINVAL;
        goto out;
    }

    entries_bytes = (uint64_t)hdr.count * HMKPM_BATCH_ENTRY_SIZE;

    if (entries_bytes > U64_MAX - HMKPM_BATCH_HDR_SIZE) {
        rc = -E2BIG;
        goto out;
    }

    entries_end = HMKPM_BATCH_HDR_SIZE + entries_bytes;

    if (hdr.data_total > U64_MAX - entries_end) {
        rc = -E2BIG;
        goto out;
    }

    io_end = entries_end + hdr.data_total;

    if (write_op) {
        if (total_len != io_end) {
            rc = -EINVAL;
            goto out;
        }
    } else {
        if (total_len < io_end) {
            rc = -ERANGE;
            goto out;
        }
    }

    /* Obter mm_struct para o PID do batch */
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

    /* Trava o mm para todo o lote de operações para estabilidade das page tables */
    hmkpm_mmap_read_lock(mm);

    data_start = entries_end;

    while (done < hdr.count) {
        uint32_t chunk_count = hdr.count - done;
        uint64_t chunk_bytes;
        void __user *entry_src;
        uint32_t i;

        if (chunk_count > HMKPM_BATCH_CHUNK_ENTRIES)
            chunk_count = HMKPM_BATCH_CHUNK_ENTRIES;

        chunk_bytes = (uint64_t)chunk_count * HMKPM_BATCH_ENTRY_SIZE;

        entry_src = (void __user *)((uint8_t __user *)user_ptr +
                                    HMKPM_BATCH_HDR_SIZE +
                                    (uint64_t)done * HMKPM_BATCH_ENTRY_SIZE);

        if (kfunc(__arch_copy_from_user)((void *)chunk,
                                         entry_src, chunk_bytes) != 0) {
            rc = -EFAULT;
            goto out_mm;
        }

        for (i = 0; i < chunk_count; ++i) {
            struct hmkpm_batch_entry *e = &chunk[i];
            uint64_t req_size = e->size;
            void __user *data_ptr;

            if (req_size == 0)
                continue;

            if (req_size > HMKPM_MAX_ENTRY_SIZE) {
                rc = -E2BIG;
                goto out_mm;
            }

            if (req_size > hdr.data_total - data_off) {
                rc = -EINVAL;
                goto out_mm;
            }

            data_ptr = (void __user *)((uint8_t __user *)user_ptr + data_start + data_off);

            ssize_t ret = pgt_rw_mm(mm, e->addr, req_size, data_ptr, write_op);
            if (ret < 0) {
                /* Page walk / cópia falhou: marca size = 0 para userspace identificar o endereço que falhou */
                e->size = 0;
                if (!write_op)
                    hmkpm_zero_user(data_ptr, req_size);
            } else if ((uint64_t)ret < req_size) {
                /* Cópia parcial: atualiza para quantidade real transferida */
                e->size = (uint64_t)ret;
                if (!write_op)
                    hmkpm_zero_user((void __user *)((uintptr_t)data_ptr + ret),
                                    req_size - (uint64_t)ret);
            } else {
                /* Sucesso total */
                e->size = req_size;
            }

            /* Sempre avança pelo tamanho requisitado para manter alinhamento estrito do buffer */
            data_off += req_size;
        }

        /* Devolve o chunk com os tamanhos reais transferidos de cada entrada ao userspace */
        if (kfunc(__arch_copy_to_user)(entry_src, chunk, chunk_bytes) != 0) {
            rc = -EFAULT;
            goto out_mm;
        }

        done += chunk_count;
    }

    if (unlikely(data_off != hdr.data_total)) {
        rc = -EINVAL;
        goto out_mm;
    }

out_mm:
    if (mm) {
        hmkpm_mmap_read_unlock(mm);
        kfunc(mmput)(mm);
        mm = NULL;
    }

out:
    args->ret = (uint64_t)(long)rc;
}

static int get_mm_mmap_sem_offset(void)
{
    if (kver > VERSION(4, 14, 0) && kver < VERSION(5, 0, 0)) {
        if (kp_kconfig_enabled("CONFIG_COMPAT")) {
            if (kp_kconfig_enabled("CONFIG_SPECULATIVE_PAGE_FAULT")) return 120;
            else return 112;
        } else {
            if (kp_kconfig_enabled("CONFIG_SPECULATIVE_PAGE_FAULT")) return 104;
            else return 96;
        }
    } else if (kver >= VERSION(5, 4, 0)) {
        if (kp_kconfig_enabled("CONFIG_COMPAT")) return 112;
        else return 96;
    } else {
        return -ENOENT;
    }
}

static void hmkpm_handle(hook_fargs3_t *args, void *udata)
{
    void __user *user_ptr;
    uint64_t total_len;
    uint64_t magic = syscall_argn(args, 0);

    if (likely(!is_hmkpm_magic(magic)))
        return;

    uid_t uid = current_uid();
    if (!is_su_allow_uid(uid))
        return;

    args->skip_origin = 1;

    if (mmap_lock_sem_offset < 0) {
        mmap_lock_sem_offset = get_mm_mmap_sem_offset();
    }

    if (magic == HMKPM_MAGIC) {
        args->ret = (uint64_t)HMKPM_MAGIC;
        return;
    }

    user_ptr = (void __user *)syscall_argn(args, 1);
    total_len = syscall_argn(args, 2);

    if (total_len == 0) {
        args->ret = (uint64_t)(long)-EINVAL;
        return;
    }

    if (unlikely(!hmkpm_user_range_ok(user_ptr, total_len))) {
        args->ret = (uint64_t)(long)-EINVAL;
        return;
    }

    if (magic == HMKPM_MAGIC_READ || magic == HMKPM_MAGIC_WRITE) {
        hmkpm_handle_single(args, user_ptr, total_len, magic);
        return;
    }

    if (magic == HMKPM_MAGIC_READ_BATCH ||
        magic == HMKPM_MAGIC_WRITE_BATCH) {
        hmkpm_handle_batch(args, user_ptr, total_len, magic);
        return;
    }

    args->ret = (uint64_t)(long)-EINVAL;
}

static inline int get_mm_mmap_lock_offset(void)
{
  if (kver >= VERSION(6, 12, 0)) {
    return 136;
  } else if (kver >= VERSION(6, 6, 0)) {
    return 144;
  } else if (kver >= VERSION(6, 1, 0)) {
    return 96;
  } else if (kver >= VERSION(5, 15, 0)) {
    return 104;
  } else if (kver >= VERSION(5, 10, 0)) {
    return 112;
  } else {
    return -ENOENT;
  }
}

static long module_init_handler(const char *args, const char *event,
                                void *__user reserved)
{
  if (kver < VERSION(4, 14, 0) || kver >= VERSION(6, 13, 0)) {
    hmkpm_error("Kernel version not supported\n");
    return -EINVAL;
  }

  mmap_lock_sem_offset = get_mm_mmap_lock_offset();

  if (pgt_pgtable_init() != 0) {
    hmkpm_error("Page table initialization failed\n");
    return -ENOENT;
  }

  hkfunc_match(__arch_copy_to_user);
  hkfunc_match(__arch_copy_from_user);
  hkfunc_match(find_task_by_vpid);
  hkfunc_match(get_task_mm);
  hkfunc_match(mmput);
  hkfunc_match(__rcu_read_lock);
  hkfunc_match(__rcu_read_unlock);
  hkfunc_match(down_read);
  hkfunc_match(up_read);

  hkvar_match(high_memory);
  if (!kv_high_memory) {
    hmkpm_error("Failed to resolve high_memory\n");
    return -ENOENT;
  }

  pgt_high_memory = (uint64_t)kvar_val(high_memory);
  pgt_phys_limit = pgt_virt_to_phys(pgt_high_memory);
  hmkpm_info("high_memory = 0x%llx\n", pgt_high_memory);

  kfunc_lookup_name(copy_from_kernel_nofault);
  if (!kf_copy_from_kernel_nofault) {
    hmkpm_info("Failed to find kfunc copy_from_kernel_nofault, using probe_kernel_read instead\n");
    hkfunc_match(probe_kernel_read);
  }

  kfunc_lookup_name(copy_to_kernel_nofault);
  if (!kf_copy_to_kernel_nofault) {
    hmkpm_info("Failed to find kfunc copy_to_kernel_nofault, using probe_kernel_write instead\n");
    hkfunc_match(probe_kernel_write);
  }

  if (init_error) {
    hmkpm_error("Symbol resolution failed, aborting..\n");
    return -ENOENT;
  }

  {
    hook_err_t err =
        hook_syscalln(__NR_getresuid, 3, (void *)hmkpm_handle, 0, 0);
    if (err) {
      hmkpm_error("install hook error: %d\n", err);
      return -ENOENT;
    }
  }

  hmkpm_info("module loaded successfully\n");
  return 0;
}

static long module_control_handler(const char *args, char __user *out_msg,
                                   int outlen) {
  return 0;
}

static long module_cleanup_handler(void *__user reserved) {
  unhook_syscalln(__NR_getresuid, (void *)hmkpm_handle, 0);
  hmkpm_info("module cleaned up\n");
  return 0;
}

KPM_INIT(module_init_handler);
KPM_CTL0(module_control_handler);
KPM_EXIT(module_cleanup_handler);
