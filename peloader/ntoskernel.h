/*
 *  Copyright (C) 2003-2005 Pontus Fuchs, Giridhar Pemmasani
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 *  GNU General Public License for more details.
 *
 */

#ifndef _NTOSKERNEL_H_
#define _NTOSKERNEL_H_

#define ARRAY_SIZE(x) (sizeof((x)) / sizeof((x)[0]))
#ifndef __packed
#define __packed __attribute__((packed))
#endif

#define int_div_round(x, y) (((x) + (y - 1)) / (y))

typedef void (*generic_func)(void);

struct wrap_export {
        const char *name;
        void *func;
};

#define WIN_SYMBOL(name, argc) {#name, (generic_func)name}
#define WIN_WIN_SYMBOL(name, argc) {#name, (generic_func)_win_ ## name}
#define WIN_FUNC_DECL(name, argc)
#define WIN_FUNC_PTR(name, argc) name

#define WIN_FUNC(name, argc) (name)
/* map name s to f - if f is different from s */
#define WIN_SYMBOL_MAP(s, f)

struct pe_image {
        char name[128];
        BOOL WINAPI (*entry)(PVOID hinstDLL, DWORD fdwReason, PVOID lpvReserved);
        void *image;
        int size;
        int type;

        IMAGE_NT_HEADERS *nt_hdr;
        IMAGE_OPTIONAL_HEADER *opt_hdr;
};

struct ntos_work_item {
        struct nt_list list;
        void *arg1;
        void *arg2;
        NTOS_WORK_FUNC func;
};

#define WRAP_DRIVER_CLIENT_ID 1


enum hw_status {
        HW_INITIALIZED = 1, HW_SUSPENDED, HW_HALTED, HW_DISABLED,
};

#define wrap_is_pci_bus(dev_bus)                        \
        (WRAP_BUS(dev_bus) == WRAP_PCI_BUS ||           \
         WRAP_BUS(dev_bus) == WRAP_PCMCIA_BUS)
#ifdef ENABLE_USB
/* earlier versions of ndiswrapper used 0 as USB_BUS */
#define wrap_is_usb_bus(dev_bus)                        \
        (WRAP_BUS(dev_bus) == WRAP_USB_BUS ||           \
         WRAP_BUS(dev_bus) == WRAP_INTERNAL_BUS)
#else
#define wrap_is_usb_bus(dev_bus) 0
#endif
#define wrap_is_bluetooth_device(dev_bus)                       \
        (WRAP_DEVICE(dev_bus) == WRAP_BLUETOOTH_DEVICE1 ||      \
         WRAP_DEVICE(dev_bus) == WRAP_BLUETOOTH_DEVICE2)

extern struct workqueue_struct *ntos_wq;
extern struct workqueue_struct *ndis_wq;
extern struct workqueue_struct *wrapndis_wq;

#define atomic_unary_op(var, size, oper)                                \
do {                                                                    \
        if (size == 1)                                                  \
                __asm__ __volatile__(                                   \
                        LOCK_PREFIX oper "b %b0\n\t" : "+m" (var));     \
        else if (size == 2)                                             \
                __asm__ __volatile__(                                   \
                        LOCK_PREFIX oper "w %w0\n\t" : "+m" (var));     \
        else if (size == 4)                                             \
                __asm__ __volatile__(                                   \
                        LOCK_PREFIX oper "l %0\n\t" : "+m" (var));      \
        else if (size == 8)                                             \
                __asm__ __volatile__(                                   \
                        LOCK_PREFIX oper "q %q0\n\t" : "+m" (var));     \
        else {                                                          \
                extern void _invalid_op_size_(void);                    \
                _invalid_op_size_();                                    \
        }                                                               \
} while (0)

#define atomic_inc_var_size(var, size) atomic_unary_op(var, size, "inc")

#define atomic_inc_var(var) atomic_inc_var_size(var, sizeof(var))

#define atomic_dec_var_size(var, size) atomic_unary_op(var, size, "dec")

#define atomic_dec_var(var) atomic_dec_var_size(var, sizeof(var))

#define pre_atomic_add(var, i)                                  \
({                                                              \
        typeof(var) pre;                                        \
        __asm__ __volatile__(                                   \
                LOCK_PREFIX "xadd %0, %1\n\t"                   \
                : "=r"(pre), "+m"(var)                          \
                : "0"(i));                                      \
        pre;                                                    \
})

#define post_atomic_add(var, i) (pre_atomic_add(var, i) + i)

//#define DEBUG_IRQL 1

#ifdef DEBUG_IRQL
#define assert_irql(cond)                                               \
do {                                                                    \
        KIRQL _irql_ = current_irql();                                  \
        if (!(cond)) {                                                  \
                WARNING("assertion '%s' failed: %d", #cond, _irql_);    \
                DBG_BLOCK(4) {                                          \
                        dump_stack();                                   \
                }                                                       \
        }                                                               \
} while (0)
#else
#define assert_irql(cond) do { } while (0)
#endif

/* When preempt is enabled, we should preempt_disable to raise IRQL to
 * DISPATCH_LEVEL, to be consistent with the semantics. However, using
 * a mutex instead, so that only ndiswrapper threads run one at a time
 * on a processor when at DISPATCH_LEVEL seems to be enough. So that
 * is what we will use until we learn otherwise. If
 * preempt_(en|dis)able is required for some reason, comment out
 * following #define. */

#define WRAP_PREEMPT 1

#if !defined(CONFIG_PREEMPT) || defined(CONFIG_PREEMPT_RT)
#ifndef WRAP_PREEMPT
#define WRAP_PREEMPT 1
#endif
#endif

#endif // _NTOSKERNEL_H_
