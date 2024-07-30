/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * Copyright (C) 2021 Microsoft Corporation
 *
 * Author: Lakshmi Ramasubramanian (nramas@linux.microsoft.com)
 *
 * Measure critical data structures maintained by SELinux
 * using IMA subsystem.
 */

#ifndef _SELINUX_IMA_H_
#define _SELINUX_IMA_H_

#include "security.h"

#ifdef CONFIG_IMA
void __init selinux_ima_config_len_init(void);
void selinux_ima_measure_state(struct selinux_state *selinux_state);
void selinux_ima_measure_state_locked(struct selinux_state *selinux_state);
#else
static inline void selinux_ima_config_len_init(void)
{
}

static inline void
selinux_ima_measure_state(struct selinux_state *selinux_state)
{
}

static inline void
selinux_ima_measure_state_locked(struct selinux_state *selinux_state)
{
}
#endif

#endif /* _SELINUX_IMA_H_ */
