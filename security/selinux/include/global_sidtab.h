/* SPDX-License-Identifier: GPL-2.0 */
/*
 * A global security identifier table (sidtab) is a lookup table
 * of security context strings indexed by SID value.
 */

#ifndef _GLOBAL_SIDTAB_H_
#define _GLOBAL_SIDTAB_H_

#ifdef CONFIG_SECURITY_SELINUX_NS
extern int global_sidtab_init(void);

struct selinux_state;
void global_sidtab_invalidate_state(struct selinux_state *state);
#else
static inline int global_sidtab_init(void)
{
	return 0;
}

static inline void global_sidtab_invalidate_state(struct selinux_state *state)
{
}
#endif /* CONFIG_SECURITY_SELINUX_NS */

#endif /* _GLOBAL_SIDTAB_H_ */
