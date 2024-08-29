/* SPDX-License-Identifier: GPL-2.0 */
/*
 * A global security identifier table (sidtab) is a lookup table
 * of security context strings indexed by SID value.
 */

#ifndef _GLOBAL_SIDTAB_H_
#define _GLOBAL_SIDTAB_H_

#include <linux/types.h>

int global_sidtab_init(void);

int global_sid_to_context(u32 sid, char **scontext, u32 *scontext_len);

int global_context_to_sid(const char *scontext, u32 scontext_len,
			  u32 *out_sid, gfp_t gfp);

#endif /* _GLOBAL_SIDTAB_H_ */
