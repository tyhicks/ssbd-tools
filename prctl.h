/*
 * prctl.h: Helper functions for interacting with prctl()
 * Copyright (C) 2018 Canonical LTD.
 * Author: Tyler Hicks <tyhicks@canonical.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301,
 * USA.
 */

#ifndef __PRCTL_H
#define __PRCTL_H

#include "cpu.h"

#ifndef PR_GET_SPECULATION_CTRL
#define PR_GET_SPECULATION_CTRL 52
#endif

#ifndef PR_SET_SPECULATION_CTRL
#define PR_SET_SPECULATION_CTRL 53
#endif

/* Speculation control variants */
#ifndef PR_SPEC_STORE_BYPASS
#define PR_SPEC_STORE_BYPASS	0
#endif

/* Return and control values for PR_SET/GET_SPECULATION_CTRL */
#ifndef PR_SPEC_NOT_AFFECTED
#define PR_SPEC_NOT_AFFECTED	0
#endif

#ifndef PR_SPEC_PRCTL
#define PR_SPEC_PRCTL		(1UL << 0)
#endif

#ifndef PR_SPEC_ENABLE
#define PR_SPEC_ENABLE		(1UL << 1)
#endif

#ifndef PR_SPEC_DISABLE
#define PR_SPEC_DISABLE		(1UL << 2)
#endif

#ifndef PR_SPEC_FORCE_DISABLE
#define PR_SPEC_FORCE_DISABLE	(1UL << 3)
#endif

int get_prctl(void);
int set_prctl(unsigned long value);

#endif
