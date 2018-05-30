/*
 * msr.h: Helper functions for interacting with MSRs
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

#ifndef __MSR_H
#define __MSR_H

#include <stdint.h>

#define IA32_SPEC_CTRL_MSR		0x48
#define IA32_ARCH_CAPABILITIES_MSR	0x10A
#define AMD64_VIRT_SPEC_CTRL_MSR	0xc001011f
#define AMD64_LS_CFG_MSR		0xc0011020

int open_msr_fd(int cpu_num);
int read_msr(uint64_t *value, int msr_fd, off_t msr);

#endif
