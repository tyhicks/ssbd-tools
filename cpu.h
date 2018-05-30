/*
 * cpu.c: Helper functions for interacting with CPUs
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

#ifndef __CPU_H
#define __CPU_H

#include <stdint.h>

#define DEFAULT_CPU_NUM		0

typedef enum { CPU_INTEL,
	       CPU_AMD_VIRT,
	       CPU_AMD_15H,
	       CPU_AMD_16H,
	       CPU_AMD_17H,
	       CPU_SSB_UNAFFECTED,
	       CPU_SSBD_UNSUPPORTED,
	      } cpu_id;

int identify_intel_cpu(cpu_id *cpu_id, int msr_fd);
int identify_amd_cpu(cpu_id *cpu_id);
void uint32_to_string(uint32_t i, char s[4]);
int identify_cpu(cpu_id *cpu_id, int msr_fd);
int restrict_to_cpu(int cpu_num);

#endif
