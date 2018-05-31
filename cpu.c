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

#define _GNU_SOURCE
#include <cpuid.h>
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#include "cpu.h"

/* Open the /dev/cpu/CPUNUM/msr file where CPUNUM is specified by cpu_num
 *
 * Returns a valid file descriptor, open for reading, on success. -1 on error.
 */
int open_msr_fd(int cpu_num)
{
	char msr_path[64];
	int msr_fd;
	int rc;

	rc = snprintf(msr_path, sizeof(msr_path), "/dev/cpu/%d/msr", cpu_num);
	if (rc < 0 || rc >= sizeof(msr_path) ){
		fprintf(stderr, "ERROR: Couldn't construct the MSR path\n");
		return -1;
	}

	msr_fd = open(msr_path, O_RDONLY | O_CLOEXEC);
	if (msr_fd < 0) {
		if (errno == ENOENT) {
			fprintf(stderr, "ERROR: The msr kernel module is not loaded\n");
		} else {
			fprintf(stderr, "ERROR: Couldn't open MSR file (%s): %m\n",
				msr_path);
		}
		return -1;
	}

	return msr_fd;
}

/* Read the value from the MSR
 *
 * Returns 0 on success. -1 on error.
 */
int read_msr(uint64_t *value, int msr_fd, off_t msr)
{
	int rc;

	rc = pread(msr_fd, value, sizeof(*value), msr);
	if (rc < 0) {
		fprintf(stderr, "ERROR: Couldn't read MSR file: %m\n");
		return -1;
	} else if (rc != sizeof(value)) {
		fprintf(stderr, "ERROR: Short read of the MSR file\n");
		return -1;
	}

	return 0;
}

/* Sets cpu_id in accordance to SSBD support of the current Intel processor
 *
 * Returns 0 on success. -1 on error.
 */
static int identify_intel_cpu(cpu_id *cpu_id, int msr_fd)
{
	uint32_t eax, ebx, ecx, edx;

	__cpuid_count(0x7, 0, eax, ebx, ecx, edx);

	if (!(edx & (1ULL << 31))) {
		*cpu_id = CPU_SSBD_UNSUPPORTED;
		return 0;
	} else if (edx & (1ULL << 29)) {
		uint64_t value;

		if (read_msr(&value, msr_fd, IA32_ARCH_CAPABILITIES_MSR))
			return -1;

		if (value & (1ULL << 4)) {
			*cpu_id = CPU_SSB_UNAFFECTED;
			return 0;
		}
	}

	*cpu_id = CPU_INTEL;
	return 0;
}

/* Sets cpu_id in accordance to SSBD support of the current AMD processor
 *
 * Returns 0 on success. -1 on error.
 */
static int identify_amd_cpu(cpu_id *cpu_id)
{
	uint32_t eax, ebx, ecx, edx;

	__cpuid(0x80000008, eax, ebx, ecx, edx);

	if (ebx & (1ULL << 26)) {
		*cpu_id = CPU_SSB_UNAFFECTED;
	} else if (ebx & (1ULL << 24)) {
		*cpu_id = CPU_INTEL;
	} else if (ebx & (1ULL << 25)) {
		*cpu_id = CPU_AMD_VIRT;
	} else {
		uint32_t base, extended, family;

		__cpuid(0x1, eax, ebx, ecx, edx);
		base = (eax >> 8) & 0xF;
		extended = (eax >> 20) & 0xFF;

		if (base < 0xF) {
			fprintf(stderr,
				"ERROR: AMD family 0x%x doesn't support SSBD\n",
				base);
			return -1;
		}

		family = base + extended;
		switch (family) {
		case 0x15:
			*cpu_id = CPU_AMD_15H;
			break;
		case 0x16:
			*cpu_id = CPU_AMD_16H;
			break;
		case 0x17:
			*cpu_id = CPU_AMD_17H;
			break;
		default:
			fprintf(stderr,
				"ERROR: AMD family 0x%x doesn't support SSBD\n",
				family);
			return -1;
		}
	}

	return 0;
}

static void uint32_to_string(uint32_t i, char s[4])
{
	s[0] = i & 0xFF;
	s[1] = i >> 8 & 0xFF;
	s[2] = i >> 16 & 0xFF;
	s[3] = i >> 24;
}

/* Sets cpu_id in accordance to SSBD support of the current processor
 *
 * Returns 0 on success. -1 on error.
 */
int identify_cpu(cpu_id *cpu_id, int msr_fd)
{
	uint32_t eax, ebx, ecx, edx;
	char vendor[13];

	__cpuid(0, eax, ebx, ecx, edx);
	uint32_to_string(ebx, vendor);
	uint32_to_string(edx, vendor + 4);
	uint32_to_string(ecx, vendor + 8);
	vendor[12] = 0;

	if (!strcmp(vendor, "GenuineIntel")) {
		return identify_intel_cpu(cpu_id, msr_fd);
	} else if (!strcmp(vendor, "AuthenticAMD")) {
		return identify_amd_cpu(cpu_id);
	} else {
		fprintf(stderr, "ERROR: Unsupported CPU vendor: %s\n", vendor);
		return 1;
	}
}

/* Restricts the current process to only run on the specified CPU
 *
 * Returns 0 on success. -1 on error.
 */
int restrict_to_cpu(int cpu_num)
{
	cpu_set_t set;

	CPU_ZERO(&set);
	CPU_SET(cpu_num, &set);
	if (sched_setaffinity(0, sizeof(set), &set) < 0) {
		fprintf(stderr, "ERROR: Couldn't set the CPU affinity mask: %m\n");
		return -1;
	}

	return 0;
}
