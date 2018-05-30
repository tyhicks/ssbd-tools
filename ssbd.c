/*
 * ssbd.c: Helper functions for interacting with the SSBD bit
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

#include <stdbool.h>
#include <stdio.h>
#include <time.h>

#include "cpu.h"
#include "msr.h"

/* Read the SSBD bit from the MSR corresponding to cpu_id
 *
 * Sets *ssbd to true if the bit is 1, false if the bit is 0.
 *
 * Returns 0 on success. -1 on error.
 */
int read_ssbd_from_msr(int msr_fd, cpu_id cpu_id, bool *ssbd)
{
	uint64_t mask, value;
	off_t msr;

	switch (cpu_id) {
	case CPU_AMD_VIRT:
		msr = AMD64_VIRT_SPEC_CTRL_MSR;
		mask = 1ULL << 2;
		break;
	case CPU_AMD_15H:
		msr = AMD64_LS_CFG_MSR;
		mask = 1ULL << 54;
		break;
	case CPU_AMD_16H:
		msr = AMD64_LS_CFG_MSR;
		mask = 1ULL << 33;
		break;
	case CPU_AMD_17H:
		msr = AMD64_LS_CFG_MSR;
		mask = 1ULL << 10;
		break;
	case CPU_INTEL:
	default:
		msr = IA32_SPEC_CTRL_MSR;
		mask = 1ULL << 2;
	}

	if (read_msr(&value, msr_fd, msr))
		return -1;

	*ssbd = !!(value & mask);
	return 0;
}

/* Reads the SSBD bit from the IA32_SPEC_CTRL MSR and verifies its value
 *
 * The expected argument should be true if the bit is expected to be 1. False
 * if it is expected to be 0.
 *
 * If seconds is 0, loop until the user interrupts the loop. If seconds is
 * (time_t) -1, only verify once. Otherwise, loop until the time at the
 * function entry time added to the number in the seconds argument is reached.
 *
 * Return 0 on success. -1 on error. 1 on a failed verification.
 */
int verify_ssbd(int msr_fd, cpu_id cpu_id, bool expected, time_t seconds)
{
	time_t cur, stop;
	int rc;

	stop = time(NULL);
	if (stop == (time_t) -1) {
		fprintf(stderr, "ERROR: Couldn't initialize the stop timer: %m\n");
		return -1;
	}

	stop += seconds;
	do {
		bool actual;
		int rc = read_ssbd_from_msr(msr_fd, cpu_id, &actual);

		if (rc) {
			fprintf(stderr, "ERROR: Couldn't perform SSBD bit verification\n");
			return -1;
		}

		if (actual != expected) {
			rc = 1;
			fprintf(stderr, "FAIL: SSBD bit verification failed (expected %d, got %d)\n",
				expected, actual);
			return 1;
		}

		cur = time(NULL);
		if (cur == (time_t) -1) {
			fprintf(stderr, "ERROR: Couldn't get the current time: %m\n");
			return -1;
		}
	} while (seconds == 0 ||
		 (seconds != ((time_t) -1) && cur < stop));

	return 0;
}
