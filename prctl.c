/*
 * prctl.c: Helper functions for interacting with prctl()
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

#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <sys/prctl.h>

#include "cpu.h"
#include "ssbd.h"

/* Verify that the prctl value matches the SSBD bit from the IA32_SPEC_CTRL MSR
 *
 * Returns 0 on success. -1 on error. 1 on a failed verification.
 */
int verify_prctl(int msr_fd, cpu_id cpu_id, int prctl_value)
{
	bool ssbd;

	if (read_ssbd_from_msr(msr_fd, cpu_id, &ssbd)) {
		fprintf(stderr, "ERROR: Couldn't perform prctl value verification\n");
		return -1;
	}

	switch (prctl_value) {
	case PR_SPEC_NOT_AFFECTED:
	case PR_SPEC_PRCTL | PR_SPEC_ENABLE:
		if (ssbd) {
			fprintf(stderr, "FAIL: SSBD bit of the IA32_SPEC_CTRL MSR is unexpectedly set\n");
			return 1;
		}
		break;
	case PR_SPEC_PRCTL | PR_SPEC_DISABLE:
	case PR_SPEC_PRCTL | PR_SPEC_FORCE_DISABLE:
	case PR_SPEC_DISABLE:
		if (!ssbd) {
			fprintf(stderr, "FAIL: SSBD bit of the IA32_SPEC_CTRL MSR is unexpectedly clear\n");
			return 1;
		}
		break;
	default:
		fprintf(stderr, "ERROR: Couldn't verify Unknown prctl value (0x%x)\n",
			prctl_value);
		return -1;
	}

	return 0;
}

/* Get the value of the PR_SPEC_STORE_BYPASS prctl
 *
 * Returns the value on success. -1 on error.
 */
int get_prctl(void)
{
	int rc = prctl(PR_GET_SPECULATION_CTRL, PR_SPEC_STORE_BYPASS, 0, 0, 0);

	if (rc < 0) {
		if (errno == EINVAL)
			fprintf(stderr, "ERROR: This kernel does not support per-process speculation control\n");
		else
			fprintf(stderr, "ERROR: Couldn't get the value of the PR_SPEC_STORE_BYPASS prctl: %m\n");
		return -1;
	} else if (!(rc & PR_SPEC_PRCTL)) {
		fprintf(stderr, "ERROR: Speculation cannot be controlled via prctl\n");
		return -1;
	}

	return rc;
}

/* Set the value of the PR_SPEC_STORE_BYPASS prctl
 *
 * Returns 0 on success. -1 on error.
 */
int set_prctl(unsigned long value)
{
	int rc;

	rc = get_prctl();
	if (rc < 0) {
		fprintf(stderr, "ERROR: Couldn't get the value of the PR_SPEC_STORE_BYPASS prctl and, therefore, cannot set it\n");
		return -1;
	}

	rc = prctl(PR_SET_SPECULATION_CTRL, PR_SPEC_STORE_BYPASS, value, 0, 0);
	if (rc < 0) {
		fprintf(stderr, "ERROR: Couldn't set the value of the PR_SPEC_STORE_BYPASS prctl: %m\n");
		return -1;
	}

	return 0;
}

/* Prints a string representation of the PR_SPEC_STORE_BYPASS prctl value */
void print_prctl(int ssbd)
{
	/* The printed strings should match what's in the kernel's
	 * task_seccomp() function
	 */
	switch (ssbd) {
	case PR_SPEC_NOT_AFFECTED:
		printf("not vulnerable\n");
		break;
	case PR_SPEC_PRCTL | PR_SPEC_DISABLE:
		printf("thread mitigated\n");
		break;
	case PR_SPEC_PRCTL | PR_SPEC_FORCE_DISABLE:
		printf("thread force mitigated\n");
		break;
	case PR_SPEC_PRCTL | PR_SPEC_ENABLE:
		printf("thread vulnerable\n");
		break;
	case PR_SPEC_DISABLE:
		printf("globally mitigated\n");
		break;
	default:
		printf("vulnerable\n");
		break;
	}
}
